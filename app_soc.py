import streamlit as st
import os
import json
import pandas as pd
import re
import uuid
import ipaddress
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

from langchain_core.messages import HumanMessage

st.set_page_config(layout="wide", page_title="FW-Agent SOC", page_icon="🛡️", initial_sidebar_state="collapsed")

CUSTOM_CSS = """
<style>
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
.stApp { background-color: #0b0f19; color: #e2e8f0; font-family: 'Inter', sans-serif; }
div[data-testid="stButton"] > button:has(p:contains("🔴 Regola FW")) { border: 2px solid #ef4444 !important; background: rgba(239,68,68,0.1) !important; color: #ef4444 !important; animation: glow-red 1.5s infinite alternate; }
div[data-testid="stButton"] > button:has(p:contains("🍯 Attiva Honeypot")) { border: 2px solid #3b82f6 !important; background: rgba(59,130,246,0.1) !important; color: #3b82f6 !important; animation: glow-blue 1.5s infinite alternate; }
div[data-testid="stButton"] > button:has(p:contains("🔄 Esegui Tutto")) { border: 2px solid #8b5cf6 !important; background: rgba(139,92,246,0.1) !important; color: #a78bfa !important; animation: glow-purple 1.5s infinite alternate; }
@keyframes glow-red { from { box-shadow: 0 0 5px rgba(239,68,68,0.4); } to { box-shadow: 0 0 20px rgba(239,68,68,0.8); } }
@keyframes glow-blue { from { box-shadow: 0 0 5px rgba(59,130,246,0.4); } to { box-shadow: 0 0 20px rgba(59,130,246,0.8); } }
@keyframes glow-purple { from { box-shadow: 0 0 5px rgba(139,92,246,0.4); } to { box-shadow: 0 0 20px rgba(139,92,246,0.8); } }
[data-testid="stChatMessage"] { background: rgba(30, 41, 59, 0.6); border-radius: 12px; padding: 1.2rem; margin-bottom: 1rem; border-left: 4px solid #38bdf8; box-shadow: 0 4px 6px rgba(0,0,0,0.2); }
[data-testid="stMetricValue"] { font-size: 2.2rem !important; font-weight: 800 !important; }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

API_AVAILABLE = bool(os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY"))
DOCKER_ENABLED = os.environ.get("FW_AGENT_ENABLE_DOCKER", "false").lower() == "true"

st.caption("Prototipo da hackathon · Dataset e scenari dimostrativi · Nessuna regola firewall viene applicata")
if not API_AVAILABLE:
    st.info("Dashboard offline: puoi esplorare i dati. Per l'analisi AI, configura GOOGLE_API_KEY nel file .env.")

for key, default in {
    "thread_id": str(uuid.uuid4()), "messages": [], "map_coords": [],
    "detected_ips": [], "is_paused_status": False,
}.items():
    if key not in st.session_state:
        st.session_state[key] = default


@st.cache_resource
def load_agent_graph():
    # Il client Gemini viene creato solo dopo una richiesta esplicita di analisi.
    from agents.soc_graph import graph
    return graph


def process_and_stream(user_prompt, approved_actions=(), approved_ips=()):
    """Trasmette messaggi e autorizzazioni separate; la chat non concede permessi."""
    if not API_AVAILABLE:
        st.warning("Configura una chiave API per utilizzare l'assistente.")
        return
    st.session_state.messages.append({"role": "user", "content": user_prompt})
    try:
        app_graph = load_agent_graph()
        config = {"configurable": {"thread_id": st.session_state.thread_id}}
        current_state = app_graph.get_state(config)
        seen = {m.id or id(m) for m in current_state.values.get("messages", [])}
        update = {
            "messages": [HumanMessage(content=user_prompt)],
            "approved_actions": list(approved_actions), "approved_ips": list(approved_ips),
        }
        if "human_approval_node" in current_state.next:
            app_graph.update_state(config, update, as_node="human_approval_node")
            graph_input = None
        else:
            graph_input = update
        with st.spinner("Analisi del dataset dimostrativo in corso..."):
            for event in app_graph.stream(graph_input, config=config, stream_mode="values"):
                for message in event.get("messages", []):
                    message_id = message.id or id(message)
                    if message_id in seen:
                        continue
                    seen.add(message_id)
                    if message.type not in {"ai", "tool"} or not message.content:
                        continue
                    if isinstance(message.content, list):
                        text = " ".join(str(p["text"]) for p in message.content if isinstance(p, dict) and "text" in p)
                    else:
                        text = str(message.content)
                    source = "tool" if message.type == "tool" else "assistant"
                    content = f"**Tool: `{message.name}`**\n\n{text}" if source == "tool" else text
                    st.session_state.messages.append({"role": "assistant", "source": source, "content": content})
                    # La mappa usa gli output dei tool, non coordinate inventate dal modello.
                    if source == "tool":
                        for lat, lon in re.findall(r"\[COORD:\s*([0-9.-]+),\s*([0-9.-]+)\]", text):
                            point = {"lat": float(lat), "lon": float(lon)}
                            if -90 <= point["lat"] <= 90 and -180 <= point["lon"] <= 180 and point not in st.session_state.map_coords:
                                st.session_state.map_coords.append(point)
                    for candidate in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
                        try:
                            ipaddress.IPv4Address(candidate)
                        except ipaddress.AddressValueError:
                            continue
                        if candidate not in st.session_state.detected_ips and not candidate.startswith("127."):
                            st.session_state.detected_ips.append(candidate)
        st.session_state.is_paused_status = "human_approval_node" in app_graph.get_state(config).next
    except Exception:
        st.error("Analisi non completata. Controlla la configurazione API, l'accesso al modello e la connessione; nessuna mitigazione è confermata da questo messaggio.")
        return
    st.rerun()


with st.sidebar:
    st.header("⚙️ SOC Config")
    st.caption("Docker: demo locale abilitata" if DOCKER_ENABLED else "Docker: sola simulazione")
    if st.button("🔄 Reset Applicazione", width="stretch"):
        st.session_state.clear()
        st.rerun()

# I contatori derivano solo dai dati letti dal file, senza incrementi casuali.
data_path = Path(__file__).resolve().parent / "data" / "siem_logs.json"
try:
    logs_data = json.loads(data_path.read_text(encoding="utf-8"))
    df_logs = pd.DataFrame(logs_data)
    anomaly_types = {"mass_file_encryption", "port_scan_detected", "ssh_login_failed_bruteforce", "multiple_login_failures"}
    df_logs["Anomalia"] = df_logs["event_type"].isin(anomaly_types).map({True: "🚨 SI", False: "No"})
    df_logs = df_logs.sort_values(by="Anomalia", ascending=False).reset_index(drop=True)
except (OSError, ValueError, KeyError, TypeError):
    st.error("Dataset dimostrativo non disponibile o non valido.")
    df_logs = pd.DataFrame()

c1, c2 = st.columns([1, 1.2], gap="large")
with c1:
    st.image(str(Path(__file__).resolve().parent / "assets" / "Logo.png"), width=220)
    st.subheader("Analisi SIEM — dati sintetici")
    anomalies_count = int((df_logs["Anomalia"] == "🚨 SI").sum()) if not df_logs.empty else 0
    m1, m2, m3 = st.columns(3)
    m1.metric("Log SIEM", value=str(len(df_logs)))
    m2.metric("Eventi anomali", value=str(anomalies_count))
    m3.metric("Ambiente", value="DEMO")
    if not df_logs.empty:
        st.markdown("**Frequenza delle categorie di eventi**")
        st.bar_chart(df_logs["event_type"].value_counts(), height=180, color="#3b82f6")
        st.markdown("**Log del dataset dimostrativo**")
        st.dataframe(df_logs[["timestamp", "source_ip", "target_host", "event_type", "Anomalia"]], height=440, width="stretch", hide_index=True)

with c2:
    st.subheader("Assistente SOC")
    if st.button("Analizza i log", key="analyse_logs", disabled=not API_AVAILABLE, width="stretch"):
        for key, value in {"thread_id": str(uuid.uuid4()), "messages": [], "map_coords": [], "detected_ips": [], "is_paused_status": False}.items():
            st.session_state[key] = value
        process_and_stream("Analizza i log sintetici e descrivi le anomalie presenti nel dataset dimostrativo.")
    with st.container(height=650):
        if not st.session_state.messages:
            st.info("Esplora i log a sinistra. Con una chiave API configurata, avvia l'analisi per ottenere triage, arricchimento degli IP e proposte di mitigazione.")
        for message in st.session_state.messages:
            avatar = "🔧" if message.get("source") == "tool" else ("👤" if message["role"] == "user" else "🛡️")
            with st.chat_message(message["role"], avatar=avatar):
                content = re.sub(r"\[COORD:[^\]]+\]", "", message["content"])
                if message.get("source") == "tool":
                    with st.expander("Risultato del tool"):
                        st.markdown(content)
                else:
                    st.markdown(content)
    if st.session_state.is_paused_status:
        st.divider()
        selected_ips = st.multiselect("IP da includere nell'azione", options=st.session_state.detected_ips, default=st.session_state.detected_ips)
        confirmed = st.checkbox("Confermo l'azione scelta per gli IP selezionati", key="confirm_actions")
        st.caption("Le regole vengono solo preparate. Il container web è una demo locale e non blocca traffico.")
        disabled = not confirmed or not selected_ips or not API_AVAILABLE
        ip_list = ", ".join(selected_ips)
        b1, b2, b3 = st.columns(3)
        if b1.button("Prepara regole", key="fw", disabled=disabled, width="stretch"):
            process_and_stream(f"Prepara bozze iptables per: {ip_list}.", ["draft_firewall_rule"], selected_ips)
        if b2.button("Demo container", key="hp", disabled=disabled, width="stretch"):
            process_and_stream(f"Richiedi il container web dimostrativo locale con target_server='demo' per: {ip_list}.", ["deploy_honeypot"], selected_ips)
        if b3.button("Entrambe", key="both", disabled=disabled, width="stretch"):
            process_and_stream(f"Prepara bozze iptables e richiedi il container web dimostrativo locale target_server='demo' per: {ip_list}.", ["draft_firewall_rule", "deploy_honeypot"], selected_ips)
    user_input = st.chat_input("Chiedi informazioni sul dataset...", disabled=not API_AVAILABLE)
    if user_input:
        process_and_stream(user_input)

st.divider()
st.subheader("Coordinate degli IP")
st.caption("Gli IP esterni del dataset sono riservati alla documentazione; le loro coordinate sono sintetiche e chiaramente etichettate dai tool.")
if st.session_state.map_coords:
    st.map(pd.DataFrame(st.session_state.map_coords), zoom=1, color="#ef4444")
else:
    st.info("Nessuna coordinata disponibile. La mappa viene popolata dagli output dei tool dopo l'analisi.")
