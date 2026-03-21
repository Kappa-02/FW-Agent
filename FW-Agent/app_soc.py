import streamlit as st
import os
import json
import time
import random
import pandas as pd
import re
import uuid
from dotenv import load_dotenv

load_dotenv()

from langchain_core.messages import HumanMessage, AIMessage, ToolMessage
from agents.soc_graph import graph as app_graph

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

if "thread_id" not in st.session_state: st.session_state.thread_id = str(uuid.uuid4())
if "messages" not in st.session_state: st.session_state.messages = []
if "first_run" not in st.session_state: st.session_state.first_run = True
if "map_coords" not in st.session_state: st.session_state.map_coords = []
if "detected_ips" not in st.session_state: st.session_state.detected_ips = []
if "is_paused_status" not in st.session_state: st.session_state.is_paused_status = False

def process_and_stream(user_prompt: str, show_in_ui: bool = True):
    """Funzione core: inietta il prompt nel LangGraph e aggiorna la UI step by step."""
    config = {"configurable": {"thread_id": st.session_state.thread_id}}
    
    if show_in_ui:
        st.session_state.messages.append({"role": "user", "content": user_prompt})
    current_state = app_graph.get_state(config)
    is_paused = current_state.next and "human_approval_node" in current_state.next
    
    kwargs = {"config": config, "stream_mode": "values"}
    if is_paused:
        app_graph.update_state(config, {"messages": [HumanMessage(content=user_prompt)]}, as_node="human_approval_node")
        kwargs["input"] = None
    else:
        kwargs["input"] = {"messages": [HumanMessage(content=user_prompt)]}
    
    with st.spinner("L'Orchestratore SOC sta investigando..."):
        last_seen_id = None
        for event in app_graph.stream(**kwargs):
            if "messages" in event:
                last_msg = event["messages"][-1]
                msg_id = getattr(last_msg, "id", None) or id(last_msg)
                if last_msg.type == "ai" and last_msg.content and msg_id != last_seen_id:
                    last_seen_id = msg_id
                    raw_c = last_msg.content
                    if isinstance(raw_c, list):
                        content_str = " ".join([str(p["text"]) for p in raw_c if isinstance(p, dict) and "text" in p])
                    else:
                        content_str = str(raw_c)
                        
                    if len(st.session_state.messages) == 0 or st.session_state.messages[-1]["content"] != content_str:
                        st.session_state.messages.append({"role": "assistant", "content": content_str})
                    
                    # Estrazione Coordinate (Super Flessibile: cattura ogni variazione di spazi)
                    matches = re.findall(r"\[COORD:\s?([0-9.-]+),\s*([0-9.-]+)\]", content_str)
                    for lat, lon in matches:
                        try:
                            if not any(c["lat"] == float(lat) and c["lon"] == float(lon) for c in st.session_state.map_coords):
                                st.session_state.map_coords.append({"lat": float(lat), "lon": float(lon)})
                        except: pass
                    
                    # Estrazione IP per Multiselect
                    ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content_str)
                    for ip in ip_matches:
                        if ip not in st.session_state.detected_ips and not ip.startswith("127."):
                            st.session_state.detected_ips.append(ip)
        
    final_state = app_graph.get_state(config)
    st.session_state.is_paused_status = final_state.next and "human_approval_node" in final_state.next
    st.rerun()

with st.sidebar:
    st.header("⚙️ SOC Config")
    if st.button("🔄 Reset Applicazione", use_container_width=True):
        st.session_state.clear()
        st.rerun()

# --------------------
# CARICAMENTO DATI REALI
# --------------------
data_path = os.path.join(os.path.dirname(__file__), "data", "siem_logs.json")
try:
    with open(data_path, "r", encoding="utf-8") as f:
        logs_data = json.load(f)
    df_logs = pd.DataFrame(logs_data)
    # Identifica le anomalie
    anomaly_types = ['mass_file_encryption', 'port_scan_detected', 'ssh_login_failed_bruteforce', 'multiple_login_failures']
    df_logs['Anomalia'] = df_logs['event_type'].isin(anomaly_types).apply(lambda x: "🚨 SI" if x else "No")
    df_logs = df_logs.sort_values(by='Anomalia', ascending=False).reset_index(drop=True)
    
    # FORZATURA COORDINATE PER DEMO (Pre-caricamento per garantire la visualizzazione)
    demo_coords = [
        {"lat": 55.7558, "lon": 37.6173},   # Mosca (IP 185.11.22.33)
        {"lat": 39.9042, "lon": 116.4074}   # Pechino (IP 45.33.22.11)
    ]
    for c in demo_coords:
        if not any(sc["lat"] == c["lat"] and sc["lon"] == c["lon"] for sc in st.session_state.map_coords):
            st.session_state.map_coords.append(c)
except Exception as e:
    df_logs = pd.DataFrame()

# --------------------
# ESECUZIONE INIZIALE
# --------------------
if st.session_state.first_run:
    st.session_state.first_run = False
    process_and_stream("analizza i log e trova tutte le minacce attive nella rete", show_in_ui=False)

# --------------------
# LAYOUT PRINCIPALE (Ottimizzato e compatto)
# --------------------
c1, c2 = st.columns([1, 1.2], gap="large")

with c1:
    try:
        logo_path = os.path.join(os.path.dirname(__file__), "image", "Logo.png")
        st.image(logo_path, width=220)
    except:
        pass
    
    st.subheader("📊 Analisi SIEM")
    
    # Conteggio reale log e anomalie
    try:
        data_path = os.path.join(os.path.dirname(__file__), "data", "siem_logs.json")
        with open(data_path, "r", encoding="utf-8") as f:
            total_logs_count = len(json.load(f))
        
        # Conta le anomalie reali dal DF
        anomalies_count = (df_logs['Anomalia'] == "🚨 SI").sum()
    except Exception:
        total_logs_count = 15420
        anomalies_count = 0
        
    m1, m2, m3 = st.columns(3)
    m1.metric("Log SIEM", value=str(total_logs_count), delta=f"+{random.randint(5, 15)}", delta_color="normal")
    m2.metric("Incidenti Rilevati", value=str(anomalies_count), delta="Minacce Attive", delta_color="inverse")
    m3.metric("Livello Rischio", value="CRITICO", delta="Inbound/Outbound", delta_color="inverse")
    
    # Grafico a Torta Eventi
    if not df_logs.empty:
        st.markdown("**Frequenza Categorie di Eventi**")
        event_counts = df_logs['event_type'].value_counts()
        st.bar_chart(event_counts, height=180, color="#3b82f6")
    
    # Rimosso st.info che appariva sempre qui al centro della Dashboard
    pass

    # Dataframe filtrato e colorato delle anomalie
    st.markdown("**🔎 Estratto Log Raw (Risaltano Anomalie)**")
    if not df_logs.empty:
        def highlight_entire_row(row):
            if row['Anomalia'] == '🚨 SI':
                return ['background-color: rgba(239, 68, 68, 0.35); color: #ef4444; font-weight: bold'] * len(row)
            return [''] * len(row)
        
        st.dataframe(
            df_logs[['timestamp', 'source_ip', 'target_host', 'event_type', 'Anomalia']].style.apply(highlight_entire_row, axis=1), 
            height=580, 
            use_container_width=True,
            column_order=('timestamp', 'source_ip', 'target_host', 'event_type') # HIDE ANOMALIA BUT KEEP FOR STYLE
        )

with c2:
    st.subheader("💬 Assistente SOC")
    # Altezza massiva per essere in linea con Logo + Metriche + Grafici + Tabella Log
    chat_container = st.container(height=950)
    with chat_container:
        for msg in st.session_state.messages:
            clean_content = re.sub(r"\[COORD:[^\]]+\]", "", msg["content"])
            if msg["role"] == "user": avatar = "👤"
            elif "triage" in clean_content.lower() or "sono stati rilevati" in clean_content.lower() or "log" in clean_content.lower(): avatar = "📡"
            elif "network" in clean_content.lower() or "report" in clean_content.lower() or "geolocalizzazione" in clean_content.lower(): avatar = "🌍"
            else: avatar = "🛡️"
            
            with st.chat_message(name=msg["role"], avatar=avatar):
                st.markdown(clean_content)
    
    if st.session_state.is_paused_status:
        st.markdown("<hr style='border-color: #ef4444;'>", unsafe_allow_html=True)
        # Selettore IP dinamico
        selected_ips = st.multiselect("🎯 Seleziona IP Target per la mitigazione:", options=st.session_state.detected_ips, default=st.session_state.detected_ips)
        ip_list_str = ", ".join(selected_ips) if selected_ips else "gli IP rilevati"
        
        b1, b2, b3 = st.columns(3)
        if b1.button("🔴 Regola FW", key="fw", use_container_width=True):
            process_and_stream(f"Genera immediatamente la regola firewall iptables per bloccare: {ip_list_str}.")
        if b2.button("🍯 Attiva Honeypot", key="hp", use_container_width=True):
            process_and_stream(f"Configura ed esegui il deploy di un honeypot Docker per distrarre i seguenti IP: {ip_list_str}.")
        if b3.button("🔄 Esegui Tutto", key="both", use_container_width=True):
            process_and_stream(f"Attuazione protocollo completo: genera regole firewall ed honeypot per: {ip_list_str}.")

    user_input = st.chat_input("Istruzioni al SOC (es. 'quali porte sono attaccate?')...")
    if user_input:
        process_and_stream(user_input)

# --------------------
# MAPPA DINAMICA FULL-WIDTH (In fondo per impatto visivo massimo)
# --------------------
st.markdown("<br><hr>", unsafe_allow_html=True)
st.markdown("<h3 style='text-align: center;'>🌍 Mappa Globale delle Minacce</h3>", unsafe_allow_html=True)
if len(st.session_state.map_coords) > 0:
    df_map = pd.DataFrame(st.session_state.map_coords)
    # Streamlit map è reattiva alla larghezza del contenitore (qui full width)
    st.map(df_map, zoom=1, color="#ef4444")
else:
    st.info("In attesa di dati geospaziali per il rendering della mappa globale...")
