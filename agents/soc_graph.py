import os
from langgraph.graph import StateGraph, START, END, MessagesState
from langgraph.checkpoint.memory import MemorySaver
from langchain_core.messages import HumanMessage, AIMessage, ToolMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI

# Tutti i tools divisi per Agente
from tools.security_tools import query_siem, check_ip_reputation, draft_firewall_rule, deploy_honeypot, ip_geolocation

# LLM Config
llm = ChatGoogleGenerativeAI(
    model=os.environ.get("FW_AGENT_MODEL", "gemini-2.5-flash"), temperature=0,
    api_key=os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY"),
)


class SOCState(MessagesState):
    # Questi campi vengono impostati dalla UI, mai dai messaggi o dagli argomenti del modello.
    approved_actions: list[str]
    approved_ips: list[str]


MITIGATION_TOOLS = {"draft_firewall_rule", "deploy_honeypot"}
# --- FUNZIONE HELPER PER ESEGUIRE QUALSIASI AGENTE ---
def run_agent_loop(agent_llm, tools_dict, messages, system_content, approved_actions=(), approved_ips=()):
    """Esegue un ciclo LLM locale finché non esaurisce i tool."""
    new_messages = []
    sys_prompt = SystemMessage(content=system_content)
    msgs_to_run = [sys_prompt] + messages.copy()

    used_actions = set()
    for _ in range(8):
        try:
            response = agent_llm.invoke(msgs_to_run)
        except Exception:
            # Conserva gli output già ottenuti e consente al nodo di consumare i permessi.
            new_messages.append(AIMessage(content=(
                "MODEL ERROR: risposta non disponibile. Consulta i risultati dei tool già eseguiti; "
                "non viene confermata alcuna azione aggiuntiva. Per un nuovo tentativo usa i controlli della UI."
            )))
            break
        new_messages.append(response)
        msgs_to_run.append(response)

        if not response.tool_calls:
            break

        for tool_call in response.tool_calls:
            tool_name = tool_call["name"]
            tool_args = tool_call["args"]
            tool_id = tool_call["id"]

            target_ip = tool_args.get("ip_address") if tool_name == "draft_firewall_rule" else tool_args.get("attacker_ip")
            action_key = (tool_name, target_ip)
            if tool_name in MITIGATION_TOOLS and (
                tool_name not in approved_actions or target_ip not in approved_ips
            ):
                tool_result = "APPROVAL REQUIRED: use the UI to confirm this action and the selected IPv4 address."
            elif tool_name in MITIGATION_TOOLS and action_key in used_actions:
                tool_result = "ACTION ALREADY ATTEMPTED: another UI confirmation is required to retry."
            elif tool_name in tools_dict:
                used_actions.add(action_key)
                try:
                    tool_result = tools_dict[tool_name].invoke(tool_args)
                except Exception as e:
                    tool_result = f"Errore interno del tool: {str(e)}"
            else:
                tool_result = f"Errore: Tool {tool_name} non riconosciuto."

            tool_msg = ToolMessage(content=str(tool_result), tool_call_id=tool_id, name=tool_name)
            new_messages.append(tool_msg)
            msgs_to_run.append(tool_msg)

    else:
        new_messages.append(AIMessage(content="Limite di passaggi raggiunto. Rivedi i risultati prima di continuare."))
    return new_messages

# --- CONFIGURAZIONE STRUMENTI PER I 3 AGENTI ---
triage_tools = [query_siem]
triage_llm = llm.bind_tools(triage_tools)
triage_dict = {t.name: t for t in triage_tools}

network_tools = [check_ip_reputation, ip_geolocation]
network_llm = llm.bind_tools(network_tools)
network_dict = {t.name: t for t in network_tools}

mitigation_tools = [draft_firewall_rule, deploy_honeypot]
mitigation_llm = llm.bind_tools(mitigation_tools)
mitigation_dict = {t.name: t for t in mitigation_tools}


# --- DEFINIZIONE DEI NODI (LE 3 PERSONAS E L'UMANO) ---

def triage_agent_node(state: MessagesState):
    """Agente 1: Livello 1 SOC. Legge i log e estrae il succo."""
    sys_content = """Analizzi un dataset SINTETICO per un prototipo SOC da hackathon, non una rete reale. Esegui il triage degli alert dimostrativi:
1. Esegui query_siem con i termini: 'encryption', 'failed', 'failure', 'brute', 'login', 'port_scan' per mappare ogni superficie d'attacco.
2. Per OGNI attività ostile rilevata (Ransomware, Brute Force, Scanning, ecc.), riporta:
   - Tipo di Minaccia e Gravità (CRITICO / ALTO / MEDIO)
   - Timestamp dell'evento e Host Target (es. Server_HR, Server_DB)
   - IP di origine (interni ed esterni) e dettagli del payload/evento.
3. Elabora una valutazione iniziale dell'incidente, spiegandone l'impatto potenziale se non mitigato.
Stile: Professionale, tecnico, esauriente. NON menzionare altri agenti, ma fornisci un report forense completo."""

    news = run_agent_loop(triage_llm, triage_dict, state["messages"], sys_content)
    return {"messages": news}

def network_agent_node(state: MessagesState):
    """Agente 2: Espande la visibilità. Indaga l'IP trovato dall'Agente 1."""
    sys_content = """Sei il modulo Network Intelligence di un prototipo SOC dimostrativo. Distingui sempre dati sintetici e informazioni esterne reali. Non inventare geolocalizzazioni o conferme di blocco. Analizza i dati tecnici forniti dal triage:
1. Estrai univocamente ogni IP sospetto o compromesso (interni ed esterni).
2. Per OGNI IP, esegui ip_geolocation e check_ip_reputation.
3. Elabora un "Unified Cyber Threat Intelligence Report" includendo:
   - Analisi Geografica Completa (Nazione, Città, ISP) - Formato richiesto: [COORD: lat, lon].
   - Reputazione Storica e Indicatori di Compromissione (IoC).
   - Analisi Comportamentale (es. 'L'attaccante sta eseguendo un brute force mirato dopo uno scanning').
   - Consigli per la Mitigazione immediata.
Stile: Puro report di intelligence forense, strutturato in sezioni chiare tramite Markdown. Termina invitando l'operatore a usare i controlli della UI per preparare bozze firewall o richiedere il container dimostrativo."""

    news = run_agent_loop(network_llm, network_dict, state["messages"], sys_content)
    return {"messages": news}

def human_approval_node(state: MessagesState):
    """Breakpoint."""
    print("\n[!] In attesa di approvazione umana...\n")
    return state

def action_node(state: SOCState):
    """Agente 3: Il Mitigatore. Esegue il volere dell'umano."""
    sys_content = """Sei l'assistente di mitigazione di un prototipo da hackathon. L'umano ha appena scritto un messaggio.
I tool sono autorizzati dal codice solo per le azioni e gli IP selezionati nella UI.
Il firewall tool genera SOLO bozze, mai regole applicate. deploy_honeypot simula o avvia un web server dimostrativo LOCALE: non blocca traffico e non è un honeypot completo.
Riporta fedelmente SIMULATION, ERROR, RULE DRAFT e DEMO CONTAINER STARTED restituiti dai tool. Non trasformare una simulazione o un errore in un successo reale.
- SE l'umano ti FA UNA DOMANDA (es. 'quali altri attacchi ci sono?'): DEVI SOLO RISPONDERE A PAROLE usando i dati dello storico. **NON devi usare i tool di mitigazione**.
- Per richiedere una bozza o un container, usa i tool solo secondo la scelta esplicita nella UI. Se ricevi APPROVAL REQUIRED, invita l'utente a confermare dai pulsanti senza tentare altri tool.
REGOLA FONDAMENTALE: Non dire che l'IP è stato bloccato. Fornisci SEMPRE il testo della regola (es. iptables) o la conferma del deploy dell'honeypot. L'utente deve poter leggere e confermare l'azione.
DEVI TASSATIVAMENTE restituire in chat l'output esatto che ha sputato fuori la shell o il tool (es. la stringa 'iptables -A ...')."""

    news = run_agent_loop(mitigation_llm, mitigation_dict, state["messages"], sys_content,
                          state.get("approved_actions", []), state.get("approved_ips", []))
    return {"messages": news, "approved_actions": [], "approved_ips": []}


# --- COSTRUZIONE DEL GRAFO MULTI-AGENTE PIPELINE ---
builder = StateGraph(SOCState)

builder.add_node("triage_agent_node", triage_agent_node)
builder.add_node("network_agent_node", network_agent_node)
builder.add_node("human_approval_node", human_approval_node)
builder.add_node("action_node", action_node)

# Flusso a "Catena di Montaggio" del SOC con LOOP CONVERSAZIONALE ALLA FINE
builder.add_edge(START, "triage_agent_node")
builder.add_edge("triage_agent_node", "network_agent_node")
builder.add_edge("network_agent_node", "human_approval_node")
builder.add_edge("human_approval_node", "action_node")
builder.add_edge("action_node", "human_approval_node") # <-- LOOP ITERATIVO!

memory = MemorySaver()
graph = builder.compile(checkpointer=memory, interrupt_before=["human_approval_node"])
