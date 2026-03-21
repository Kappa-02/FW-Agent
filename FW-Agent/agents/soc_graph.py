from typing import Annotated
from langgraph.graph import StateGraph, START, END, MessagesState
from langgraph.checkpoint.memory import MemorySaver
from langchain_core.messages import HumanMessage, AIMessage, ToolMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI

# Tutti i tools divisi per Agente
from tools.security_tools import query_siem, check_ip_reputation, draft_firewall_rule, deploy_honeypot, ip_geolocation

# LLM Config
llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)
# --- FUNZIONE HELPER PER ESEGUIRE QUALSIASI AGENTE ---
def run_agent_loop(agent_llm, tools_dict, messages, system_content):
    """Esegue un ciclo LLM locale finché non esaurisce i tool."""
    new_messages = []
    sys_prompt = SystemMessage(content=system_content)
    msgs_to_run = [sys_prompt] + messages.copy()
    
    while True:
        response = agent_llm.invoke(msgs_to_run)
        new_messages.append(response)
        msgs_to_run.append(response)
        
        if not response.tool_calls:
            break
            
        for tool_call in response.tool_calls:
            tool_name = tool_call["name"]
            tool_args = tool_call["args"]
            tool_id = tool_call["id"]
            
            print(f"[*] Tool in esecuzione: {tool_name} con arg: {tool_args}")
            
            if tool_name in tools_dict:
                try:
                    tool_result = tools_dict[tool_name].invoke(tool_args)
                except Exception as e:
                    tool_result = f"Errore interno del tool: {str(e)}"
            else:
                tool_result = f"Errore: Tool {tool_name} non riconosciuto."
                
            tool_msg = ToolMessage(content=str(tool_result), tool_call_id=tool_id, name=tool_name)
            new_messages.append(tool_msg)
            msgs_to_run.append(tool_msg)
            
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
    sys_content = """Sei un Analista SOC Senior. Esegui il Triage Automatizzato degli alert SIEM con estremo dettaglio:
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
    sys_content = """Sei il Modulo Network Intelligence del Cyber Security Operation Center. Analizza i dati tecnici forniti dal triage:
1. Estrai univocamente ogni IP sospetto o compromesso (interni ed esterni).
2. Per OGNI IP, esegui ip_geolocation e check_ip_reputation.
3. Elabora un "Unified Cyber Threat Intelligence Report" includendo:
   - Analisi Geografica Completa (Nazione, Città, ISP) - Formato richiesto: [COORD: lat, lon].
   - Reputazione Storica e Indicatori di Compromissione (IoC).
   - Analisi Comportamentale (es. 'L'attaccante sta eseguendo un brute force mirato dopo uno scanning').
   - Consigli per la Mitigazione immediata.
Stile: Puro report di intelligence forense, strutturato in sezioni chiare tramite Markdown. Termina chiedendo all'operatore ROOT se desidera attivare misure di mitigazione (Firewall/Honeypot)."""
    
    news = run_agent_loop(network_llm, network_dict, state["messages"], sys_content)
    return {"messages": news}

def human_approval_node(state: MessagesState):
    """Breakpoint."""
    print("\n[!] In attesa di approvazione umana...\n")
    return state

def action_node(state: MessagesState):
    """Agente 3: Il Mitigatore. Esegue il volere dell'umano."""
    sys_content = """Sei l'Agente 3: Mitigazione Zero Trust. L'umano ha appena scritto un messaggio.
ATTENZIONE, REGOLE ZERO TRUST:
- SE l'umano ti FA UNA DOMANDA (es. 'quali altri attacchi ci sono?'): DEVI SOLO RISPONDERE A PAROLE usando i dati dello storico. **NON devi usare i tool di mitigazione**.
- SE E SOLO SE l'umano USA VERBI IMPERATIVI (es. 'blocca', 'crea regola', 'metti honeypot'): USA i tool draft_firewall_rule e deploy_honeypot.
REGOLA FONDAMENTALE: Non dire che l'IP è stato bloccato. Fornisci SEMPRE il testo della regola (es. iptables) o la conferma del deploy dell'honeypot. L'utente deve poter leggere e confermare l'azione.
DEVI TASSATIVAMENTE restituire in chat l'output esatto che ha sputato fuori la shell o il tool (es. la stringa 'iptables -A ...')."""
    
    news = run_agent_loop(mitigation_llm, mitigation_dict, state["messages"], sys_content)
    return {"messages": news}


# --- COSTRUZIONE DEL GRAFO MULTI-AGENTE PIPELINE ---
builder = StateGraph(MessagesState)

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
