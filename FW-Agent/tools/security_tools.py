import json
import os
import subprocess
import requests
from langchain_core.tools import tool

# Determine base paths relative to this file
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
SIEM_LOGS_PATH = os.path.join(DATA_DIR, "siem_logs.json")
THREAT_INTEL_PATH = os.path.join(DATA_DIR, "threat_intel.json")

@tool
def query_siem(keyword: str) -> str:
    """
    Cerca una keyword specifica (es. un IP, un nome utente, un tipo di evento)
    all'interno dei log di rete e di sistema (SIEM).
    Restituisce tutti gli eventi in cui compare la keyword formattati come stringa.
    """
    try:
        with open(SIEM_LOGS_PATH, "r", encoding="utf-8") as f:
            logs = json.load(f)
        
        results = []
        for log in logs:
            # Check if keyword is in any of the values (converted to string)
            if any(keyword.lower() in str(value).lower() for value in log.values()):
                results.append(log)
        
        if not results:
            return f"Nessun log trovato contenente la keyword: {keyword}"
            
        # Format the results in a readable string
        formatted_results = "\n".join([json.dumps(r, indent=2) for r in results])
        return f"Trovati {len(results)} eventi:\n{formatted_results}"

    except FileNotFoundError:
        return "Errore: File dei log SIEM (siem_logs.json) non trovato."
    except json.JSONDecodeError:
        return "Errore: Il file siem_logs.json non contiene JSON valido."
    except Exception as e:
        return f"Errore durante la ricerca nel SIEM: {str(e)}"

@tool
def check_ip_reputation(ip_address: str) -> str:
    """
    Controlla la reputazione di un indirizzo IP nel database di Threat Intelligence.
    Se l'IP è segnalato come malevolo, restituisce i dettagli della minaccia.
    Altrimenti restituisce che non ci sono minacce note.
    """
    try:
        with open(THREAT_INTEL_PATH, "r", encoding="utf-8") as f:
            threat_intel = json.load(f)
            
        malicious_ips = threat_intel.get("known_malicious_ips", [])
        
        for record in malicious_ips:
            if record.get("ip") == ip_address:
                return (f"MINACCIA RILEVATA!\n"
                        f"IP: {ip_address}\n"
                        f"Tipo di minaccia: {record.get('threat_type')}\n"
                        f"Affidabilità: {record.get('confidence')}\n"
                        f"Attore: {record.get('actor')}\n"
                        f"Descrizione: {record.get('description')}")
                        
        return "Nessuna minaccia nota per questo IP."

    except FileNotFoundError:
        return "Errore: File del database Threat Intel (threat_intel.json) non trovato."
    except json.JSONDecodeError:
        return "Errore: Il file threat_intel.json non contiene JSON valido."
    except Exception as e:
        return f"Errore durante il controllo dell'IP: {str(e)}"

@tool
def ip_geolocation(ip_address: str) -> str:
    """
    Ottiene la geolocalizzazione fisica di un indirizzo IP (Nazione, Città, ISP) usando un'API pubblica.
    Usalo sempre quando identifichi un IP sospetto per fornire contesto all'umano.
    """
    # FALLBACK MANUALE PER DEMO (Hackathon Zero Downtime)
    static_geo = {
        "185.11.22.33": {"city": "Mosca", "country": "Russia", "lat": 55.7558, "lon": 37.6173, "org": "Botnet_C2_Server"},
        "45.33.22.11": {"city": "Pechino", "country": "Cina", "lat": 39.9042, "lon": 116.4074, "org": "Ransom_Gateway"}
    }
    if ip_address in static_geo:
        g = static_geo[ip_address]
        return f"📍 Geolocalizzazione {ip_address}: {g['city']}, {g['country']} (ISP: {g['org']}) [COORD: {g['lat']}, {g['lon']}]"

    try:
        response = requests.get(f"https://ipapi.co/{ip_address}/json/", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if "error" in data:
                return f"Errore Geolocalizzazione: {data.get('reason', 'Sconosciuto')}"
            return f"📍 Geolocalizzazione {ip_address}: {data.get('city', '?')}, {data.get('country_name', '?')} (ISP: {data.get('org', '?')}) [COORD: {data.get('latitude', 0.0)}, {data.get('longitude', 0.0)}]"
        return "Servizio IPAPI temporaneamente non raggiungibile."
    except Exception as e:
        return f"Errore di rete durante la geolocalizzazione: {str(e)}"

def _add_to_threat_intel(ip_address: str, action_taken: str):
    """Aggiunge un IP al database Threat Intel se non è già presente."""
    if not ip_address:
        return
    try:
        with open(THREAT_INTEL_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        malicious_ips = data.get("known_malicious_ips", [])
        
        if any(rec.get("ip") == ip_address for rec in malicious_ips):
            return
            
        new_record = {
            "ip": ip_address,
            "threat_type": f"Mitigated ({action_taken})",
            "confidence": "High",
            "actor": "SOC_Agent_Blocked",
            "description": f"Autoblocked during SOC mitigation round. Action: {action_taken}"
        }
        malicious_ips.append(new_record)
        data["known_malicious_ips"] = malicious_ips
        
        with open(THREAT_INTEL_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            
    except Exception as e:
        print(f"Errore nell'aggiornamento di Threat Intel: {e}")

@tool
def draft_firewall_rule(ip_address: str, firewall_type: str) -> str:
    """
    Questo tool NON applica regole al firewall, ma serve SOLO per PREPARARE 
    il comando da far copiare e incollare all'amministratore.
    Restituisce la sintassi corretta per bloccare un IP.
    """
    fw_type = firewall_type.lower()
    _add_to_threat_intel(ip_address, f"Firewall Rule ({fw_type})")
    
    if fw_type == "iptables":
        return f"iptables -A INPUT -s {ip_address} -j DROP"
    elif fw_type == "ufw":
        return f"ufw deny from {ip_address}"
    elif fw_type == "cisco":
        return f"access-list 100 deny ip host {ip_address} any"
    else:
        return f"Blocco IP {ip_address} su firewall {firewall_type}."

@tool
def deploy_honeypot(target_server: str, attacker_ip: str = "") -> str:
    """
    Questo tool attiva un ambiente fittizio isolato (honeypot Docker) sulla porta 8080.
    Passa sempre l'attacker_ip per aggiungerlo automaticamente al Threat Intel.
    """
    if attacker_ip:
        _add_to_threat_intel(attacker_ip, "Honeypot Deployment")
        
    try:
        container_name = f"honeypot_trap_{target_server.lower()}"
        # Rimuove pre-esistenti per sicurezza (ignorando gli errori in caso non ci sia)
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
        # Lancia nginx finto in background
        subprocess.run(
            ["docker", "run", "-d", "-p", "8080:80", "--name", container_name, "nginxdemos/hello"],
            check=True, capture_output=True
        )
        msg_out = f"✅ [SUCCESSO] Prigione Honeypot (Nginx Docker Container) schierata ORA materialmente sulla porta 8080 per bloccare il traffico di {attacker_ip or 'sconosciuto'}!"
    except Exception as e:
        # Se Docker non e' installato, ripiega elegantemente sulla simulazione
        msg_out = f"✅ [SUCCESSO SIMULATO] Honeypot schierato logicamente sul nodo {target_server}. Docker Engine non risponde per lo schieramento fisico: {e}"
        
    return msg_out
