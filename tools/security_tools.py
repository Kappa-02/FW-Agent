import json
import os
import subprocess
import ipaddress
import re
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
    """Restituisce coordinate dimostrative etichettate, o consulta IPAPI per IP pubblici."""
    try:
        address = ipaddress.IPv4Address(ip_address)
    except ipaddress.AddressValueError:
        return "ERROR: invalid IPv4 address."

    # Indirizzi riservati alla documentazione: coordinate sintetiche, non attribuzioni reali.
    demo_geo = {
        "203.0.113.10": (55.7558, 37.6173),
        "198.51.100.20": (39.9042, 116.4074),
    }
    if ip_address in demo_geo:
        lat, lon = demo_geo[ip_address]
        return f"DEMO: synthetic coordinates for {ip_address}; not a real location. [COORD: {lat}, {lon}]"
    if not address.is_global:
        return "Geolocation unavailable for private or reserved addresses."
    try:
        response = requests.get(f"https://ipapi.co/{address}/json/", timeout=5)
        response.raise_for_status()
        data = response.json()
        if data.get("error"):
            return "Geolocation unavailable from IPAPI."
        lat, lon = data.get("latitude"), data.get("longitude")
        if lat is None or lon is None:
            return "Geolocation unavailable: missing coordinates."
        return (f"IPAPI: {address}: {data.get('city', '?')}, {data.get('country_name', '?')} "
                f"(ISP: {data.get('org', '?')}) [COORD: {float(lat)}, {float(lon)}]")
    except (requests.RequestException, ValueError, TypeError):
        return "Geolocation unavailable: network or response error."


@tool
def draft_firewall_rule(ip_address: str, firewall_type: str) -> str:
    """Prepara una regola IPv4 da revisionare; non la applica e non modifica la threat intelligence."""
    try:
        address = ipaddress.IPv4Address(ip_address)
    except ipaddress.AddressValueError:
        return "ERROR: invalid IPv4 address."
    commands = {
        "iptables": f"iptables -A INPUT -s {address} -j DROP",
        "ufw": f"ufw deny from {address}",
        "cisco": f"access-list 100 deny ip host {address} any",
    }
    command = commands.get(firewall_type.lower())
    if command is None:
        return "ERROR: unsupported firewall type. Choose iptables, ufw or cisco."
    return f"RULE DRAFT — NOT APPLIED. Review before using on a real system.\n{command}"


@tool
def deploy_honeypot(target_server: str, attacker_ip: str = "") -> str:
    """Simula o avvia un container web dimostrativo locale. Non blocca né devia traffico."""
    try:
        ipaddress.IPv4Address(attacker_ip)
    except ipaddress.AddressValueError:
        return "ERROR: invalid attacker IPv4 address."
    target = target_server.lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,39}", target):
        return "ERROR: invalid demo container label."
    if os.environ.get("FW_AGENT_ENABLE_DOCKER", "false").lower() != "true":
        return ("SIMULATION: no container was started. The local web demo does not block "
                "or redirect traffic. Set FW_AGENT_ENABLE_DOCKER=true to opt in.")
    container_name = f"fw-agent-demo-{target}"
    try:
        subprocess.run(
            ["docker", "run", "-d", "-p", "127.0.0.1:8080:80", "--name", container_name,
             "nginxdemos/hello"],
            check=True, capture_output=True, text=True, timeout=90,
        )
    except (OSError, subprocess.SubprocessError):
        return ("ERROR: Docker demo could not start. Check Docker, image availability, "
                "port 8080 and the container name. No successful deployment is confirmed.")
    return (f"DEMO CONTAINER STARTED: {container_name} at http://127.0.0.1:8080. "
            "This is a local sample web server, not a complete honeypot; it does not block "
            f"or redirect traffic from {attacker_ip}. No firewall rules were applied.")
