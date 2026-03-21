# 🛡️ FW-Agent
**Agente AI per l'automatizzazione di Firewall e Analisi SOC**

FW-Agent è un'applicazione avanzata che simula un Security Operations Center (SOC) intelligente. Sfrutta il potenziale dei Large Language Models (LLM) tramite **LangGraph** e **LangChain** per orchestrare una squadra di agenti AI autonomi capaci di analizzare log di rete, identificare minacce e suggerire o applicare mitigazioni difensive. L'interfaccia utente è sviluppata in **Streamlit** per offrire una dashboard chiara ed interattiva in tempo reale.

## 🚀 Funzionalità Principali

- **Dashboard Real-Time**: Interfaccia Streamlit moderna che visualizza metriche SIEM, log di rete anomali e una mappa globale interattiva delle minacce.
- **Orchestrazione Multi-Agente (LangGraph)**:
  - 🕵️ **1. Triage Agent**: Analizza automaticamente i log SIEM per rilevare schemi d'attacco (brute force, ransomware, port scan).
  - 🌍 **2. Network Intelligence Agent**: Arricchisce i dati investigando gli IP sospetti con geolocalizzazione e controlli di reputazione (Threat Intel).
  - 🛡️ **3. Mitigation Agent**: Esegue azioni difensive mirate, ma *solo* previa autorizzazione (paradigma Zero Trust).
- **Human-in-the-Loop**: Il sistema richiede l'approvazione umana (tramite prompt o bottoni rapidi) prima di applicare modifiche infrastrutturali.
- **Risposte Attive (Tools)**:
  - Generazione di regole Firewall pronte all'uso (iptables, ufw, cisco).
  - Schieramento automatico di Honeypot (via container Docker) per intrappolare gli attaccanti.

## 📂 Struttura del Progetto

```text
FW-Agent/
├── app_soc.py            # Entry point dell'applicazione (Dashboard Streamlit)
├── agents/
│   └── soc_graph.py      # Definizione del workflow LangGraph e dei 3 Agenti AI
├── tools/
│   └── security_tools.py # Strumenti tecnici (query SIEM, check IP, regole FW, honeypot)
├── data/
│   ├── siem_logs.json    # Log simulati del SIEM per l'analisi
│   └── threat_intel.json # Database locale di IP malevoli noti (Threat Intelligence)
├── image/                # Asset grafici (logo, etc.)
└── requirements.txt      # Dipendenze del progetto Python
```

## 🛠️ Requisiti di Sistema

- Python 3.10+
- Una API Key di Google (per utilizzare i modelli Gemini come `gemini-2.5-flash`).
- Docker (opzionale, ma raccomandato per il corretto funzionamento del tool di deploy `deploy_honeypot`).

## 💻 Installazione

1. Clona il repository o naviga nella cartella del progetto.
2. Crea un ambiente virtuale (raccomandato):
   ```bash
   python -m venv venv
   source venv/bin/activate  # Su Windows: venv\Scripts\activate
   ```
3. Installa le dipendenze:
   ```bash
   pip install -r FW-Agent/requirements.txt
   ```
4. Configura le variabili d'ambiente:
   - Crea un file `.env` nella cartella in cui eseguirai l'app.
   - Aggiungi la tua chiave per accedere a Google Generative AI:
     ```env
     GOOGLE_API_KEY=la_tua_chiave_api_qui
     ```

## ▶️ Esecuzione

Per avviare la SOC Dashboard, posizionati all'interno della cartella principale (o nella sub-directory contenente l'app) ed esegui:
```bash
python.exe -m streamlit run FW-Agent/app_soc.py
```
*(Nota: per il corretto caricamento dei path dei file temporanei e dei dati, assicurati di avviare il comando Streamlit con la configurazione di working directory appropriata).*

## 🧠 Flusso di Lavoro dell'Agente
1. **Analisi Iniziale**: L'applicazione carica automaticamente `siem_logs.json` e innesca il grafo segnalando "analizza i log e trova tutte le minacce attive nella rete".
2. **Streaming Risultati**: Man mano che gli agenti lavorano, il ragionamento logico (estrazione IP, geolocalizzazione) viene elaborato e stampato real-time nel modulo di chat SOC della dashboard.
3. **Mappa Minacce**: Se gli IP sospetti vengono geolocalizzati, le coordinate si posizioneranno visivamente sulla mappa in basso.
4. **Approvazione dell'Operatore**: Individuato l'attacco, l'esecuzione agentica passa per un nodo di break e si mette in attesa della conferma del team di sicurezza.
5. **Azione Definitiva**: L'utente può interagire verbalmente oppure cliccare i pulsanti appositi ("Regola FW", "Attiva Honeypot") per scatenare la reazione difensiva.
