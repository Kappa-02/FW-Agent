import os
import requests
import json
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")
api_key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")

if not api_key:
    print("Nessuna API KEY trovata!")
else:
    url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
    response = requests.get(url, timeout=10)
    if response.status_code == 200:
        models = response.json().get("models", [])
        print("Modelli supportati:")
        for m in models:
            methods = m.get("supportedGenerationMethods", [])
            if "generateContent" in methods:
                print(m.get("name"))
    else:
        print(f"Errore {response.status_code}: verifica chiave API e accesso al servizio.")
