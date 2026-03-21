import os
import requests
import json
from dotenv import load_dotenv

load_dotenv()
api_key = os.environ.get("GEMINI_API_KEY")

if not api_key:
    print("Nessuna API KEY trovata!")
else:
    url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
    response = requests.get(url)
    if response.status_code == 200:
        models = response.json().get("models", [])
        print("Modelli supportati:")
        for m in models:
            methods = m.get("supportedGenerationMethods", [])
            if "generateContent" in methods:
                print(m.get("name"))
    else:
        print(f"Errore {response.status_code}: {response.text}")
