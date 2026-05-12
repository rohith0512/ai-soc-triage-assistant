from groq import Groq
from dotenv import load_dotenv
import os
import json

load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def triage_alert(alert_text: str) -> dict:
    prompt = f"""
You are a SOC Analyst. Analyze the following security alert and respond ONLY in this exact JSON format with no extra text, no markdown, no backticks:

{{
  "severity": "Low or Medium or High or Critical",
  "mitre_tactic": "e.g. Initial Access",
  "mitre_technique": "e.g. T1078 - Valid Accounts",
  "summary": "One sentence explaining what happened",
  "recommended_action": "What the analyst should do next"
}}

Alert:
{alert_text}
"""
    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}]
        )
        raw = response.choices[0].message.content.strip()
        parsed = json.loads(raw)
        return parsed
    except json.JSONDecodeError:
        return {"error": "AI response was not valid JSON", "raw": raw}
    except Exception as e:
        return {"error": str(e)}