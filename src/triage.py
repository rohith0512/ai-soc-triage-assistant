from groq import Groq
from dotenv import load_dotenv
import os

load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def triage_alert(alert_text: str) -> str:
    prompt = f"""
You are a SOC Analyst. Analyze the following security alert and respond ONLY in this exact JSON format with no extra text:

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
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content