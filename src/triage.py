from groq import Groq
from dotenv import load_dotenv
import os
import json

load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def triage_alert(alert_text: str) -> dict:
    prompt = f"""
You are an expert SOC Analyst with 10 years of experience in incident response and threat detection.

Analyze the following security alert and respond ONLY in this exact JSON format with no extra text, no markdown, no backticks:

{{
  "severity": "Low or Medium or High or Critical",
  "mitre_tactic": "Primary MITRE ATT&CK tactic",
  "mitre_technique": "Primary technique ID and name e.g. T1078 - Valid Accounts",
  "additional_techniques": "Other relevant technique IDs if multiple are present, else None",
  "confidence": "Low or Medium or High - how confident you are in this classification",
  "summary": "Two sentence explanation of what happened and why it is a threat",
  "immediate_action": "What the analyst must do in the next 15 minutes",
  "investigation_steps": "Three specific steps to investigate this alert further",
  "false_positive_check": "One question the analyst should ask to rule out a false positive"
}}

Severity guidelines:
- Critical: Active ransomware, confirmed breach, data exfiltration in progress
- High: Brute force success, malware execution, C2 communication detected
- Medium: Multiple failed logins, suspicious process, policy violation
- Low: Single failed login, minor anomaly, informational

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