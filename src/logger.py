import subprocess
import json
import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'logs', 'triage.db')

def get_windows_events(event_id: int, count: int = 5) -> list:
    """
    Pulls recent Windows Event Logs by Event ID
    Common Event IDs:
    4625 - Failed logon
    4624 - Successful logon
    4688 - Process creation
    4698 - Scheduled task created
    """
    query = f"Get-WinEvent -FilterHashtable @{{LogName='Security'; Id={event_id}}} -MaxEvents {count} | Select-Object TimeCreated, Id, Message | ConvertTo-Json"

    try:
        result = subprocess.run(
            ["powershell", "-Command", query],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode != 0:
            return [{"error": result.stderr.strip()}]

        data = json.loads(result.stdout)
        if isinstance(data, dict):
            data = [data]
        return data
    except json.JSONDecodeError:
        return [{"error": "Could not parse event log output"}]
    except Exception as e:
        return [{"error": str(e)}]


def format_event_for_triage(event: dict) -> str:
    """Converts a Windows event log entry into alert text for triage"""
    return f"""
Event ID: {event.get('Id', 'Unknown')}
Time: {event.get('TimeCreated', 'Unknown')}
Details: {event.get('Message', 'No message available')[:500]}
"""


def init_db():
    """Creates the database and table if they don't exist"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS triage_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            severity TEXT,
            confidence TEXT,
            mitre_tactic TEXT,
            mitre_technique TEXT,
            additional_techniques TEXT,
            summary TEXT,
            immediate_action TEXT,
            investigation_steps TEXT,
            false_positive_check TEXT,
            raw_alert TEXT
        )
    ''')
    conn.commit()
    conn.close()


def log_triage_result(alert_text: str, result: dict):
    """Saves a triage result to the database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO triage_logs (
            timestamp, severity, confidence, mitre_tactic,
            mitre_technique, additional_techniques, summary,
            immediate_action, investigation_steps,
            false_positive_check, raw_alert
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        result.get("severity"),
        result.get("confidence"),
        result.get("mitre_tactic"),
        result.get("mitre_technique"),
        result.get("additional_techniques"),
        result.get("summary"),
        result.get("immediate_action"),
        result.get("investigation_steps"),
        result.get("false_positive_check"),
        alert_text.strip()
    ))
    conn.commit()
    conn.close()