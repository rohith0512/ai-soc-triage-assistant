import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from triage import triage_alert

test_alert = """
Event: Failed login attempt
Source IP: 192.168.1.105
Target: Domain Controller (WIN-DC01)
Time: 2024-01-15 03:22:11
Details: 47 failed login attempts in 2 minutes using username 'administrator'
"""

result = triage_alert(test_alert)

if "error" in result:
    print(f"ERROR: {result['error']}")
else:
    print("=" * 50)
    print("SOC ALERT TRIAGE REPORT")
    print("=" * 50)
    print(f"Severity         : {result['severity']}")
    print(f"MITRE Tactic     : {result['mitre_tactic']}")
    print(f"MITRE Technique  : {result['mitre_technique']}")
    print(f"Summary          : {result['summary']}")
    print(f"Recommended Action: {result['recommended_action']}")
    print("=" * 50)
from logger import get_windows_events, format_event_for_triage

print("\n--- TESTING WINDOWS EVENT LOG INGESTION ---")
print("Pulling last 3 failed logon events (Event ID 4625)...")

events = get_windows_events(event_id=4625, count=3)

for i, event in enumerate(events):
    if "error" in event:
        print(f"Error pulling logs: {event['error']}")
    else:
        print(f"\nEvent {i+1}:")
        alert_text = format_event_for_triage(event)
        result = triage_alert(alert_text)
        if "error" not in result:
            print(f"Severity: {result['severity']}")
            print(f"MITRE Technique: {result['mitre_technique']}")
            print(f"Action: {result['recommended_action']}")