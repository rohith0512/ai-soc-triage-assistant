import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from triage import triage_alert
from logger import get_windows_events, format_event_for_triage, init_db, log_triage_result
from reporter import generate_report

# Initialize database
init_db()

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
    print(f"Severity              : {result['severity']}")
    print(f"Confidence            : {result['confidence']}")
    print(f"MITRE Tactic          : {result['mitre_tactic']}")
    print(f"MITRE Technique       : {result['mitre_technique']}")
    print(f"Additional Techniques : {result['additional_techniques']}")
    print(f"Summary               : {result['summary']}")
    print(f"Immediate Action      : {result['immediate_action']}")
    print(f"Investigation Steps   : {result['investigation_steps']}")
    print(f"False Positive Check  : {result['false_positive_check']}")
    print("=" * 50)

    log_triage_result(test_alert, result)
    print("✓ Result logged to database")

    report_path = generate_report(test_alert, result)
    print(f"✓ Incident report saved to: {report_path}")

print("\n--- WINDOWS EVENT LOG INGESTION ---")
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
            print(f"Severity        : {result['severity']}")
            print(f"Confidence      : {result['confidence']}")
            print(f"MITRE Technique : {result['mitre_technique']}")
            print(f"Immediate Action: {result['immediate_action']}")
            log_triage_result(alert_text, result)
            generate_report(alert_text, result)

print("\n--- TESTING EVENT ID 4720 - NEW USER ACCOUNT CREATED ---")
print("Pulling last 3 user account creation events...")

events_4720 = get_windows_events(event_id=4720, count=3)

for i, event in enumerate(events_4720):
    if "error" in event:
        print(f"Error pulling logs: {event['error']}")
    else:
        print(f"\nEvent {i+1}:")
        alert_text = format_event_for_triage(event)
        result = triage_alert(alert_text)
        if "error" not in result:
            print(f"Severity        : {result['severity']}")
            print(f"Confidence      : {result['confidence']}")
            print(f"MITRE Technique : {result['mitre_technique']}")
            print(f"Immediate Action: {result['immediate_action']}")
            log_triage_result(alert_text, result)
            generate_report(alert_text, result)

print("\n✓ All results logged and reports generated")