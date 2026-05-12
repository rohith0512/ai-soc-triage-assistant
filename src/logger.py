import subprocess
import json

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