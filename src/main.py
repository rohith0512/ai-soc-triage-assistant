import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from triage import triage_alert

test_alert = """
Event: Malicious macro execution detected
Source Host: DESKTOP-HR-004
User: james.wilson
Time: 2024-03-12 09:22:05
Details: Word document 'Invoice_March2024.docm' opened from email attachment. 
Macro executed PowerShell command, downloaded payload from http://malicious-domain.ru/payload.exe. 
Process chain: WINWORD.EXE > powershell.exe > payload.exe. 
Outbound connection attempted to C2 server 91.234.56.78.
"""

result = triage_alert(test_alert)
print(result)