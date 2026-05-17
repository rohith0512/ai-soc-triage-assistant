# 🛡️ AI-Powered SOC Alert Triage Assistant

An AI-assisted security alert triage tool built for SOC analysts. Classifies alerts by severity, maps them to MITRE ATT&CK techniques, performs IP reputation lookups, and auto-generates incident reports.

## 🎯 What It Does

- **AI Triage** — Analyzes security alerts using Groq API (LLaMA 3.3 70B) and returns structured triage output
- **MITRE ATT&CK Mapping** — Maps every alert to relevant tactics and techniques automatically
- **Severity Classification** — Low / Medium / High / Critical with confidence scoring
- **IP Reputation Lookup** — Real-time threat intel via AbuseIPDB (country, abuse score, ISP, Tor detection)
- **Windows Event Log Ingestion** — Pulls live logs directly from Windows Security event log
- **File Upload** — Upload CSV or TXT log files from any machine for bulk triage
- **Brute Force Correlation** — Automatically detects and escalates brute force patterns
- **SQLite Case Logging** — Every triage result saved to database automatically
- **Automated Incident Reports** — Markdown report generated for every alert
- **Alert History Dashboard** — View, filter, and analyze all past triage results

## 🖥️ Tech Stack

- Python 3.x
- Groq API (LLaMA 3.3 70B)
- AbuseIPDB API
- SQLite
- Streamlit
- PowerShell (Windows Event Log ingestion)



## 📁 Project Structure

## 🖼️ Demo Screenshots

### Main Dashboard
![Main Dashboard](screenshots/Screenshot%202026-05-17%20143225.png)

### Triage Report
![Triage Report](screenshots/Screenshot%202026-05-17%20143307.png)

### IP Reputation Lookup
![IP Reputation](screenshots/Screenshot%202026-05-17%20143329.png)

### Alert History Dashboard
![Alert History](screenshots/Screenshot%202026-05-17%20143346.png)