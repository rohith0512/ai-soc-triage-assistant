import streamlit as st
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from triage import triage_alert
from logger import init_db, log_triage_result
from reporter import generate_report

# Initialize database
init_db()

# Page config
st.set_page_config(
    page_title="AI SOC Triage Assistant",
    page_icon="🛡️",
    layout="wide"
)

# Header
st.title("🛡️ AI-Powered SOC Alert Triage Assistant")
st.markdown("Analyze security alerts with AI — MITRE ATT&CK mapping, severity classification, and automated incident reports.")
st.divider()

# Quick test alerts
QUICK_ALERTS = {
    "🔴 Ransomware Alert": """Event: Suspicious file encryption activity detected
Source IP: 10.0.0.45
Target: File Server (FS-PROD-01)
Time: 2024-03-10 02:15:33
Details: Process 'svchost.exe' modified 4,200 files in 3 minutes, changing extensions to '.locked'. Shadow copies deleted via vssadmin. User account: svc_backup. Antivirus disabled 10 minutes prior.""",

    "🟠 Brute Force Alert": """Event: Failed login attempt
Source IP: 192.168.1.105
Target: Domain Controller (WIN-DC01)
Time: 2024-01-15 03:22:11
Details: 47 failed login attempts in 2 minutes using username 'administrator'""",

    "🟡 Phishing Alert": """Event: Malicious macro execution detected
Source Host: DESKTOP-HR-004
User: james.wilson
Time: 2024-03-12 09:22:05
Details: Word document 'Invoice_March2024.docm' opened from email attachment. Macro executed PowerShell command, downloaded payload from http://malicious-domain.ru/payload.exe. Process chain: WINWORD.EXE > powershell.exe > payload.exe. Outbound connection attempted to C2 server 91.234.56.78."""
}

# Input section
col1, col2 = st.columns([2, 1])

with col2:
    st.subheader("⚡ Quick Test Alerts")
    selected_quick = st.radio(
        "Select a test alert:",
        options=["None"] + list(QUICK_ALERTS.keys()),
        index=0
    )

with col1:
    st.subheader("📋 Paste Security Alert")
    
    if selected_quick != "None":
        default_text = QUICK_ALERTS[selected_quick]
    else:
        default_text = ""
    
    alert_text = st.text_area(
        "Enter alert details below:",
        value=default_text,
        height=200,
        placeholder="Paste your security alert here..."
    )

# Analyze button
if st.button("🔍 Analyze Alert", type="primary", use_container_width=True):
    if not alert_text.strip():
        st.error("Please paste an alert or select a quick test alert.")
    else:
        with st.spinner("Analyzing alert with AI..."):
            result = triage_alert(alert_text)

        if "error" in result:
            st.error(f"Error: {result['error']}")
        else:
            st.divider()
            st.subheader("📊 Triage Report")

            severity = result.get("severity", "Unknown")
            severity_colors = {
                "Critical": "🔴",
                "High": "🟠",
                "Medium": "🟡",
                "Low": "🟢"
            }
            icon = severity_colors.get(severity, "⚪")

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Severity", f"{icon} {severity}")
            with col2:
                st.metric("Confidence", result.get("confidence", "Unknown"))
            with col3:
                st.metric("MITRE Tactic", result.get("mitre_tactic", "Unknown"))

            st.divider()

            col1, col2 = st.columns(2)

            with col1:
                st.markdown("**🎯 MITRE Technique**")
                st.info(result.get("mitre_technique", "N/A"))

                st.markdown("**📌 Additional Techniques**")
                st.info(result.get("additional_techniques", "None"))

                st.markdown("**📝 Summary**")
                st.write(result.get("summary", "N/A"))

            with col2:
                st.markdown("**⚡ Immediate Action**")
                st.warning(result.get("immediate_action", "N/A"))

                st.markdown("**🔎 Investigation Steps**")
                st.write(result.get("investigation_steps", "N/A"))

                st.markdown("**❓ False Positive Check**")
                st.write(result.get("false_positive_check", "N/A"))

            st.divider()

            log_triage_result(alert_text, result)
            report_path = generate_report(alert_text, result)

            st.success("✓ Result logged to database")
            st.success(f"✓ Incident report saved to: {report_path}")