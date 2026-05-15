import streamlit as st
import sqlite3
import os
import pandas as pd

st.set_page_config(page_title="Alert History", page_icon="📁", layout="wide")

st.title("📁 Alert History Dashboard")
st.markdown("All triage results logged by the SOC Alert Triage Assistant.")
st.divider()

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'logs', 'triage.db')

try:
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM triage_logs ORDER BY timestamp DESC", conn)
    conn.close()

    if df.empty:
        st.info("No alerts have been triaged yet.")
    else:
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Alerts", len(df))
        with col2:
            critical_high = len(df[df['severity'].isin(['Critical', 'High'])])
            st.metric("High/Critical", f"🔴 {critical_high}")
        with col3:
            medium = len(df[df['severity'] == 'Medium'])
            st.metric("Medium", f"🟡 {medium}")
        with col4:
            low = len(df[df['severity'] == 'Low'])
            st.metric("Low", f"🟢 {low}")

        st.divider()

        # Filters
        col1, col2 = st.columns(2)
        with col1:
            severity_filter = st.multiselect(
                "Filter by Severity:",
                options=["Critical", "High", "Medium", "Low"],
                default=["Critical", "High", "Medium", "Low"]
            )
        with col2:
            search = st.text_input("Search by keyword:")

        # Apply filters
        filtered_df = df[df['severity'].isin(severity_filter)]
        if search:
            filtered_df = filtered_df[
                filtered_df['summary'].str.contains(search, case=False, na=False) |
                filtered_df['mitre_technique'].str.contains(search, case=False, na=False)
            ]

        st.divider()

        # Display table
        st.subheader(f"Showing {len(filtered_df)} alerts")
        st.dataframe(
            filtered_df[['timestamp', 'severity', 'confidence', 'mitre_tactic', 'mitre_technique', 'summary']],
            use_container_width=True,
            hide_index=True
        )

        st.divider()

        # Severity chart
        st.subheader("📊 Severity Distribution")
        severity_counts = df['severity'].value_counts()
        st.bar_chart(severity_counts)

except Exception as e:
    st.error(f"Could not load alert history: {e}")