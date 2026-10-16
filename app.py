import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from src.engine import load_events, analyze_events

st.set_page_config(
    page_title="SOC Detection & Incident Response",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SOC Detection & Incident Response Platform")
st.caption("Security monitoring • Risk scoring • Incident management")

if "incidents" not in st.session_state:
    st.session_state.incidents = analyze_events(load_events())

if "notes" not in st.session_state:
    st.session_state.notes = {}

incidents = st.session_state.incidents

col1, col2, col3, col4 = st.columns(4)
col1.metric("Events Analyzed", len(load_events()))
col2.metric("Incidents Detected", len(incidents))
col3.metric(
    "High / Critical",
    sum(i["severity"] in ("HIGH", "CRITICAL") for i in incidents)
)
col4.metric(
    "Open Incidents",
    sum(i["status"] == "Open" for i in incidents)
)

st.divider()
st.subheader("🚨 Security Alerts")

severity_filter = st.multiselect(
    "Filter by severity",
    ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
    default=["CRITICAL", "HIGH", "MEDIUM", "LOW"]
)

filtered = [
    i for i in incidents
    if i["severity"] in severity_filter
]

if filtered:
    df = pd.DataFrame([
        {
            "Event ID": i["event_id"],
            "Severity": i["severity"],
            "Risk Score": i["risk_score"],
            "Event Type": i["event_type"],
            "Source IP": i["src_ip"],
            "Host": i["host"],
            "Status": i["status"]
        }
        for i in filtered
    ])
    st.dataframe(df, use_container_width=True, hide_index=True)
else:
    st.info("No incidents match this filter.")

st.divider()
st.subheader("🔎 Incident Investigation")

if incidents:
    selected_id = st.selectbox(
        "Select incident",
        [i["event_id"] for i in incidents]
    )
    incident = next(i for i in incidents if i["event_id"] == selected_id)

    st.write(f"**Severity:** {incident['severity']}")
    st.write(f"**Risk score:** {incident['risk_score']}/100")
    st.write(f"**Event type:** {incident['event_type']}")
    st.write(f"**Source IP:** {incident['src_ip']}")
    st.write(f"**Host:** {incident['host']}")
    st.write("**Detection reasons:**")
    for reason in incident["reasons"]:
        st.write(f"- {reason}")

    new_status = st.selectbox(
        "Update incident status",
        ["Open", "Investigating", "Contained", "Closed"],
        index=["Open", "Investigating", "Contained", "Closed"].index(
            incident["status"]
        ),
        key=f"status_{selected_id}"
    )
    incident["status"] = new_status

    note = st.text_area(
        "Analyst notes",
        value=incident.get("analyst_notes", ""),
        key=f"note_{selected_id}"
    )
    incident["analyst_notes"] = note

    st.caption("Status and notes are held in this dashboard session.")

st.divider()
st.subheader("📄 Export Report")

report = {
    "total_events": len(load_events()),
    "total_incidents": len(incidents),
    "incidents": incidents
}
report_json = json.dumps(report, indent=2)

st.download_button(
    "Download JSON Report",
    data=report_json,
    file_name="soc_incident_report.json",
    mime="application/json"
)

if incidents:
    csv_data = pd.DataFrame(incidents).to_csv(index=False)
    st.download_button(
        "Download CSV Report",
        data=csv_data,
        file_name="soc_incident_report.csv",
        mime="text/csv"
    )

st.caption("Demo uses synthetic security events; it does not monitor live systems.")
