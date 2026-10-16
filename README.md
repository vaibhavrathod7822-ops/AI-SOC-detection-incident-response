AI SOC Detection & Incident Response Platform

LIVE DEMO :
https://ai-soc-detection-incident-response-vaibhav-official-nej2954kuvr.streamlit.app/

A Python-based Security Operations Center (SOC) prototype for analyzing security events, assigning risk scores, and supporting incident investigation through an interactive dashboard.

Features

- Analyze sample security events from JSON.
- Detect repeated failed logins and suspicious process activity.
- Assign risk scores and severity levels.
- Review incidents and update their status.
- Add analyst notes during investigation.
- Export incident reports in JSON and CSV formats.

Technology Stack

- Python
- Streamlit
- Pandas
- JSON
- Unit testing with "unittest"

Project Structure

- "app.py" — interactive SOC dashboard
- "src/engine.py" — event analysis and risk scoring
- "data/security_events.json" — synthetic sample events
- "tests/test_engine.py" — automated tests
- "reports/" — generated security reports
- "requirements.txt" — Python dependencies

Run Locally

pip install -r requirements.txt
streamlit run app.py

Testing

python -m unittest discover -s tests -v

Scope and Limitations

This prototype uses synthetic security events and rule-based detection. It does not monitor live systems or automatically contain real threats. Incident status and analyst notes are maintained in the current dashboard session.

Future Improvements

- Persistent incident storage
- Additional detection and correlation rules
- Integration with real security log sources
- Machine learning-based anomaly detection

Disclaimer

This project is intended for educational and defensive cybersecurity use.
