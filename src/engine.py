import json
from collections import Counter, defaultdict
from pathlib import Path

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "security_events.json"
REPORT_FILE = Path(__file__).resolve().parent.parent / "reports" / "security_report.json"


def load_events(file_path=DATA_FILE):
    with open(file_path, "r", encoding="utf-8") as file:
        events = json.load(file)

    if not isinstance(events, list):
        raise ValueError("Security events must be a JSON list.")

    return events


def analyze_events(events):
    failed_logins = Counter()
    for event in events:
        if event.get("event_type") == "failed_login":
            failed_logins[event.get("src_ip", "unknown")] += 1

    incidents = []

    for event in events:
        event_type = event.get("event_type", "")
        src_ip = event.get("src_ip", "unknown")
        score = 0
        reasons = []

        if event_type == "failed_login":
            count = failed_logins[src_ip]
            if count >= 5:
                score += 50
                reasons.append(f"Repeated failed logins: {count}")
            elif count >= 3:
                score += 35
                reasons.append(f"Multiple failed logins: {count}")
            elif count >= 2:
                score += 15
                reasons.append(f"Repeated failed logins: {count}")

        if event_type == "successful_login" and failed_logins[src_ip] >= 3:
            score += 35
            reasons.append("Successful login from an IP with repeated failures")

        if event_type == "suspicious_process":
            score += 50
            reasons.append("Suspicious process activity reported")

        if event_type == "blocked_connection":
            score += 15
            reasons.append("Firewall blocked a connection")

        if score >= 70:
            severity = "CRITICAL"
        elif score >= 50:
            severity = "HIGH"
        elif score >= 25:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        if score > 0:
            incidents.append({
                "event_id": event.get("event_id", "UNKNOWN"),
                "timestamp": event.get("timestamp", ""),
                "source": event.get("source", "unknown"),
                "event_type": event_type,
                "username": event.get("username", "unknown"),
                "src_ip": src_ip,
                "host": event.get("host", "unknown"),
                "risk_score": min(score, 100),
                "severity": severity,
                "reasons": reasons,
                "status": "Open",
                "analyst_notes": ""
            })

    return sorted(
        incidents,
        key=lambda item: item["risk_score"],
        reverse=True
    )


def generate_report(events, incidents):
    severity_counts = Counter(item["severity"] for item in incidents)

    report = {
        "total_events": len(events),
        "total_incidents": len(incidents),
        "severity_counts": dict(severity_counts),
        "incidents": incidents
    }

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(REPORT_FILE, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    return report


def main():
    events = load_events()
    incidents = analyze_events(events)
    report = generate_report(events, incidents)

    print("=== SOC Detection Engine ===")
    print(f"Events analyzed: {report['total_events']}")
    print(f"Incidents detected: {report['total_incidents']}")
    print(f"Severity counts: {report['severity_counts']}")

    for incident in incidents:
        print(
            f"[{incident['severity']}] "
            f"{incident['event_id']} | "
            f"Risk: {incident['risk_score']} | "
            f"IP: {incident['src_ip']} | "
            f"{', '.join(incident['reasons'])}"
        )

    print(f"\nReport saved to: {REPORT_FILE}")


if __name__ == "__main__":
    main()
