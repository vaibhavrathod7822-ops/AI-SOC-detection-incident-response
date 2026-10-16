import unittest

from src.engine import analyze_events


class TestSOCEngine(unittest.TestCase):

    def test_repeated_failed_logins_detected(self):
        events = [
            {
                "event_id": f"EVT-{i}",
                "event_type": "failed_login",
                "src_ip": "192.0.2.10",
                "username": "admin",
                "host": "server-01"
            }
            for i in range(1, 4)
        ]

        incidents = analyze_events(events)

        self.assertEqual(len(incidents), 3)
        self.assertTrue(
            all(item["risk_score"] == 35 for item in incidents)
        )

    def test_suspicious_process_detected(self):
        events = [{
            "event_id": "EVT-TEST",
            "event_type": "suspicious_process",
            "src_ip": "198.51.100.20",
            "username": "user01",
            "host": "workstation-01"
        }]

        incidents = analyze_events(events)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["severity"], "HIGH")

    def test_normal_login_does_not_create_incident(self):
        events = [{
            "event_id": "EVT-NORMAL",
            "event_type": "successful_login",
            "src_ip": "192.0.2.25",
            "username": "analyst",
            "host": "server-01"
        }]

        incidents = analyze_events(events)

        self.assertEqual(incidents, [])


if __name__ == "__main__":
    unittest.main()
