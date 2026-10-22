# Synthetic demonstration data

These files contain fictional events for the hackathon prototype. They are not collected production telemetry and do not establish that an address, organisation or person is malicious.

| File | Purpose |
| --- | --- |
| `siem_logs.json` | Default dashboard scenario: 55 events, including scanning, failed logins and file encryption. |
| `threat_intel.json` | Fictional indicators used by the local reputation lookup. Read-only during analysis and action proposals. |
| `examples/massive_traffic_log.json` | Additional local scenario preserved from the original project folder: 40 events with protocol and byte fields. |
| `examples/stress_test_logs.json` | Additional local scenario preserved from the original project folder: 40 events. The filename does not represent a measured performance benchmark. |

The two additional scenarios are reference fixtures; the current dashboard and SIEM query tool load `siem_logs.json`.

External example addresses use documentation ranges (`192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24`). Private addresses represent fictional internal hosts. The coordinates returned for the two main external examples are synthetic and explicitly labelled `DEMO`; other private or reserved addresses are not sent to the geolocation service.

These files are not changed by drafting a firewall rule or requesting a demo container.
