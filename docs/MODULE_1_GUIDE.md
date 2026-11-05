# Module 1 Guide — Forensic Investigation & CyberRangeCZ Assessment

## 1. Objective & Workflow

Module 1 is an independent forensic investigation exercise where a trainee analyzes the provided evidence artifacts and completes the CyberRangeCZ assessment.

```text
[ Trainee Accesses CyberRangeCZ ]
               │
               ▼
   [ Private Sandbox Created ]
               │
               ▼
[ Incident Emulation & Telemetry Generated ]
               │
               ▼
  [ Evidence Package Staged in /home/debian/lab/ ]
               │
               ▼
[ Trainee Investigates Artifacts (Wireshark, tshark, jq) ]
               │
               ▼
 [ Trainee Submits Answers to Assessment Checkpoints Q1-Q10 ]
               │
               ▼
[ Automated Scoring Engine Evaluates Submissions & Logs Results ]
```

---

## 2. Assessment Questions & Derived Answers

| Question | Investigation Target | Derived Canonical Answer | Supporting Evidence Artifact |
| :--- | :--- | :--- | :--- |
| **Q1** | Affected Workstation Hostname | `DESKTOP-WKSTN42` | `incident.json`, `process_events.jsonl` |
| **Q2** | Initiating Malicious Binary | `invoice_review.exe` | `process_events.jsonl` (Sysmon Event ID 1) |
| **Q3** | Parent Process Name | `explorer.exe` (PID 2840) | `process_events.jsonl` |
| **Q4** | First Suspicious Timestamp (UTC) | `2026-11-06T09:14:22Z` | `process_events.jsonl` (UtcTime) |
| **Q5** | Modified Canary File Extension | `.locked` | `file_activity.jsonl`, `file_hashes.json` |
| **Q6** | External C2 Destination IP & Port | `10.10.50.30:8080` | `network_capture.pcap`, `c2_conversations.json` |
| **Q7** | Wazuh Shadow Copy Alert Rule ID | `100202` | `wazuh_alerts.json` |
| **Q8** | Extortion Note Filename | `RESTORE_FILES_INFO.txt` | `indicators.json`, `file_activity.jsonl` |
| **Q9** | ATT&CK Defense Impairment ID | `T1490` | `wazuh_alerts.json` (Inhibit System Recovery) |
| **Q10** | Immediate SOC Containment Action | `isolate` / `isolation` | SOC Incident Response Playbook |

---

## 3. CyberRangeCZ Training Definition Configuration

The exercise is fully defined in `training_definition.json`.
- Adheres to CyberRangeCZ / KYPO schema with `info` level (rules of engagement) and `training` levels (tasks Q1 through Q10).
- Configurable maximum score per question: 10 points (100 points total).
- Instructor-defined hints deduct 2 points per hint revealed.
- Answer matching supports regex and case-insensitive aliases via `evidence_collector/assessment_evaluator.py`.
