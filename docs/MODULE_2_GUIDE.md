# Module 2 Guide — Interactive SOC Investigation, Detection & Response

## 1. Purpose & Learning Philosophy

Module 2 takes the **SAME** incident evidence generated in Module 1 (`INC-2026-9842`) and transitions the trainee into an interactive, pedagogical SOC analyst experience.

Rather than just answering quiz questions, the trainee is guided through:
1. Understanding the broader context of the attack.
2. Interactively navigating the Windows process hierarchy.
3. Comparing pre- and post-encryption file hashes.
4. Analyzing captured TCP streams and HTTP C2 payloads in Wireshark style.
5. Correlating Wazuh SIEM detection rules.
6. Mapping techniques to the MITRE ATT&CK framework.
7. Executing controlled, safe containment and recovery actions.
8. Generating a certified final assessment report.

---

## 2. Progressive Lesson Structure

- **Lesson 1 — Understanding the Incident & Triage:** High-level incident metadata, affected workstation identification, and victim user context.
- **Lesson 2 — Process Ancestry & Defense Impairment:** Interactive process tree visualization showing `explorer.exe` (PID 2840) -> `invoice_review.exe` (PID 4912) -> `cmd.exe` (PID 5120) -> `vssadmin.exe` (PID 5288).
- **Lesson 3 — File System Activity & Forensic Hashes:** Comparing pre- and post-attack SHA-256 hashes of 5 canary finance documents and inspecting `RESTORE_FILES_INFO.txt`.
- **Lesson 4 — Network Investigation & C2 Analysis:** Filtering packet captures, viewing TCP handshakes, HTTP key negotiation, and session heartbeats.
- **Lesson 5 — Wazuh Detection & SIEM Correlation:** Reviewing triggered alert rules (100201 through 100204), severity levels, and raw event payloads.
- **Lesson 6 — MITRE ATT&CK Mapping:** Grounding technique assignments in empirical incident telemetry (T1204.002, T1490, T1071.001, T1486).
- **Lesson 7 — Incident Response & Controlled Remediation:** Following the change-control lifecycle (Preview -> Confirm -> Execute -> Verify).
- **Lesson 8 — Comprehensive Assessment & Certification:** Final evaluation and report generation.

---

## 3. Running Module 2

Start the FastAPI application:
```bash
python -m uvicorn module2.server:app --host 0.0.0.0 --port 8000
```
Open your browser to:
`http://localhost:8000`
Trainees interact with the dark SOC investigation console, submit checkpoints, track their score in real time, and execute safe containment playbooks.
