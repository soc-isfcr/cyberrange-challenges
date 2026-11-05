"""
Deterministic Lesson Definitions for Module 2 Interactive Investigation.
Defines Lessons 1 through 8 with learning objectives, evidence requirements,
interactive checkpoints, hints, and completion criteria.
"""

LESSONS = [
    {
        "id": "lesson_1",
        "order": 1,
        "title": "Lesson 1 — Understanding the Incident & Triage",
        "category": "Incident Overview",
        "objectives": [
            "Understand modern ransomware attack lifecycles and kill-chains",
            "Perform initial SOC alert triage on the affected endpoint",
            "Identify the victim system, user context, and incident scope"
        ],
        "explanation": (
            "Modern ransomware campaigns follow a structured progression: initial access, defense impairment, "
            "C2 key negotiation, mass file encryption, and extortion. In this exercise, Wazuh SIEM received multiple "
            "high-priority alerts from endpoint DESKTOP-WKSTN42. As a SOC analyst, your first responsibility is to review "
            "the incident manifest, confirm the authenticity of the collected telemetry, and verify the affected system."
        ),
        "required_evidence": ["incident.json", "manifest.json", "incident_timeline.json"],
        "checkpoints": [
            {
                "id": "L1_C1",
                "question": "What is the NetBIOS hostname and user account identified as the victim in the incident metadata?",
                "patterns": [r"^desktop-wkstn42\s*(\\|\/)?\s*j\.doe$", r"^desktop-wkstn42.*j\.doe.*"],
                "max_score": 10,
                "hint": "Check incident.json under 'affected_host' for hostname and logged_in_user."
            }
        ]
    },
    {
        "id": "lesson_2",
        "order": 2,
        "title": "Lesson 2 — Process Ancestry & Defense Impairment",
        "category": "Process Analysis",
        "objectives": [
            "Trace process ancestry and identify parent-child relationships",
            "Analyze suspicious command-line invocations targeting recovery mechanisms",
            "Identify why ransomware adversaries impair Volume Shadow Copies"
        ],
        "explanation": (
            "Ransomware routinely impairs host recovery options prior to encryption to prevent system administrators "
            "from using Windows Volume Shadow Copies or System Restore. Attackers frequently execute 'vssadmin delete shadows /all /quiet'. "
            "By analyzing Sysmon Event ID 1 (Process Creation), you can trace the execution chain from user space (explorer.exe) "
            "to the malicious binary (invoice_review.exe) down to the spawned administrative utility."
        ),
        "required_evidence": ["endpoint/process_events.jsonl"],
        "checkpoints": [
            {
                "id": "L2_C1",
                "question": "What process ID (PID) was assigned to invoice_review.exe upon execution?",
                "patterns": [r"^4912$"],
                "max_score": 10,
                "hint": "Filter process_events.jsonl for Image matching invoice_review.exe and check ProcessId."
            },
            {
                "id": "L2_C2",
                "question": "Which child process and command line was executed by invoice_review.exe to delete system shadow copies?",
                "patterns": [r"^.*vssadmin(\.exe)?\s+delete\s+shadows\s+\/all\s+\/quiet.*$"],
                "max_score": 10,
                "hint": "Inspect the command line for vssadmin.exe spawned via cmd.exe."
            }
        ]
    },
    {
        "id": "lesson_3",
        "order": 3,
        "title": "Lesson 3 — File System Activity & Forensic Hashes",
        "category": "File Forensics",
        "objectives": [
            "Distinguish normal user file modifications from high-volume ransomware behavior",
            "Compare original and encrypted file cryptographic hashes (SHA-256)",
            "Identify the extortion ransom note dropped into the victim directory"
        ],
        "explanation": (
            "Ransomware leaves distinct file-system signatures: rapid creation of renamed files appending an extension "
            "(e.g., .locked), deletion or overwriting of original files, and dropping an extortion notice. In this lesson, "
            "you will examine the canary directory FinanceReports and compare pre- and post-encryption cryptographic hashes."
        ),
        "required_evidence": ["endpoint/file_activity.jsonl", "forensic/file_hashes.json"],
        "checkpoints": [
            {
                "id": "L3_C1",
                "question": "How many canary finance documents were encrypted with the .locked extension?",
                "patterns": [r"^5$"],
                "max_score": 10,
                "hint": "Count the non-ransom note entries in forensic/file_hashes.json."
            },
            {
                "id": "L3_C2",
                "question": "What is the exact filename of the ransom note dropped into FinanceReports?",
                "patterns": [r"^restore_files_info\.txt$"],
                "max_score": 10,
                "hint": "Check the last entry in forensic/file_hashes.json or indicators.json."
            }
        ]
    },
    {
        "id": "lesson_4",
        "order": 4,
        "title": "Lesson 4 — Network Investigation & C2 Analysis",
        "category": "Network Forensics",
        "objectives": [
            "Inspect captured network traffic using packet headers and session flows",
            "Analyze C2 session negotiation and cryptographic key exchange parameters",
            "Correlate outbound network sockets with initiating endpoint processes"
        ],
        "explanation": (
            "Ransomware families often contact an external Command and Control (C2) server prior to encryption "
            "to transmit victim telemetry, exchange cryptographic keys, or report encryption progress. "
            "The packet capture network_capture.pcap contains full Ethernet IPv4 TCP streams between the infected host "
            "and the mock C2 service."
        ),
        "required_evidence": ["network/network_capture.pcap", "network/c2_conversations.json"],
        "checkpoints": [
            {
                "id": "L4_C1",
                "question": "What HTTP URI was requested by invoice_review.exe for the initial session negotiation?",
                "patterns": [r"^\/api\/v1\/session\/negotiate$"],
                "max_score": 10,
                "hint": "Filter the PCAP for HTTP POST requests or examine c2_conversations.json."
            },
            {
                "id": "L4_C2",
                "question": "What session token string was returned by the C2 server in the negotiation response?",
                "patterns": [r"^ses-98214-lock$"],
                "max_score": 10,
                "hint": "Inspect the JSON response body of packet #6 or c2_conversations.json."
            }
        ]
    },
    {
        "id": "lesson_5",
        "order": 5,
        "title": "Lesson 5 — Wazuh Detection & SIEM Correlation",
        "category": "SOC Detection",
        "objectives": [
            "Analyze Wazuh alert structures, rule IDs, and severity scoring",
            "Correlate raw Windows Event Logs / Sysmon events with fired SIEM alerts",
            "Evaluate detection efficacy and identify potential detection gaps"
        ],
        "explanation": (
            "Wazuh correlates endpoint events received via the Wazuh Agent using XML-based decoders and rules. "
            "In this lesson, you will evaluate the alerts triggered during the attack, noting their rule severity levels "
            "(Levels 9 through 14) and validating whether each stage of the attack chain was successfully caught."
        ),
        "required_evidence": ["wazuh/wazuh_alerts.json"],
        "checkpoints": [
            {
                "id": "L5_C1",
                "question": "Which Wazuh rule ID triggered with the highest alert level (Level 14)?",
                "patterns": [r"^100203$"],
                "max_score": 10,
                "hint": "Search wazuh_alerts.json for level 14."
            }
        ]
    },
    {
        "id": "lesson_6",
        "order": 6,
        "title": "Lesson 6 — MITRE ATT&CK Mapping & Threat Intelligence",
        "category": "Threat Intelligence",
        "objectives": [
            "Map observed incident indicators to standardized MITRE ATT&CK techniques",
            "Validate supporting evidence for each technique assignment",
            "Distinguish between observed facts and theoretical threat model assumptions"
        ],
        "explanation": (
            "Every technique assigned to an incident must be supported by empirical evidence. "
            "We map the observed behavior to: T1204.002 (User Execution), T1490 (Inhibit System Recovery), "
            "T1071.001 (Web Protocols), and T1486 (Data Encrypted for Impact)."
        ),
        "required_evidence": ["forensic/indicators.json", "incident_timeline.json"],
        "checkpoints": [
            {
                "id": "L6_C1",
                "question": "Which MITRE ATT&CK technique ID corresponds to Data Encrypted for Impact?",
                "patterns": [r"^t?1486$"],
                "max_score": 10,
                "hint": "Check the MITRE block of Wazuh Rule 100203."
            }
        ]
    },
    {
        "id": "lesson_7",
        "order": 7,
        "title": "Lesson 7 — Incident Response & Controlled Remediation",
        "category": "Incident Response",
        "objectives": [
            "Follow the NIST / SANS Incident Response lifecycle (Containment, Eradication, Recovery)",
            "Execute authorized containment actions to isolate the endpoint",
            "Safely restore encrypted canary files using the verified lab key",
            "Perform post-remediation verification scanning"
        ],
        "explanation": (
            "Remediation must follow a strict change-control process: Preview -> Authorize -> Execute -> Verify. "
            "In this interactive simulator, you will execute containment steps: isolating the workstation, "
            "terminating malicious processes, shutting down mock C2 beaconing, and reversing the canary file encryption."
        ),
        "required_evidence": ["endpoint/process_events.jsonl", "forensic/file_hashes.json"],
        "checkpoints": [
            {
                "id": "L7_C1",
                "question": "What is the primary objective of host network isolation during ransomware containment?",
                "patterns": [r"^.*(stop|prevent|block|halt).*(c2|spread|lateral|exfiltration|communication).*$"],
                "max_score": 10,
                "hint": "Consider what happens if the malware continues communicating with C2 or spreads laterally."
            }
        ]
    },
    {
        "id": "lesson_8",
        "order": 8,
        "title": "Lesson 8 — Comprehensive Assessment & Certification",
        "category": "Assessment",
        "objectives": [
            "Demonstrate mastery across all investigation disciplines",
            "Review cumulative investigation score and learning metrics",
            "Generate certified incident investigation report"
        ],
        "explanation": (
            "Congratulations on investigating the ransomware intrusion. Review your performance summary, "
            "verify all checkpoints have been achieved, and finalize your incident report."
        ),
        "required_evidence": ["manifest.json", "incident.json"],
        "checkpoints": [
            {
                "id": "L8_C1",
                "question": "Confirm final report submission by entering the incident identifier:",
                "patterns": [r"^inc-2026-9842$"],
                "max_score": 10,
                "hint": "The incident ID is INC-2026-9842."
            }
        ]
    }
]
