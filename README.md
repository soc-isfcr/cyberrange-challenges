# SOC CyberRange — Ransomware Incident Simulation & Interactive Investigation

[![Preflight Check](https://img.shields.io/badge/Preflight-Verified-brightgreen)](docs/DEPLOYMENT.md)
[![Tests](https://img.shields.io/badge/Tests-9%2F9%20Passing-brightgreen)](tests/test_end_to_end.py)
[![Evidence Schema](https://img.shields.io/badge/Schema-v2.0.0-blue)](docs/EVIDENCE_SCHEMA.md)
[![Platform](https://img.shields.io/badge/CyberRangeCZ-KYPO%20Compatible-orange)](topology.yml)

## 1. Overview

This repository provides an industry-grade, evidence-driven SOC training challenge consisting of two connected modules:

- **Module 1: Malware Incident Simulation and Forensic Investigation**  
  A reproducible Windows ransomware-behavior emulation exercise running inside an isolated sandbox, producing genuine endpoint telemetry (Sysmon, Security Event Logs), network traffic captures (Ethernet/TCP/HTTP PCAP), and Wazuh SIEM detection alerts. Trainees investigate the evidence package and complete the 10-question CyberRangeCZ assessment.
  
- **Module 2: Interactive Malware Investigation, Detection & Response Training**  
  An interactive dark SOC analyst training application built on the **SAME** incident evidence (`INC-2026-9842`). Features 8 progressive lessons, an interactive process tree visualizer, PCAP packet and payload inspector, cryptographic file hash comparator, Wazuh SIEM alert analyzer, MITRE ATT&CK mapper, and a controlled containment and remediation console.

---

## 2. Repository Structure

```text
malware-challenge/
├── topology.yml                   # CyberRangeCZ sandbox topology definition
├── variables.yml                  # Parameterized environment variables
├── training_definition.json       # CyberRangeCZ training definition (Q1-Q10)
│
├── preflight/                     # Environment preflight & image validators
│   └── check_environment.py
│
├── simulation/                    # Safe ransomware emulation engine
│   ├── Invoke-RansomSimulation.ps1
│   ├── mock_c2_server.py
│   └── simulation_engine.py
│
├── provisioning/                  # Ansible provisioning playbooks
│   └── playbook.yml
│
├── rules/                         # Wazuh custom detection rules
│   └── ransomware_rules.xml
│
├── evidence_collector/            # Assessment evaluator & verification suite
│   └── assessment_evaluator.py
│
├── evidence/INC-2026-9842/        # Versioned incident evidence package
│   ├── manifest.json
│   ├── incident.json
│   ├── incident_timeline.json
│   ├── endpoint/
│   │   ├── process_events.jsonl
│   │   ├── file_activity.jsonl
│   │   ├── sysmon_events.jsonl
│   │   └── system_events.evtx
│   ├── network/
│   │   ├── network_capture.pcap
│   │   └── c2_conversations.json
│   ├── wazuh/
│   │   └── wazuh_alerts.json
│   ├── forensic/
│   │   ├── file_hashes.json
│   │   └── indicators.json
│   └── metadata/
│       ├── collection_metadata.json
│       └── checksums.sha256
│
├── module2/                       # Module 2 interactive SOC web service
│   ├── server.py
│   ├── evidence_loader.py
│   ├── lessons_data.py
│   └── remediation_engine.py
│
├── tests/                         # Automated validation suite (pytest)
│   └── test_end_to_end.py
│
└── docs/                          # Comprehensive technical documentation
    ├── SYSTEM_ARCHITECTURE.md
    ├── SANDBOX_TOPOLOGY.md
    ├── SIMULATION_DESIGN.md
    ├── EVIDENCE_SCHEMA.md
    ├── MODULE_1_GUIDE.md
    ├── MODULE_2_GUIDE.md
    ├── DEPLOYMENT.md
    ├── SECURITY_MODEL.md
    ├── TESTING.md
    └── TROUBLESHOOTING.md
```

---

## 3. Quick Start & Operational Commands

### Step 1: Run Preflight Check
Verify topology syntax, IP mappings, and environment prerequisites:
```bash
python preflight/check_environment.py
```

### Step 2: Generate / Verify Evidence Package
Generate or verify the certified incident evidence package (`INC-2026-9842`):
```bash
python simulation/simulation_engine.py
```

### Step 3: Run Full Validation Test Suite
Execute end-to-end automated tests with pytest:
```bash
python -m pytest -v tests/test_end_to_end.py
```

### Step 4: Launch Module 2 Interactive Investigation Console
Start the dark SOC analyst web application:
```bash
python -m uvicorn module2.server:app --host 0.0.0.0 --port 8000
```
Open your browser to: **`http://localhost:8000`**

---

## 4. CyberRangeCZ Integration

1. **Topology Definition:** `topology.yml` defines the multi-node lab environment (`target`, `analyst`, `wazuh`, `mockc2`, `router1`) over CIDR `10.10.50.0/24`.
2. **Provisioning:** `provisioning/playbook.yml` provisions Wazuh rules, installs forensic tools on Kali, starts Mock C2, and prepares the Windows endpoint.
3. **Assessment:** `training_definition.json` configures the 10-level CyberRangeCZ assessment with questions, answers, hints, and scoring.
4. **Offline Replay Fallback:** When live OpenStack Windows images or cloud quotas are unavailable, the system transparently utilizes the verified offline telemetry package so training is never blocked.

---

## 5. Documentation Directory

Detailed technical guides are available in the [`docs/`](docs/) directory:
- [System Architecture](docs/SYSTEM_ARCHITECTURE.md)
- [Sandbox Topology](docs/SANDBOX_TOPOLOGY.md)
- [Simulation Design](docs/SIMULATION_DESIGN.md)
- [Evidence Schema](docs/EVIDENCE_SCHEMA.md)
- [Module 1 Guide](docs/MODULE_1_GUIDE.md)
- [Module 2 Guide](docs/MODULE_2_GUIDE.md)
- [Deployment Guide](docs/DEPLOYMENT.md)
- [Security Model](docs/SECURITY_MODEL.md)
- [Testing Guide](docs/TESTING.md)
- [Troubleshooting & FAQs](docs/TROUBLESHOOTING.md)
