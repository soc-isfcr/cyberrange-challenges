# System Architecture Specification

## 1. Architectural Philosophy & Core Tenets

The SOC CyberRange Ransomware Simulation & Interactive Investigation architecture is designed around evidence fidelity, deterministic reproducibility, absolute lab safety, and native interoperability with CyberRangeCZ (KYPO CRP).

```mermaid
graph TD
    subgraph RangeInfra["Infrastructure & Orchestration Layer (OpenStack / CyberRangeCZ)"]
        Router["Debian Router (router1)<br>10.10.50.2"]
        Net["Lab Network (lab-network)<br>10.10.50.0/24"]
    end

    subgraph Targets["Target & Simulation Layer"]
        WinTarget["Windows Target (target)<br>10.10.50.42<br>DESKTOP-WKSTN42"]
        SimEngine["Safe Simulation Runner<br>(Invoke-RansomSimulation.ps1)"]
        Decoy["Canary Decoy Directory<br>FinanceReports/*.locked"]
        MockC2["Mock C2 Server (mockc2)<br>10.10.50.30:8080"]
    end

    subgraph SOC["SOC Detection & Monitoring Layer"]
        WazuhMgr["Wazuh SOC Manager (wazuh)<br>10.10.50.10"]
        WazuhRules["Custom Ransomware Rules<br>Rules 100201 - 100204"]
        AlertsFeed["Alerts Feed<br>/opt/lab/alerts.json"]
    end

    subgraph Evidence["Evidence & Data Contract Layer"]
        Pkg["Evidence Package (INC-2026-9842)<br>manifest.json + checksums.sha256"]
        PCAP["Network Capture<br>network_capture.pcap"]
        Logs["Endpoint Telemetry<br>Sysmon & Security EVTX/JSONL"]
        Hashes["Forensic Hashes<br>file_hashes.json"]
    end

    subgraph Training["Training & Investigation Layer"]
        M1["Module 1: Forensic Investigation<br>(CyberRangeCZ Assessment Q1-Q10)"]
        M2["Module 2: Interactive SOC Web SPA<br>(FastAPI + Dark SOC UI)"]
        Remediation["Controlled Remediation Engine<br>(Preview -> Authorize -> Execute -> Verify)"]
    end

    Router --- Net
    Net --- WinTarget
    Net --- MockC2
    Net --- WazuhMgr
    WinTarget --> SimEngine
    SimEngine --> Decoy
    SimEngine -. Outbound C2 Handshake .-> MockC2
    WinTarget -. Telemetry Forwarding .-> WazuhMgr
    WazuhMgr --> WazuhRules --> AlertsFeed

    SimEngine --> Logs
    MockC2 --> PCAP
    AlertsFeed --> Pkg
    Logs --> Pkg
    PCAP --> Pkg
    Hashes --> Pkg

    Pkg ==> M1
    Pkg ==> M2
    M2 --> Remediation
```

---

## 2. Layer-by-Layer Architectural Breakdown

### 2.1 Infrastructure & Sandbox Layer
- **Orchestration:** Managed through CyberRangeCZ topology definition (`topology.yml`) and Ansible playbooks (`provisioning/playbook.yml`).
- **Network Segmentation:** Isolated CIDR `10.10.50.0/24`. All lab nodes communicate over private virtual networking behind a dedicated router (`10.10.50.2`).
- **Target Isolation:** The Windows endpoint has zero internet ingress/egress. Interservice traffic is restricted to the internal lab router and mock services.

### 2.2 Endpoint Simulation Layer
- **Target OS:** Windows 10 Pro 64-bit (Build 19045).
- **Emulation Principles:**
  - Strictly non-destructive, reversible cryptographic file modifications.
  - No credential dumping, no privilege escalation exploits, no unconstrained worm propagation.
  - Operation constrained to canary directory `C:\Users\j.doe\Documents\FinanceReports`.
  - Process creation reproduces authentic enterprise attack telemetry (Sysmon Event ID 1: `explorer.exe` -> `invoice_review.exe` -> `cmd.exe` -> `vssadmin.exe delete shadows /all /quiet`).

### 2.3 SOC Detection Layer
- **SIEM Manager:** Wazuh 4.14 All-in-One deployment (`10.10.50.10`).
- **Detection Logic:**
  - `100201` (Level 10): Suspicious binary launched from user `Downloads` directory.
  - `100202` (Level 12): Volume Shadow Copy deletion via `vssadmin.exe`.
  - `100203` (Level 14): Mass file renaming appending `.locked` and ransom note dropped.
  - `100204` (Level 9): Outbound connection to unclassified external port (8080).
- **Export Mechanism:** Continuous export to `/opt/lab/alerts.json` for trainee consumption.

### 2.4 Evidence & Data Contract Layer
- **Single Source of Truth:** `evidence/INC-2026-9842/`.
- Every generated artifact is indexed in `manifest.json` and validated against `checksums.sha256`.
- Rigorous separation of **Observed Facts**, **Derived Findings**, **Analyst Interpretations**, and **Assessment Criteria**.

### 2.5 Training & Investigation Layer
- **Module 1:** CyberRangeCZ platform assessment via `training_definition.json` evaluating trainee findings across 10 structured questions.
- **Module 2:** Standalone or integrated interactive dark SOC web application offering 8 guided lessons, an interactive process tree visualizer, PCAP payload inspector, Wazuh alert correlation cards, MITRE ATT&CK mapping, and a gated change-control remediation console.

