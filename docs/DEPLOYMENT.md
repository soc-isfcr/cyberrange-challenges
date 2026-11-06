# Deployment Guide — CyberRangeCZ & Standalone Environments

## 1. Prerequisites

### For CyberRangeCZ (KYPO CRP / OpenStack)
- CyberRangeCZ platform access with OpenStack project quota.
- OpenStack Glance images:
  - `ubuntu-noble-x86_64` (Wazuh SIEM Manager)
  - `kali` (Analyst Workstation)
  - `debian-12-x86_64` (Mock C2 & Lab Router)
  - `windows-10-x86_64` (Victim Endpoint with WinRM enabled)
- Flavors defined: `wazuh.server50`, `analyst.kali30`, `standard.tiny`, `windows.workstation40`.

### For Standalone / Offline Evaluation Mode
- Python 3.10+ (Python 3.13 tested).
- Python libraries: `fastapi`, `uvicorn`, `pydantic`, `pyyaml`, `pytest`, `requests`, `httpx`.
- Browser (Chrome, Firefox, Edge).

---

## 2. Deployment Procedures

### Procedure A: CyberRangeCZ Platform Integration
1. Push `malware-challenge` repository to your internal CyberRange Git server (e.g., GitLab).
2. Register the sandbox definition in CyberRangeCZ pointing to `topology.yml` and `provisioning/playbook.yml`.
3. Import `training_definition.json` into the CyberRangeCZ Training Definition Manager.
4. Launch a training run; the platform provisions the nodes and initiates the provisioning playbook.

### Procedure B: Preflight Verification & Offline Telemetry Engine
1. Run preflight environment check:
   ```bash
   python preflight/check_environment.py
   ```
2. Generate or refresh the verified incident evidence package:
   ```bash
   python simulation/simulation_engine.py
   ```
3. Run the automated test suite:
   ```bash
   pytest -v tests/test_end_to_end.py
   ```
4. Start the Module 2 interactive SOC server:
   ```bash
   python -m uvicorn module2.server:app --host 0.0.0.0 --port 8000
   ```
5. Access the investigation interface at `http://localhost:8000`.

---

## 3. Windows Image Preparation (for Live OpenStack)
To prepare a custom Windows 10 base box for CyberRangeCZ:
1. Install Windows 10 Enterprise / Pro on a KVM virtual disk.
2. Install Cloudbase-Init for OpenStack metadata and user initialization.
3. Enable WinRM HTTPS / HTTP and allow remote PowerShell execution:
   ```powershell
   winrm quickconfig -q
   winrm set winrm/config/service/auth '@{Basic="true"}'
   winrm set winrm/config/service '@{AllowUnencrypted="true"}'
   ```
4. Install Sysmon 64-bit with a standard configuration file.
5. Sysprep and upload image to OpenStack Glance as `windows-10-x86_64`.

