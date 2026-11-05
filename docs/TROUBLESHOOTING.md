# Troubleshooting Guide & Operational FAQs

## 1. Diagnostics & Common Issues

### Issue 1: OpenStack Glance image `windows-10-x86_64` not found
- **Symptom:** Preflight check or CyberRangeCZ sandbox allocation fails reporting missing image.
- **Cause:** Cloud administrator has not uploaded a prepared Windows 10 base box image to OpenStack Glance.
- **Resolution:**
  1. Follow the image preparation steps in `docs/DEPLOYMENT.md` to build and upload the base box.
  2. For development or assessment testing where OpenStack is not connected, use the pre-built evidence package (`python simulation/simulation_engine.py`) and launch Module 2 directly.

### Issue 2: Checksum mismatch or evidence package corruption
- **Symptom:** Preflight verification reports `Hash mismatch on ...`.
- **Cause:** Artifact files were edited or truncated manually.
- **Resolution:**
  Regenerate the certified evidence package:
  ```bash
  python simulation/simulation_engine.py
  ```

### Issue 3: WinRM connection timeout on Windows target
- **Symptom:** Ansible playbook fails at `win_ping` task.
- **Cause:** WinRM service not started, firewall blocking port 5985/5986, or UAC remote elevation restriction.
- **Resolution:**
  Log in to the VM console and run:
  ```powershell
  Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Value 1 -Type DWord
  Restart-Service WinRM
  ```

### Issue 4: Wazuh Manager does not trigger alerts on custom rules
- **Symptom:** Events appear in Wazuh agent archives but no alerts trigger on rule 100201-100204.
- **Cause:** `ransomware_rules.xml` syntax error or manager not restarted.
- **Resolution:**
  Test XML syntax:
  ```bash
  /var/ossec/bin/wazuh-logtest
  ```
  Restart manager:
  ```bash
  systemctl restart wazuh-manager
  ```

### Issue 5: Port 8000 already in use when launching Module 2
- **Resolution:**
  Specify an alternate port via the `PORT` environment variable:
  ```bash
  $env:PORT = "8088"; python -m uvicorn module2.server:app --port 8088
  ```
