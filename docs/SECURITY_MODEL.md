# Security Model & Access Boundaries

## 1. Threat Model & Boundaries

This challenge is an enterprise security training environment. The simulation design enforces rigorous security controls:

```text
[ Infrastructure Management Network ]
                 │ (WinRM / SSH Out-of-band)
                 ▼
     [ Isolated Lab Network (10.10.50.0/24) ]
     ┌───────────────────────┬───────────────────────┐
     ▼                       ▼                       ▼
[ Windows Target ]    [ Mock C2 Server ]     [ Wazuh Manager ]
(Canary Decoy only)   (Harmless Mock Only)   (Read-Only Alerts)
```

1. **No Destructive Exploits:** The simulation runner never deploys weaponized exploits, worms, credential theft tools (e.g. Mimikatz), or boot wipers.
2. **Canary Sandboxing:** File modification is strictly isolated to `FinanceReports`. The simulation engine verifies directory path boundaries prior to initiating any file write or rename operation.
3. **Emergency Stop:** The Mock C2 service and simulation engine support immediate halting via `POST /api/v1/emergency_stop` or through the interactive remediation console.
4. **Credential Isolation:** No live credentials, OpenStack tokens, Wazuh master keys, or private SSH keys are stored in version control or visible in trainee directories.
5. **Answer Key Protection:** The Module 1 assessment key is strictly decoupled from the trainee evidence package and resides only in instructor evaluation modules.
6. **Multi-Tenant Session Isolation:** In CyberRangeCZ, each trainee receives an isolated OpenStack project sandbox and unique virtual routing table.

