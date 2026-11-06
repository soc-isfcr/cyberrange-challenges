# Sandbox Topology Specification

## 1. Node Inventory & Specifications

| Node Name | Role | Base Box Image | Mgmt Protocol | Mgmt User | Hardware Flavor | Internal IP |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `wazuh` | SOC SIEM & Telemetry Manager | `ubuntu-noble-x86_64` | SSH | `ubuntu` | `wazuh.server50` (4 vCPU, 8GB RAM, 50GB disk) | `10.10.50.10` |
| `analyst` | Kali Analyst Workstation | `kali` | SSH | `debian` | `analyst.kali30` (2 vCPU, 4GB RAM, 30GB disk) | `10.10.50.20` |
| `mockc2` | Controlled C2 Service | `debian-12-x86_64` | SSH | `debian` | `standard.tiny` (1 vCPU, 1GB RAM, 10GB disk) | `10.10.50.30` |
| `target` | Victim Windows Endpoint | `windows-10-x86_64` | WINRM | `Administrator` | `windows.workstation40` (4 vCPU, 8GB RAM, 40GB disk) | `10.10.50.42` |
| `router1` | Lab Gateway & Firewall Router | `debian-12-x86_64` | SSH | `debian` | `standard.tiny` (1 vCPU, 1GB RAM, 10GB disk) | `10.10.50.2` |

---

## 2. Virtual Network Topology

```text
               +-------------------------------------------+
               |        CyberRangeCZ Router (router1)      |
               |                10.10.50.2                 |
               +---------------------+---------------------+
                                     |
                                     | (lab-network: 10.10.50.0/24)
          +--------------------------+--------------------------+
          |                          |                          |
+---------+---------+      +---------+---------+      +---------+---------+
|    wazuh manager  |      |   kali analyst    |      |  mock c2 server   |
|    10.10.50.10    |      |    10.10.50.20    |      |    10.10.50.30    |
+-------------------+      +-------------------+      +-------------------+
                                     |
                           +---------+---------+
                           |  windows 10 target|
                           |  (DESKTOP-WKSTN42)|
                           |    10.10.50.42    |
                           +-------------------+
```

---

## 3. Network Segmentation & Firewall Policy

1. **Management Network (Out-of-Band):**
   - CyberRangeCZ Ansible orchestration reaches nodes over private OpenStack management interfaces via SSH (Linux) and WinRM (Windows).
   - Trainees have zero direct access to the management subnet.
2. **Lab Network (`lab-network`, 10.10.50.0/24):**
   - Trainee analyst workstation (`10.10.50.20`) has access to investigate telemetry feeds and exported evidence.
   - `target` (`10.10.50.42`) can only communicate with:
     - `wazuh` (`10.10.50.10`) on TCP port `1514` (Wazuh agent event delivery) and `1515` (agent registration).
     - `mockc2` (`10.10.50.30`) on TCP port `8080` (HTTP simulation handshake).
   - All outbound traffic to public external networks (Internet) is dropped at `router1`.

---

## 4. Hardware Sizing & Resource Footprint

- Total vCPUs: 12 cores
- Total Memory: 22 GB RAM
- Total Storage: 140 GB SSD
- Preflight verification ensures that if OpenStack quotas are exceeded, the offline replay engine can be used without disruption.

