# Evidence Package Schema & Data Contract

## 1. Directory Structure

```text
evidence/INC-2026-9842/
├── manifest.json                  # Top-level manifest, schema versions, integrity index
├── incident.json                  # High-level incident metadata and scope
├── incident_timeline.json         # Chronological event log with MITRE mappings
├── endpoint/
│   ├── process_events.jsonl       # Sysmon Event ID 1 & Sec 4688 records
│   ├── file_activity.jsonl        # Sysmon Event ID 11 file creation / rename records
│   ├── system_events.evtx         # Windows EVTX binary event log container
│   └── sysmon_events.jsonl        # Complete normalized Sysmon telemetry dump
├── network/
│   ├── network_capture.pcap       # Wireshark / tshark Ethernet PCAP capture
│   └── c2_conversations.json      # Structured HTTP/TCP session metadata
├── wazuh/
│   └── wazuh_alerts.json          # Native Wazuh alert objects with rule metadata
├── forensic/
│   ├── file_hashes.json           # Pre- and post-encryption SHA-256 comparison table
│   └── indicators.json            # IOC repository (IPs, hashes, paths, URIs)
└── metadata/
    ├── collection_metadata.json   # Host, collector versions, start/end timestamps
    └── checksums.sha256           # SHA-256 checksums of all package artifacts
```

---

## 2. Manifest Specification (`manifest.json`)

```json
{
  "incident_id": "INC-2026-9842",
  "scenario_id": "soc-ransomware-investigation",
  "scenario_version": "1.0.0",
  "evidence_schema_version": "2.0.0",
  "target_hostname": "DESKTOP-WKSTN42",
  "target_os": "Windows 10 Pro (Build 19045)",
  "collection_start_utc": "2026-11-06T09:14:00.000Z",
  "collection_end_utc": "2026-11-06T09:16:00.000Z",
  "data_classification": {
    "observed_facts": [ ... ],
    "derived_findings": [ ... ],
    "analyst_interpretations": [ ... ],
    "expected_containment": [ ... ]
  },
  "artifacts": {
    "endpoint/process_events.jsonl": {
      "path": "endpoint/process_events.jsonl",
      "size_bytes": 2865,
      "sha256": "...",
      "category": "endpoint"
    }
  }
}
```

---

## 3. Data Integrity & Validation Rules

1. **Checksum Enforcement:** Every file in the package must match its SHA-256 record in `metadata/checksums.sha256`.
2. **Timestamps:** All timestamps MUST use UTC in ISO 8601 extended format with millisecond precision (`YYYY-MM-DDTHH:MM:SS.sssZ`).
3. **No Synthetic Hallucinations:** Telemetry files must not contain fictional data fields. If an event source was inactive, the file must honestly reflect missing telemetry rather than substituting fake entries.
4. **Shared Contract:** The same incident package is loaded by both Module 1 and Module 2, guaranteeing identical evidence across the entire exercise.
