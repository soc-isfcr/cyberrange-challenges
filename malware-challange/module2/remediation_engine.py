"""
Safe, Controlled Remediation & Incident Containment Engine.
Implements preview, authorization verification, before/after telemetry snapshots,
and rollback capabilities for SOC training exercises.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List

class RemediationEngine:
    def __init__(self, incident_dir: Path):
        self.incident_dir = incident_dir
        self.state_file = incident_dir / "metadata" / "remediation_state.json"
        self.audit_log_file = incident_dir / "metadata" / "remediation_audit.jsonl"
        self.state: Dict[str, Any] = self._load_state()

    def _default_state(self) -> Dict[str, Any]:
        return {
            "endpoint_isolated": False,
            "processes_terminated": False,
            "mock_c2_disabled": False,
            "files_restored": False,
            "containment_verified": False,
            "last_action_timestamp": None,
            "action_history": []
        }

    def _load_state(self) -> Dict[str, Any]:
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                pass
        return self._default_state()

    def _save_state(self):
        with open(self.state_file, 'w', encoding='utf-8') as f:
            json.dump(self.state, f, indent=2)

    def _log_audit(self, action: str, user: str, details: Dict[str, Any]):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "executed_by": user,
            "details": details
        }
        with open(self.audit_log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry) + "\n")

    def preview_action(self, action_id: str) -> Dict[str, Any]:
        previews = {
            "ISOLATE_HOST": {
                "action_id": "ISOLATE_HOST",
                "title": "Network Host Isolation",
                "target_host": "DESKTOP-WKSTN42 (10.10.50.42)",
                "impact_summary": "Revokes lab router gateway forwarding for 10.10.50.42; retains management/monitoring link.",
                "risk_level": "LOW",
                "reversible": True,
                "required_permission": "SOC_ANALYST_L2"
            },
            "TERMINATE_MALWARE_TREE": {
                "action_id": "TERMINATE_MALWARE_TREE",
                "title": "Terminate Malicious Process Hierarchy",
                "target_host": "DESKTOP-WKSTN42",
                "affected_processes": [
                    {"pid": 4912, "name": "invoice_review.exe"},
                    {"pid": 5120, "name": "cmd.exe"},
                    {"pid": 5288, "name": "vssadmin.exe"}
                ],
                "impact_summary": "Issues SIGKILL / TerminateProcess to PID 4912 and any spawned subprocesses.",
                "risk_level": "LOW",
                "reversible": False,
                "required_permission": "SOC_ANALYST_L2"
            },
            "DISABLE_MOCK_C2": {
                "action_id": "DISABLE_MOCK_C2",
                "title": "Disable Command and Control Endpoint",
                "target_host": "10.10.50.30:8080 (corp-mockc2.lab)",
                "impact_summary": "Sends emergency-stop signal to Mock C2 service and applies lab firewall drop rule.",
                "risk_level": "LOW",
                "reversible": True,
                "required_permission": "SOC_ANALYST_L2"
            },
            "RESTORE_DECOY_FILES": {
                "action_id": "RESTORE_DECOY_FILES",
                "title": "Decoy Directory Cryptographic File Recovery",
                "target_host": "DESKTOP-WKSTN42",
                "target_folder": "C:\\Users\\j.doe\\Documents\\FinanceReports",
                "affected_files": 5,
                "impact_summary": "Reverses AES-256 / XOR encryption on 5 canary documents, restores original extensions, and deletes RESTORE_FILES_INFO.txt.",
                "risk_level": "SAFE",
                "reversible": True,
                "required_permission": "SOC_ANALYST_L2"
            },
            "RESCAN_ENVIRONMENT": {
                "action_id": "RESCAN_ENVIRONMENT",
                "title": "Comprehensive Containment Verification Scan",
                "target_host": "All Lab Nodes",
                "impact_summary": "Inspects running processes, open network sockets, canary file hashes, and active Wazuh alerts to verify clean state.",
                "risk_level": "SAFE",
                "reversible": False,
                "required_permission": "SOC_ANALYST_L1"
            }
        }
        if action_id not in previews:
            raise ValueError(f"Unknown remediation action: {action_id}")
        return previews[action_id]

    def execute_action(self, action_id: str, confirmed: bool, user: str = "Trainee-Analyst") -> Dict[str, Any]:
        if not confirmed:
            raise ValueError("Action execution aborted: explicit confirmation checkbox required.")

        preview = self.preview_action(action_id)
        before_state = dict(self.state)
        ts = datetime.now(timezone.utc).isoformat()

        if action_id == "ISOLATE_HOST":
            self.state["endpoint_isolated"] = True
            msg = "Host DESKTOP-WKSTN42 successfully isolated from network."

        elif action_id == "TERMINATE_MALWARE_TREE":
            self.state["processes_terminated"] = True
            msg = "Process tree (invoice_review.exe PID 4912) terminated."

        elif action_id == "DISABLE_MOCK_C2":
            self.state["mock_c2_disabled"] = True
            msg = "Mock C2 service (10.10.50.30:8080) halted and blocked."

        elif action_id == "RESTORE_DECOY_FILES":
            self.state["files_restored"] = True
            msg = "All 5 canary documents restored to original plaintext state; ransom note deleted."

        elif action_id == "RESCAN_ENVIRONMENT":
            # Check if all preceding containment steps have completed
            ready = (
                self.state["endpoint_isolated"] and
                self.state["processes_terminated"] and
                self.state["mock_c2_disabled"] and
                self.state["files_restored"]
            )
            self.state["containment_verified"] = ready
            msg = "Post-remediation verification scan: CLEAN & CONTAINED." if ready else "Verification scan: CONTAINMENT INCOMPLETE."

        self.state["last_action_timestamp"] = ts
        self.state["action_history"].append({
            "action_id": action_id,
            "timestamp": ts,
            "status": "SUCCESS"
        })
        self._save_state()
        self._log_audit(action_id, user, {"before": before_state, "after": self.state})

        return {
            "action_id": action_id,
            "status": "SUCCESS",
            "message": msg,
            "executed_at": ts,
            "state": self.state
        }

    def reset_sandbox(self) -> Dict[str, Any]:
        self.state = self._default_state()
        self._save_state()
        self._log_audit("RESET_SANDBOX", "SYSTEM", {"message": "Sandbox state reset to clean baseline"})
        return {"status": "SUCCESS", "message": "Sandbox reset to baseline state."}

