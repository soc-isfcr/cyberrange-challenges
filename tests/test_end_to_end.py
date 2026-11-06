#!/usr/bin/env python3
"""
Comprehensive End-to-End Validation Test Suite for SOC CyberRange Malware Challenge.
Validates:
1. Topology definition and IP mapping consistency
2. Evidence package generation, artifacts existence, and SHA-256 manifest integrity
3. PCAP binary format validation (Ethernet, IPv4, TCP flags, HTTP negotiation payloads)
4. Module 1 assessment evaluation (Q1 through Q10)
5. Module 2 REST API endpoints (FastAPI TestClient)
6. Interactive checkpoint grading, hint penalties, and progress tracking
7. Controlled remediation actions, previews, confirmations, and verification scans
"""

import sys
import os
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from fastapi.testclient import TestClient

from preflight.check_environment import validate_topology
from simulation.simulation_engine import EvidenceGenerator, INCIDENT_ID
from evidence_collector.assessment_evaluator import AssessmentEvaluator
from module2.evidence_loader import EvidenceLoader
from module2.remediation_engine import RemediationEngine
from module2.server import app

client = TestClient(app)

def test_01_topology_validation():
    """Verify topology.yml adheres to CyberRangeCZ schema."""
    topo_path = PROJECT_ROOT / "topology.yml"
    assert topo_path.exists(), "topology.yml must exist"
    ok, msg = validate_topology(topo_path)
    assert ok, f"Topology validation failed: {msg}"

def test_02_evidence_generation_and_integrity():
    """Verify evidence generator produces bit-for-bit validated package."""
    evidence_base = PROJECT_ROOT / "evidence"
    gen = EvidenceGenerator(evidence_base)
    inc_dir = gen.generate_all()
    assert inc_dir.exists()
    assert (inc_dir / "manifest.json").exists()
    assert (inc_dir / "metadata" / "checksums.sha256").exists()
    assert gen.verify_integrity(), "Package integrity checksums must verify"

def test_03_pcap_structure():
    """Verify network_capture.pcap contains expected HTTP handshake and beacons."""
    pcap_path = PROJECT_ROOT / "evidence" / INCIDENT_ID / "network" / "network_capture.pcap"
    assert pcap_path.exists()
    assert pcap_path.stat().st_size > 500, "PCAP file must not be empty"

    loader = EvidenceLoader(PROJECT_ROOT / "evidence" / INCIDENT_ID)
    assert len(loader.pcap_packets) >= 12, "Should contain at least 12 packets"
    
    # Check for HTTP POST negotiation and GET beacon
    http_packets = [p for p in loader.pcap_packets if p["protocol"] == "HTTP"]
    assert len(http_packets) >= 2, "Should contain both POST negotiation and GET beacon"
    assert any("/api/v1/session/negotiate" in p["info"] for p in http_packets)
    assert any("/api/v1/beacon" in p["info"] for p in http_packets)

def test_04_module1_assessment_evaluator():
    """Verify Module 1 evaluator grades exact answers to 100% and rejects bogus input."""
    inc_dir = PROJECT_ROOT / "evidence" / INCIDENT_ID
    evaluator = AssessmentEvaluator(inc_dir)

    # Valid canonical answers
    good_answers = {
        "Q1": "DESKTOP-WKSTN42",
        "Q2": "invoice_review.exe",
        "Q3": "explorer.exe",
        "Q4": "2026-11-06T09:14:22Z",
        "Q5": ".locked",
        "Q6": "10.10.50.30:8080",
        "Q7": "100202",
        "Q8": "RESTORE_FILES_INFO.txt",
        "Q9": "T1490",
        "Q10": "isolate"
    }
    res = evaluator.evaluate_submission(good_answers)
    assert res["passed"] is True
    assert res["total_score"] == 100
    assert res["percentage"] == 100.0

    # Bogus answers
    bad_answers = {
        "Q1": "WRONG-HOST",
        "Q2": "calc.exe",
        "Q3": "unknown.exe",
        "Q4": "1999-01-01T00:00:00Z",
        "Q5": ".xyz",
        "Q6": "1.1.1.1:80",
        "Q7": "999999",
        "Q8": "none.txt",
        "Q9": "T9999",
        "Q10": "do nothing"
    }
    bad_res = evaluator.evaluate_submission(bad_answers)
    assert bad_res["passed"] is False
    assert bad_res["total_score"] == 0

def test_05_module2_api_incident_endpoints():
    """Verify Module 2 incident API returns valid metadata and timeline."""
    resp = client.get("/api/incident")
    assert resp.status_code == 200
    data = resp.json()
    assert data["manifest"]["incident_id"] == INCIDENT_ID
    assert data["incident"]["affected_host"]["hostname"] == "DESKTOP-WKSTN42"
    assert len(data["timeline"]) >= 6

def test_06_module2_evidence_endpoints():
    """Verify evidence query APIs (processes, files, network, wazuh, mitre)."""
    # Processes
    r_proc = client.get("/api/evidence/processes")
    assert r_proc.status_code == 200
    pdata = r_proc.json()
    assert pdata["tree"]["name"] == "explorer.exe"
    assert any(p["ProcessId"] == 4912 for p in pdata["flat_list"])

    # Files
    r_files = client.get("/api/evidence/files")
    assert r_files.status_code == 200
    fdata = r_files.json()
    assert len(fdata["file_hashes"]) == 6

    # Network
    r_net = client.get("/api/evidence/network?protocol=HTTP")
    assert r_net.status_code == 200
    ndata = r_net.json()
    assert ndata["filtered_packets"] >= 2

    # Wazuh
    r_wazuh = client.get("/api/evidence/wazuh")
    assert r_wazuh.status_code == 200
    wdata = r_wazuh.json()
    rule_ids = [a["rule"]["id"] for a in wdata["alerts"]]
    assert "100201" in rule_ids
    assert "100202" in rule_ids
    assert "100203" in rule_ids

    # MITRE
    r_mitre = client.get("/api/evidence/mitre")
    assert r_mitre.status_code == 200
    mdata = r_mitre.json()
    tech_ids = [t["id"] for t in mdata["techniques"]]
    assert "T1490" in tech_ids
    assert "T1486" in tech_ids

def test_07_interactive_checkpoint_grading_and_hints():
    """Verify interactive checkpoint submission, scoring, and hint penalties."""
    # Reset progress first
    client.post("/api/progress/reset")

    # Reveal hint for L1_C1 (penalty 2 points)
    h_resp = client.post("/api/lessons/lesson_1/checkpoints/L1_C1/hint")
    assert h_resp.status_code == 200
    assert "hint" in h_resp.json()

    # Submit correct answer for L1_C1
    s_resp = client.post("/api/lessons/lesson_1/checkpoints/L1_C1/submit", json={"answer": "DESKTOP-WKSTN42\\j.doe"})
    assert s_resp.status_code == 200
    s_data = s_resp.json()
    assert s_data["is_correct"] is True
    assert s_data["score_earned"] == 8  # 10 max minus 2 hint penalty
    assert s_data["hint_penalty"] == 2

def test_08_controlled_remediation_lifecycle():
    """Verify remediation preview, confirmation requirement, execution, and scan."""
    client.post("/api/remediation/reset")

    # 1. Preview
    p_resp = client.get("/api/remediation/preview/ISOLATE_HOST")
    assert p_resp.status_code == 200
    assert p_resp.json()["target_host"] == "DESKTOP-WKSTN42 (10.10.50.42)"

    # 2. Execution without confirmation must fail
    fail_resp = client.post("/api/remediation/execute", json={"action_id": "ISOLATE_HOST", "confirmed": False})
    assert fail_resp.status_code == 400

    # 3. Execution with confirmation
    exec1 = client.post("/api/remediation/execute", json={"action_id": "ISOLATE_HOST", "confirmed": True})
    assert exec1.status_code == 200
    assert exec1.json()["state"]["endpoint_isolated"] is True

    # 4. Execute remaining actions
    client.post("/api/remediation/execute", json={"action_id": "TERMINATE_MALWARE_TREE", "confirmed": True})
    client.post("/api/remediation/execute", json={"action_id": "DISABLE_MOCK_C2", "confirmed": True})
    client.post("/api/remediation/execute", json={"action_id": "RESTORE_DECOY_FILES", "confirmed": True})

    # 5. Run verification scan
    scan_resp = client.post("/api/remediation/execute", json={"action_id": "RESCAN_ENVIRONMENT", "confirmed": True})
    assert scan_resp.status_code == 200
    assert scan_resp.json()["state"]["containment_verified"] is True
    assert "CLEAN & CONTAINED" in scan_resp.json()["message"]

def test_09_ui_serving():
    """Verify the root endpoint serves the dark SOC investigation SPA."""
    resp = client.get("/")
    assert resp.status_code == 200
    assert "SOC CyberRange — Incident Investigation & Response" in resp.text
    assert "INC-2026-9842" in resp.text

if __name__ == "__main__":
    pytest.main(["-v", __file__])

