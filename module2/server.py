#!/usr/bin/env python3
"""
Module 2 Interactive SOC Training & Investigation Web Server.
Serves:
- REST APIs for incident evidence, lessons, checkpoints, and remediation
- Single-Page Interactive SOC Analyst Web Interface
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Query, Body
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .evidence_loader import EvidenceLoader
from .lessons_data import LESSONS
from .remediation_engine import RemediationEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("Module2Server")

BASE_DIR = Path(__file__).resolve().parent.parent
INCIDENT_DIR = BASE_DIR / "evidence" / "INC-2026-9842"

loader = EvidenceLoader(INCIDENT_DIR)
remediation_engine = RemediationEngine(INCIDENT_DIR)

app = FastAPI(
    title="SOC CyberRange — Interactive Incident Investigation",
    description="Module 2: Ransomware Incident Simulation, SOC Detection & Interactive Response",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# Trainee progress store (in-memory with file backup)
PROGRESS_FILE = INCIDENT_DIR / "metadata" / "trainee_progress.json"

def load_progress() -> Dict[str, Any]:
    if PROGRESS_FILE.exists():
        try:
            with open(PROGRESS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "completed_lessons": [],
        "checkpoint_scores": {},
        "hints_used": {},
        "total_score": 0,
        "max_score": 100,
        "percentage": 0.0
    }

def save_progress(p: Dict[str, Any]):
    with open(PROGRESS_FILE, 'w', encoding='utf-8') as f:
        json.dump(p, f, indent=2)

progress = load_progress()

# ------------------------------------------------------------------------------
# API Endpoints
# ------------------------------------------------------------------------------
@app.get("/api/incident")
def get_incident():
    return {
        "manifest": loader.manifest,
        "incident": loader.incident,
        "timeline": loader.timeline,
        "indicators": loader.indicators,
        "integrity_verified": loader.integrity_verified
    }

@app.get("/api/lessons")
def get_lessons():
    resp = []
    for l in LESSONS:
        l_copy = dict(l)
        l_copy["completed"] = l["id"] in progress["completed_lessons"]
        # Hide regex patterns from trainee
        sanitized_checkpoints = []
        for cp in l.get("checkpoints", []):
            score_data = progress["checkpoint_scores"].get(cp["id"], {})
            sanitized_checkpoints.append({
                "id": cp["id"],
                "question": cp["question"],
                "max_score": cp["max_score"],
                "score_awarded": score_data.get("earned", 0),
                "is_passed": score_data.get("passed", False),
                "hint_revealed": cp["id"] in progress["hints_used"]
            })
        l_copy["checkpoints"] = sanitized_checkpoints
        resp.append(l_copy)
    return {
        "lessons": resp,
        "progress": progress
    }

class CheckpointSubmit(BaseModel):
    answer: str

@app.post("/api/lessons/{lesson_id}/checkpoints/{checkpoint_id}/hint")
def reveal_hint(lesson_id: str, checkpoint_id: str):
    for l in LESSONS:
        if l["id"] == lesson_id:
            for cp in l.get("checkpoints", []):
                if cp["id"] == checkpoint_id:
                    progress["hints_used"][checkpoint_id] = True
                    save_progress(progress)
                    return {"checkpoint_id": checkpoint_id, "hint": cp["hint"]}
    raise HTTPException(status_code=404, detail="Checkpoint not found")

@app.post("/api/lessons/{lesson_id}/checkpoints/{checkpoint_id}/submit")
def submit_checkpoint(lesson_id: str, checkpoint_id: str, req: CheckpointSubmit):
    import re
    user_ans = req.answer.strip().lower()
    
    for l in LESSONS:
        if l["id"] == lesson_id:
            for cp in l.get("checkpoints", []):
                if cp["id"] == checkpoint_id:
                    matched = any(re.match(p, user_ans) for p in cp["patterns"])
                    penalty = 2 if checkpoint_id in progress["hints_used"] else 0
                    earned = max(0, cp["max_score"] - penalty) if matched else 0

                    progress["checkpoint_scores"][checkpoint_id] = {
                        "passed": matched,
                        "earned": earned,
                        "max": cp["max_score"],
                        "submitted": req.answer
                    }
                    
                    # Update totals
                    tot = sum(c.get("earned", 0) for c in progress["checkpoint_scores"].values())
                    progress["total_score"] = tot
                    progress["percentage"] = round((tot / progress["max_score"]) * 100, 1)

                    # Check if all checkpoints in lesson are passed
                    all_cps = [c["id"] for c in l.get("checkpoints", [])]
                    if all(progress["checkpoint_scores"].get(cid, {}).get("passed", False) for cid in all_cps):
                        if l["id"] not in progress["completed_lessons"]:
                            progress["completed_lessons"].append(l["id"])

                    save_progress(progress)

                    return {
                        "checkpoint_id": checkpoint_id,
                        "is_correct": matched,
                        "score_earned": earned,
                        "max_score": cp["max_score"],
                        "hint_penalty": penalty,
                        "feedback": "Correct! Finding confirmed from evidence." if matched else "Incorrect. Please review the associated evidence and retry.",
                        "lesson_completed": l["id"] in progress["completed_lessons"]
                    }
    raise HTTPException(status_code=404, detail="Checkpoint not found")

@app.get("/api/evidence/processes")
def get_processes():
    return {
        "tree": loader.process_tree,
        "flat_list": loader.processes
    }

@app.get("/api/evidence/files")
def get_files():
    return {
        "file_hashes": loader.file_hashes,
        "file_activity": loader.files
    }

@app.get("/api/evidence/network")
def get_network(protocol: Optional[str] = None, q: Optional[str] = None):
    pkts = loader.pcap_packets
    if protocol and protocol.upper() != "ALL":
        pkts = [p for p in pkts if p["protocol"].upper() == protocol.upper()]
    if q:
        query = q.lower()
        pkts = [p for p in pkts if query in p["info"].lower() or query in p["src_ip"] or query in p["dst_ip"] or query in p["payload_preview"].lower()]
    return {
        "total_packets": len(loader.pcap_packets),
        "filtered_packets": len(pkts),
        "packets": pkts,
        "c2_conversations": loader.c2_conversations
    }

@app.get("/api/evidence/wazuh")
def get_wazuh():
    return {
        "alerts": loader.wazuh_alerts,
        "total_alerts": len(loader.wazuh_alerts)
    }

@app.get("/api/evidence/mitre")
def get_mitre():
    mappings = [
        {
            "id": "T1204.002",
            "name": "User Execution: Malicious File",
            "tactic": "Execution",
            "evidence": "Sysmon Event ID 1: invoice_review.exe executed from Downloads by j.doe",
            "wazuh_rule": "100201",
            "confidence": "High (Observed Telemetry)"
        },
        {
            "id": "T1490",
            "name": "Inhibit System Recovery: Volume Shadow Copy Deletion",
            "tactic": "Impact",
            "evidence": "Sysmon Event ID 1: vssadmin.exe delete shadows /all /quiet executed with PID 5288",
            "wazuh_rule": "100202",
            "confidence": "Verified (Process Lineage & Arguments)"
        },
        {
            "id": "T1071.001",
            "name": "Application Layer Protocol: Web Protocols",
            "tactic": "Command and Control",
            "evidence": "PCAP packets #1-#12: Outbound HTTP POST and GET to Mock C2 (10.10.50.30:8080)",
            "wazuh_rule": "100204",
            "confidence": "Verified (Full Packet Capture)"
        },
        {
            "id": "T1486",
            "name": "Data Encrypted for Impact",
            "tactic": "Impact",
            "evidence": "Sysmon Event ID 11: 5 canary files renamed to .locked; RESTORE_FILES_INFO.txt created",
            "wazuh_rule": "100203",
            "confidence": "Verified (File Hashes & Extortion Note)"
        }
    ]
    return {"techniques": mappings}

@app.get("/api/remediation/status")
def get_remediation_status():
    return remediation_engine.state

@app.get("/api/remediation/preview/{action_id}")
def preview_remediation(action_id: str):
    try:
        return remediation_engine.preview_action(action_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

class RemediationExecuteReq(BaseModel):
    action_id: str
    confirmed: bool
    user: Optional[str] = "SOC-Analyst-Trainee"

@app.post("/api/remediation/execute")
def execute_remediation(req: RemediationExecuteReq):
    try:
        res = remediation_engine.execute_action(req.action_id, req.confirmed, req.user)
        return res
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/remediation/reset")
def reset_remediation():
    return remediation_engine.reset_sandbox()

@app.post("/api/progress/reset")
def reset_trainee_progress():
    global progress
    progress = {
        "completed_lessons": [],
        "checkpoint_scores": {},
        "hints_used": {},
        "total_score": 0,
        "max_score": 100,
        "percentage": 0.0
    }
    save_progress(progress)
    return {"status": "SUCCESS", "message": "Trainee progress reset."}

# ------------------------------------------------------------------------------
# High-Fidelity Professional SOC Investigation Frontend
# ------------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def serve_ui():
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SOC CyberRange — Incident Investigation & Response</title>
  <style>
    :root {
      --bg-dark: #0a0e14;
      --bg-card: #121820;
      --bg-panel: #161f2c;
      --border: #263342;
      --text-main: #e6edf3;
      --text-muted: #8b949e;
      --accent-blue: #58a6ff;
      --accent-green: #3fb950;
      --accent-amber: #d29922;
      --accent-red: #f85149;
      --accent-purple: #bc8cff;
      --mono-font: 'JetBrains Mono', 'SFMono-Regular', Consolas, Menlo, monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg-dark);
      color: var(--text-main);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      display: flex;
      height: 100vh;
      overflow: hidden;
    }
    /* Layout */
    #sidebar {
      width: 320px;
      background-color: var(--bg-card);
      border-right: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      flex-shrink: 0;
    }
    #main-content {
      flex: 1;
      display: flex;
      flex-direction: column;
      overflow: hidden;
      background-color: var(--bg-dark);
    }
    /* Header */
    .soc-header {
      padding: 12px 20px;
      background-color: var(--bg-card);
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .badge {
      display: inline-block;
      padding: 3px 8px;
      font-size: 11px;
      font-weight: 600;
      border-radius: 4px;
      text-transform: uppercase;
      font-family: var(--mono-font);
    }
    .badge-critical { background: rgba(248, 81, 73, 0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }
    .badge-success { background: rgba(63, 185, 80, 0.2); color: var(--accent-green); border: 1px solid var(--accent-green); }
    .badge-info { background: rgba(88, 166, 255, 0.2); color: var(--accent-blue); border: 1px solid var(--accent-blue); }
    .badge-amber { background: rgba(210, 153, 34, 0.2); color: var(--accent-amber); border: 1px solid var(--accent-amber); }
    
    /* Navigation */
    .nav-section-title {
      font-size: 11px;
      text-transform: uppercase;
      color: var(--text-muted);
      letter-spacing: 0.5px;
      padding: 14px 16px 6px 16px;
      font-weight: 700;
    }
    .nav-list { list-style: none; overflow-y: auto; flex: 1; }
    .nav-item {
      padding: 10px 16px;
      font-size: 13px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      cursor: pointer;
      border-left: 3px solid transparent;
      transition: all 0.15s ease;
      color: var(--text-muted);
    }
    .nav-item:hover { background-color: var(--bg-panel); color: var(--text-main); }
    .nav-item.active {
      background-color: var(--bg-panel);
      color: var(--accent-blue);
      border-left-color: var(--accent-blue);
      font-weight: 600;
    }
    /* Tabs bar */
    .tab-bar {
      display: flex;
      background-color: var(--bg-card);
      border-bottom: 1px solid var(--border);
      padding: 0 16px;
      gap: 8px;
    }
    .tab-btn {
      padding: 10px 14px;
      background: none;
      border: none;
      border-bottom: 2px solid transparent;
      color: var(--text-muted);
      font-size: 13px;
      cursor: pointer;
      font-weight: 500;
      transition: all 0.2s;
    }
    .tab-btn:hover { color: var(--text-main); }
    .tab-btn.active { color: var(--accent-blue); border-bottom-color: var(--accent-blue); font-weight: 600; }
    
    /* Content Area */
    .view-container {
      flex: 1;
      padding: 20px;
      overflow-y: auto;
      display: none;
    }
    .view-container.active { display: block; }

    /* Tables */
    .soc-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      font-family: var(--mono-font);
      background-color: var(--bg-card);
      border-radius: 6px;
      overflow: hidden;
      border: 1px solid var(--border);
    }
    .soc-table th {
      background-color: var(--bg-panel);
      text-align: left;
      padding: 10px 12px;
      color: var(--text-muted);
      font-weight: 600;
      border-bottom: 1px solid var(--border);
    }
    .soc-table td {
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }
    .soc-table tr:hover { background-color: rgba(88, 166, 255, 0.05); }

    /* Cards */
    .card {
      background-color: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 16px;
      margin-bottom: 16px;
    }
    .card-title {
      font-size: 15px;
      font-weight: 600;
      margin-bottom: 8px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    
    /* Process Tree */
    .proc-node {
      margin-left: 20px;
      border-left: 2px dashed var(--border);
      padding: 8px 0 8px 16px;
      position: relative;
    }
    .proc-box {
      background: var(--bg-panel);
      border: 1px solid var(--border);
      padding: 10px 14px;
      border-radius: 6px;
      display: inline-block;
      font-family: var(--mono-font);
      font-size: 12px;
      min-width: 450px;
    }
    .proc-box.suspicious {
      border-color: var(--accent-red);
      background: rgba(248, 81, 73, 0.08);
    }

    /* Checkpoint Drawer */
    .checkpoint-box {
      background: var(--bg-panel);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 14px;
      margin-top: 14px;
    }
    .checkpoint-input {
      background: var(--bg-dark);
      border: 1px solid var(--border);
      color: var(--text-main);
      padding: 8px 12px;
      border-radius: 4px;
      font-family: var(--mono-font);
      font-size: 13px;
      width: 60%;
    }
    .btn {
      padding: 8px 16px;
      font-size: 13px;
      font-weight: 600;
      border-radius: 4px;
      cursor: pointer;
      border: none;
      transition: all 0.2s;
    }
    .btn-primary { background: #238636; color: #fff; }
    .btn-primary:hover { background: #2ea043; }
    .btn-secondary { background: var(--border); color: var(--text-main); }
    .btn-danger { background: var(--accent-red); color: #fff; }

    /* Hex / Payload Viewer */
    .payload-viewer {
      background: #000;
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 12px;
      font-family: var(--mono-font);
      font-size: 12px;
      color: #39ff14;
      white-space: pre-wrap;
      max-height: 200px;
      overflow-y: auto;
      margin-top: 8px;
    }
  </style>
</head>
<body>

  <!-- Left Sidebar -->
  <aside id="sidebar">
    <div style="padding: 16px; border-bottom: 1px solid var(--border);">
      <div style="font-weight: 700; font-size: 16px; display: flex; align-items: center; gap: 8px;">
        <span style="color: var(--accent-red);">🛡️</span> SOC CyberRange
      </div>
      <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px; font-family: var(--mono-font);">
        CASE: INC-2026-9842 | WKSTN42
      </div>
      <div style="margin-top: 10px; display: flex; gap: 6px;">
        <span class="badge badge-critical">Active Incident</span>
        <span class="badge badge-success" id="integrity-badge">Checksums Valid</span>
      </div>
    </div>

    <!-- Progress Overview -->
    <div style="padding: 12px 16px; border-bottom: 1px solid var(--border); font-size: 12px;">
      <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
        <span style="color: var(--text-muted);">Trainee Progress</span>
        <span id="progress-percent" style="font-weight: 700; color: var(--accent-blue);">0%</span>
      </div>
      <div style="background: var(--bg-dark); height: 6px; border-radius: 3px; overflow: hidden;">
        <div id="progress-bar" style="background: var(--accent-blue); width: 0%; height: 100%; transition: width 0.3s;"></div>
      </div>
      <div style="margin-top: 6px; color: var(--text-muted); font-size: 11px;" id="score-text">
        Score: 0 / 100 points
      </div>
    </div>

    <!-- Navigation List -->
    <div class="nav-section-title">Investigation Lessons</div>
    <ul class="nav-list" id="lesson-nav-list">
      <!-- Injected dynamically via JS -->
    </ul>

    <div class="nav-section-title">Evidence & Response</div>
    <ul class="nav-list" style="flex: 0 0 auto; max-height: 220px; border-top: 1px solid var(--border);">
      <li class="nav-item" onclick="switchTab('processes')"><span>🌳 Process Tree</span></li>
      <li class="nav-item" onclick="switchTab('files')"><span>📁 File Forensics</span></li>
      <li class="nav-item" onclick="switchTab('network')"><span>🌐 Network PCAP</span></li>
      <li class="nav-item" onclick="switchTab('wazuh')"><span>🚨 Wazuh Alerts</span></li>
      <li class="nav-item" onclick="switchTab('mitre')"><span>🎯 MITRE ATT&CK</span></li>
      <li class="nav-item" onclick="switchTab('remediation')"><span>🛠️ Remediation Console</span></li>
    </ul>
  </aside>

  <!-- Main Investigation Workspace -->
  <main id="main-content">
    <!-- Top Header -->
    <header class="soc-header">
      <div>
        <h2 id="view-title" style="font-size: 16px; font-weight: 600;">Lesson 1: Understanding the Incident & Triage</h2>
        <span id="view-subtitle" style="font-size: 12px; color: var(--text-muted);">Endpoint telemetry and SIEM alert correlation</span>
      </div>
      <div style="display: flex; gap: 8px;">
        <button class="btn btn-secondary" onclick="resetSandbox()">Reset Lab</button>
        <button class="btn btn-secondary" onclick="exportReport()">Export Report</button>
      </div>
    </header>

    <!-- Contextual Tabs Bar -->
    <div class="tab-bar">
      <button class="tab-btn active" id="tab-lesson" onclick="switchTab('lesson')">Guided Lesson</button>
      <button class="tab-btn" id="tab-timeline" onclick="switchTab('timeline')">Incident Timeline</button>
      <button class="tab-btn" id="tab-processes" onclick="switchTab('processes')">Process Tree</button>
      <button class="tab-btn" id="tab-files" onclick="switchTab('files')">File Hashes</button>
      <button class="tab-btn" id="tab-network" onclick="switchTab('network')">PCAP Inspector</button>
      <button class="tab-btn" id="tab-wazuh" onclick="switchTab('wazuh')">Wazuh SIEM</button>
      <button class="tab-btn" id="tab-mitre" onclick="switchTab('mitre')">ATT&CK Matrix</button>
      <button class="tab-btn" id="tab-remediation" onclick="switchTab('remediation')">Remediation</button>
    </div>

    <!-- VIEW 1: Guided Lesson View -->
    <div class="view-container active" id="view-lesson">
      <div class="card">
        <div class="card-title">
          <span id="lesson-header-title">Lesson Overview</span>
          <span class="badge badge-info" id="lesson-status-badge">In Progress</span>
        </div>
        <p id="lesson-explanation" style="font-size: 14px; line-height: 1.6; color: var(--text-muted); margin-bottom: 16px;"></p>
        
        <div style="font-weight: 600; font-size: 13px; margin-bottom: 8px;">Learning Objectives:</div>
        <ul id="lesson-objectives" style="font-size: 13px; color: var(--text-muted); padding-left: 20px; line-height: 1.6;"></ul>
      </div>

      <div class="card">
        <div class="card-title">Investigation Checkpoints</div>
        <div id="checkpoints-container">
          <!-- Injected via JS -->
        </div>
      </div>
    </div>

    <!-- VIEW 2: Timeline View -->
    <div class="view-container" id="view-timeline">
      <div class="card">
        <div class="card-title">Chronological Attack Progression Timeline</div>
        <table class="soc-table">
          <thead>
            <tr>
              <th>Timestamp (UTC)</th>
              <th>Attack Stage</th>
              <th>Source</th>
              <th>Process / Entity</th>
              <th>Description</th>
              <th>ATT&CK</th>
            </tr>
          </thead>
          <tbody id="timeline-tbody"></tbody>
        </table>
      </div>
    </div>

    <!-- VIEW 3: Process Hierarchy View -->
    <div class="view-container" id="view-processes">
      <div class="card">
        <div class="card-title">Endpoint Process Ancestry Graph (Sysmon Event ID 1)</div>
        <div id="process-tree-container" style="padding: 10px 0;"></div>
      </div>
    </div>

    <!-- VIEW 4: File Activity & Hashes -->
    <div class="view-container" id="view-files">
      <div class="card">
        <div class="card-title">Decoy Directory Cryptographic File Hash Comparison</div>
        <table class="soc-table">
          <thead>
            <tr>
              <th>Original File</th>
              <th>Original SHA-256</th>
              <th>Modified Target (.locked)</th>
              <th>Encrypted SHA-256</th>
              <th>State</th>
            </tr>
          </thead>
          <tbody id="files-tbody"></tbody>
        </table>
      </div>
    </div>

    <!-- VIEW 5: PCAP Network Inspector -->
    <div class="view-container" id="view-network">
      <div class="card">
        <div class="card-title">
          <span>Network Packet Capture (network_capture.pcap)</span>
          <div style="display: flex; gap: 8px;">
            <select id="pcap-proto-filter" class="checkpoint-input" style="width: 120px;" onchange="filterPcap()">
              <option value="ALL">All Protocols</option>
              <option value="HTTP">HTTP Only</option>
              <option value="TCP">TCP Only</option>
            </select>
          </div>
        </div>
        <table class="soc-table" style="margin-bottom: 12px;">
          <thead>
            <tr>
              <th>#</th>
              <th>Time (s)</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Protocol</th>
              <th>Length</th>
              <th>Information Summary</th>
            </tr>
          </thead>
          <tbody id="pcap-tbody"></tbody>
        </table>

        <div style="font-weight: 600; font-size: 13px; margin-top: 16px;">Packet Payload Inspector:</div>
        <div class="payload-viewer" id="packet-payload-viewer">// Select a packet to inspect raw application payload...</div>
      </div>
    </div>

    <!-- VIEW 6: Wazuh Alerts -->
    <div class="view-container" id="view-wazuh">
      <div class="card">
        <div class="card-title">Wazuh SIEM Detections (wazuh_alerts.json)</div>
        <table class="soc-table">
          <thead>
            <tr>
              <th>Rule ID</th>
              <th>Level</th>
              <th>Rule Description</th>
              <th>Agent Host</th>
              <th>MITRE ATT&CK</th>
              <th>Raw Telemetry</th>
            </tr>
          </thead>
          <tbody id="wazuh-tbody"></tbody>
        </table>
      </div>
    </div>

    <!-- VIEW 7: MITRE ATT&CK Matrix -->
    <div class="view-container" id="view-mitre">
      <div class="card">
        <div class="card-title">Empirical MITRE ATT&CK Mapping</div>
        <table class="soc-table">
          <thead>
            <tr>
              <th>Technique ID</th>
              <th>Technique Name</th>
              <th>Tactic</th>
              <th>Supporting Evidence Citation</th>
              <th>Confidence Status</th>
            </tr>
          </thead>
          <tbody id="mitre-tbody"></tbody>
        </table>
      </div>
    </div>

    <!-- VIEW 8: Remediation Console -->
    <div class="view-container" id="view-remediation">
      <div class="card">
        <div class="card-title">Controlled Incident Containment Console</div>
        <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 16px;">
          Execute authorized containment playbooks following the change-control verification model.
        </p>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 20px;">
          <div class="card" style="margin-bottom: 0;">
            <div style="font-weight: 600; font-size: 14px; margin-bottom: 8px;">1. Network Host Isolation</div>
            <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 10px;">
              Target: DESKTOP-WKSTN42 (10.10.50.42). Revokes lab router forwarding.
            </p>
            <button class="btn btn-secondary" onclick="previewRemediation('ISOLATE_HOST')">Preview & Execute</button>
          </div>

          <div class="card" style="margin-bottom: 0;">
            <div style="font-weight: 600; font-size: 14px; margin-bottom: 8px;">2. Terminate Process Tree</div>
            <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 10px;">
              Target: PID 4912 (invoice_review.exe) & child processes (cmd, vssadmin).
            </p>
            <button class="btn btn-secondary" onclick="previewRemediation('TERMINATE_MALWARE_TREE')">Preview & Execute</button>
          </div>

          <div class="card" style="margin-bottom: 0;">
            <div style="font-weight: 600; font-size: 14px; margin-bottom: 8px;">3. Block Mock C2 Service</div>
            <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 10px;">
              Target: 10.10.50.30:8080. Stops beaconing and key exchange portal.
            </p>
            <button class="btn btn-secondary" onclick="previewRemediation('DISABLE_MOCK_C2')">Preview & Execute</button>
          </div>

          <div class="card" style="margin-bottom: 0;">
            <div style="font-weight: 600; font-size: 14px; margin-bottom: 8px;">4. Restore Decoy Files</div>
            <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 10px;">
              Target: FinanceReports folder. Reverses canary file encryption via lab key.
            </p>
            <button class="btn btn-secondary" onclick="previewRemediation('RESTORE_DECOY_FILES')">Preview & Execute</button>
          </div>
        </div>

        <div class="card">
          <div style="font-weight: 600; font-size: 14px; margin-bottom: 8px;">5. Post-Remediation Verification Scan</div>
          <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 10px;">
            Audits endpoint sockets, running processes, and file integrity to verify full containment.
          </p>
          <button class="btn btn-primary" onclick="previewRemediation('RESCAN_ENVIRONMENT')">Run Verification Scan</button>
          <div id="remediation-status-display" style="margin-top: 12px; font-family: var(--mono-font); font-size: 12px;"></div>
        </div>
      </div>
    </div>
  </main>

  <!-- Modal for Remediation Preview -->
  <div id="remediation-modal" style="display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.7); z-index: 1000; align-items: center; justify-content: center;">
    <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; width: 500px; padding: 20px;">
      <h3 id="modal-title" style="margin-bottom: 10px;">Action Preview</h3>
      <div id="modal-body" style="font-size: 13px; color: var(--text-muted); line-height: 1.6; margin-bottom: 16px;"></div>
      <label style="display: flex; align-items: center; gap: 8px; font-size: 13px; margin-bottom: 16px;">
        <input type="checkbox" id="modal-confirm-cb"> I confirm authorization to execute this containment action.
      </label>
      <div style="display: flex; justify-content: flex-end; gap: 10px;">
        <button class="btn btn-secondary" onclick="closeModal()">Cancel</button>
        <button class="btn btn-danger" id="modal-exec-btn" onclick="executeRemediation()">Authorize & Execute</button>
      </div>
    </div>
  </div>

  <script>
    let currentLessonId = "lesson_1";
    let lessonsCache = [];
    let currentActionPreview = null;

    async function init() {
      await fetchIncident();
      await fetchLessons();
      await fetchTimeline();
      await fetchProcesses();
      await fetchFiles();
      await fetchNetwork();
      await fetchWazuh();
      await fetchMitre();
      await fetchRemediationStatus();
    }

    async function fetchIncident() {
      const res = await fetch('/api/incident');
      const data = await res.json();
      if (data.integrity_verified) {
        document.getElementById('integrity-badge').innerText = "Checksums Valid (SHA-256)";
      }
    }

    async function fetchLessons() {
      const res = await fetch('/api/lessons');
      const data = await res.json();
      lessonsCache = data.lessons;

      const navList = document.getElementById('lesson-nav-list');
      navList.innerHTML = '';
      data.lessons.forEach(l => {
        const li = document.createElement('li');
        li.className = `nav-item ${l.id === currentLessonId ? 'active' : ''}`;
        li.onclick = () => selectLesson(l.id);
        li.innerHTML = `
          <span>${l.title.split('—')[0]}</span>
          <span class="badge ${l.completed ? 'badge-success' : 'badge-amber'}">${l.completed ? 'Done' : 'Open'}</span>
        `;
        navList.appendChild(li);
      });

      document.getElementById('progress-percent').innerText = `${data.progress.percentage}%`;
      document.getElementById('progress-bar').style.width = `${data.progress.percentage}%`;
      document.getElementById('score-text').innerText = `Score: ${data.progress.total_score} / ${data.progress.max_score} pts`;

      renderCurrentLesson();
    }

    function selectLesson(id) {
      currentLessonId = id;
      switchTab('lesson');
      renderCurrentLesson();
      fetchLessons();
    }

    function renderCurrentLesson() {
      const lesson = lessonsCache.find(l => l.id === currentLessonId);
      if (!lesson) return;

      document.getElementById('view-title').innerText = lesson.title;
      document.getElementById('view-subtitle').innerText = lesson.category;
      document.getElementById('lesson-header-title').innerText = lesson.title;
      document.getElementById('lesson-explanation').innerText = lesson.explanation;
      
      const objList = document.getElementById('lesson-objectives');
      objList.innerHTML = lesson.objectives.map(o => `<li>${o}</li>`).join('');

      const cpContainer = document.getElementById('checkpoints-container');
      cpContainer.innerHTML = '';

      lesson.checkpoints.forEach(cp => {
        const box = document.createElement('div');
        box.className = 'checkpoint-box';
        box.innerHTML = `
          <div style="font-weight: 600; font-size: 13px; margin-bottom: 6px; display: flex; justify-content: space-between;">
            <span>${cp.question}</span>
            <span class="badge ${cp.is_passed ? 'badge-success' : 'badge-amber'}">${cp.is_passed ? 'Achieved (' + cp.score_awarded + ' pts)' : 'Pending'}</span>
          </div>
          <div style="display: flex; gap: 8px; margin-top: 10px;">
            <input type="text" class="checkpoint-input" id="input-${cp.id}" placeholder="Type your evidence-derived answer...">
            <button class="btn btn-primary" onclick="submitAns('${lesson.id}', '${cp.id}')">Submit</button>
            <button class="btn btn-secondary" onclick="revealHint('${lesson.id}', '${cp.id}')">Hint (-2 pts)</button>
          </div>
          <div id="hint-${cp.id}" style="display: none; margin-top: 8px; font-size: 12px; color: var(--accent-amber);"></div>
          <div id="fb-${cp.id}" style="margin-top: 6px; font-size: 12px;"></div>
        `;
        cpContainer.appendChild(box);
      });
    }

    async function submitAns(lessonId, checkpointId) {
      const val = document.getElementById(`input-${checkpointId}`).value;
      const res = await fetch(`/api/lessons/${lessonId}/checkpoints/${checkpointId}/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ answer: val })
      });
      const data = await res.json();
      const fb = document.getElementById(`fb-${checkpointId}`);
      fb.innerText = data.feedback;
      fb.style.color = data.is_correct ? 'var(--accent-green)' : 'var(--accent-red)';
      await fetchLessons();
    }

    async function revealHint(lessonId, checkpointId) {
      const res = await fetch(`/api/lessons/${lessonId}/checkpoints/${checkpointId}/hint`, { method: 'POST' });
      const data = await res.json();
      const hBox = document.getElementById(`hint-${checkpointId}`);
      hBox.style.display = 'block';
      hBox.innerText = `💡 HINT: ${data.hint}`;
    }

    async function fetchTimeline() {
      const res = await fetch('/api/incident');
      const data = await res.json();
      const tb = document.getElementById('timeline-tbody');
      tb.innerHTML = data.timeline.map(t => `
        <tr>
          <td>${t.timestamp}</td>
          <td><span class="badge badge-info">${t.stage}</span></td>
          <td>${t.source}</td>
          <td><code>${t.process}</code></td>
          <td>${t.description}</td>
          <td><span class="badge badge-amber">${t.technique}</span></td>
        </tr>
      `).join('');
    }

    async function fetchProcesses() {
      const res = await fetch('/api/evidence/processes');
      const data = await res.json();
      const container = document.getElementById('process-tree-container');
      
      function renderNode(node) {
        let html = `
          <div class="proc-node">
            <div class="proc-box ${node.is_suspicious ? 'suspicious' : ''}">
              <div style="font-weight: 700; color: ${node.is_suspicious ? 'var(--accent-red)' : 'var(--accent-blue)'};">
                ${node.name} (PID: ${node.pid})
              </div>
              <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">
                CMD: <code>${node.command_line}</code>
              </div>
              <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">
                Time: ${node.utc_time} | User: ${node.user}
              </div>
            </div>
        `;
        if (node.children && node.children.length > 0) {
          node.children.forEach(c => { html += renderNode(c); });
        }
        html += `</div>`;
        return html;
      }
      container.innerHTML = renderNode(data.tree);
    }

    async function fetchFiles() {
      const res = await fetch('/api/evidence/files');
      const data = await res.json();
      const tb = document.getElementById('files-tbody');
      tb.innerHTML = data.file_hashes.map(f => `
        <tr>
          <td><code>${f.original_filename || '(Ransom Note)'}</code></td>
          <td style="font-size: 11px;"><code>${f.original_sha256 ? f.original_sha256.substring(0, 16) + '...' : 'N/A'}</code></td>
          <td><code>${f.encrypted_filename}</code></td>
          <td style="font-size: 11px;"><code>${f.encrypted_sha256.substring(0, 16)}...</code></td>
          <td><span class="badge ${f.encrypted_filename.endsWith('.locked') ? 'badge-critical' : 'badge-amber'}">Locked</span></td>
        </tr>
      `).join('');
    }

    let pcapCache = [];
    async function fetchNetwork() {
      const res = await fetch('/api/evidence/network');
      const data = await res.json();
      pcapCache = data.packets;
      renderPcap(pcapCache);
    }

    function renderPcap(packets) {
      const tb = document.getElementById('pcap-tbody');
      tb.innerHTML = packets.map(p => `
        <tr onclick="inspectPacket(${p.packet_no})" style="cursor: pointer;">
          <td>${p.packet_no}</td>
          <td>${p.timestamp_epoch.toFixed(4)}</td>
          <td>${p.src_ip}:${p.src_port}</td>
          <td>${p.dst_ip}:${p.dst_port}</td>
          <td><span class="badge badge-info">${p.protocol}</span></td>
          <td>${p.length} B</td>
          <td>${p.info}</td>
        </tr>
      `).join('');
    }

    function filterPcap() {
      const proto = document.getElementById('pcap-proto-filter').value;
      if (proto === 'ALL') {
        renderPcap(pcapCache);
      } else {
        renderPcap(pcapCache.filter(p => p.protocol.toUpperCase() === proto));
      }
    }

    function inspectPacket(num) {
      const pkt = pcapCache.find(p => p.packet_no === num);
      if (!pkt) return;
      const viewer = document.getElementById('packet-payload-viewer');
      viewer.innerText = `[PACKET #${pkt.packet_no} PAYLOAD - ${pkt.src_ip}:${pkt.src_port} -> ${pkt.dst_ip}:${pkt.dst_port}]\n\n` +
                         (pkt.payload_preview || "(No application layer payload)");
    }

    async function fetchWazuh() {
      const res = await fetch('/api/evidence/wazuh');
      const data = await res.json();
      const tb = document.getElementById('wazuh-tbody');
      tb.innerHTML = data.alerts.map(a => `
        <tr>
          <td><span class="badge badge-critical">${a.rule.id}</span></td>
          <td><span class="badge ${a.rule.level >= 12 ? 'badge-critical' : 'badge-amber'}">Level ${a.rule.level}</span></td>
          <td>${a.rule.description}</td>
          <td>${a.agent.name} (${a.agent.ip})</td>
          <td>${a.rule.mitre.id.join(', ')}</td>
          <td><button class="btn btn-secondary" style="padding: 2px 6px; font-size: 11px;" onclick='alert(JSON.stringify(${JSON.stringify(a.data)}, null, 2))'>Inspect JSON</button></td>
        </tr>
      `).join('');
    }

    async function fetchMitre() {
      const res = await fetch('/api/evidence/mitre');
      const data = await res.json();
      const tb = document.getElementById('mitre-tbody');
      tb.innerHTML = data.techniques.map(m => `
        <tr>
          <td><span class="badge badge-amber">${m.id}</span></td>
          <td><b>${m.name}</b></td>
          <td>${m.tactic}</td>
          <td>${m.evidence}</td>
          <td><span class="badge badge-success">${m.confidence}</span></td>
        </tr>
      `).join('');
    }

    async function fetchRemediationStatus() {
      const res = await fetch('/api/remediation/status');
      const state = await res.json();
      const disp = document.getElementById('remediation-status-display');
      disp.innerHTML = `
        Endpoint Isolated: <b>${state.endpoint_isolated ? 'YES' : 'NO'}</b> |
        Malware Terminated: <b>${state.processes_terminated ? 'YES' : 'NO'}</b> |
        Mock C2 Blocked: <b>${state.mock_c2_disabled ? 'YES' : 'NO'}</b> |
        Files Restored: <b>${state.files_restored ? 'YES' : 'NO'}</b> |
        Containment Status: <span class="badge ${state.containment_verified ? 'badge-success' : 'badge-amber'}">${state.containment_verified ? 'CLEAN & CONTAINED' : 'PENDING ACTION'}</span>
      `;
    }

    async function previewRemediation(actionId) {
      const res = await fetch(`/api/remediation/preview/${actionId}`);
      currentActionPreview = await res.json();
      document.getElementById('modal-title').innerText = currentActionPreview.title;
      document.getElementById('modal-body').innerHTML = `
        <p><b>Target:</b> ${currentActionPreview.target_host}</p>
        <p style="margin-top: 6px;"><b>Impact:</b> ${currentActionPreview.impact_summary}</p>
        <p style="margin-top: 6px;"><b>Risk Level:</b> <span class="badge badge-info">${currentActionPreview.risk_level}</span></p>
      `;
      document.getElementById('modal-confirm-cb').checked = false;
      document.getElementById('remediation-modal').style.display = 'flex';
    }

    function closeModal() {
      document.getElementById('remediation-modal').style.display = 'none';
      currentActionPreview = null;
    }

    async function executeRemediation() {
      const confirmed = document.getElementById('modal-confirm-cb').checked;
      if (!confirmed) {
        alert("Please check the confirmation box.");
        return;
      }
      const res = await fetch('/api/remediation/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action_id: currentActionPreview.action_id, confirmed: true })
      });
      const data = await res.json();
      closeModal();
      alert(data.message);
      await fetchRemediationStatus();
    }

    async function resetSandbox() {
      if (confirm("Reset the lab environment to baseline?")) {
        await fetch('/api/remediation/reset', { method: 'POST' });
        await fetch('/api/progress/reset', { method: 'POST' });
        await init();
        alert("Lab state and progress reset.");
      }
    }

    function exportReport() {
      window.open('/api/incident', '_blank');
    }

    function switchTab(tabId) {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.view-container').forEach(v => v.classList.remove('active'));
      
      const btn = document.getElementById(`tab-${tabId}`);
      const view = document.getElementById(`view-${tabId}`);
      if (btn) btn.classList.add('active');
      if (view) view.classList.add('active');
    }

    window.onload = init;
  </script>
</body>
</html>
"""
    return HTMLResponse(content=html_content, status_code=200)

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("module2.server:app", host="0.0.0.0", port=port, reload=False)

