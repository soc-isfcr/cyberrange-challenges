"""
Evidence Package Loader & Parser for Module 2 Interactive Investigation.
Loads, verifies, and provides structured query interfaces for INC-2026-9842 artifacts.
"""

import os
import json
import struct
import socket
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional

class EvidenceLoader:
    def __init__(self, incident_dir: Path):
        self.incident_dir = incident_dir
        self.manifest: Dict[str, Any] = {}
        self.incident: Dict[str, Any] = {}
        self.timeline: List[Dict[str, Any]] = []
        self.processes: List[Dict[str, Any]] = []
        self.process_tree: Dict[str, Any] = {}
        self.files: List[Dict[str, Any]] = []
        self.file_hashes: List[Dict[str, Any]] = []
        self.pcap_packets: List[Dict[str, Any]] = []
        self.c2_conversations: List[Dict[str, Any]] = []
        self.wazuh_alerts: List[Dict[str, Any]] = []
        self.indicators: Dict[str, Any] = {}
        self.integrity_verified: bool = False
        self.load_and_verify()

    def load_and_verify(self):
        manifest_path = self.incident_dir / "manifest.json"
        if not manifest_path.exists():
            raise FileNotFoundError(f"Incident manifest not found at {manifest_path}")

        with open(manifest_path, 'r', encoding='utf-8') as f:
            self.manifest = json.load(f)

        self._verify_checksums()
        self._load_incident_summary()
        self._load_timeline()
        self._load_processes()
        self._load_files()
        self._load_pcap()
        self._load_wazuh()
        self._load_indicators()

    def _verify_checksums(self):
        checksum_path = self.incident_dir / "metadata" / "checksums.sha256"
        if not checksum_path.exists():
            self.integrity_verified = False
            return

        with open(checksum_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                expected_sha, rel_path = line.split("  ", 1)
                file_path = self.incident_dir / rel_path
                if not file_path.exists():
                    self.integrity_verified = False
                    return
                h = hashlib.sha256()
                with open(file_path, 'rb') as ff:
                    while chunk := ff.read(65536):
                        h.update(chunk)
                if h.hexdigest() != expected_sha:
                    self.integrity_verified = False
                    return
        self.integrity_verified = True

    def _load_incident_summary(self):
        p = self.incident_dir / "incident.json"
        if p.exists():
            with open(p, 'r', encoding='utf-8') as f:
                self.incident = json.load(f)

    def _load_timeline(self):
        p = self.incident_dir / "incident_timeline.json"
        if p.exists():
            with open(p, 'r', encoding='utf-8') as f:
                self.timeline = json.load(f)

    def _load_processes(self):
        p = self.incident_dir / "endpoint" / "process_events.jsonl"
        self.processes = []
        if p.exists():
            with open(p, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        self.processes.append(json.loads(line))
        self._build_process_tree()

    def _build_process_tree(self):
        # Build hierarchy tree: explorer.exe -> invoice_review.exe -> cmd.exe -> vssadmin.exe
        root_node = {
            "name": "explorer.exe",
            "pid": 2840,
            "ppid": None,
            "image": "C:\\Windows\\explorer.exe",
            "command_line": "C:\\Windows\\Explorer.EXE",
            "user": "DESKTOP-WKSTN42\\j.doe",
            "utc_time": "2026-11-06T09:10:00.000Z",
            "is_suspicious": False,
            "children": []
        }

        # Map child processes from loaded events
        proc_map = {2840: root_node}
        for ev in self.processes:
            pid = ev["ProcessId"]
            ppid = ev["ParentProcessId"]
            node = {
                "name": Path(ev["Image"]).name,
                "pid": pid,
                "ppid": ppid,
                "image": ev["Image"],
                "command_line": ev["CommandLine"],
                "user": ev["User"],
                "utc_time": ev["UtcTime"],
                "sha256": ev.get("Hashes", "").replace("SHA256=", ""),
                "is_suspicious": "invoice_review" in ev["Image"] or "vssadmin" in ev["Image"],
                "children": []
            }
            proc_map[pid] = node

        for pid, node in proc_map.items():
            ppid = node["ppid"]
            if ppid and ppid in proc_map:
                proc_map[ppid]["children"].append(node)

        self.process_tree = root_node

    def _load_files(self):
        fh_p = self.incident_dir / "forensic" / "file_hashes.json"
        if fh_p.exists():
            with open(fh_p, 'r', encoding='utf-8') as f:
                self.file_hashes = json.load(f)

        fa_p = self.incident_dir / "endpoint" / "file_activity.jsonl"
        self.files = []
        if fa_p.exists():
            with open(fa_p, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        self.files.append(json.loads(line))

    def _load_pcap(self):
        pcap_p = self.incident_dir / "network" / "network_capture.pcap"
        self.pcap_packets = []
        if not pcap_p.exists():
            return

        with open(pcap_p, 'rb') as f:
            gh = f.read(24)
            if len(gh) < 24:
                return
            magic, v_maj, v_min, tz, sig, snaplen, net = struct.unpack('<IHHiIII', gh)
            pkt_id = 0
            while True:
                ph = f.read(16)
                if len(ph) < 16:
                    break
                pkt_id += 1
                sec, usec, incl_len, orig_len = struct.unpack('<IIII', ph)
                raw = f.read(incl_len)
                if len(raw) < 54:
                    continue
                src_mac = ':'.join(f'{b:02x}' for b in raw[6:12])
                dst_mac = ':'.join(f'{b:02x}' for b in raw[0:6])
                src_ip = socket.inet_ntoa(raw[26:30])
                dst_ip = socket.inet_ntoa(raw[30:34])
                sport, dport = struct.unpack('!HH', raw[34:38])
                seq, ack = struct.unpack('!II', raw[38:46])
                flags = raw[47]
                payload = raw[54:]

                flags_list = []
                if flags & 0x02: flags_list.append("SYN")
                if flags & 0x10: flags_list.append("ACK")
                if flags & 0x08: flags_list.append("PSH")
                if flags & 0x01: flags_list.append("FIN")

                info = f"{sport} -> {dport} [{','.join(flags_list)}]"
                protocol = "TCP"
                payload_text = ""
                if payload:
                    try:
                        text = payload.decode('utf-8', errors='replace')
                        if text.startswith("POST") or text.startswith("GET") or text.startswith("HTTP/"):
                            protocol = "HTTP"
                            info = text.split("\r\n")[0]
                        payload_text = text
                    except Exception:
                        payload_text = payload.hex()

                self.pcap_packets.append({
                    "packet_no": pkt_id,
                    "timestamp_epoch": sec + (usec / 1000000.0),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": sport,
                    "dst_port": dport,
                    "protocol": protocol,
                    "flags": flags_list,
                    "length": incl_len,
                    "info": info,
                    "payload_preview": payload_text[:300],
                    "raw_hex": raw[:80].hex()
                })

        c2_p = self.incident_dir / "network" / "c2_conversations.json"
        if c2_p.exists():
            with open(c2_p, 'r', encoding='utf-8') as f:
                self.c2_conversations = json.load(f)

    def _load_wazuh(self):
        p = self.incident_dir / "wazuh" / "wazuh_alerts.json"
        self.wazuh_alerts = []
        if p.exists():
            with open(p, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        self.wazuh_alerts.append(json.loads(line))

    def _load_indicators(self):
        p = self.incident_dir / "forensic" / "indicators.json"
        if p.exists():
            with open(p, 'r', encoding='utf-8') as f:
                self.indicators = json.load(f)
