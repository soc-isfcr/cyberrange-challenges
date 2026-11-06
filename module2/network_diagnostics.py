"""
Interactive Network Diagnostics, Node State Management & Diagnostic Packet Generator.
Supports:
- Live Node Power & Link Status (UP, DOWN, ISOLATED)
- Dynamic Ping (ICMP Echo Request/Reply with live RTT, packet loss, and server down alerts)
- Dynamic Traceroute (Hop-by-hop latency, TTL expiration, and gateway/host down detection)
- Real-time diagnostic packet injection into the PCAP packet stream
"""

import time
import random
from typing import Dict, List, Any, Optional

class NetworkDiagnosticsEngine:
    def __init__(self, pcap_packet_ref: List[Dict[str, Any]]):
        self.pcap_packets = pcap_packet_ref
        self.nodes = {
            "router1": {
                "name": "router1",
                "ip": "10.10.50.2",
                "mac": "02:42:0a:0a:32:02",
                "role": "Lab Gateway & Core Router",
                "os": "Debian 12 Bookworm",
                "status": "UP",  # UP, DOWN
                "type": "router"
            },
            "wazuh": {
                "name": "wazuh",
                "ip": "10.10.50.10",
                "mac": "02:42:0a:0a:32:0a",
                "role": "Wazuh SIEM & Log Collector",
                "os": "Ubuntu 24.04 Noble",
                "status": "UP",
                "type": "server"
            },
            "analyst": {
                "name": "analyst",
                "ip": "10.10.50.20",
                "mac": "02:42:0a:0a:32:14",
                "role": "Kali Analyst Workstation",
                "os": "Kali Linux",
                "status": "UP",
                "type": "workstation"
            },
            "mockc2": {
                "name": "mockc2",
                "ip": "10.10.50.30",
                "mac": "02:42:0a:0a:32:1e",
                "role": "Mock C2 Service (Port 8080)",
                "os": "Debian 12 Bookworm",
                "status": "UP",
                "type": "server"
            },
            "target": {
                "name": "target",
                "ip": "10.10.50.42",
                "mac": "02:42:0a:0a:32:2a",
                "role": "Victim Workstation (DESKTOP-WKSTN42)",
                "os": "Windows 10 Pro 22H2",
                "status": "UP",
                "type": "victim"
            }
        }

    def list_nodes(self) -> List[Dict[str, Any]]:
        return list(self.nodes.values())

    def get_node(self, identifier: str) -> Optional[Dict[str, Any]]:
        ident = identifier.strip().lower()
        for n in self.nodes.values():
            if n["name"].lower() == ident or n["ip"] == ident:
                return n
        return None

    def toggle_node(self, node_name: str, status: Optional[str] = None) -> Dict[str, Any]:
        node = self.get_node(node_name)
        if not node:
            raise ValueError(f"Node '{node_name}' not found.")
        
        if status:
            new_st = status.upper()
            if new_st not in ["UP", "DOWN", "ISOLATED"]:
                raise ValueError("Status must be UP, DOWN, or ISOLATED")
            node["status"] = new_st
        else:
            # Toggle between UP and DOWN
            node["status"] = "DOWN" if node["status"] == "UP" else "UP"

        return {
            "node": node["name"],
            "ip": node["ip"],
            "status": node["status"],
            "message": f"Node {node['name']} ({node['ip']}) is now {node['status']}."
        }

    def _inject_packet(self, src_ip: str, dst_ip: str, protocol: str, info: str, length: int = 84, payload: str = ""):
        next_no = len(self.pcap_packets) + 1
        now_epoch = time.time()
        self.pcap_packets.append({
            "packet_no": next_no,
            "timestamp_epoch": now_epoch,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": 0,
            "dst_port": 0,
            "protocol": protocol,
            "flags": [],
            "length": length,
            "info": info,
            "payload_preview": payload or info,
            "raw_hex": "0800" + "".join(f"{random.randint(0,255):02x}" for _ in range(32))
        })

    def ping(self, src_ident: str, dst_ident: str, count: int = 4) -> Dict[str, Any]:
        src = self.get_node(src_ident) or self.nodes["analyst"]
        dst = self.get_node(dst_ident)
        router = self.nodes["router1"]

        output_lines = []
        packets_sent = count
        packets_recv = 0
        rtts = []

        if not dst:
            # Try to interpret as IP directly
            dst_ip = dst_ident
            dst_name = dst_ident
            is_valid_lab_ip = dst_ip.startswith("10.10.50.")
            dst_status = "UNKNOWN"
        else:
            dst_ip = dst["ip"]
            dst_name = dst["name"]
            is_valid_lab_ip = True
            dst_status = dst["status"]

        output_lines.append(f"PING {dst_ip} ({dst_name}) 56(84) bytes of data from {src['name']} ({src['ip']}).")

        # Check Source State
        if src["status"] == "DOWN":
            output_lines.append(f"ping: connect: Network is down (Source node {src['name']} is powered OFF).")
            return {
                "success": False,
                "server_down": False,
                "source_down": True,
                "output": "\n".join(output_lines),
                "stats": {"sent": 0, "received": 0, "loss_pct": 100}
            }

        # Check Destination State
        if not is_valid_lab_ip:
            output_lines.append(f"ping: unknown host {dst_ident}")
            return {
                "success": False,
                "server_down": False,
                "output": "\n".join(output_lines),
                "stats": {"sent": 0, "received": 0, "loss_pct": 100}
            }

        # Check Gateway Router
        router_down = (router["status"] == "DOWN") and (src["name"] != dst_name)

        for seq in range(1, count + 1):
            # Inject ICMP Echo Request packet into PCAP
            self._inject_packet(
                src_ip=src["ip"],
                dst_ip=dst_ip,
                protocol="ICMP",
                info=f"Echo (ping) request  id=0x{seq:04x}, seq={seq}/256, ttl=64",
                payload=f"ICMP Echo Request from {src['ip']} to {dst_ip} seq={seq}"
            )

            if router_down:
                output_lines.append(f"From {src['ip']} icmp_seq={seq} Destination Net Unreachable (Gateway router1 is DOWN)")
                self._inject_packet(
                    src_ip=src["ip"],
                    dst_ip=src["ip"],
                    protocol="ICMP",
                    info=f"Destination net unreachable (Router DOWN) for seq {seq}"
                )

            elif dst_status == "DOWN":
                output_lines.append(f"From {router['ip']} icmp_seq={seq} Destination Host Unreachable (SERVER IS DOWN)")
                # Inject ICMP Host Unreachable
                self._inject_packet(
                    src_ip=router["ip"],
                    dst_ip=src["ip"],
                    protocol="ICMP",
                    info=f"Destination host unreachable (Host {dst_name} is DOWN)"
                )

            elif dst_status == "ISOLATED" and src["name"] != "router1":
                output_lines.append(f"From {router['ip']} icmp_seq={seq} Communication administratively prohibited (HOST ISOLATED)")
                self._inject_packet(
                    src_ip=router["ip"],
                    dst_ip=src["ip"],
                    protocol="ICMP",
                    info=f"Destination administratively prohibited (Host ISOLATED)"
                )

            else:
                # Success: Host is UP
                packets_recv += 1
                rtt = round(random.uniform(0.35, 0.95), 3)
                rtts.append(rtt)
                output_lines.append(f"64 bytes from {dst_ip}: icmp_seq={seq} ttl=64 time={rtt} ms")
                # Inject ICMP Echo Reply
                self._inject_packet(
                    src_ip=dst_ip,
                    dst_ip=src["ip"],
                    protocol="ICMP",
                    info=f"Echo (ping) reply    id=0x{seq:04x}, seq={seq}/256, ttl=64 (reply in {rtt}ms)",
                    payload=f"ICMP Echo Reply from {dst_ip} to {src['ip']} seq={seq}"
                )

        loss_pct = round(((packets_sent - packets_recv) / packets_sent) * 100, 1)
        output_lines.append(f"--- {dst_ip} ping statistics ---")
        output_lines.append(f"{packets_sent} packets transmitted, {packets_recv} received, {loss_pct}% packet loss")

        if rtts:
            min_rtt = min(rtts)
            max_rtt = max(rtts)
            avg_rtt = round(sum(rtts) / len(rtts), 3)
            output_lines.append(f"rtt min/avg/max = {min_rtt}/{avg_rtt}/{max_rtt} ms")
            output_lines.append("[+] STATUS: Host is ONLINE and responding.")
        else:
            if dst_status == "DOWN":
                output_lines.append("[!] CRITICAL: SERVER IS DOWN / POWERED OFF!")
            elif dst_status == "ISOLATED":
                output_lines.append("[!] SECURITY ALERT: TARGET HOST IS ISOLATED FROM ROUTING.")
            else:
                output_lines.append("[!] ERROR: Destination unreachable.")

        return {
            "success": packets_recv > 0,
            "server_down": dst_status == "DOWN",
            "host_isolated": dst_status == "ISOLATED",
            "output": "\n".join(output_lines),
            "stats": {
                "sent": packets_sent,
                "received": packets_recv,
                "loss_pct": loss_pct,
                "rtts": rtts
            }
        }

    def traceroute(self, src_ident: str, dst_ident: str, max_hops: int = 5) -> Dict[str, Any]:
        src = self.get_node(src_ident) or self.nodes["analyst"]
        dst = self.get_node(dst_ident)
        router = self.nodes["router1"]

        output_lines = []
        if not dst:
            dst_ip = dst_ident
            dst_name = dst_ident
            dst_status = "UNKNOWN"
        else:
            dst_ip = dst["ip"]
            dst_name = dst["name"]
            dst_status = dst["status"]

        output_lines.append(f"traceroute to {dst_ip} ({dst_name}), {max_hops} hops max, 60 byte packets")

        if src["status"] == "DOWN":
            output_lines.append(f"traceroute: Network is down (Source node {src['name']} is powered OFF).")
            return {"success": False, "output": "\n".join(output_lines)}

        # Hop 1: Router
        r1_rtt1 = round(random.uniform(0.25, 0.45), 3)
        r1_rtt2 = round(random.uniform(0.22, 0.40), 3)
        r1_rtt3 = round(random.uniform(0.28, 0.48), 3)

        self._inject_packet(
            src_ip=src["ip"],
            dst_ip=router["ip"],
            protocol="ICMP",
            info=f"Traceroute Probe Hop 1 TTL=1 to {dst_ip}"
        )

        if router["status"] == "DOWN":
            output_lines.append(f" 1  * * * Request timed out (Gateway router1 is DOWN)")
            output_lines.append(f" 2  * * * Request timed out")
            output_lines.append("[!] TRACEROUTE FAILED: Core lab gateway is DOWN.")
            return {"success": False, "server_down": True, "output": "\n".join(output_lines)}

        output_lines.append(f" 1  {router['name']} ({router['ip']})  {r1_rtt1} ms  {r1_rtt2} ms  {r1_rtt3} ms")

        # Hop 2: Destination
        self._inject_packet(
            src_ip=src["ip"],
            dst_ip=dst_ip,
            protocol="ICMP",
            info=f"Traceroute Probe Hop 2 TTL=2 to {dst_ip}"
        )

        if dst_status == "DOWN":
            output_lines.append(f" 2  * * * Destination Host Unreachable [SERVER IS DOWN]")
            output_lines.append("[!] TRACEROUTE HALTED: Target server is POWERED OFF / DOWN.")
            return {"success": False, "server_down": True, "output": "\n".join(output_lines)}

        elif dst_status == "ISOLATED":
            output_lines.append(f" 2  !X !X !X Communication Administratively Prohibited [HOST ISOLATED]")
            output_lines.append("[!] TRACEROUTE HALTED: Target host is ISOLATED by SOC containment policy.")
            return {"success": False, "host_isolated": True, "output": "\n".join(output_lines)}

        else:
            d_rtt1 = round(random.uniform(0.55, 0.85), 3)
            d_rtt2 = round(random.uniform(0.52, 0.80), 3)
            d_rtt3 = round(random.uniform(0.58, 0.92), 3)
            output_lines.append(f" 2  {dst_name} ({dst_ip})  {d_rtt1} ms  {d_rtt2} ms  {d_rtt3} ms")
            output_lines.append(f"[+] TRACEROUTE COMPLETED: Reached {dst_name} in 2 hops.")
            return {"success": True, "server_down": False, "output": "\n".join(output_lines)}
