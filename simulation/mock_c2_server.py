#!/usr/bin/env python3
"""
Controlled Mock C2 Service for Ransomware Simulation Training.
Operates strictly on isolated lab networks. Does NOT perform any harmful operations.
"""

import sys
import json
import logging
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S%z'
)
logger = logging.getLogger("MockC2")

class MockC2Handler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.52 (Ubuntu)"
    sys_version = ""

    def _send_json(self, status_code: int, data: dict):
        body = json.dumps(data, indent=2).encode('utf-8')
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        parsed = urlparse(self.path)
        content_len = int(self.headers.get('Content-Length', 0))
        post_body = self.rfile.read(content_len) if content_len > 0 else b""
        
        logger.info(f"POST {self.path} from {self.client_address[0]}:{self.client_address[1]}")
        logger.info(f"Headers: {dict(self.headers)}")

        if parsed.path == "/api/v1/session/negotiate":
            try:
                payload = json.loads(post_body.decode('utf-8'))
            except Exception:
                payload = {}
            
            victim_host = payload.get("host", "UNKNOWN-HOST")
            victim_user = payload.get("user", "unknown")
            logger.info(f"Session Negotiation from {victim_host} (User: {victim_user})")

            resp = {
                "status": "established",
                "session_token": "SES-98214-LOCK",
                "encryption_alg": "AES256-GCM",
                "server_time": datetime.now(timezone.utc).isoformat(),
                "action": "proceed_encryption"
            }
            self._send_json(200, resp)
            return

        elif parsed.path == "/api/v1/emergency_stop":
            logger.warning("Emergency Stop command received!")
            self._send_json(200, {"status": "stopped", "message": "Simulation halted."})
            return

        self._send_json(404, {"error": "Not Found"})

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)

        logger.info(f"GET {self.path} from {self.client_address[0]}:{self.client_address[1]}")

        if parsed.path == "/api/v1/beacon":
            session = qs.get("session", [""])[0]
            status = qs.get("status", [""])[0]
            logger.info(f"Heartbeat beacon received: session={session}, status={status}")

            resp = {
                "ack": True,
                "command": "proceed",
                "server_time": datetime.now(timezone.utc).isoformat()
            }
            self._send_json(200, resp)
            return

        elif parsed.path == "/recover":
            html = """<!DOCTYPE html>
<html>
<head><title>Decryption Service</title></head>
<body style="font-family: monospace; background: #111; color: #00ff66; padding: 40px;">
  <h2>[CYBERRANGE SOC TRAINING EXERCISE]</h2>
  <p>Victim Reference ID: <b>WKSTN42-99824</b></p>
  <p>Status: Files in canary directory FinanceReports encrypted via AES-256 simulation key.</p>
  <p>This is a safe training exercise. Follow Module 2 incident response steps to restore files.</p>
</body>
</html>""".encode('utf-8')
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
            return

        self._send_json(404, {"error": "Not Found"})

    def log_message(self, format, *args):
        # Override to avoid double stderr printing
        pass

def run(host="0.0.0.0", port=8080):
    server_addr = (host, port)
    httpd = HTTPServer(server_addr, MockC2Handler)
    logger.info(f"Mock C2 Service listening on {host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Stopping Mock C2 Service...")
        httpd.server_close()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run(port=port)
