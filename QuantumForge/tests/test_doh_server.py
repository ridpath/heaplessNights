#!/usr/bin/env python3

import json
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import ssl
import os

class DoHServer(BaseHTTPRequestHandler):
    
    trigger_enabled = True
    
    def log_message(self, format, *args):
        sys.stderr.write("[DoH Server] %s - %s\n" % (self.address_string(), format % args))
    
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        
        if parsed.path == '/dns-query':
            self.handle_doh_query(params)
        else:
            self.send_error(404, "Not Found")
    
    def do_POST(self):
        parsed = urlparse(self.path)
        
        if parsed.path == '/beacon':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            
            sys.stderr.write(f"[+] Beacon received: {len(body)} bytes\n")
            sys.stderr.write(f"[*] Headers: {dict(self.headers)}\n")
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        else:
            self.send_error(404, "Not Found")
    
    def handle_doh_query(self, params):
        name = params.get('name', [''])[0]
        qtype = params.get('type', ['1'])[0]
        
        sys.stderr.write(f"[*] DoH Query: name={name}, type={qtype}\n")
        
        if name == 'c2.example.com' and (qtype == '16' or qtype == 'TXT'):
            if DoHServer.trigger_enabled:
                response = {
                    "Status": 0,
                    "TC": False,
                    "RD": True,
                    "RA": True,
                    "AD": False,
                    "CD": False,
                    "Question": [
                        {
                            "name": "c2.example.com.",
                            "type": 16
                        }
                    ],
                    "Answer": [
                        {
                            "name": "c2.example.com.",
                            "type": 16,
                            "TTL": 300,
                            "data": "\"C2_TRIGGER:1\""
                        }
                    ]
                }
                sys.stderr.write("[+] Returning C2_TRIGGER:1\n")
            else:
                response = {
                    "Status": 0,
                    "TC": False,
                    "RD": True,
                    "RA": True,
                    "AD": False,
                    "CD": False,
                    "Question": [
                        {
                            "name": "c2.example.com.",
                            "type": 16
                        }
                    ],
                    "Answer": []
                }
                sys.stderr.write("[*] No trigger (disabled)\n")
        else:
            response = {
                "Status": 3,
                "TC": False,
                "RD": True,
                "RA": True,
                "AD": False,
                "CD": False,
                "Question": [
                    {
                        "name": name,
                        "type": int(qtype) if qtype.isdigit() else 1
                    }
                ],
                "Comment": "NXDOMAIN"
            }
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/dns-json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

def run_http_server(port=8443):
    server_address = ('', port)
    httpd = HTTPServer(server_address, DoHServer)
    
    sys.stderr.write(f"[*] Starting DoH test server on port {port}\n")
    sys.stderr.write(f"[*] DoH endpoint: http://localhost:{port}/dns-query\n")
    sys.stderr.write(f"[*] Beacon endpoint: http://localhost:{port}/beacon\n")
    sys.stderr.write(f"[*] C2 trigger: {'ENABLED' if DoHServer.trigger_enabled else 'DISABLED'}\n")
    sys.stderr.write(f"\n[*] Test with:\n")
    sys.stderr.write(f"    curl 'http://localhost:{port}/dns-query?name=c2.example.com&type=16'\n")
    sys.stderr.write(f"\n")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\n[*] Shutting down server\n")
        httpd.shutdown()

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='DoH C2 Test Server')
    parser.add_argument('--port', type=int, default=8443, help='Port to listen on (default: 8443)')
    parser.add_argument('--no-trigger', action='store_true', help='Disable C2 trigger in responses')
    
    args = parser.parse_args()
    
    if args.no_trigger:
        DoHServer.trigger_enabled = False
    
    run_http_server(args.port)
