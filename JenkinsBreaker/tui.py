#!/usr/bin/env python3
"""
JenkinsBreaker Textual TUI - Interactive Terminal Interface
Provides real-time Jenkins exploitation dashboard with rich visualizations
"""

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import Header, Footer, Button, Static, Input, DataTable, Log, TabbedContent, TabPane, Label
from textual.binding import Binding
from rich.table import Table as RichTable
import asyncio
import requests
from datetime import datetime
from typing import Dict, List, Optional

class TargetInfo(Static):
    """Displays target Jenkins server information"""
    
    def __init__(self):
        super().__init__()
        self.target_url = ""
        self.version = "Unknown"
        self.plugins = []
    
    def set_target(self, url: str, version: str = "Unknown", plugins: List[str] = None):
        self.target_url = url
        self.version = version
        self.plugins = plugins or []
        self.update_display()
    
    def update_display(self):
        table = RichTable(title="Target Information", show_header=True, header_style="bold magenta")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("URL", self.target_url)
        table.add_row("Version", self.version)
        table.add_row("Plugins", str(len(self.plugins)))
        table.add_row("Status", "[green]Online[/green]" if self.target_url else "[red]Not Connected[/red]")
        
        self.update(table)


class ExploitLog(Log):
    """Real-time exploit execution log"""
    
    def log_info(self, message: str):
        self.write_line(f"[cyan][INFO][/cyan] {message}")
    
    def log_success(self, message: str):
        self.write_line(f"[green][PASS][/green] {message}")
    
    def log_error(self, message: str):
        self.write_line(f"[red][FAIL][/red] {message}")
    
    def log_warning(self, message: str):
        self.write_line(f"[yellow][WARN][/yellow] {message}")


class CVETable(DataTable):
    """Displays available CVE exploits with metadata"""
    
    def __init__(self):
        super().__init__()
        self.add_column("CVE", width=20)
        self.add_column("Name", width=40)
        self.add_column("Risk", width=10)
        self.add_column("Auth", width=8)
        self.add_column("Status", width=12)
        
        self.cves = [
            ("CVE-2024-23897", "CLI Arbitrary File Read", "High", "No", "Ready"),
            ("CVE-2019-1003029", "Groovy RCE Sandbox Bypass", "Critical", "No", "Ready"),
            ("CVE-2018-1000861", "Stapler RCE", "Critical", "No", "Ready"),
            ("CVE-2021-21686", "Agent Path Traversal", "High", "Yes", "Ready"),
            ("CVE-2020-2100", "Git Plugin RCE", "High", "Yes", "Ready"),
            ("CVE-2018-1000600", "GitHub Plugin SSRF", "Medium", "Yes", "Ready"),
            ("CVE-2019-10358", "Maven Info Disclosure", "Medium", "No", "Ready"),
            ("CVE-2018-1000402", "AWS CodeDeploy Exposure", "High", "Yes", "Ready"),
        ]
        
        for cve_id, name, risk, auth, status in self.cves:
            risk_color = {"Critical": "[red]", "High": "[orange1]", "Medium": "[yellow]"}.get(risk, "[white]")
            self.add_row(
                cve_id,
                name,
                f"{risk_color}{risk}[/]",
                auth,
                f"[green]{status}[/]"
            )


class JenkinsBreakerTUI(App):
    """Textual TUI for JenkinsBreaker"""
    
    CSS = """
    Screen {
        background: $surface;
    }
    
    #main-container {
        height: 100%;
    }
    
    #target-panel {
        height: 15;
        border: solid $accent;
        margin: 1;
    }
    
    #control-panel {
        height: 10;
        border: solid $accent;
        margin: 1;
    }
    
    #cve-table {
        height: 20;
        border: solid $accent;
        margin: 1;
    }
    
    #exploit-log {
        height: 1fr;
        border: solid $accent;
        margin: 1;
    }
    
    Input {
        margin: 1;
    }
    
    Button {
        margin: 1;
    }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("e", "enumerate", "Enumerate"),
        Binding("x", "exploit", "Exploit"),
        Binding("c", "connect", "Connect"),
        Binding("r", "reset", "Reset"),
    ]
    
    def compose(self) -> ComposeResult:
        yield Header()
        
        with Vertical(id="main-container"):
            with Container(id="target-panel"):
                yield TargetInfo()
            
            with Container(id="control-panel"):
                yield Label("Jenkins URL:")
                yield Input(placeholder="http://jenkins.example.com:8080", id="url-input")
                yield Label("Username:")
                yield Input(placeholder="admin", id="username-input")
                yield Label("Password:")
                yield Input(placeholder="password", password=True, id="password-input")
                
                with Horizontal():
                    yield Button("Connect", id="connect-btn", variant="primary")
                    yield Button("Enumerate", id="enumerate-btn", variant="success")
                    yield Button("Auto Exploit", id="exploit-btn", variant="warning")
                    yield Button("Reset", id="reset-btn", variant="error")
            
            with Container(id="cve-table"):
                yield CVETable()
            
            with Container(id="exploit-log"):
                yield ExploitLog()
        
        yield Footer()
    
    def on_mount(self) -> None:
        self.title = "JenkinsBreaker TUI v2.0"
        log = self.query_one(ExploitLog)
        log.log_info("JenkinsBreaker TUI started")
        log.log_info("Press 'c' to connect to target")
    
    def action_quit(self) -> None:
        self.exit()
    
    def action_reset(self) -> None:
        log = self.query_one(ExploitLog)
        log.clear()
        log.log_info("Session reset")
    
    async def action_connect(self) -> None:
        url_input = self.query_one("#url-input", Input)
        username_input = self.query_one("#username-input", Input)
        password_input = self.query_one("#password-input", Input)
        
        url = url_input.value
        username = username_input.value
        password = password_input.value
        
        log = self.query_one(ExploitLog)
        log.log_info(f"Connecting to {url}...")
        
        try:
            resp = requests.get(url, timeout=5)
            version = resp.headers.get('X-Jenkins', 'Unknown')
            
            target_info = self.query_one(TargetInfo)
            target_info.set_target(url, version)
            
            log.log_success(f"Connected to Jenkins {version}")
            
            if username and password:
                log.log_info(f"Authenticated as {username}")
        
        except Exception as e:
            log.log_error(f"Connection failed: {str(e)}")
    
    async def action_enumerate(self) -> None:
        log = self.query_one(ExploitLog)
        log.log_info("Enumerating target...")
        
        url_input = self.query_one("#url-input", Input)
        url = url_input.value
        
        if not url:
            log.log_error("No target URL specified")
            return
        
        try:
            resp = requests.get(f"{url}/pluginManager/api/json?depth=1", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                plugins = data.get("plugins", [])
                log.log_success(f"Enumerated {len(plugins)} plugins")
                
                for plugin in plugins[:5]:
                    log.log_info(f"  - {plugin.get('shortName')} v{plugin.get('version')}")
            else:
                log.log_warning("Plugin enumeration failed")
        
        except Exception as e:
            log.log_error(f"Enumeration failed: {str(e)}")
    
    async def action_exploit(self) -> None:
        log = self.query_one(ExploitLog)
        log.log_info("Starting auto-exploitation...")
        log.log_warning("This is a demo - implement exploit execution here")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "connect-btn":
            asyncio.create_task(self.action_connect())
        elif event.button.id == "enumerate-btn":
            asyncio.create_task(self.action_enumerate())
        elif event.button.id == "exploit-btn":
            asyncio.create_task(self.action_exploit())
        elif event.button.id == "reset-btn":
            self.action_reset()


if __name__ == "__main__":
    app = JenkinsBreakerTUI()
    app.run()
