"""
Rich Terminal User Interface for Obscura

Provides live status dashboard with:
- Real-time process monitoring
- Progress bars for attacks
- Hardware status display
- Attack history and logs
- MITRE ATT&CK technique tracking
"""

import threading
import time
from datetime import datetime
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.text import Text
    from rich.tree import Tree
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


@dataclass
class AttackProgress:
    """Track attack execution progress"""
    attack_name: str
    target: str
    progress: float = 0.0
    status: str = "running"
    started_at: datetime = field(default_factory=datetime.now)
    mitre_id: Optional[str] = None


class ObscuraTUI:
    """
    Rich TUI for Obscura with real-time monitoring.
    
    Features:
    - Live hardware status
    - Active attack monitoring
    - Process tracking
    - Attack history
    - MITRE ATT&CK mapping
    """
    
    def __init__(self, orchestrator, hardware_profile=None):
        """
        Initialize TUI.
        
        Args:
            orchestrator: AttackOrchestrator instance
            hardware_profile: HardwareProfile instance (optional)
        """
        if not RICH_AVAILABLE:
            raise ImportError("Rich library not available. Install with: pip install rich")
        
        self.orchestrator = orchestrator
        self.hardware_profile = hardware_profile
        self.console = Console()
        self.running = False
        self.update_thread = None
        
        self.attack_progress: Dict[str, AttackProgress] = {}
        self.attack_history: List[Dict[str, Any]] = []
        self.log_messages: List[str] = []
        self.max_logs = 50
        
        self.start_time = datetime.now()
        self.packet_count = 0
        self.attack_count = 0
    
    def add_attack_progress(self, attack_name: str, target: str, mitre_id: Optional[str] = None) -> None:
        """Add attack to progress tracking."""
        attack_id = f"{attack_name}_{target}"
        self.attack_progress[attack_id] = AttackProgress(
            attack_name=attack_name,
            target=target,
            mitre_id=mitre_id
        )
        self.attack_count += 1
    
    def update_attack_progress(self, attack_name: str, target: str, progress: float, status: str = "running") -> None:
        """Update attack progress."""
        attack_id = f"{attack_name}_{target}"
        if attack_id in self.attack_progress:
            self.attack_progress[attack_id].progress = progress
            self.attack_progress[attack_id].status = status
            
            if status in ["completed", "failed"]:
                self.attack_history.append({
                    'attack': attack_name,
                    'target': target,
                    'status': status,
                    'mitre_id': self.attack_progress[attack_id].mitre_id,
                    'timestamp': datetime.now()
                })
                del self.attack_progress[attack_id]
    
    def add_log(self, message: str) -> None:
        """Add log message."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_messages.append(f"[{timestamp}] {message}")
        if len(self.log_messages) > self.max_logs:
            self.log_messages.pop(0)
    
    def increment_packet_count(self) -> None:
        """Increment packet counter."""
        self.packet_count += 1
    
    def generate_header(self) -> Panel:
        """Generate header panel."""
        uptime = datetime.now() - self.start_time
        uptime_str = str(uptime).split('.')[0]
        
        header_text = Text()
        header_text.append("OBSCURA ", style="bold red")
        header_text.append("Multi-Vector Adversarial Framework", style="cyan")
        header_text.append(f"\nUptime: {uptime_str} ", style="green")
        header_text.append(f"| Packets: {self.packet_count:,} ", style="yellow")
        header_text.append(f"| Attacks: {self.attack_count}", style="magenta")
        
        return Panel(header_text, border_style="blue")
    
    def generate_hardware_status(self) -> Table:
        """Generate hardware status table."""
        table = Table(title="Hardware Status", show_header=True, header_style="bold cyan")
        table.add_column("Component", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Details", style="dim")
        
        if self.hardware_profile:
            sdr_status = "✓ Available" if self.hardware_profile.has_any_sdr else "✗ None"
            sdr_color = "green" if self.hardware_profile.has_any_sdr else "red"
            sdr_details = f"{len(self.hardware_profile.sdr_devices)} device(s)"
            table.add_row("SDR Devices", f"[{sdr_color}]{sdr_status}[/{sdr_color}]", sdr_details)
            
            wifi_status = "✓ Available" if self.hardware_profile.has_monitor_wifi else "✗ None"
            wifi_color = "green" if self.hardware_profile.has_monitor_wifi else "red"
            wifi_details = f"{len(self.hardware_profile.wifi_interfaces)} interface(s)"
            table.add_row("Wi-Fi (Monitor)", f"[{wifi_color}]{wifi_status}[/{wifi_color}]", wifi_details)
            
            ble_status = "✓ Available" if self.hardware_profile.has_ble else "✗ None"
            ble_color = "green" if self.hardware_profile.has_ble else "red"
            ble_details = f"{len(self.hardware_profile.ble_interfaces)} interface(s)"
            table.add_row("BLE", f"[{ble_color}]{ble_status}[/{ble_color}]", ble_details)
            
            fallback = "✓ Active" if self.hardware_profile.fallback_mode else "✗ Disabled"
            fallback_color = "yellow" if self.hardware_profile.fallback_mode else "green"
            table.add_row("Fallback Mode", f"[{fallback_color}]{fallback}[/{fallback_color}]", ".iq fixtures")
        else:
            table.add_row("Hardware Profile", "[yellow]Not loaded[/yellow]", "")
        
        return table
    
    def generate_process_status(self) -> Table:
        """Generate process status table."""
        table = Table(title="Active Processes", show_header=True, header_style="bold green")
        table.add_column("Type", style="cyan")
        table.add_column("Count", justify="center")
        table.add_column("Status", style="dim")
        
        counts = self.orchestrator.process_manager.get_process_count()
        
        hackrf_status = "Running" if counts['hackrf'] > 0 else "Idle"
        hackrf_color = "green" if counts['hackrf'] > 0 else "dim"
        table.add_row("HackRF/SDR", str(counts['hackrf']), f"[{hackrf_color}]{hackrf_status}[/{hackrf_color}]")
        
        attacks_status = f"{counts['attacks']} active"
        attacks_color = "green" if counts['attacks'] > 0 else "dim"
        table.add_row("Attack Processes", str(counts['attacks']), f"[{attacks_color}]{attacks_status}[/{attacks_color}]")
        
        total_status = f"{counts['total']} total"
        table.add_row("Total", str(counts['total']), f"[bold]{total_status}[/bold]")
        
        return table
    
    def generate_attack_progress(self) -> Panel:
        """Generate attack progress panel."""
        if not self.attack_progress:
            return Panel("[dim]No active attacks[/dim]", title="Attack Progress", border_style="yellow")
        
        progress_text = Text()
        for attack_id, attack in self.attack_progress.items():
            elapsed = (datetime.now() - attack.started_at).total_seconds()
            progress_text.append(f"├─ {attack.attack_name}", style="cyan")
            progress_text.append(f" → {attack.target}\n", style="yellow")
            progress_text.append(f"│  Status: {attack.status} ", style="green")
            progress_text.append(f"| Elapsed: {elapsed:.1f}s", style="dim")
            if attack.mitre_id:
                progress_text.append(f" | MITRE: {attack.mitre_id}", style="magenta")
            progress_text.append("\n")
        
        return Panel(progress_text, title="Attack Progress", border_style="green")
    
    def generate_attack_history(self) -> Table:
        """Generate attack history table."""
        table = Table(title="Recent Attacks", show_header=True, header_style="bold magenta")
        table.add_column("Time", style="dim")
        table.add_column("Attack", style="cyan")
        table.add_column("Target", style="yellow")
        table.add_column("Status", justify="center")
        table.add_column("MITRE", style="magenta")
        
        recent = self.attack_history[-10:]
        for entry in recent:
            timestamp = entry['timestamp'].strftime("%H:%M:%S")
            status_icon = "✓" if entry['status'] == "completed" else "✗"
            status_color = "green" if entry['status'] == "completed" else "red"
            mitre_id = entry.get('mitre_id', 'N/A')
            
            table.add_row(
                timestamp,
                entry['attack'],
                entry['target'],
                f"[{status_color}]{status_icon}[/{status_color}]",
                mitre_id
            )
        
        if not recent:
            table.add_row("", "[dim]No attack history[/dim]", "", "", "")
        
        return table
    
    def generate_logs(self) -> Panel:
        """Generate logs panel."""
        log_text = "\n".join(self.log_messages[-15:]) if self.log_messages else "[dim]No logs yet[/dim]"
        return Panel(log_text, title="Recent Logs", border_style="blue")
    
    def generate_layout(self) -> Layout:
        """Generate complete dashboard layout."""
        layout = Layout()
        
        layout.split_column(
            Layout(name="header", size=4),
            Layout(name="main", ratio=1),
            Layout(name="logs", size=12)
        )
        
        layout["main"].split_row(
            Layout(name="left"),
            Layout(name="right")
        )
        
        layout["left"].split_column(
            Layout(name="hardware"),
            Layout(name="processes")
        )
        
        layout["right"].split_column(
            Layout(name="progress"),
            Layout(name="history")
        )
        
        layout["header"].update(self.generate_header())
        layout["hardware"].update(self.generate_hardware_status())
        layout["processes"].update(self.generate_process_status())
        layout["progress"].update(self.generate_attack_progress())
        layout["history"].update(self.generate_attack_history())
        layout["logs"].update(self.generate_logs())
        
        return layout
    
    def run(self, update_interval: float = 1.0) -> None:
        """
        Run live TUI.
        
        Args:
            update_interval: Refresh interval in seconds
        """
        self.running = True
        
        try:
            with Live(self.generate_layout(), console=self.console, refresh_per_second=1/update_interval) as live:
                while self.running:
                    live.update(self.generate_layout())
                    time.sleep(update_interval)
        except KeyboardInterrupt:
            self.running = False
            self.console.print("\n[yellow]TUI stopped by user[/yellow]")
    
    def stop(self) -> None:
        """Stop TUI."""
        self.running = False
    
    def print_summary(self) -> None:
        """Print session summary."""
        self.console.print("\n[bold cyan]═══ Session Summary ═══[/bold cyan]\n")
        
        summary_table = Table(show_header=False, box=None)
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="green")
        
        uptime = datetime.now() - self.start_time
        summary_table.add_row("Uptime", str(uptime).split('.')[0])
        summary_table.add_row("Packets Processed", f"{self.packet_count:,}")
        summary_table.add_row("Attacks Launched", str(self.attack_count))
        summary_table.add_row("Successful Attacks", str(sum(1 for h in self.attack_history if h['status'] == 'completed')))
        summary_table.add_row("Failed Attacks", str(sum(1 for h in self.attack_history if h['status'] == 'failed')))
        
        self.console.print(summary_table)
        self.console.print()


def create_tui(orchestrator, hardware_profile=None) -> Optional[ObscuraTUI]:
    """
    Factory function to create TUI instance.
    
    Args:
        orchestrator: AttackOrchestrator instance
        hardware_profile: HardwareProfile instance (optional)
        
    Returns:
        ObscuraTUI instance or None if rich not available
    """
    if not RICH_AVAILABLE:
        return None
    
    return ObscuraTUI(orchestrator, hardware_profile)
