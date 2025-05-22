import argparse
import sys
import threading
import scapy.all as scapy
import os
from queue import Queue
import webbrowser 

from .attacks import AttackOrchestrator, DecisionEngine
from .utils import (
    log_message, setup_monitor_mode, get_wireless_interfaces,
    get_supported_channels, channel_hopper, stealth_mode, packet_handler
)
from .ui import ObscuraApp
from .satellite_ui import run_server  # Added import

def sniffing_thread(interface, decision_engine, orchestrator, ui, detected_networks_queue, detected_cameras_queue):
    while orchestrator.running.is_set():
        try:
            scapy.sniff(
                iface=interface,
                prn=lambda pkt: packet_handler(
                    pkt, decision_engine, orchestrator, ui,
                    detected_networks_queue, detected_cameras_queue
                ),
                store=0,
                timeout=10
            )
        except Exception as e:
            if orchestrator.running.is_set():
                log_message(f"[DEBUG] Sniffing error: {e}", ui=ui)

def load_plugins(orchestrator):
    plugins_dir = os.path.join(os.path.dirname(__file__), "attack_plugins")
    if not os.path.exists(plugins_dir):
        log_message("[yellow]Plugin directory 'attack_plugins/' not found, skipping plugin load.")
        return

    try:
        orchestrator.load_all_plugins()
        log_message("[green]✓ Loaded all plugins from attack_plugins/[/green]")
    except Exception as e:
        log_message(f"[red]✗ Plugin loading failed: {e}[/red]")

def launch_satellite_dashboard():
    threading.Thread(target=run_server, daemon=True).start()
    try:
        webbrowser.open("http://127.0.0.1:5000", new=2)
    except Exception as e:
        log_message(f"[yellow]⚠ Failed to open browser automatically: {e}[/yellow]")
    log_message("[green]✓ Satellite dashboard launched from UI[/green]")


def main():
    parser = argparse.ArgumentParser(description="Obscura Jammer Framework")
    parser.add_argument('--interface', help="Wireless interface (e.g., wlan0)")
    parser.add_argument('--debug', action='store_true', help="Enable debug mode")
    parser.add_argument('--simulate', action='store_true', help="Run in simulation mode (no real attacks)")
    parser.add_argument('--battery-saver', action='store_true', help="Enable battery-saver mode (pulsed jamming)")
    parser.add_argument('--satellite', action='store_true', help="Launch satellite dashboard server")
    args = parser.parse_args()

    interfaces = get_wireless_interfaces()
    if not interfaces:
        log_message("[red]✗ No wireless interfaces found.[/red]")
        sys.exit(1)

    interface = args.interface or interfaces[0]
    monitor_interface = setup_monitor_mode(interface)
    if not monitor_interface:
        log_message(f"[red]✗ Failed to set {interface} to monitor mode.[/red]")
        sys.exit(1)
    interface = monitor_interface

    # Prepare dependencies
    channels = get_supported_channels(interface)
    stealth_mode(interface)
    decision_engine = DecisionEngine()
    detected_networks_queue = Queue()
    detected_cameras_queue = Queue()

    # Initialize Orchestrator
    orchestrator = AttackOrchestrator(
        interface=interface,
        simulate_mode=args.simulate,
        battery_saver=args.battery_saver
    )

    # Load plugins dynamically
    load_plugins(orchestrator)

    # Initialize UI
    ui = ObscuraApp(
        detected_networks_queue=detected_networks_queue,
        detected_cameras_queue=detected_cameras_queue,
        orchestrator=orchestrator
    )

    # Conditionally run satellite dashboard server
    if args.satellite:
        threading.Thread(target=run_server, daemon=True).start()
    else:
        # Expose launcher through UI integration
        ui.orchestrator.launch_satellite_dashboard = launch_satellite_dashboard

    # Background Threads
    threading.Thread(target=channel_hopper, args=(interface, channels), daemon=True).start()
    threading.Thread(
        target=sniffing_thread,
        args=(interface, decision_engine, orchestrator, ui, detected_networks_queue, detected_cameras_queue),
        daemon=True
    ).start()

    # Launch UI
    try:
        ui.run()
    except Exception as e:
        log_message(f"[red]✗ UI Exception: {e}[/red]", ui=ui)
    finally:
        orchestrator.running.clear()
        if hasattr(orchestrator, 'hackrf_process') and orchestrator.hackrf_process:
            orchestrator.hackrf_process.terminate()
        log_message("[green]✓ Application terminated cleanly[/green]", ui=ui)

if __name__ == "__main__":
    main()
