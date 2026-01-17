import argparse
import sys
import os
import json
import threading
from queue import Queue
from pathlib import Path

from .attacks import AttackOrchestrator, DecisionEngine
from .orchestrator import AutonomousOrchestrator
from .utils import (
    log_message, setup_monitor_mode, get_wireless_interfaces,
    get_supported_channels, channel_hopper, stealth_mode, packet_handler
)
from .hardware import (
    get_hardware_profile, print_hardware_summary,
    get_preferred_sdr, get_preferred_wifi_interface, get_preferred_ble_interface
)
from .tui import create_tui
from .config import ConfigManager, generate_config_template
from .reporting import AttackReporter


def check_safety_interlocks(override: bool = False):
    """
    Check RF safety interlocks.
    
    Returns True if safe to proceed, False otherwise.
    """
    rf_lock = os.environ.get('OBSCURA_RF_LOCK', '0')
    
    if rf_lock != '1' and not override:
        print("[ERROR] RF safety interlock not set.")
        print("[ERROR] OBSCURA_RF_LOCK environment variable must be set to '1'")
        print("[ERROR] This tool can emit RF signals and must be used in authorized environments only.")
        print("[ERROR] Use --override-safety to bypass this check (authorized use only)")
        print("")
        print("[WARNING] This software must be operated inside a Faraday cage or")
        print("[WARNING] in an authorized RF testing environment.")
        print("[WARNING] Unauthorized RF emissions are illegal.")
        return False
    
    if override:
        print("[WARNING] Safety interlock bypassed via --override-safety")
        print("[WARNING] Ensure you are in an authorized testing environment")
        print("")
    
    return True


def list_available_attacks(orchestrator):
    """List all available attacks from loaded plugins and default vectors."""
    print("\n=== Available Attack Vectors ===\n")
    
    print("Default Attack Vectors:")
    for attack_name in sorted(orchestrator.attack_vectors.keys()):
        print(f"  - {attack_name}")
    
    print("\nLoaded Plugins:")
    plugins = orchestrator.list_plugins()
    if plugins:
        for plugin in sorted(plugins):
            print(f"  - {plugin}")
    else:
        print("  (No plugins found in attack_plugins/)")
    
    print(f"\nTotal: {len(orchestrator.attack_vectors)} attack vectors available")
    print("")


def load_specific_plugins(orchestrator, plugin_list):
    """Load specific plugins by name."""
    success_count = 0
    fail_count = 0
    
    for plugin_name in plugin_list:
        try:
            orchestrator.load_plugin(plugin_name)
            print(f"[+] Loaded plugin: {plugin_name}")
            success_count += 1
        except Exception as e:
            print(f"[!] Failed to load plugin '{plugin_name}': {e}")
            fail_count += 1
    
    print(f"\n[*] Plugin loading complete: {success_count} succeeded, {fail_count} failed")
    return success_count > 0


def run_interactive_mode(orchestrator):
    """Run Obscura in interactive terminal mode."""
    print("\n=== Obscura Interactive Mode ===")
    print("Commands:")
    print("  list              - List available attacks")
    print("  run <attack>      - Execute an attack")
    print("  status            - Show orchestrator status")
    print("  stop              - Stop all running attacks")
    print("  exit              - Exit interactive mode")
    print("")
    
    while True:
        try:
            cmd = input("obscura> ").strip()
            
            if not cmd:
                continue
            
            parts = cmd.split()
            command = parts[0].lower()
            
            if command == 'exit' or command == 'quit':
                print("[*] Exiting interactive mode")
                break
            
            elif command == 'list':
                list_available_attacks(orchestrator)
            
            elif command == 'run' and len(parts) > 1:
                attack_name = parts[1]
                if attack_name in orchestrator.attack_vectors:
                    print(f"[*] Executing attack: {attack_name}")
                    try:
                        orchestrator.execute_attack(attack_name)
                        print(f"[+] Attack '{attack_name}' executed")
                    except Exception as e:
                        print(f"[!] Attack failed: {e}")
                else:
                    print(f"[!] Unknown attack: {attack_name}")
                    print(f"[*] Use 'list' to see available attacks")
            
            elif command == 'status':
                print(f"[*] Interface: {orchestrator.interface}")
                print(f"[*] Running: {orchestrator.running.is_set()}")
                print(f"[*] Simulate mode: {orchestrator.simulate_mode}")
                process_counts = orchestrator.process_manager.get_process_count()
                print(f"[*] Active attacks: {process_counts['total']} (HackRF: {process_counts['hackrf']}, Other: {process_counts['attacks']})")
            
            elif command == 'stop':
                print("[*] Stopping all attacks...")
                orchestrator.running.clear()
                print("[+] All attacks stopped")
            
            else:
                print(f"[!] Unknown command: {command}")
                print("[*] Type 'exit' to quit or use available commands")
        
        except KeyboardInterrupt:
            print("\n[*] Interrupted. Type 'exit' to quit.")
        except EOFError:
            print("\n[*] EOF detected, exiting")
            break
        except Exception as e:
            print(f"[!] Error: {e}")


def run_auto_mode(orchestrator, traits_file, simulate_mode=False, report_format='markdown'):
    """Run autonomous attack selection based on traits."""
    print(f"[*] Running autonomous mode with traits from: {traits_file}")
    
    if not os.path.exists(traits_file):
        print(f"[!] Traits file not found: {traits_file}")
        return False
    
    try:
        auto_orchestrator = AutonomousOrchestrator(
            attack_orchestrator=orchestrator,
            simulate_mode=simulate_mode
        )
        
        if not auto_orchestrator.load_traits_from_file(traits_file):
            print("[!] Failed to load traits file")
            return False
        
        with open(traits_file, 'r') as f:
            traits = json.load(f)
        
        print(f"[+] Loaded traits for {len(traits)} target types")
        print("")
        
        print("[*] Select a target type to attack:")
        target_types = list(traits.keys())
        for i, target_type in enumerate(target_types, 1):
            print(f"  {i}. {target_type}")
        print("")
        
        try:
            selection = input("Enter target number (or 'all' to test all): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Cancelled")
            return False
        
        if selection.lower() == 'all':
            targets_to_test = target_types
        else:
            try:
                idx = int(selection) - 1
                if 0 <= idx < len(target_types):
                    targets_to_test = [target_types[idx]]
                else:
                    print("[!] Invalid selection")
                    return False
            except ValueError:
                print("[!] Invalid input")
                return False
        
        print("")
        for target_type in targets_to_test:
            print(f"[*] Testing against target: {target_type}")
            print("="*60)
            
            target_data = traits[target_type].copy()
            target_data['device_type'] = target_type
            
            chain = auto_orchestrator.run_ooda_loop(
                target_data=target_data,
                max_attacks=3
            )
            
            output_dir = os.path.join(os.path.dirname(__file__), '..', 'logs')
            os.makedirs(output_dir, exist_ok=True)
            
            reporter = AttackReporter(output_dir=output_dir)
            
            if report_format in ['markdown', 'all']:
                md_file = reporter.generate_markdown_report(chain)
                print(f"[+] Markdown report: {md_file}")
            
            if report_format in ['html', 'all']:
                html_file = reporter.generate_html_report(chain)
                print(f"[+] HTML report: {html_file}")
            
            if report_format in ['pdf', 'all']:
                try:
                    pdf_file = reporter.generate_pdf_report(chain)
                    print(f"[+] PDF report: {pdf_file}")
                except ImportError as e:
                    print(f"[!] PDF generation skipped: {e}")
            
            if report_format in ['json', 'all']:
                json_file = reporter.save_json_log(chain)
                print(f"[+] JSON log: {json_file}")
            
            dot_file = os.path.join(output_dir, f"chain_{chain.chain_id}.dot")
            auto_orchestrator.export_chain_to_dot(chain, dot_file)
            print(f"[+] DOT graph: {dot_file}")
            
            print("")
        
        print("[+] Autonomous mode completed")
        return True
        
    except Exception as e:
        print(f"[!] Failed to run auto mode: {e}")
        import traceback
        traceback.print_exc()
        return False


def export_attack_graph(orchestrator, output_file):
    """Export attack graph to file with plugin metadata and attack categories."""
    print(f"[*] Exporting attack graph to: {output_file}")
    
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    attack_vectors = orchestrator.attack_vectors
    plugins = orchestrator.list_plugins()
    attack_log = orchestrator.attack_log
    
    attack_categories = {
        'wifi': [],
        'bluetooth': [],
        'camera': [],
        'sdr': [],
        'satellite': [],
        'chain': [],
        'other': []
    }
    
    for attack_name in attack_vectors.keys():
        if 'wifi' in attack_name or 'rogue_ap' in attack_name or 'evil_twin' in attack_name:
            attack_categories['wifi'].append(attack_name)
        elif 'bluetooth' in attack_name or 'ble' in attack_name:
            attack_categories['bluetooth'].append(attack_name)
        elif 'camera' in attack_name or 'mjpeg' in attack_name or 'rtsp' in attack_name:
            attack_categories['camera'].append(attack_name)
        elif 'rf' in attack_name or 'gps' in attack_name or 'drone' in attack_name:
            attack_categories['sdr'].append(attack_name)
        elif 'satellite' in attack_name or 'adsb' in attack_name or 'eas' in attack_name:
            attack_categories['satellite'].append(attack_name)
        elif 'chain_' in attack_name:
            attack_categories['chain'].append(attack_name)
        else:
            attack_categories['other'].append(attack_name)
    
    graph_data = {
        "total_attacks": len(attack_vectors),
        "plugins": plugins,
        "categories": {k: len(v) for k, v in attack_categories.items() if v},
        "attacks_by_category": {k: v for k, v in attack_categories.items() if v},
        "execution_log": attack_log
    }
    
    if output_file.endswith('.json'):
        with open(output_file, 'w') as f:
            json.dump(graph_data, f, indent=2)
        print(f"[+] Exported attack graph to JSON: {output_file}")
        print(f"[*] Total attacks: {graph_data['total_attacks']}")
        print(f"[*] Categories: {', '.join(graph_data['categories'].keys())}")
    
    elif output_file.endswith('.dot') or output_file.endswith('.svg'):
        dot_content = "digraph AttackGraph {\n"
        dot_content += "  rankdir=TB;\n"
        dot_content += "  node [shape=box, style=filled];\n"
        dot_content += "  graph [fontname=\"Arial\", fontsize=14, label=\"Obscura Attack Graph\", labelloc=t];\n"
        dot_content += "  node [fontname=\"Arial\", fontsize=10];\n"
        dot_content += "  edge [fontname=\"Arial\", fontsize=8];\n\n"
        
        dot_content += '  obscura [label="Obscura\\nFramework", fillcolor=lightblue, shape=ellipse];\n\n'
        
        category_colors = {
            'wifi': 'lightgreen',
            'bluetooth': 'lightcyan',
            'camera': 'lightyellow',
            'sdr': 'lightcoral',
            'satellite': 'plum',
            'chain': 'orange',
            'other': 'lightgray'
        }
        
        for category, attacks in attack_categories.items():
            if not attacks:
                continue
            
            color = category_colors.get(category, 'lightgray')
            
            dot_content += f'  subgraph cluster_{category} {{\n'
            dot_content += f'    label="{category.upper()}";\n'
            dot_content += f'    style=filled;\n'
            dot_content += f'    fillcolor={color};\n'
            dot_content += f'    node [fillcolor=white];\n\n'
            
            for attack in attacks:
                attack_safe = attack.replace('-', '_').replace(' ', '_')
                
                executed = any(log.get('attack') == attack for log in attack_log)
                if executed:
                    log_entry = next((log for log in attack_log if log.get('attack') == attack), {})
                    success = log_entry.get('success', False)
                    border_color = 'green' if success else 'red'
                    dot_content += f'    {attack_safe} [label="{attack}", color={border_color}, penwidth=2.0];\n'
                else:
                    dot_content += f'    {attack_safe} [label="{attack}"];\n'
            
            dot_content += '  }\n\n'
        
        for category in attack_categories.keys():
            if attack_categories[category]:
                first_attack = attack_categories[category][0].replace('-', '_').replace(' ', '_')
                dot_content += f'  obscura -> {first_attack} [style=invis];\n'
        
        if plugins:
            dot_content += '\n  subgraph cluster_plugins {\n'
            dot_content += '    label="LOADED PLUGINS";\n'
            dot_content += '    style=dashed;\n'
            dot_content += '    fillcolor=white;\n'
            for plugin in plugins:
                plugin_safe = plugin.replace('-', '_').replace(' ', '_')
                dot_content += f'    plugin_{plugin_safe} [label="{plugin}", shape=component, fillcolor=wheat];\n'
            dot_content += '  }\n\n'
        
        dot_content += "}\n"
        
        dot_file = output_file.replace('.svg', '.dot') if output_file.endswith('.svg') else output_file
        
        with open(dot_file, 'w') as f:
            f.write(dot_content)
        
        print(f"[+] Exported attack graph to DOT: {dot_file}")
        
        if output_file.endswith('.svg'):
            try:
                import subprocess
                result = subprocess.run(['dot', '-Tsvg', dot_file, '-o', output_file], 
                                     check=True, timeout=30, capture_output=True, text=True)
                print(f"[+] Converted to SVG: {output_file}")
                print(f"[*] Graph contains {len(attack_vectors)} attacks across {len([c for c in attack_categories.values() if c])} categories")
            except FileNotFoundError:
                print(f"[!] graphviz not installed - cannot convert to SVG")
                print(f"[*] Install with: apt-get install graphviz (Linux) or brew install graphviz (macOS)")
                print(f"[*] DOT file available at: {dot_file}")
            except subprocess.CalledProcessError as e:
                print(f"[!] Failed to convert to SVG: {e}")
                print(f"[*] DOT file available at: {dot_file}")
            except subprocess.TimeoutExpired:
                print(f"[!] Conversion to SVG timed out (graph may be too large)")
                print(f"[*] DOT file available at: {dot_file}")
    
    else:
        print(f"[!] Unsupported export format: {output_file}")
        print(f"[*] Supported formats: .json, .dot, .svg")
        return False
    
    return True


def main():
    """Main entry point for Obscura CLI."""
    parser = argparse.ArgumentParser(
        description="Obscura - Multi-Vector Adversarial Framework (Terminal-Only Mode)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  obscura --list-attacks
  obscura --interactive --interface wlan0
  obscura --load wifi,ble,rf --interface wlan0
  obscura --auto --target traits.json
  obscura --auto --target traits.json --report-format html
  obscura --auto --target traits.json --report-format pdf
  obscura --auto --target traits.json --report-format all
  obscura --export attack_graph.svg
  obscura --tui --config myconfig.yaml
  
Environment Variables:
  OBSCURA_RF_LOCK=1     Required to enable RF operations (safety interlock)

Legal Notice:
  This software is for authorized research and red-team testing only.
  RF emissions must be strictly controlled and comply with all laws.
  Use in unauthorized environments is strictly prohibited.
        """
    )
    
    parser.add_argument('--interface', 
                        help="Wireless interface (e.g., wlan0)")
    
    parser.add_argument('--interactive', 
                        action='store_true',
                        help="Run in interactive terminal mode")
    
    parser.add_argument('--load', 
                        help="Load specific plugins (comma-separated, e.g., wifi,ble,rf)")
    
    parser.add_argument('--auto', 
                        action='store_true',
                        help="Run autonomous attack selection mode")
    
    parser.add_argument('--target', 
                        default='traits.json',
                        help="Target traits file for --auto mode (default: traits.json)")
    
    parser.add_argument('--list-attacks', 
                        action='store_true',
                        help="List all available attacks and exit")
    
    parser.add_argument('--export', 
                        metavar='FILE',
                        help="Export attack graph (.json, .dot, or .svg)")
    
    parser.add_argument('--dry-run', 
                        action='store_true',
                        help="Dry run mode - no actual attacks executed")
    
    parser.add_argument('--override-safety', 
                        action='store_true',
                        help="Override RF safety interlock (authorized use only)")
    
    parser.add_argument('--simulate', 
                        action='store_true',
                        help="Run in simulation mode (no real attacks)")
    
    parser.add_argument('--debug', 
                        action='store_true',
                        help="Enable debug output")
    
    parser.add_argument('--show-hardware', 
                        action='store_true',
                        help="Display hardware detection summary and exit")
    
    parser.add_argument('--tui', 
                        action='store_true',
                        help="Run with Rich terminal user interface (TUI)")
    
    parser.add_argument('--config', 
                        metavar='FILE',
                        help="Load configuration from file (.json or .yaml)")
    
    parser.add_argument('--generate-config', 
                        metavar='FILE',
                        help="Generate configuration template and exit")
    
    parser.add_argument('--report-format',
                        choices=['markdown', 'html', 'pdf', 'json', 'all'],
                        default='markdown',
                        help="Report format for auto mode (default: markdown)")
    
    args = parser.parse_args()
    
    if args.generate_config:
        format = "yaml" if args.generate_config.endswith(('.yaml', '.yml')) else "json"
        generate_config_template(args.generate_config, format)
        sys.exit(0)
    
    config_manager = ConfigManager()
    if args.config:
        try:
            config_manager.load(args.config)
            print(f"[+] Configuration loaded from: {args.config}")
            
            errors = config_manager.validate()
            if errors:
                print("[ERROR] Configuration validation failed:")
                for error in errors:
                    print(f"  - {error}")
                sys.exit(1)
        except Exception as e:
            print(f"[ERROR] Failed to load config: {e}")
            sys.exit(1)
    else:
        try:
            config_manager.load()
            if config_manager.config_path:
                print(f"[+] Configuration loaded from: {config_manager.config_path}")
        except:
            pass
    
    if args.show_hardware:
        print("[*] Detecting hardware...")
        fixtures_dir = Path(__file__).parent.parent / "fixtures"
        profile = get_hardware_profile(fixtures_dir)
        print_hardware_summary(profile)
        
        if profile.fallback_mode:
            print("[INFO] No hardware detected - fallback mode will be used")
            print("[INFO] Attacks will use .iq fixture files (no RF emission)")
        else:
            print("[SUCCESS] Hardware detected - live RF operations available")
        
        sys.exit(0)
    
    if not check_safety_interlocks(args.override_safety):
        print("\n[*] Set OBSCURA_RF_LOCK=1 to proceed, or use --override-safety")
        print("[*] Example: export OBSCURA_RF_LOCK=1")
        sys.exit(1)
    
    if args.list_attacks:
        print("[*] Initializing orchestrator to enumerate attacks...")
        
        orchestrator = AttackOrchestrator(
            interface="none",
            simulate_mode=True,
            battery_saver=False
        )
        
        orchestrator.register_default_attacks()
        
        try:
            orchestrator.load_all_plugins()
        except Exception as e:
            print(f"[!] Warning: Some plugins failed to load: {e}")
            print("[*] Listing available attacks from core modules...")
        
        list_available_attacks(orchestrator)
        sys.exit(0)
    
    if args.export:
        print("[*] Initializing orchestrator for export...")
        
        orchestrator = AttackOrchestrator(
            interface="none",
            simulate_mode=True,
            battery_saver=False
        )
        
        orchestrator.register_default_attacks()
        
        try:
            orchestrator.load_all_plugins()
        except Exception as e:
            print(f"[!] Warning: Some plugins failed to load: {e}")
            print("[*] Exporting core attack vectors only...")
        
        success = export_attack_graph(orchestrator, args.export)
        sys.exit(0 if success else 1)
    
    if args.dry_run:
        print("[*] DRY RUN MODE - No actual attacks will be executed")
        args.simulate = True
    
    interfaces = get_wireless_interfaces()
    if not interfaces and not args.simulate:
        print("[ERROR] No wireless interfaces found")
        print("[*] Use --simulate for testing without hardware")
        sys.exit(1)
    
    interface = args.interface or config_manager.get('interface', interfaces[0] if interfaces else "wlan0")
    
    if not args.simulate and interface not in ['none', 'wlan0']:
        print(f"[*] Setting up monitor mode on {interface}...")
        monitor_interface = setup_monitor_mode(interface)
        if not monitor_interface:
            print(f"[ERROR] Failed to set {interface} to monitor mode")
            sys.exit(1)
        interface = monitor_interface
        print(f"[+] Monitor mode enabled: {interface}")
    
    print(f"[*] Initializing Obscura on interface: {interface}")
    
    battery_saver = config_manager.get('battery_saver', False)
    orchestrator = AttackOrchestrator(
        interface=interface,
        simulate_mode=args.simulate or config_manager.get('simulate_mode', False),
        battery_saver=battery_saver
    )
    
    orchestrator.register_default_attacks()
    
    if args.load:
        plugin_list = [p.strip() for p in args.load.split(',')]
        print(f"[*] Loading specific plugins: {', '.join(plugin_list)}")
        load_specific_plugins(orchestrator, plugin_list)
    else:
        print("[*] Loading all available plugins...")
        plugins = orchestrator.list_plugins()
        if plugins:
            loaded = 0
            failed = 0
            for plugin in plugins:
                try:
                    orchestrator.load_plugin(plugin)
                    loaded += 1
                except Exception as e:
                    failed += 1
                    if args.debug:
                        print(f"[!] Failed to load plugin '{plugin}': {e}")
            print(f"[+] Loaded {loaded} plugins ({failed} failed)")
        else:
            print("[*] No plugins found in attack_plugins/")
    
    if args.auto:
        traits_file = args.target
        if not os.path.isabs(traits_file):
            traits_file = os.path.join(os.path.dirname(__file__), traits_file)
        
        success = run_auto_mode(orchestrator, traits_file, simulate_mode=args.simulate, report_format=args.report_format)
        sys.exit(0 if success else 1)
    
    if args.tui:
        print("[*] Starting Rich TUI...")
        fixtures_dir = Path(__file__).parent.parent / "fixtures"
        hardware_profile = get_hardware_profile(fixtures_dir)
        
        tui = create_tui(orchestrator, hardware_profile)
        if not tui:
            print("[ERROR] Rich library not installed. Install with: pip install rich")
            print("[*] Falling back to interactive mode...")
            args.interactive = True
        else:
            tui.add_log("Obscura TUI initialized")
            tui.add_log(f"Interface: {interface}")
            tui.add_log(f"Simulate mode: {args.simulate}")
            
            try:
                import threading
                tui_thread = threading.Thread(target=tui.run, kwargs={'update_interval': 1.0}, daemon=True)
                tui_thread.start()
                
                print("[+] TUI running. Press Ctrl+C to stop.")
                while tui.running:
                    import time
                    time.sleep(0.5)
            except KeyboardInterrupt:
                print("\n[*] Stopping TUI...")
                tui.stop()
                tui.print_summary()
            finally:
                orchestrator.running.clear()
                print("[*] Shutdown complete")
            sys.exit(0)
    
    if args.interactive:
        try:
            run_interactive_mode(orchestrator)
        except KeyboardInterrupt:
            print("\n[*] Interrupted")
        finally:
            orchestrator.running.clear()
            print("[*] Shutdown complete")
        sys.exit(0)
    
    print("\n[*] No operation specified")
    print("[*] Use --help to see available options")
    print("[*] Common usage:")
    print("    obscura --list-attacks                    # List all attack vectors")
    print("    obscura --show-hardware                   # Display hardware status")
    print("    obscura --generate-config obscura.yaml    # Generate config template")
    print("    obscura --config obscura.yaml --tui       # Run with config + TUI")
    print("    obscura --tui --simulate                  # Run with Rich TUI (demo mode)")
    print("    obscura --interactive --interface wlan0   # Interactive mode")
    print("    obscura --auto --target traits.json       # Autonomous OODA mode")
    print("")
    sys.exit(0)


if __name__ == "__main__":
    main()
