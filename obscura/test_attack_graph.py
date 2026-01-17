#!/usr/bin/env python3
"""
Test script for attack graph generation in Obscura.

Tests:
1. Export attack graph to JSON
2. Export attack graph to DOT
3. Export attack graph to SVG (if graphviz available)
4. Export attack chain with execution results
5. Verify graph contains plugin names and success/failure status
"""

import os
import sys
import json
import subprocess
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'obscura'))

from obscura.attacks import AttackOrchestrator
from obscura.orchestrator import AutonomousOrchestrator


def check_graphviz_installed():
    """Check if graphviz is installed."""
    try:
        result = subprocess.run(['dot', '-V'], capture_output=True, timeout=5)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def test_export_json():
    """Test exporting attack graph to JSON."""
    print("[TEST] Exporting attack graph to JSON...")
    
    orchestrator = AttackOrchestrator(
        interface="none",
        simulate_mode=True,
        battery_saver=False
    )
    
    orchestrator.register_default_attacks()
    
    try:
        orchestrator.load_all_plugins()
        print("[+] Loaded plugins successfully")
    except Exception as e:
        print(f"[!] Warning: Some plugins failed to load: {e}")
    
    output_file = os.path.join(os.path.dirname(__file__), 'graphs', 'attack_graph.json')
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    from obscura.cli import export_attack_graph
    success = export_attack_graph(orchestrator, output_file)
    
    if not success:
        print("[FAIL] JSON export failed")
        return False
    
    if not os.path.exists(output_file):
        print(f"[FAIL] JSON file not created: {output_file}")
        return False
    
    with open(output_file, 'r') as f:
        data = json.load(f)
    
    required_keys = ['total_attacks', 'plugins', 'categories', 'attacks_by_category']
    for key in required_keys:
        if key not in data:
            print(f"[FAIL] Missing key in JSON: {key}")
            return False
    
    print(f"[PASS] JSON export successful")
    print(f"  Total attacks: {data['total_attacks']}")
    print(f"  Plugins: {len(data['plugins'])}")
    print(f"  Categories: {list(data['categories'].keys())}")
    
    return True


def test_export_dot():
    """Test exporting attack graph to DOT format."""
    print("\n[TEST] Exporting attack graph to DOT...")
    
    orchestrator = AttackOrchestrator(
        interface="none",
        simulate_mode=True,
        battery_saver=False
    )
    
    orchestrator.register_default_attacks()
    
    try:
        orchestrator.load_all_plugins()
    except Exception as e:
        print(f"[!] Warning: {e}")
    
    output_file = os.path.join(os.path.dirname(__file__), 'graphs', 'attack_graph.dot')
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    from obscura.cli import export_attack_graph
    success = export_attack_graph(orchestrator, output_file)
    
    if not success:
        print("[FAIL] DOT export failed")
        return False
    
    if not os.path.exists(output_file):
        print(f"[FAIL] DOT file not created: {output_file}")
        return False
    
    with open(output_file, 'r') as f:
        content = f.read()
    
    if 'digraph AttackGraph' not in content:
        print("[FAIL] DOT file does not contain valid graph")
        return False
    
    if 'cluster_' not in content:
        print("[FAIL] DOT file does not contain category clusters")
        return False
    
    print(f"[PASS] DOT export successful")
    print(f"  File size: {len(content)} bytes")
    print(f"  Contains categories: {'cluster_wifi' in content}")
    
    return True


def test_export_svg():
    """Test exporting attack graph to SVG."""
    print("\n[TEST] Exporting attack graph to SVG...")
    
    if not check_graphviz_installed():
        print("[SKIP] graphviz not installed, skipping SVG test")
        print("[INFO] Install with: apt-get install graphviz (Linux) or brew install graphviz (macOS)")
        return True
    
    orchestrator = AttackOrchestrator(
        interface="none",
        simulate_mode=True,
        battery_saver=False
    )
    
    orchestrator.register_default_attacks()
    
    try:
        orchestrator.load_all_plugins()
    except Exception as e:
        print(f"[!] Warning: {e}")
    
    output_file = os.path.join(os.path.dirname(__file__), 'graphs', 'attack_graph.svg')
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    from obscura.cli import export_attack_graph
    success = export_attack_graph(orchestrator, output_file)
    
    if not success:
        print("[FAIL] SVG export failed")
        return False
    
    svg_file = output_file
    if not os.path.exists(svg_file):
        print(f"[FAIL] SVG file not created: {svg_file}")
        return False
    
    with open(svg_file, 'r') as f:
        content = f.read()
    
    if '<svg' not in content:
        print("[FAIL] SVG file does not contain valid SVG")
        return False
    
    print(f"[PASS] SVG export successful")
    print(f"  File size: {len(content)} bytes")
    print(f"  Output: {svg_file}")
    
    return True


def test_attack_chain_export():
    """Test exporting attack chain with execution results."""
    print("\n[TEST] Exporting attack chain with execution results...")
    
    orchestrator = AttackOrchestrator(
        interface="none",
        simulate_mode=True,
        battery_saver=False
    )
    
    orchestrator.register_default_attacks()
    
    try:
        orchestrator.load_all_plugins()
    except Exception as e:
        print(f"[!] Warning: {e}")
    
    auto_orchestrator = AutonomousOrchestrator(
        attack_orchestrator=orchestrator,
        simulate_mode=True
    )
    
    target_data = {
        'device_type': 'camera',
        'vendor': 'Test Vendor',
        'services': ['rtsp', 'http'],
        'protocols': ['wifi'],
        'signal_strength': -60
    }
    
    chain = auto_orchestrator.run_ooda_loop(target_data, max_attacks=3)
    
    output_dir = os.path.join(os.path.dirname(__file__), 'graphs')
    os.makedirs(output_dir, exist_ok=True)
    
    json_file = os.path.join(output_dir, 'attack_chain.json')
    success_json = auto_orchestrator.export_chain_to_json(chain, json_file)
    
    if not success_json:
        print("[FAIL] Chain JSON export failed")
        return False
    
    if not os.path.exists(json_file):
        print(f"[FAIL] Chain JSON file not created: {json_file}")
        return False
    
    with open(json_file, 'r') as f:
        chain_data = json.load(f)
    
    required_keys = ['chain_id', 'device_type', 'attacks', 'scores', 'execution_log']
    for key in required_keys:
        if key not in chain_data:
            print(f"[FAIL] Missing key in chain JSON: {key}")
            return False
    
    print(f"[PASS] Chain JSON export successful")
    print(f"  Chain ID: {chain_data['chain_id']}")
    print(f"  Target: {chain_data['device_type']}")
    print(f"  Attacks: {len(chain_data['attacks'])}")
    print(f"  Execution log entries: {len(chain_data['execution_log'])}")
    
    dot_file = os.path.join(output_dir, 'attack_chain.dot')
    success_dot = auto_orchestrator.export_chain_to_dot(chain, dot_file)
    
    if not success_dot:
        print("[FAIL] Chain DOT export failed")
        return False
    
    if not os.path.exists(dot_file):
        print(f"[FAIL] Chain DOT file not created: {dot_file}")
        return False
    
    with open(dot_file, 'r') as f:
        dot_content = f.read()
    
    if 'digraph AttackChain' not in dot_content:
        print("[FAIL] DOT file does not contain valid chain graph")
        return False
    
    if 'SUCCESS' not in dot_content and 'FAILED' not in dot_content:
        print("[FAIL] DOT file does not contain execution status")
        return False
    
    print(f"[PASS] Chain DOT export successful")
    print(f"  Contains success/failure status: True")
    print(f"  Contains target node: {'target [label=' in dot_content}")
    
    if check_graphviz_installed():
        svg_file = dot_file.replace('.dot', '.svg')
        if os.path.exists(svg_file):
            print(f"[PASS] Chain SVG auto-generated: {svg_file}")
        else:
            print(f"[INFO] Chain SVG not auto-generated")
    
    return True


def main():
    """Run all attack graph tests."""
    print("=" * 70)
    print("Obscura Attack Graph Generation Test Suite")
    print("=" * 70)
    print("")
    
    os.environ['OBSCURA_RF_LOCK'] = '1'
    
    tests = [
        ("JSON Export", test_export_json),
        ("DOT Export", test_export_dot),
        ("SVG Export", test_export_svg),
        ("Attack Chain Export", test_attack_chain_export),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"[ERROR] {test_name} raised exception: {e}")
            import traceback
            traceback.print_exc()
            results.append((test_name, False))
    
    print("\n" + "=" * 70)
    print("Test Results Summary")
    print("=" * 70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"{status} {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n[SUCCESS] All attack graph generation tests passed!")
        print("\nGenerated files:")
        graphs_dir = os.path.join(os.path.dirname(__file__), 'graphs')
        if os.path.exists(graphs_dir):
            for filename in os.listdir(graphs_dir):
                filepath = os.path.join(graphs_dir, filename)
                size = os.path.getsize(filepath)
                print(f"  - {filename} ({size} bytes)")
        return 0
    else:
        print(f"\n[FAILURE] {total - passed} test(s) failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
