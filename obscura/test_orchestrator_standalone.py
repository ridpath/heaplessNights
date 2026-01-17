"""
Standalone test for Autonomous Orchestrator

Run this to validate orchestrator functionality without pytest.
"""

import os
import sys
import json

sys.path.insert(0, os.path.dirname(__file__))

from obscura.attacks import AttackOrchestrator
from obscura.orchestrator import AutonomousOrchestrator


def test_basic_functionality():
    """Test basic orchestrator functionality."""
    print("="*70)
    print("Autonomous Orchestrator - Standalone Test")
    print("="*70)
    print()
    
    print("[1/6] Initializing AttackOrchestrator...")
    orchestrator = AttackOrchestrator(
        interface="wlan0",
        simulate_mode=True,
        battery_saver=False
    )
    orchestrator.register_default_attacks()
    print(f"  [+] Registered {len(orchestrator.attack_vectors)} attack vectors")
    print()
    
    print("[2/6] Initializing AutonomousOrchestrator...")
    auto_orch = AutonomousOrchestrator(
        attack_orchestrator=orchestrator,
        simulate_mode=True
    )
    print("  [+] Autonomous orchestrator initialized")
    print()
    
    print("[3/6] Loading test traits...")
    traits_file = os.path.join(os.path.dirname(__file__), 'tests', 'test_traits.json')
    
    if not os.path.exists(traits_file):
        print(f"  [!] WARNING: Traits file not found: {traits_file}")
        print("  [*] Proceeding with manual target data...")
        traits_loaded = False
    else:
        result = auto_orch.load_traits_from_file(traits_file)
        if result:
            print(f"  [+] Loaded {len(auto_orch.trait_db)} trait profiles")
            traits_loaded = True
        else:
            print("  [!] Failed to load traits")
            traits_loaded = False
    print()
    
    print("[4/6] Testing OODA Loop - Drone Target")
    print("-"*70)
    target_drone = {
        'device_type': 'drone',
        'vendor': 'DJI',
        'services': ['gps', 'wifi', 'bluetooth'],
        'protocols': ['wifi', 'gps'],
        'signal_strength': -45
    }
    
    chain_drone = auto_orch.run_ooda_loop(target_drone, max_attacks=3)
    print()
    print(f"  Chain ID: {chain_drone.chain_id}")
    print(f"  Attacks Selected: {len(chain_drone.attacks)}")
    print(f"  Primary Attacks: {', '.join(chain_drone.attacks[:3])}")
    print(f"  Fallback Chains: {len(chain_drone.fallback_chains)}")
    print(f"  Execution Success: {chain_drone.success}")
    print()
    
    print("[5/6] Testing OODA Loop - Camera Target")
    print("-"*70)
    target_camera = {
        'device_type': 'camera',
        'vendor': 'Ring',
        'services': ['http', 'rtsp', 'mjpeg'],
        'protocols': ['wifi', 'http'],
        'signal_strength': -55
    }
    
    chain_camera = auto_orch.run_ooda_loop(target_camera, max_attacks=3)
    print()
    print(f"  Chain ID: {chain_camera.chain_id}")
    print(f"  Attacks Selected: {len(chain_camera.attacks)}")
    print(f"  Primary Attacks: {', '.join(chain_camera.attacks[:3])}")
    print(f"  Fallback Chains: {len(chain_camera.fallback_chains)}")
    print(f"  Execution Success: {chain_camera.success}")
    print()
    
    print("[6/6] Testing Export Functionality")
    print("-"*70)
    
    logs_dir = os.path.join(os.path.dirname(__file__), 'logs')
    os.makedirs(logs_dir, exist_ok=True)
    
    json_file = os.path.join(logs_dir, f"test_{chain_drone.chain_id}.json")
    result_json = auto_orch.export_chain_to_json(chain_drone, json_file)
    
    if result_json and os.path.exists(json_file):
        print(f"  [+] Exported JSON: {json_file}")
        with open(json_file, 'r') as f:
            data = json.load(f)
        print(f"      - Attacks: {len(data['attacks'])}")
        print(f"      - Scores: {len(data['scores'])}")
    else:
        print(f"  [!] Failed to export JSON")
    
    dot_file = os.path.join(logs_dir, f"test_{chain_camera.chain_id}.dot")
    result_dot = auto_orch.export_chain_to_dot(chain_camera, dot_file)
    
    if result_dot and os.path.exists(dot_file):
        print(f"  [+] Exported DOT: {dot_file}")
        svg_file = dot_file.replace('.dot', '.svg')
        if os.path.exists(svg_file):
            print(f"  [+] Exported SVG: {svg_file}")
    else:
        print(f"  [!] Failed to export DOT graph")
    
    print()
    print("="*70)
    print("Test Summary")
    print("="*70)
    print(f"  Attack Vectors Available: {len(orchestrator.attack_vectors)}")
    print(f"  Trait Profiles Loaded: {len(auto_orch.trait_db)}")
    print(f"  Test Chains Generated: 2")
    print(f"  Drone Chain Success: {chain_drone.success}")
    print(f"  Camera Chain Success: {chain_camera.success}")
    print()
    
    all_success = chain_drone.success and chain_camera.success and result_json and result_dot
    
    if all_success:
        print("[+] ALL TESTS PASSED")
        return 0
    else:
        print("[!] SOME TESTS FAILED")
        return 1


def test_scoring_mechanism():
    """Test attack scoring mechanism."""
    print()
    print("="*70)
    print("Attack Scoring Test")
    print("="*70)
    print()
    
    orchestrator = AttackOrchestrator(interface="wlan0", simulate_mode=True)
    orchestrator.register_default_attacks()
    
    auto_orch = AutonomousOrchestrator(orchestrator, simulate_mode=True)
    
    from obscura.orchestrator import TargetTrait
    
    test_cases = [
        (TargetTrait(device_type='drone', services=['gps'], signal_strength=-45), 'gps_spoof', 80.0),
        (TargetTrait(device_type='camera', services=['rtsp'], signal_strength=-50), 'camera_jam', 70.0),
        (TargetTrait(device_type='router', protocols=['wifi'], signal_strength=-40), 'wifi_deauth', 70.0),
        (TargetTrait(device_type='bluetooth', services=['bluetooth'], signal_strength=-60), 'bluetooth_jam', 60.0),
    ]
    
    print("Target Type          Attack              Expected    Actual     Pass")
    print("-"*70)
    
    all_passed = True
    for target, attack, expected_min in test_cases:
        score = auto_orch._score_attack(attack, target)
        passed = score.score >= expected_min
        all_passed = all_passed and passed
        
        status = "[PASS]" if passed else "[FAIL]"
        print(f"{target.device_type:20} {attack:20} >= {expected_min:5.1f}    {score.score:6.1f}   {status}")
    
    print()
    if all_passed:
        print("[+] Scoring mechanism validated")
        return 0
    else:
        print("[!] Scoring mechanism issues detected")
        return 1


def main():
    """Run all standalone tests."""
    print()
    print("#"*70)
    print("#  Obscura - Autonomous Orchestrator Validation")
    print("#"*70)
    print()
    
    try:
        result1 = test_basic_functionality()
        result2 = test_scoring_mechanism()
        
        print()
        print("#"*70)
        if result1 == 0 and result2 == 0:
            print("#  VALIDATION COMPLETE - ALL TESTS PASSED")
        else:
            print("#  VALIDATION COMPLETE - SOME FAILURES")
        print("#"*70)
        print()
        
        return result1 or result2
        
    except Exception as e:
        print()
        print(f"[ERROR] Test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
