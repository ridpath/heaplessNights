"""
Test script for Obscura Logging and Reporting System

Validates:
- JSON structured logging to logs/
- Markdown report generation
- Attack chain summary with MITRE ATT&CK mapping
- Chain score and duration tracking
- Report file structure and contents
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

from obscura.attacks import AttackOrchestrator
from obscura.orchestrator import AutonomousOrchestrator, AttackChain, TargetTrait, AttackScore
from obscura.reporting import AttackReporter


def test_logging_directory_structure():
    """Test that logs directory is created and structured correctly."""
    print("\n" + "="*70)
    print("Test 1: Logging Directory Structure")
    print("="*70)
    
    logs_dir = Path(__file__).parent / 'logs'
    
    reporter = AttackReporter(output_dir=str(logs_dir))
    
    assert logs_dir.exists(), f"Logs directory not created: {logs_dir}"
    print(f"[+] Logs directory exists: {logs_dir}")
    
    assert logs_dir.is_dir(), "Logs path is not a directory"
    print("[+] Logs path is a directory")
    
    print("[+] Test 1 PASSED\n")
    return True


def test_json_logging():
    """Test JSON structured logging."""
    print("="*70)
    print("Test 2: JSON Structured Logging")
    print("="*70)
    
    logs_dir = Path(__file__).parent / 'logs'
    reporter = AttackReporter(output_dir=str(logs_dir))
    
    target = TargetTrait(
        device_type='drone',
        vendor='DJI Phantom 4',
        services=['gps', 'wifi', 'bluetooth'],
        protocols=['wifi', 'gps'],
        signal_strength=-45,
        location={'lat': 37.7749, 'lon': -122.4194}
    )
    
    scores = [
        AttackScore(
            plugin_name='gps_spoof',
            score=92.5,
            confidence=0.92,
            reason='GPS spoofing highly effective against commercial drones',
            requirements_met=True,
            mitre_id='T1499'
        ),
        AttackScore(
            plugin_name='rf_jam',
            score=78.0,
            confidence=0.78,
            reason='RF jamming can disrupt drone control signals',
            requirements_met=True,
            mitre_id='T0809'
        )
    ]
    
    chain = AttackChain(
        chain_id=f'test_json_{int(datetime.now().timestamp())}',
        target_traits=target,
        attacks=['gps_spoof', 'rf_jam'],
        scores=scores,
        fallback_chains=[['wifi_deauth', 'bluetooth_jam']],
        success=True,
        start_time=1000.0,
        end_time=1015.5
    )
    
    chain.execution_log = [
        {
            'attack': 'gps_spoof',
            'success': True,
            'timestamp': 1005.0,
            'execution_time': 5.0
        },
        {
            'attack': 'rf_jam',
            'success': True,
            'timestamp': 1015.5,
            'execution_time': 10.5
        }
    ]
    
    json_file = reporter.save_json_log(chain)
    
    assert os.path.exists(json_file), f"JSON file not created: {json_file}"
    print(f"[+] JSON log created: {json_file}")
    
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    assert 'chain_id' in data, "Missing chain_id in JSON"
    assert 'chain_score' in data, "Missing chain_score in JSON"
    assert 'timestamp' in data, "Missing timestamp in JSON"
    assert 'target' in data, "Missing target in JSON"
    assert 'attacks' in data, "Missing attacks in JSON"
    assert 'execution_log' in data, "Missing execution_log in JSON"
    assert 'duration_seconds' in data, "Missing duration_seconds in JSON"
    
    print(f"[+] JSON structure validated")
    print(f"    - Chain ID: {data['chain_id']}")
    print(f"    - Chain Score: {data['chain_score']:.1f}/100")
    print(f"    - Duration: {data['duration_seconds']:.2f}s")
    print(f"    - Attacks: {len(data['attacks'])}")
    print(f"    - Execution Log Entries: {len(data['execution_log'])}")
    
    for attack in data['attacks']:
        assert 'name' in attack, "Attack missing name"
        assert 'score' in attack, "Attack missing score"
        assert 'mitre_id' in attack, "Attack missing mitre_id"
        assert 'mitre_info' in attack, "Attack missing mitre_info"
    
    print(f"[+] All attacks have required fields")
    print("[+] Test 2 PASSED\n")
    return True


def test_markdown_report_generation():
    """Test Markdown report generation with MITRE ATT&CK mapping."""
    print("="*70)
    print("Test 3: Markdown Report Generation")
    print("="*70)
    
    logs_dir = Path(__file__).parent / 'logs'
    reporter = AttackReporter(output_dir=str(logs_dir))
    
    target = TargetTrait(
        device_type='camera',
        vendor='Ring Doorbell Pro',
        services=['http', 'rtsp', 'mjpeg'],
        protocols=['wifi', 'http'],
        signal_strength=-55
    )
    
    scores = [
        AttackScore(
            plugin_name='camera_jam',
            score=85.0,
            confidence=0.85,
            reason='RF jamming effective against 2.4GHz cameras',
            requirements_met=True,
            mitre_id='T0885'
        ),
        AttackScore(
            plugin_name='mjpeg_inject',
            score=72.0,
            confidence=0.72,
            reason='Video stream injection possible via MITM',
            requirements_met=True,
            mitre_id='T1557'
        )
    ]
    
    chain = AttackChain(
        chain_id=f'test_md_{int(datetime.now().timestamp())}',
        target_traits=target,
        attacks=['camera_jam', 'mjpeg_inject'],
        scores=scores,
        success=True,
        start_time=2000.0,
        end_time=2025.8
    )
    
    chain.execution_log = [
        {
            'attack': 'camera_jam',
            'success': True,
            'timestamp': 2010.0,
            'execution_time': 10.0
        },
        {
            'attack': 'mjpeg_inject',
            'success': True,
            'timestamp': 2025.8,
            'execution_time': 15.8
        }
    ]
    
    md_file = reporter.generate_markdown_report(chain)
    
    assert os.path.exists(md_file), f"Markdown file not created: {md_file}"
    print(f"[+] Markdown report created: {md_file}")
    
    with open(md_file, 'r') as f:
        content = f.read()
    
    required_sections = [
        '# Obscura Attack Chain Report',
        'Chain ID:',
        'Chain Score:',
        'Duration:',
        'Target Information',
        'Device Type:',
        'Attack Chain',
        'MITRE ATT&CK',
        'Execution Log'
    ]
    
    for section in required_sections:
        assert section in content, f"Missing section: {section}"
    
    print(f"[+] All required sections present")
    
    assert 'T0885' in content, "Missing MITRE technique T0885"
    assert 'T1557' in content, "Missing MITRE technique T1557"
    print(f"[+] MITRE ATT&CK mapping included")
    
    assert 'camera_jam' in content, "Missing attack: camera_jam"
    assert 'mjpeg_inject' in content, "Missing attack: mjpeg_inject"
    print(f"[+] Attack details included")
    
    assert 'Ring Doorbell Pro' in content, "Missing vendor info"
    assert 'camera' in content, "Missing device type"
    print(f"[+] Target information included")
    
    print("[+] Test 3 PASSED\n")
    return True


def test_chain_score_calculation():
    """Test chain score calculation algorithm."""
    print("="*70)
    print("Test 4: Chain Score Calculation")
    print("="*70)
    
    logs_dir = Path(__file__).parent / 'logs'
    reporter = AttackReporter(output_dir=str(logs_dir))
    
    target = TargetTrait(device_type='test', signal_strength=-50)
    
    test_cases = [
        {
            'name': 'High score, all success',
            'scores': [
                AttackScore('attack1', 90.0, 0.9, 'test', True),
                AttackScore('attack2', 85.0, 0.85, 'test', True)
            ],
            'exec_log': [
                {'attack': 'attack1', 'success': True, 'timestamp': 1.0, 'execution_time': 1.0},
                {'attack': 'attack2', 'success': True, 'timestamp': 2.0, 'execution_time': 1.0}
            ],
            'success': True,
            'expected_min': 70.0
        },
        {
            'name': 'Medium score, partial success',
            'scores': [
                AttackScore('attack1', 60.0, 0.6, 'test', True),
                AttackScore('attack2', 55.0, 0.55, 'test', True)
            ],
            'exec_log': [
                {'attack': 'attack1', 'success': True, 'timestamp': 1.0, 'execution_time': 1.0},
                {'attack': 'attack2', 'success': False, 'timestamp': 2.0, 'execution_time': 1.0}
            ],
            'success': False,
            'expected_min': 30.0
        }
    ]
    
    print("Test Case                    Chain Score    Expected    Pass")
    print("-"*70)
    
    all_passed = True
    for tc in test_cases:
        chain = AttackChain(
            chain_id='test',
            target_traits=target,
            attacks=[s.plugin_name for s in tc['scores']],
            scores=tc['scores'],
            success=tc['success'],
            start_time=1.0,
            end_time=10.0
        )
        chain.execution_log = tc['exec_log']
        
        score = reporter.calculate_chain_score(chain)
        passed = score >= tc['expected_min']
        all_passed = all_passed and passed
        
        status = "[PASS]" if passed else "[FAIL]"
        print(f"{tc['name']:28} {score:6.1f}         >={tc['expected_min']:5.1f}    {status}")
    
    print()
    if all_passed:
        print("[+] Chain score calculation validated")
        print("[+] Test 4 PASSED\n")
        return True
    else:
        print("[!] Test 4 FAILED\n")
        return False


def test_full_integration():
    """Test full integration: orchestrator → execution → reporting."""
    print("="*70)
    print("Test 5: Full Integration (Orchestrator + Reporting)")
    print("="*70)
    
    orchestrator = AttackOrchestrator(
        interface='wlan0',
        simulate_mode=True
    )
    orchestrator.register_default_attacks()
    
    print(f"[+] Orchestrator initialized with {len(orchestrator.attack_vectors)} attacks")
    
    auto_orch = AutonomousOrchestrator(
        attack_orchestrator=orchestrator,
        simulate_mode=True
    )
    
    print(f"[+] Autonomous orchestrator initialized")
    
    target_data = {
        'device_type': 'drone',
        'vendor': 'DJI',
        'services': ['gps', 'wifi'],
        'protocols': ['wifi', 'gps'],
        'signal_strength': -45
    }
    
    print(f"[+] Running OODA loop against drone target...")
    chain = auto_orch.run_ooda_loop(target_data, max_attacks=3)
    
    print(f"    - Chain ID: {chain.chain_id}")
    print(f"    - Attacks: {len(chain.attacks)}")
    print(f"    - Success: {chain.success}")
    
    logs_dir = Path(__file__).parent / 'logs'
    reporter = AttackReporter(output_dir=str(logs_dir))
    
    print(f"[+] Generating reports...")
    
    json_file = reporter.save_json_log(chain)
    print(f"    - JSON: {Path(json_file).name}")
    
    md_file = reporter.generate_markdown_report(chain)
    print(f"    - Markdown: {Path(md_file).name}")
    
    html_file = reporter.generate_html_report(chain)
    print(f"    - HTML: {Path(html_file).name}")
    
    assert os.path.exists(json_file), "JSON report not created"
    assert os.path.exists(md_file), "Markdown report not created"
    assert os.path.exists(html_file), "HTML report not created"
    
    with open(json_file, 'r') as f:
        json_data = json.load(f)
    
    assert json_data['chain_id'] == chain.chain_id, "Chain ID mismatch"
    assert 'chain_score' in json_data, "Chain score missing"
    
    chain_score = reporter.calculate_chain_score(chain)
    print(f"[+] Chain Score: {chain_score:.1f}/100")
    
    print(f"[+] All reports generated successfully")
    print("[+] Test 5 PASSED\n")
    return True


def test_mitre_attack_mapping():
    """Test MITRE ATT&CK mapping in reports."""
    print("="*70)
    print("Test 6: MITRE ATT&CK Mapping")
    print("="*70)
    
    logs_dir = Path(__file__).parent / 'logs'
    reporter = AttackReporter(output_dir=str(logs_dir))
    
    print(f"[+] MITRE ATT&CK database loaded")
    print(f"    - Total mappings: {len(reporter.MITRE_ATTACK_DB)}")
    
    common_attacks = [
        'gps_spoof', 'camera_jam', 'wifi_deauth',
        'rogue_ap', 'bluetooth_jam', 'satellite_disrupt'
    ]
    
    mapped_count = 0
    for attack in common_attacks:
        if attack in reporter.MITRE_ATTACK_DB:
            mapped_count += 1
            info = reporter.MITRE_ATTACK_DB[attack]
            print(f"    - {attack:20} -> {info['id']:8} ({info['tactic']})")
    
    print(f"[+] {mapped_count}/{len(common_attacks)} common attacks mapped")
    
    target = TargetTrait(device_type='multi', signal_strength=-50)
    
    chains = []
    for attack in common_attacks[:3]:
        if attack in reporter.MITRE_ATTACK_DB:
            chain = AttackChain(
                chain_id=f'test_{attack}',
                target_traits=target,
                attacks=[attack],
                scores=[
                    AttackScore(
                        plugin_name=attack,
                        score=80.0,
                        confidence=0.8,
                        reason='Test',
                        requirements_met=True,
                        mitre_id=reporter.MITRE_ATTACK_DB[attack]['id']
                    )
                ],
                success=True
            )
            chains.append(chain)
    
    matrix = reporter.generate_mitre_matrix(chains)
    
    print(f"[+] MITRE ATT&CK Matrix generated")
    print(f"    - Tactics: {matrix['total_tactics']}")
    print(f"    - Techniques: {matrix['total_techniques']}")
    print(f"    - Coverage: {matrix['coverage_summary']}")
    
    print("[+] Test 6 PASSED\n")
    return True


def main():
    """Run all logging and reporting tests."""
    print("\n" + "#"*70)
    print("#  Obscura - Logging and Reporting System Validation")
    print("#"*70)
    print()
    
    tests = [
        ("Logging Directory Structure", test_logging_directory_structure),
        ("JSON Structured Logging", test_json_logging),
        ("Markdown Report Generation", test_markdown_report_generation),
        ("Chain Score Calculation", test_chain_score_calculation),
        ("Full Integration", test_full_integration),
        ("MITRE ATT&CK Mapping", test_mitre_attack_mapping)
    ]
    
    results = []
    
    try:
        for test_name, test_func in tests:
            try:
                result = test_func()
                results.append((test_name, result))
            except Exception as e:
                print(f"[!] {test_name} FAILED with exception: {e}")
                import traceback
                traceback.print_exc()
                results.append((test_name, False))
        
        print("#"*70)
        print("#  Test Summary")
        print("#"*70)
        print()
        
        for test_name, result in results:
            status = "[PASS]" if result else "[FAIL]"
            print(f"  {status} {test_name}")
        
        passed = sum(1 for _, r in results if r)
        total = len(results)
        
        print()
        print(f"  Total: {passed}/{total} tests passed")
        print()
        
        if passed == total:
            print("#"*70)
            print("#  ALL TESTS PASSED - LOGGING AND REPORTING OPERATIONAL")
            print("#"*70)
            print()
            return 0
        else:
            print("#"*70)
            print("#  SOME TESTS FAILED")
            print("#"*70)
            print()
            return 1
            
    except Exception as e:
        print()
        print(f"[ERROR] Test suite failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
