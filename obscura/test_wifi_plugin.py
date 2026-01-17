#!/usr/bin/env python3
"""
Test script for Wi-Fi attack plugin in dry-run mode.
Verifies all attack functions execute without errors.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'obscura'))

from obscura.attacks import AttackOrchestrator


def test_wifi_plugin():
    """Test Wi-Fi plugin loading and execution in dry-run mode."""
    
    print("\n" + "="*60)
    print("Wi-Fi Attack Plugin - Dry Run Test")
    print("="*60 + "\n")
    
    print("[*] Initializing orchestrator in simulate mode...")
    orchestrator = AttackOrchestrator(
        interface="wlan0mon",
        simulate_mode=True,
        battery_saver=False
    )
    
    print("[*] Registering default attacks...")
    orchestrator.register_default_attacks()
    
    print("[*] Loading Wi-Fi attack plugin...")
    try:
        orchestrator.load_plugin('wifi_attacks')
        print("[+] Wi-Fi plugin loaded successfully\n")
    except Exception as e:
        print(f"[!] Failed to load Wi-Fi plugin: {e}")
        return False
    
    print("[*] Testing Wi-Fi attack vectors:\n")
    
    tests = [
        {
            'name': 'Wi-Fi Deauth (Scapy)',
            'attack': 'wifi_deauth_scapy',
            'args': {
                'target_bssid': '00:11:22:33:44:55',
                'client_mac': 'AA:BB:CC:DD:EE:FF',
                'count': 50
            }
        },
        {
            'name': 'Wi-Fi Deauth (aireplay-ng)',
            'attack': 'wifi_deauth_aireplay',
            'args': {
                'target_bssid': '00:11:22:33:44:55',
                'count': 10
            }
        },
        {
            'name': 'Beacon Flood',
            'attack': 'wifi_beacon_flood',
            'args': {
                'count': 25,
                'channel': 6
            }
        },
        {
            'name': 'Rogue AP',
            'attack': 'wifi_rogue_ap',
            'args': {
                'ssid': 'Test_Free_WiFi',
                'channel': 11,
                'duration': 10
            }
        },
        {
            'name': 'Channel Hopping (Auto)',
            'attack': 'wifi_channel_hop',
            'args': {
                'duration': 20,
                'hop_interval': 1.0,
                'band': 'auto'
            }
        },
        {
            'name': 'Channel Hopping (2.4GHz)',
            'attack': 'wifi_channel_hop',
            'args': {
                'duration': 15,
                'hop_interval': 1.5,
                'band': '2.4'
            }
        },
        {
            'name': 'Channel Hopping (5GHz)',
            'attack': 'wifi_channel_hop',
            'args': {
                'duration': 15,
                'hop_interval': 1.5,
                'band': '5'
            }
        },
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        print(f"\n--- Test: {test['name']} ---")
        try:
            attack_func = orchestrator.attack_vectors.get(test['attack'])
            
            if not attack_func:
                print(f"[!] Attack '{test['attack']}' not found in registry")
                failed += 1
                continue
            
            result = attack_func(orchestrator, **test['args'])
            
            if result:
                print(f"[+] {test['name']} - PASSED")
                passed += 1
            else:
                print(f"[!] {test['name']} - FAILED (returned False)")
                failed += 1
                
        except Exception as e:
            print(f"[!] {test['name']} - FAILED with exception: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("\n" + "="*60)
    print(f"Test Results: {passed} passed, {failed} failed")
    print("="*60 + "\n")
    
    if failed == 0:
        print("[+] All Wi-Fi plugin tests passed successfully!")
        return True
    else:
        print(f"[!] {failed} test(s) failed")
        return False


if __name__ == '__main__':
    os.environ['OBSCURA_RF_LOCK'] = '1'
    
    success = test_wifi_plugin()
    
    sys.exit(0 if success else 1)
