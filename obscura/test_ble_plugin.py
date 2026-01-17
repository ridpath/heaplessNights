"""
Test script for BLE Attack Plugin
Verifies that all BLE attack functions load and execute in dry-run mode.
"""

import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / 'obscura'))

from obscura.attacks import AttackOrchestrator


def test_ble_plugin_registration():
    """Test that BLE plugin registers successfully."""
    print("\n=== Testing BLE Plugin Registration ===\n")
    
    orchestrator = AttackOrchestrator(
        interface="hci0",
        simulate_mode=True,
        battery_saver=False
    )
    
    orchestrator.register_default_attacks()
    
    try:
        orchestrator.load_plugin('ble_attacks')
        print("[+] BLE plugin loaded successfully")
    except Exception as e:
        print(f"[!] Failed to load BLE plugin: {e}")
        return False
    
    expected_attacks = [
        'ble_hid_spoof_keyboard',
        'ble_mac_rotation',
        'ble_gatt_fuzzing',
        'ble_advertising_jam'
    ]
    
    missing_attacks = []
    for attack in expected_attacks:
        if attack not in orchestrator.attack_vectors:
            missing_attacks.append(attack)
            print(f"[!] Missing attack: {attack}")
        else:
            print(f"[+] Found attack: {attack}")
    
    if missing_attacks:
        print(f"\n[!] {len(missing_attacks)} attacks missing")
        return False
    
    print(f"\n[+] All {len(expected_attacks)} BLE attacks registered successfully")
    return True


def test_ble_hid_keyboard():
    """Test BLE HID keyboard spoofing in dry-run mode."""
    print("\n=== Testing BLE HID Keyboard Spoofing ===\n")
    
    orchestrator = AttackOrchestrator(
        interface="hci0",
        simulate_mode=True,
        battery_saver=False
    )
    
    orchestrator.register_default_attacks()
    orchestrator.load_plugin('ble_attacks')
    
    try:
        attack_func = orchestrator.attack_vectors['ble_hid_spoof_keyboard']
        result = attack_func(
            orchestrator,
            target_text="Test payload",
            interface="hci0"
        )
        
        if result:
            print("[+] BLE HID keyboard spoofing test passed")
        else:
            print("[!] BLE HID keyboard spoofing test failed")
        
        return result
        
    except Exception as e:
        print(f"[!] BLE HID keyboard test error: {e}")
        return False


def test_ble_mac_rotation():
    """Test BLE MAC rotation in dry-run mode."""
    print("\n=== Testing BLE MAC Rotation ===\n")
    
    orchestrator = AttackOrchestrator(
        interface="hci0",
        simulate_mode=True,
        battery_saver=False
    )
    
    orchestrator.register_default_attacks()
    orchestrator.load_plugin('ble_attacks')
    
    try:
        attack_func = orchestrator.attack_vectors['ble_mac_rotation']
        result = attack_func(
            orchestrator,
            interface="hci0",
            rotation_interval=10,
            duration=30
        )
        
        if result:
            print("[+] BLE MAC rotation test passed")
        else:
            print("[!] BLE MAC rotation test failed")
        
        return result
        
    except Exception as e:
        print(f"[!] BLE MAC rotation test error: {e}")
        return False


def test_ble_gatt_fuzzing():
    """Test BLE GATT fuzzing in dry-run mode."""
    print("\n=== Testing BLE GATT Fuzzing ===\n")
    
    orchestrator = AttackOrchestrator(
        interface="hci0",
        simulate_mode=True,
        battery_saver=False
    )
    
    orchestrator.register_default_attacks()
    orchestrator.load_plugin('ble_attacks')
    
    try:
        attack_func = orchestrator.attack_vectors['ble_gatt_fuzzing']
        result = attack_func(
            orchestrator,
            target_device=None,
            service_uuid=None,
            use_llm_assist=True,
            fuzz_iterations=50
        )
        
        if result:
            print("[+] BLE GATT fuzzing test passed")
        else:
            print("[!] BLE GATT fuzzing test failed")
        
        return result
        
    except Exception as e:
        print(f"[!] BLE GATT fuzzing test error: {e}")
        return False


def test_ble_advertising_jam():
    """Test BLE advertising jamming in dry-run mode."""
    print("\n=== Testing BLE Advertising Jamming ===\n")
    
    orchestrator = AttackOrchestrator(
        interface="hci0",
        simulate_mode=True,
        battery_saver=False
    )
    
    orchestrator.register_default_attacks()
    orchestrator.load_plugin('ble_attacks')
    
    try:
        attack_func = orchestrator.attack_vectors['ble_advertising_jam']
        result = attack_func(
            orchestrator,
            interface="hci0",
            duration=10,
            channels=[37, 38, 39]
        )
        
        if result:
            print("[+] BLE advertising jamming test passed")
        else:
            print("[!] BLE advertising jamming test failed")
        
        return result
        
    except Exception as e:
        print(f"[!] BLE advertising jamming test error: {e}")
        return False


def main():
    """Run all BLE plugin tests."""
    print("=" * 60)
    print("BLE Attack Plugin Test Suite")
    print("=" * 60)
    
    tests = [
        ("Plugin Registration", test_ble_plugin_registration),
        ("HID Keyboard Spoofing", test_ble_hid_keyboard),
        ("MAC Rotation", test_ble_mac_rotation),
        ("GATT Fuzzing", test_ble_gatt_fuzzing),
        ("Advertising Jamming", test_ble_advertising_jam),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n[!] Test '{test_name}' crashed: {e}")
            results.append((test_name, False))
    
    print("\n" + "=" * 60)
    print("Test Results Summary")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"{status} {test_name}")
    
    print("\n" + "=" * 60)
    print(f"Total: {passed}/{total} tests passed")
    print("=" * 60)
    
    return passed == total


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
