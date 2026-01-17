"""
Comprehensive Hardware Abstraction Test Suite

Tests hardware detection, fallback mechanisms, and integration with attack plugins.
"""

import sys
import os
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'obscura'))

from obscura.hardware import (
    get_hardware_profile,
    print_hardware_summary,
    get_preferred_sdr,
    get_preferred_wifi_interface,
    get_preferred_ble_interface,
    find_iq_fixtures,
    check_command_exists,
    detect_all_sdr_devices,
    detect_wifi_interfaces,
    detect_ble_interfaces
)


def test_command_detection():
    """Test command availability detection."""
    print("\n" + "="*80)
    print("COMMAND DETECTION TEST")
    print("="*80)
    
    test_commands = ['python', 'cmd', 'ping', 'nonexistent_command_12345']
    
    for cmd in test_commands:
        exists = check_command_exists(cmd)
        status = "[+]" if exists else "[-]"
        print(f"{status} Command '{cmd}': {'Available' if exists else 'Not found'}")
    
    print("")


def test_individual_detectors():
    """Test individual hardware detectors."""
    print("\n" + "="*80)
    print("INDIVIDUAL DETECTOR TEST")
    print("="*80)
    
    print("\n[SDR Detection]")
    sdr_devices = detect_all_sdr_devices()
    if sdr_devices:
        for device in sdr_devices:
            print(f"  [+] {device.name} ({device.device_type})")
    else:
        print("  [-] No SDR devices detected")
    
    print("\n[Wi-Fi Detection]")
    wifi_interfaces = detect_wifi_interfaces()
    if wifi_interfaces:
        for iface in wifi_interfaces:
            print(f"  [+] {iface.name} ({iface.mac})")
    else:
        print("  [-] No Wi-Fi interfaces detected")
    
    print("\n[BLE Detection]")
    ble_interfaces = detect_ble_interfaces()
    if ble_interfaces:
        for iface in ble_interfaces:
            print(f"  [+] {iface.name} ({iface.mac})")
    else:
        print("  [-] No BLE interfaces detected")
    
    print("")


def test_fallback_mechanisms():
    """Test fallback to .iq fixtures."""
    print("\n" + "="*80)
    print("FALLBACK MECHANISM TEST")
    print("="*80)
    
    fixtures_dir = Path(__file__).parent / "fixtures"
    
    print(f"\nFixtures directory: {fixtures_dir}")
    print(f"Exists: {fixtures_dir.exists()}")
    
    iq_files = find_iq_fixtures(fixtures_dir)
    
    print(f"\nFound {len(iq_files)} .iq fixture files:")
    for iq_file in iq_files:
        size_mb = iq_file.stat().st_size / (1024 * 1024)
        print(f"  [+] {iq_file.name} ({size_mb:.2f} MB)")
    
    print("")


def test_preferred_selection():
    """Test preferred device selection."""
    print("\n" + "="*80)
    print("PREFERRED DEVICE SELECTION TEST")
    print("="*80)
    
    fixtures_dir = Path(__file__).parent / "fixtures"
    profile = get_hardware_profile(fixtures_dir)
    
    print("\n[Preferred SDR]")
    preferred_sdr = get_preferred_sdr(profile)
    if preferred_sdr:
        print(f"  [+] {preferred_sdr.name} ({preferred_sdr.device_type})")
    else:
        print(f"  [-] No SDR available (fallback mode)")
    
    print("\n[Preferred Wi-Fi]")
    preferred_wifi = get_preferred_wifi_interface(profile)
    if preferred_wifi:
        print(f"  [+] {preferred_wifi.name} ({preferred_wifi.mac})")
        print(f"      Monitor capable: {preferred_wifi.monitor_capable}")
        print(f"      Monitor active: {preferred_wifi.monitor_active}")
    else:
        print(f"  [-] No Wi-Fi interface available")
    
    print("\n[Preferred BLE]")
    preferred_ble = get_preferred_ble_interface(profile)
    if preferred_ble:
        print(f"  [+] {preferred_ble.name} ({preferred_ble.mac})")
    else:
        print(f"  [-] No BLE interface available")
    
    print("")


def test_integration_with_plugins():
    """Test integration with attack plugins."""
    print("\n" + "="*80)
    print("PLUGIN INTEGRATION TEST")
    print("="*80)
    
    print("\n[Testing SDR Plugin Integration]")
    try:
        from obscura.attack_plugins.sdr_attacks import detect_sdr_hardware
        hardware = detect_sdr_hardware()
        print(f"  SDR plugin detect_sdr_hardware() result:")
        for device_type, available in hardware.items():
            status = "[+]" if available else "[-]"
            print(f"    {status} {device_type}: {'Available' if available else 'Not detected'}")
    except Exception as e:
        print(f"  [!] SDR plugin test failed: {e}")
    
    print("\n[Testing Wi-Fi Plugin Integration]")
    try:
        from obscura.attack_plugins.wifi_attacks import check_tool_availability
        tools = ['iw', 'iwconfig', 'airmon-ng', 'aireplay-ng']
        for tool in tools:
            available = check_tool_availability(tool)
            status = "[+]" if available else "[-]"
            print(f"    {status} {tool}: {'Available' if available else 'Not found'}")
    except Exception as e:
        print(f"  [!] Wi-Fi plugin test failed: {e}")
    
    print("\n[Testing BLE Plugin Integration]")
    try:
        from obscura.attack_plugins.ble_attacks import BLEAK_AVAILABLE, BLUEPY_AVAILABLE
        print(f"    {'[+]' if BLEAK_AVAILABLE else '[-]'} Bleak library: {'Available' if BLEAK_AVAILABLE else 'Not installed'}")
        print(f"    {'[+]' if BLUEPY_AVAILABLE else '[-]'} Bluepy library: {'Available' if BLUEPY_AVAILABLE else 'Not installed'}")
    except Exception as e:
        print(f"  [!] BLE plugin test failed: {e}")
    
    print("")


def test_full_profile_generation():
    """Test full hardware profile generation."""
    print("\n" + "="*80)
    print("FULL HARDWARE PROFILE TEST")
    print("="*80)
    
    fixtures_dir = Path(__file__).parent / "fixtures"
    
    print("\n[Generating Hardware Profile]")
    profile = get_hardware_profile(fixtures_dir)
    
    print(f"\nProfile Summary:")
    print(f"  - SDR devices: {len(profile.sdr_devices)}")
    print(f"  - Wi-Fi interfaces: {len(profile.wifi_interfaces)}")
    print(f"  - BLE interfaces: {len(profile.ble_interfaces)}")
    print(f"  - Has any SDR: {profile.has_any_sdr}")
    print(f"  - Has monitor Wi-Fi: {profile.has_monitor_wifi}")
    print(f"  - Has BLE: {profile.has_ble}")
    print(f"  - Fallback mode: {profile.fallback_mode}")
    
    print("\n[Full Hardware Summary]")
    print_hardware_summary(profile)


def main():
    """Run all tests."""
    print("\n" + "="*80)
    print("OBSCURA HARDWARE ABSTRACTION COMPREHENSIVE TEST SUITE")
    print("="*80)
    
    test_command_detection()
    test_individual_detectors()
    test_fallback_mechanisms()
    test_preferred_selection()
    test_integration_with_plugins()
    test_full_profile_generation()
    
    print("\n" + "="*80)
    print("TEST SUITE COMPLETE")
    print("="*80)
    
    fixtures_dir = Path(__file__).parent / "fixtures"
    profile = get_hardware_profile(fixtures_dir)
    
    print("\n[FINAL STATUS]")
    if profile.fallback_mode:
        print("[WARNING] Fallback mode active - no hardware detected")
        print("[INFO] Attacks will use .iq fixture files (no RF emission)")
        print("[INFO] To enable hardware mode, connect SDR/Wi-Fi/BLE devices")
    else:
        print("[SUCCESS] Hardware mode active - live RF operations available")
        print(f"[INFO] Detected: {len(profile.sdr_devices)} SDR, {len(profile.wifi_interfaces)} Wi-Fi, {len(profile.ble_interfaces)} BLE")
    
    print("")


if __name__ == "__main__":
    main()
