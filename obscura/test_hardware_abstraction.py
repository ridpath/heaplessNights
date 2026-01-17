"""
Hardware Abstraction Testing Script

Tests hardware detection and fallback mechanisms.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'obscura'))

from obscura.hardware import (
    get_hardware_profile,
    print_hardware_summary,
    get_preferred_sdr,
    get_preferred_wifi_interface,
    get_preferred_ble_interface,
    find_iq_fixtures
)
from pathlib import Path


def test_hardware_detection():
    """Test hardware detection."""
    print("\n" + "="*80)
    print("HARDWARE ABSTRACTION LAYER TEST")
    print("="*80)
    
    fixtures_dir = Path(__file__).parent / "fixtures"
    
    print(f"\n[1] Testing hardware profile generation...")
    profile = get_hardware_profile(fixtures_dir)
    
    print(f"    - SDR devices detected: {len(profile.sdr_devices)}")
    print(f"    - Wi-Fi interfaces detected: {len(profile.wifi_interfaces)}")
    print(f"    - BLE interfaces detected: {len(profile.ble_interfaces)}")
    print(f"    - Fallback mode: {profile.fallback_mode}")
    
    print(f"\n[2] Printing hardware summary...")
    print_hardware_summary(profile)
    
    print(f"\n[3] Testing preferred device selection...")
    
    preferred_sdr = get_preferred_sdr(profile)
    if preferred_sdr:
        print(f"    [+] Preferred SDR: {preferred_sdr.name} ({preferred_sdr.device_type})")
    else:
        print(f"    [-] No SDR available (fallback mode)")
    
    preferred_wifi = get_preferred_wifi_interface(profile)
    if preferred_wifi:
        print(f"    [+] Preferred Wi-Fi: {preferred_wifi.name} ({preferred_wifi.mac})")
        print(f"        Monitor capable: {preferred_wifi.monitor_capable}")
        print(f"        Monitor active: {preferred_wifi.monitor_active}")
    else:
        print(f"    [-] No Wi-Fi interface available")
    
    preferred_ble = get_preferred_ble_interface(profile)
    if preferred_ble:
        print(f"    [+] Preferred BLE: {preferred_ble.name} ({preferred_ble.mac})")
    else:
        print(f"    [-] No BLE interface available")
    
    print(f"\n[4] Testing .iq fixture detection...")
    iq_files = find_iq_fixtures(fixtures_dir)
    print(f"    Found {len(iq_files)} .iq fixture files:")
    for iq_file in iq_files:
        print(f"      - {iq_file.name} ({iq_file.stat().st_size} bytes)")
    
    print(f"\n[5] Testing preferred SDR type selection...")
    for sdr_type in ['hackrf', 'rtlsdr', 'usrp', 'limesdr', 'bladerf']:
        preferred = get_preferred_sdr(profile, preferred_type=sdr_type)
        if preferred:
            print(f"    [+] Preferred {sdr_type}: {preferred.name}")
    
    print("\n" + "="*80)
    print("HARDWARE DETECTION RESULTS")
    print("="*80)
    
    if profile.has_any_sdr:
        print("[+] SDR hardware available - live RF operations enabled")
    else:
        print("[-] No SDR hardware - fallback to .iq fixtures")
    
    if profile.has_monitor_wifi:
        print("[+] Monitor-capable Wi-Fi interface available")
    else:
        print("[-] No monitor-capable Wi-Fi interface")
    
    if profile.has_ble:
        print("[+] BLE interface available")
    else:
        print("[-] No BLE interface")
    
    print("\n" + "="*80)
    print("TEST COMPLETE")
    print("="*80 + "\n")
    
    return profile


if __name__ == "__main__":
    profile = test_hardware_detection()
    
    if profile.fallback_mode:
        print("\n[WARNING] Fallback mode active - attacks will use simulated data")
        print("[INFO] To enable hardware mode, ensure SDR devices are connected")
    else:
        print("\n[SUCCESS] Hardware mode active - live RF operations available")
