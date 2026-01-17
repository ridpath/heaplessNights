#!/usr/bin/env python3
"""
Verify that Wi-Fi plugin attacks are properly registered.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'obscura'))

from obscura.attacks import AttackOrchestrator

def main():
    print("\n" + "="*60)
    print("Wi-Fi Plugin Attack Registration Verification")
    print("="*60 + "\n")
    
    orchestrator = AttackOrchestrator(
        interface="wlan0mon",
        simulate_mode=True,
        battery_saver=False
    )
    
    print("[*] Loading Wi-Fi plugin...")
    try:
        orchestrator.load_plugin('wifi_attacks')
    except Exception as e:
        print(f"[!] Failed to load plugin: {e}")
        return False
    
    print("\n[*] Checking registered Wi-Fi attack vectors:\n")
    
    wifi_attacks = [
        'wifi_deauth_scapy',
        'wifi_deauth_aireplay',
        'wifi_beacon_flood',
        'wifi_rogue_ap',
        'wifi_channel_hop'
    ]
    
    all_registered = True
    
    for attack in wifi_attacks:
        if attack in orchestrator.attack_vectors:
            print(f"  [+] {attack} - REGISTERED")
        else:
            print(f"  [!] {attack} - NOT FOUND")
            all_registered = False
    
    print("\n" + "="*60)
    
    if all_registered:
        print("[+] All Wi-Fi attacks registered successfully!")
    else:
        print("[!] Some Wi-Fi attacks were not registered")
    
    print(f"\nTotal attacks registered: {len(orchestrator.attack_vectors)}")
    print("="*60 + "\n")
    
    return all_registered


if __name__ == '__main__':
    os.environ['OBSCURA_RF_LOCK'] = '1'
    success = main()
    sys.exit(0 if success else 1)
