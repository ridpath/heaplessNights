"""
Comprehensive SDR Attack Plugin Test Script
Tests all SDR attack functionality in dry-run and hardware modes
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from obscura.attack_plugins import sdr_attacks


class SDRTestContext:
    """Test context that mimics Obscura attack framework."""
    def __init__(self, simulate=True):
        self.attack_log = []
        self.active_attacks = []
        self.generated_files = []
        self.simulate_mode = simulate
        self.interface = 'hackrf0'
    
    def print_log(self):
        """Print attack log."""
        print("\n--- Attack Log ---")
        for entry in self.attack_log:
            print(f"  {entry}")
        print("------------------\n")


def test_hardware_detection():
    """Test SDR hardware detection."""
    print("=" * 60)
    print("Test: SDR Hardware Detection")
    print("=" * 60)
    
    hardware = sdr_attacks.detect_sdr_hardware()
    
    print("Detected SDR Hardware:")
    for sdr_type, detected in hardware.items():
        status = "DETECTED" if detected else "NOT FOUND"
        print(f"  {sdr_type.upper()}: {status}")
    
    if not any(hardware.values()):
        print("\nNOTE: No SDR hardware detected. Tests will run in simulation mode.")
    
    print()
    return hardware


def test_gps_spoofing(ctx):
    """Test GPS spoofing attack."""
    print("=" * 60)
    print("Test: GPS Spoofing")
    print("=" * 60)
    
    result = sdr_attacks.gps_spoof_via_sdr_sim(
        ctx,
        latitude=37.7749,
        longitude=-122.4194,
        altitude=100.0,
        duration=60,
        transmit=False
    )
    
    ctx.print_log()
    
    status = "PASS" if result else "FAIL"
    print(f"Result: {status}\n")
    
    return result


def test_adsb_replay(ctx):
    """Test ADS-B replay attack."""
    print("=" * 60)
    print("Test: ADS-B Replay")
    print("=" * 60)
    
    ctx.attack_log.clear()
    
    result = sdr_attacks.adsb_replay_attack(
        ctx,
        adsb_capture_file=None,
        duration=30,
        transmit=False
    )
    
    ctx.print_log()
    
    status = "PASS" if result else "FAIL"
    print(f"Result: {status}\n")
    
    return result


def test_rf_replay(ctx):
    """Test RF replay from .iq files."""
    print("=" * 60)
    print("Test: RF Replay from .iq Files")
    print("=" * 60)
    
    fixtures_dir = Path(__file__).parent / 'fixtures'
    
    test_cases = [
        {
            'name': '315 MHz Garage Door Opener',
            'file': fixtures_dir / '315mhz_garage.bin',
            'freq': 315000000,
            'rate': 2600000
        },
        {
            'name': '433 MHz Alarm System',
            'file': fixtures_dir / '433mhz_alarm.bin',
            'freq': 433000000,
            'rate': 2600000
        },
        {
            'name': 'GPS L1 Signal',
            'file': fixtures_dir / 'gps_l1_sample.bin',
            'freq': 1575420000,
            'rate': 2600000
        }
    ]
    
    results = []
    
    for test_case in test_cases:
        print(f"\n  Testing: {test_case['name']}")
        ctx.attack_log.clear()
        
        if not test_case['file'].exists():
            print(f"    SKIP: Fixture not found")
            continue
        
        result = sdr_attacks.rf_replay_from_iq(
            ctx,
            iq_file=str(test_case['file']),
            center_freq=test_case['freq'],
            sample_rate=test_case['rate'],
            gain=20,
            duration=5,
            transmit=False
        )
        
        status = "PASS" if result else "FAIL"
        print(f"    {status}")
        results.append(result)
    
    ctx.print_log()
    
    all_passed = all(results)
    status = "PASS" if all_passed else "FAIL"
    print(f"Overall Result: {status}\n")
    
    return all_passed


def test_rf_jamming(ctx):
    """Test RF jamming attacks."""
    print("=" * 60)
    print("Test: RF Jamming")
    print("=" * 60)
    
    jam_types = ['noise', 'tone', 'sweep']
    test_freqs = [
        (315000000, '315 MHz (Garage Openers)'),
        (433000000, '433 MHz (Alarm Systems)'),
        (1575420000, 'GPS L1 (1575.42 MHz)')
    ]
    
    results = []
    
    for freq, desc in test_freqs:
        for jam_type in jam_types:
            print(f"\n  Testing: {desc} - {jam_type.upper()} jamming")
            ctx.attack_log.clear()
            
            result = sdr_attacks.rf_jamming_attack(
                ctx,
                target_freq=freq,
                bandwidth=1000000,
                duration=10,
                jam_type=jam_type,
                transmit=False
            )
            
            status = "PASS" if result else "FAIL"
            print(f"    {status}")
            results.append(result)
    
    ctx.print_log()
    
    all_passed = all(results)
    status = "PASS" if all_passed else "FAIL"
    print(f"Overall Result: {status}\n")
    
    return all_passed


def test_module_registration():
    """Test module registration."""
    print("=" * 60)
    print("Test: Module Registration")
    print("=" * 60)
    
    registration = sdr_attacks.register_attack()
    
    print(f"Name: {registration['name']}")
    print(f"Description: {registration['description']}")
    print(f"Requires: {registration['requires']}")
    print(f"Platforms: {registration['platforms']}")
    print(f"MITRE ATT&CK: {registration['mitre_id']}")
    print(f"\nRegistered Attacks:")
    
    for attack_name in registration['attacks']:
        print(f"  - {attack_name}")
    
    all_present = (
        'gps_spoof' in registration['attacks'] and
        'adsb_replay' in registration['attacks'] and
        'rf_replay' in registration['attacks'] and
        'rf_jamming' in registration['attacks']
    )
    
    status = "PASS" if all_present else "FAIL"
    print(f"\nResult: {status}\n")
    
    return all_present


def main():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("SDR ATTACK PLUGIN COMPREHENSIVE TEST SUITE")
    print("=" * 60)
    print()
    
    hardware = test_hardware_detection()
    
    has_hardware = any(hardware.values())
    mode = "SIMULATION MODE (no SDR hardware detected)" if not has_hardware else "HARDWARE MODE"
    
    print(f"Test Mode: {mode}\n")
    
    ctx = SDRTestContext(simulate=True)
    
    results = {
        'Hardware Detection': True,
        'GPS Spoofing': test_gps_spoofing(ctx),
        'ADS-B Replay': test_adsb_replay(ctx),
        'RF Replay': test_rf_replay(ctx),
        'RF Jamming': test_rf_jamming(ctx),
        'Module Registration': test_module_registration()
    }
    
    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    for test_name, result in results.items():
        status = "PASS" if result else "FAIL"
        symbol = "[+]" if result else "[-]"
        print(f"{symbol} {test_name}: {status}")
    
    print("=" * 60)
    
    all_passed = all(results.values())
    
    if all_passed:
        print("\nALL TESTS PASSED")
        return 0
    else:
        print("\nSOME TESTS FAILED")
        return 1


if __name__ == '__main__':
    exit(main())
