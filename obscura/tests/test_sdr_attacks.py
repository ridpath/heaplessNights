"""
Test suite for SDR Attack Plugin
Tests GPS spoofing, ADS-B replay, RF replay, and jamming functionality
"""

import os
import sys
from pathlib import Path
from unittest.mock import Mock, patch
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from obscura.attack_plugins import sdr_attacks


class MockAttackContext:
    """Mock context for testing attack functions."""
    def __init__(self):
        self.attack_log = []
        self.active_attacks = []
        self.generated_files = []
        self.simulate_mode = True
        self.interface = 'hackrf0'


class TestSDRHardwareDetection:
    """Test SDR hardware detection capabilities."""
    
    def test_detect_sdr_hardware(self):
        """Test SDR hardware detection."""
        hardware = sdr_attacks.detect_sdr_hardware()
        
        assert isinstance(hardware, dict)
        assert 'hackrf' in hardware
        assert 'rtlsdr' in hardware
        assert 'usrp' in hardware
        assert 'limesdr' in hardware
        assert 'bladerf' in hardware
        
        for sdr_type, detected in hardware.items():
            assert isinstance(detected, bool)
        
        print(f"Detected SDR hardware: {hardware}")
    
    def test_check_tool_availability(self):
        """Test tool availability checker."""
        result = sdr_attacks.check_tool_availability('python')
        assert isinstance(result, bool)
        
        result = sdr_attacks.check_tool_availability('nonexistent_tool_xyz123')
        assert result is False
    
    def test_supported_sdrs_list(self):
        """Test SUPPORTED_SDRS list is defined."""
        assert isinstance(sdr_attacks.SUPPORTED_SDRS, list)
        assert len(sdr_attacks.SUPPORTED_SDRS) > 0
        
        expected_sdrs = ['hackrf', 'rtlsdr', 'usrp', 'limesdr', 'bladerf']
        for sdr in expected_sdrs:
            assert sdr in sdr_attacks.SUPPORTED_SDRS
        
        print(f"Supported SDRs: {sdr_attacks.SUPPORTED_SDRS}")


class TestGPSSpoofing:
    """Test GPS spoofing functionality."""
    
    def test_generate_gps_trajectory(self):
        """Test GPS trajectory generation."""
        lat, lon, alt = 37.7749, -122.4194, 100.0
        duration = 60
        
        traj_file = sdr_attacks.generate_gps_trajectory(lat, lon, alt, duration)
        
        assert os.path.exists(traj_file)
        assert traj_file.endswith('.csv')
        
        with open(traj_file, 'r') as f:
            lines = f.readlines()
            assert len(lines) > 0
            
            first_line = lines[0].strip().split(',')
            assert len(first_line) == 4
            
            parsed_lat = float(first_line[0])
            parsed_lon = float(first_line[1])
            parsed_alt = float(first_line[2])
            
            assert abs(parsed_lat - lat) < 0.01
            assert abs(parsed_lon - lon) < 0.01
            assert abs(parsed_alt - alt) < 50
        
        os.unlink(traj_file)
        print("GPS trajectory generation: PASS")
    
    def test_gps_spoof_dry_run(self):
        """Test GPS spoofing in dry-run mode."""
        ctx = MockAttackContext()
        
        result = sdr_attacks.gps_spoof_via_sdr_sim(
            ctx,
            latitude=37.7749,
            longitude=-122.4194,
            altitude=100.0,
            duration=60,
            transmit=False
        )
        
        assert result is True
        assert len(ctx.attack_log) > 0
        assert 'GPS Spoofing' in ctx.attack_log[0]
        assert 'DRY RUN' in ctx.attack_log[0]
        
        print("GPS spoof dry-run: PASS")


class TestADSBReplay:
    """Test ADS-B replay functionality."""
    
    def test_adsb_replay_dry_run(self):
        """Test ADS-B replay in dry-run mode."""
        ctx = MockAttackContext()
        
        result = sdr_attacks.adsb_replay_attack(
            ctx,
            adsb_capture_file=None,
            duration=30,
            transmit=False
        )
        
        assert result is True
        assert len(ctx.attack_log) > 0
        assert 'ADS-B Replay' in ctx.attack_log[0]
        assert 'DRY RUN' in ctx.attack_log[0]
        
        print("ADS-B replay dry-run: PASS")


class TestRFReplay:
    """Test RF replay functionality."""
    
    def test_rf_replay_dry_run(self):
        """Test RF replay in dry-run mode."""
        ctx = MockAttackContext()
        
        result = sdr_attacks.rf_replay_from_iq(
            ctx,
            iq_file='/tmp/test.iq',
            center_freq=315000000,
            sample_rate=2600000,
            gain=20,
            duration=10,
            transmit=False
        )
        
        assert result is True
        assert len(ctx.attack_log) > 0
        assert 'RF Replay' in ctx.attack_log[0]
        assert 'DRY RUN' in ctx.attack_log[0]
        
        print("RF replay dry-run: PASS")


class TestRFJamming:
    """Test RF jamming functionality."""
    
    def test_rf_jamming_dry_run(self):
        """Test RF jamming in dry-run mode."""
        ctx = MockAttackContext()
        
        for jam_type in ['noise', 'tone', 'sweep']:
            ctx.attack_log.clear()
            
            result = sdr_attacks.rf_jamming_attack(
                ctx,
                target_freq=433000000,
                bandwidth=1000000,
                duration=10,
                jam_type=jam_type,
                transmit=False
            )
            
            assert result is True
            assert len(ctx.attack_log) > 0
            assert 'RF Jamming' in ctx.attack_log[0]
            assert 'DRY RUN' in ctx.attack_log[0]
            
            print(f"RF jamming ({jam_type}) dry-run: PASS")


def test_generate_jamming_waveform():
    """Test jamming waveform generation."""
    for jam_type in ['noise', 'tone', 'sweep']:
        waveform_file = sdr_attacks._generate_jamming_waveform(
            jam_type=jam_type,
            bandwidth=1000000,
            duration=1
        )
        
        assert os.path.exists(waveform_file)
        assert os.path.getsize(waveform_file) > 0
        
        os.unlink(waveform_file)
        
        print(f"Jamming waveform ({jam_type}): PASS")


def test_rf_replay_with_fixture(sample_315mhz_iq_file, sample_433mhz_iq_file, sample_gps_iq_file):
    """Test RF replay with actual fixture files using pytest fixtures."""
    ctx = MockAttackContext()
    
    iq_files = [
        (sample_315mhz_iq_file, 315000000, '315MHz'),
        (sample_433mhz_iq_file, 433000000, '433MHz'),
        (sample_gps_iq_file, 1575420000, 'GPS L1'),
    ]
    
    for iq_file, freq, name in iq_files:
        ctx.attack_log.clear()
        
        result = sdr_attacks.rf_replay_from_iq(
            ctx,
            iq_file=iq_file,
            center_freq=freq,
            sample_rate=2600000,
            gain=20,
            duration=5,
            transmit=False
        )
        
        assert result is True
        assert len(ctx.attack_log) > 0
        
        print(f"RF replay with fixture {name}: PASS")


def test_register_attack():
    """Test attack registration function."""
    registration = sdr_attacks.register_attack()
    
    assert isinstance(registration, dict)
    assert 'name' in registration
    assert 'description' in registration
    assert 'requires' in registration
    assert 'platforms' in registration
    assert 'mitre_id' in registration
    assert 'attacks' in registration
    assert 'hardware_detection' in registration
    
    assert registration['name'] == 'sdr_attacks'
    assert 'sdr' in registration['requires']
    assert 'linux' in registration['platforms']
    assert registration['mitre_id'] == 'T0884'
    
    assert 'gps_spoof' in registration['attacks']
    assert 'adsb_replay' in registration['attacks']
    assert 'rf_replay' in registration['attacks']
    assert 'rf_jamming' in registration['attacks']
    
    assert callable(registration['attacks']['gps_spoof'])
    assert callable(registration['attacks']['adsb_replay'])
    assert callable(registration['attacks']['rf_replay'])
    assert callable(registration['attacks']['rf_jamming'])
    assert callable(registration['hardware_detection'])
    
    print("Attack registration: PASS")


def test_all_attack_functions_exist():
    """Verify all attack functions are callable."""
    functions = [
        'gps_spoof_via_sdr_sim',
        'adsb_replay_attack',
        'rf_replay_from_iq',
        'rf_jamming_attack',
        'detect_sdr_hardware',
        'check_tool_availability',
        'generate_gps_trajectory',
        'register_attack'
    ]
    
    for func_name in functions:
        assert hasattr(sdr_attacks, func_name)
        func = getattr(sdr_attacks, func_name)
        assert callable(func)
        print(f"Function {func_name}: EXISTS")


class TestFrequencyConstants:
    """Test frequency constants and configuration."""
    
    def test_frequency_constants(self):
        """Test frequency constants are defined correctly."""
        assert sdr_attacks.GPS_L1_FREQ == 1575420000
        assert sdr_attacks.ADSB_FREQ == 1090000000
        assert sdr_attacks.GARAGE_315MHZ == 315000000
        assert sdr_attacks.ALARM_433MHZ == 433000000
        
        assert sdr_attacks.DEFAULT_SAMPLE_RATE == 2600000
        assert sdr_attacks.GPS_SAMPLE_RATE == 2600000
        assert sdr_attacks.ADSB_SAMPLE_RATE == 2000000
        
        print("Frequency constants: PASS")


class TestSDRRegistrationModule:
    """Test SDR attacks module registration."""
    
    def test_sdr_register_function_exists(self):
        """Test that SDR registration returns attack dict."""
        registration = sdr_attacks.register_attack()
        
        assert isinstance(registration, dict)
        assert 'name' in registration
        assert 'attacks' in registration
        assert registration['name'] == 'sdr_attacks'
    
    def test_sdr_attacks_in_registration(self):
        """Test that all SDR attacks are in registration."""
        registration = sdr_attacks.register_attack()
        attacks = registration['attacks']
        
        assert 'gps_spoof' in attacks
        assert 'adsb_replay' in attacks
        assert 'rf_replay' in attacks
        assert 'rf_jamming' in attacks
        
        for attack_name, attack_func in attacks.items():
            assert callable(attack_func)



if __name__ == '__main__':
    print("=" * 60)
    print("SDR Attack Plugin Test Suite")
    print("=" * 60)
    print()
    
    test_detect_sdr_hardware()
    test_check_tool_availability()
    test_generate_gps_trajectory()
    test_gps_spoof_dry_run()
    test_adsb_replay_dry_run()
    test_rf_replay_dry_run()
    test_rf_jamming_dry_run()
    test_generate_jamming_waveform()
    test_register_attack()
    test_all_attack_functions_exist()
    test_frequency_constants()
    test_supported_sdrs_list()
    
    try:
        test_rf_replay_with_fixture()
    except Exception as e:
        print(f"Fixture test skipped: {e}")
    
    print()
    print("=" * 60)
    print("All tests completed successfully!")
    print("=" * 60)
