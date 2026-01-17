"""
Test suite for BLE Attack Plugin

Tests HID spoofing, MAC rotation, GATT fuzzing, and advertising jamming.
"""

import os
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from obscura.attack_plugins import ble_attacks


class TestBLEPluginRegistration:
    """Test BLE plugin registration and interface."""
    
    def test_register_function_exists(self):
        """Test that register function exists."""
        assert hasattr(ble_attacks, 'register')
        assert callable(ble_attacks.register)
    
    def test_all_attack_functions_exist(self):
        """Test that all BLE attack functions exist."""
        expected_functions = [
            'ble_hid_spoof_keyboard',
            'ble_mac_rotation',
            'ble_gatt_fuzzing',
            'ble_advertising_jam'
        ]
        
        for func_name in expected_functions:
            assert hasattr(ble_attacks, func_name), f"{func_name} not found"
            assert callable(getattr(ble_attacks, func_name)), f"{func_name} not callable"
    
    def test_advertising_channels_constant(self):
        """Test that advertising channels constant is defined."""
        assert hasattr(ble_attacks, 'ADVERTISING_CHANNELS')
        channels = ble_attacks.ADVERTISING_CHANNELS
        assert isinstance(channels, list)
        assert len(channels) == 3
        assert 37 in channels
        assert 38 in channels
        assert 39 in channels


class TestBLEHIDSpoofing:
    """Test BLE HID keyboard spoofing."""
    
    def test_hid_spoof_dry_run(self, mock_attack_context):
        """Test HID keyboard spoofing in dry-run mode."""
        result = ble_attacks.ble_hid_spoof_keyboard(
            mock_attack_context,
            target_text="Test payload",
            interface="hci0"
        )
        
        assert result is True
        assert len(mock_attack_context.attack_log) > 0
    
    def test_hid_spoof_long_payload(self, mock_attack_context):
        """Test HID spoofing with longer payload."""
        long_text = "This is a much longer test payload " * 10
        
        result = ble_attacks.ble_hid_spoof_keyboard(
            mock_attack_context,
            target_text=long_text,
            interface="hci0"
        )
        
        assert result is True
    
    def test_hid_spoof_special_chars(self, mock_attack_context):
        """Test HID spoofing with special characters."""
        special_text = "Test!@#$%^&*()_+-={}[]|:;<>?,./~`"
        
        result = ble_attacks.ble_hid_spoof_keyboard(
            mock_attack_context,
            target_text=special_text,
            interface="hci0"
        )
        
        assert result is True


class TestBLEMACRotation:
    """Test BLE MAC address rotation."""
    
    def test_mac_rotation_dry_run(self, mock_attack_context):
        """Test MAC rotation in dry-run mode."""
        result = ble_attacks.ble_mac_rotation(
            mock_attack_context,
            interface="hci0",
            rotation_interval=10,
            duration=30
        )
        
        assert result is True
        assert len(mock_attack_context.attack_log) > 0
    
    def test_mac_rotation_short_interval(self, mock_attack_context):
        """Test MAC rotation with short interval."""
        result = ble_attacks.ble_mac_rotation(
            mock_attack_context,
            interface="hci0",
            rotation_interval=5,
            duration=20
        )
        
        assert result is True
    
    def test_mac_rotation_long_duration(self, mock_attack_context):
        """Test MAC rotation with longer duration."""
        result = ble_attacks.ble_mac_rotation(
            mock_attack_context,
            interface="hci0",
            rotation_interval=15,
            duration=60
        )
        
        assert result is True


class TestBLEGATTFuzzing:
    """Test BLE GATT profile fuzzing."""
    
    def test_gatt_fuzzing_dry_run(self, mock_attack_context):
        """Test GATT fuzzing in dry-run mode."""
        result = ble_attacks.ble_gatt_fuzzing(
            mock_attack_context,
            target_device=None,
            service_uuid=None,
            use_llm_assist=False,
            fuzz_iterations=50
        )
        
        assert result is True
        assert len(mock_attack_context.attack_log) > 0
    
    def test_gatt_fuzzing_with_llm(self, mock_attack_context):
        """Test GATT fuzzing with LLM assistance."""
        result = ble_attacks.ble_gatt_fuzzing(
            mock_attack_context,
            target_device=None,
            service_uuid=None,
            use_llm_assist=True,
            fuzz_iterations=25
        )
        
        assert result is True
    
    def test_gatt_fuzzing_specific_service(self, mock_attack_context):
        """Test GATT fuzzing with specific service UUID."""
        result = ble_attacks.ble_gatt_fuzzing(
            mock_attack_context,
            target_device="AA:BB:CC:DD:EE:FF",
            service_uuid="0000180f-0000-1000-8000-00805f9b34fb",
            use_llm_assist=False,
            fuzz_iterations=30
        )
        
        assert result is True


class TestBLEAdvertisingJam:
    """Test BLE advertising channel jamming."""
    
    def test_advertising_jam_dry_run(self, mock_attack_context):
        """Test advertising jamming in dry-run mode."""
        result = ble_attacks.ble_advertising_jam(
            mock_attack_context,
            interface="hci0",
            duration=10,
            channels=[37, 38, 39]
        )
        
        assert result is True
        assert len(mock_attack_context.attack_log) > 0
    
    def test_advertising_jam_single_channel(self, mock_attack_context):
        """Test jamming single advertising channel."""
        result = ble_attacks.ble_advertising_jam(
            mock_attack_context,
            interface="hci0",
            duration=15,
            channels=[37]
        )
        
        assert result is True
    
    def test_advertising_jam_all_channels(self, mock_attack_context):
        """Test jamming all advertising channels."""
        result = ble_attacks.ble_advertising_jam(
            mock_attack_context,
            interface="hci0",
            duration=20,
            channels=[37, 38, 39]
        )
        
        assert result is True


class TestBLEUtilities:
    """Test BLE utility functions."""
    
    def test_generate_random_mac(self):
        """Test random MAC address generation."""
        mac = ble_attacks.generate_random_mac()
        
        assert isinstance(mac, str)
        assert len(mac.split(':')) == 6
        
        for octet in mac.split(':'):
            assert len(octet) == 2
            int(octet, 16)
    
    def test_tool_availability_check(self):
        """Test tool availability checking."""
        result = ble_attacks.check_tool_availability('python')
        assert isinstance(result, bool)
    
    def test_advertising_channels_constant(self):
        """Test advertising channel constant."""
        assert hasattr(ble_attacks, 'ADVERTISING_CHANNELS')
        channels = ble_attacks.ADVERTISING_CHANNELS
        
        assert isinstance(channels, list)
        assert len(channels) == 3
        assert 37 in channels
        assert 38 in channels
        assert 39 in channels


class TestBLEOrchestratorIntegration:
    """Integration tests with AttackOrchestrator."""
    
    def test_plugin_loads_in_orchestrator(self, ble_orchestrator):
        """Test that BLE plugin loads successfully."""
        assert 'ble_hid_spoof_keyboard' in ble_orchestrator.attack_vectors
        assert 'ble_mac_rotation' in ble_orchestrator.attack_vectors
        assert 'ble_gatt_fuzzing' in ble_orchestrator.attack_vectors
        assert 'ble_advertising_jam' in ble_orchestrator.attack_vectors
    
    def test_execute_hid_spoof_via_orchestrator(self, ble_orchestrator):
        """Test executing HID spoof via orchestrator."""
        attack_func = ble_orchestrator.attack_vectors['ble_hid_spoof_keyboard']
        
        result = attack_func(
            ble_orchestrator,
            target_text="Test",
            interface="hci0"
        )
        
        assert result is True
    
    def test_execute_mac_rotation_via_orchestrator(self, ble_orchestrator):
        """Test executing MAC rotation via orchestrator."""
        attack_func = ble_orchestrator.attack_vectors['ble_mac_rotation']
        
        result = attack_func(
            ble_orchestrator,
            interface="hci0",
            rotation_interval=10,
            duration=20
        )
        
        assert result is True
    
    def test_execute_gatt_fuzzing_via_orchestrator(self, ble_orchestrator):
        """Test executing GATT fuzzing via orchestrator."""
        attack_func = ble_orchestrator.attack_vectors['ble_gatt_fuzzing']
        
        result = attack_func(
            ble_orchestrator,
            target_device=None,
            service_uuid=None,
            use_llm_assist=False,
            fuzz_iterations=10
        )
        
        assert result is True
    
    def test_execute_advertising_jam_via_orchestrator(self, ble_orchestrator):
        """Test executing advertising jam via orchestrator."""
        attack_func = ble_orchestrator.attack_vectors['ble_advertising_jam']
        
        result = attack_func(
            ble_orchestrator,
            interface="hci0",
            duration=5,
            channels=[37, 38, 39]
        )
        
        assert result is True


def test_ble_plugin_standalone():
    """Standalone integration test for BLE plugin."""
    os.environ['OBSCURA_RF_LOCK'] = '1'
    
    from obscura.attacks import AttackOrchestrator
    
    orchestrator = AttackOrchestrator(
        interface="hci0",
        simulate_mode=True,
        battery_saver=False
    )
    
    orchestrator.register_default_attacks()
    orchestrator.load_plugin('ble_attacks')
    
    tests = [
        ('ble_hid_spoof_keyboard', {'target_text': 'Test', 'interface': 'hci0'}),
        ('ble_mac_rotation', {'interface': 'hci0', 'rotation_interval': 10, 'duration': 20}),
        ('ble_gatt_fuzzing', {'target_device': None, 'service_uuid': None, 'use_llm_assist': False, 'fuzz_iterations': 10}),
        ('ble_advertising_jam', {'interface': 'hci0', 'duration': 5, 'channels': [37, 38, 39]}),
    ]
    
    for attack_name, kwargs in tests:
        attack_func = orchestrator.attack_vectors[attack_name]
        result = attack_func(orchestrator, **kwargs)
        assert result is True, f"{attack_name} failed"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
