"""
Test suite for Wi-Fi Attack Plugin

Tests deauth, beacon flood, rogue AP, and channel hopping functionality
in both 2.4GHz and 5GHz bands.
"""

import os
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from obscura.attack_plugins import wifi_attacks


class TestWiFiPluginRegistration:
    """Test Wi-Fi plugin registration and interface."""
    
    def test_register_function_exists(self):
        """Test that register function exists."""
        assert hasattr(wifi_attacks, 'register')
        assert callable(wifi_attacks.register)
    
    def test_all_attack_functions_exist(self):
        """Test that all Wi-Fi attack functions exist."""
        expected_functions = [
            'wifi_deauth_scapy',
            'wifi_deauth_aireplay',
            'wifi_beacon_flood',
            'wifi_rogue_ap',
            'wifi_channel_hop'
        ]
        
        for func_name in expected_functions:
            assert hasattr(wifi_attacks, func_name), f"{func_name} not found"
            assert callable(getattr(wifi_attacks, func_name)), f"{func_name} not callable"
    
    def test_channel_constants_defined(self):
        """Test that channel constants are defined."""
        assert hasattr(wifi_attacks, 'CHANNELS_2_4GHZ')
        assert hasattr(wifi_attacks, 'CHANNELS_5GHZ')
        assert isinstance(wifi_attacks.CHANNELS_2_4GHZ, list)
        assert isinstance(wifi_attacks.CHANNELS_5GHZ, list)
        assert len(wifi_attacks.CHANNELS_2_4GHZ) > 0
        assert len(wifi_attacks.CHANNELS_5GHZ) > 0


class TestWiFiDeauthScapy:
    """Test Wi-Fi deauth using Scapy."""
    
    def test_deauth_scapy_dry_run(self, mock_attack_context):
        """Test Scapy deauth in dry-run mode."""
        result = wifi_attacks.wifi_deauth_scapy(
            mock_attack_context,
            target_bssid='00:11:22:33:44:55',
            client_mac='AA:BB:CC:DD:EE:FF',
            count=50,
            interface='wlan0mon'
        )
        
        assert result is True
        assert len(mock_attack_context.attack_log) > 0
    
    def test_deauth_scapy_broadcast(self, mock_attack_context):
        """Test Scapy deauth with broadcast client."""
        result = wifi_attacks.wifi_deauth_scapy(
            mock_attack_context,
            target_bssid='00:11:22:33:44:55',
            client_mac='FF:FF:FF:FF:FF:FF',
            count=25,
            interface='wlan0mon'
        )
        
        assert result is True


class TestWiFiDeauthAireplay:
    """Test Wi-Fi deauth using aireplay-ng."""
    
    def test_deauth_aireplay_dry_run(self, mock_attack_context):
        """Test aireplay-ng deauth in dry-run mode."""
        result = wifi_attacks.wifi_deauth_aireplay(
            mock_attack_context,
            target_bssid='00:11:22:33:44:55',
            count=10,
            interface='wlan0mon'
        )
        
        assert result is True
        assert len(mock_attack_context.attack_log) > 0


class TestWiFiBeaconFlood:
    """Test Wi-Fi beacon flood attack."""
    
    def test_beacon_flood_dry_run(self, mock_attack_context):
        """Test beacon flood in dry-run mode."""
        result = wifi_attacks.wifi_beacon_flood(
            mock_attack_context,
            count=25,
            channel=6,
            interface='wlan0mon'
        )
        
        assert result is True
        assert len(mock_attack_context.attack_log) > 0
    
    def test_beacon_flood_5ghz(self, mock_attack_context):
        """Test beacon flood on 5GHz channel."""
        result = wifi_attacks.wifi_beacon_flood(
            mock_attack_context,
            count=20,
            channel=36,
            interface='wlan0mon'
        )
        
        assert result is True


class TestWiFiRogueAP:
    """Test Wi-Fi rogue access point."""
    
    def test_rogue_ap_dry_run(self, mock_attack_context):
        """Test rogue AP in dry-run mode."""
        result = wifi_attacks.wifi_rogue_ap(
            mock_attack_context,
            ssid='Test_Free_WiFi',
            channel=11,
            interface='wlan0',
            duration=10
        )
        
        assert result is True
        assert len(mock_attack_context.attack_log) > 0
    
    def test_rogue_ap_custom_parameters(self, mock_attack_context):
        """Test rogue AP with custom parameters."""
        result = wifi_attacks.wifi_rogue_ap(
            mock_attack_context,
            ssid='SecureNetwork',
            channel=6,
            interface='wlan0',
            duration=15
        )
        
        assert result is True


class TestWiFiChannelHopping:
    """Test Wi-Fi channel hopping."""
    
    def test_channel_hop_auto(self, mock_attack_context):
        """Test channel hopping with auto band selection."""
        result = wifi_attacks.wifi_channel_hop(
            mock_attack_context,
            interface='wlan0mon',
            duration=20,
            hop_interval=1.0,
            band='auto'
        )
        
        assert result is True
        assert len(mock_attack_context.attack_log) > 0
    
    def test_channel_hop_2_4ghz(self, mock_attack_context):
        """Test channel hopping on 2.4GHz only."""
        result = wifi_attacks.wifi_channel_hop(
            mock_attack_context,
            interface='wlan0mon',
            duration=15,
            hop_interval=1.5,
            band='2.4'
        )
        
        assert result is True
    
    def test_channel_hop_5ghz(self, mock_attack_context):
        """Test channel hopping on 5GHz only."""
        result = wifi_attacks.wifi_channel_hop(
            mock_attack_context,
            interface='wlan0mon',
            duration=15,
            hop_interval=1.5,
            band='5'
        )
        
        assert result is True


class TestWiFiUtilities:
    """Test Wi-Fi utility functions."""
    
    def test_tool_availability_check(self):
        """Test tool availability checking."""
        result = wifi_attacks.check_tool_availability('python')
        assert isinstance(result, bool)
    
    def test_channel_constants(self):
        """Test channel constants."""
        assert wifi_attacks.CHANNELS_2_4GHZ == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
        assert len(wifi_attacks.CHANNELS_5GHZ) > 0
        assert 36 in wifi_attacks.CHANNELS_5GHZ


class TestWiFiOrchestratorIntegration:
    """Integration tests with AttackOrchestrator."""
    
    def test_plugin_loads_in_orchestrator(self, wifi_orchestrator):
        """Test that Wi-Fi plugin loads successfully."""
        assert 'wifi_deauth_scapy' in wifi_orchestrator.attack_vectors
        assert 'wifi_deauth_aireplay' in wifi_orchestrator.attack_vectors
        assert 'wifi_beacon_flood' in wifi_orchestrator.attack_vectors
        assert 'wifi_rogue_ap' in wifi_orchestrator.attack_vectors
        assert 'wifi_channel_hop' in wifi_orchestrator.attack_vectors
    
    def test_execute_deauth_via_orchestrator(self, wifi_orchestrator):
        """Test executing deauth via orchestrator."""
        attack_func = wifi_orchestrator.attack_vectors['wifi_deauth_scapy']
        
        result = attack_func(
            wifi_orchestrator,
            target_bssid='00:11:22:33:44:55',
            client_mac='AA:BB:CC:DD:EE:FF',
            count=10
        )
        
        assert result is True
    
    def test_execute_beacon_flood_via_orchestrator(self, wifi_orchestrator):
        """Test executing beacon flood via orchestrator."""
        attack_func = wifi_orchestrator.attack_vectors['wifi_beacon_flood']
        
        result = attack_func(
            wifi_orchestrator,
            count=15,
            channel=6
        )
        
        assert result is True


def test_wifi_plugin_standalone():
    """Standalone integration test for Wi-Fi plugin."""
    os.environ['OBSCURA_RF_LOCK'] = '1'
    
    from obscura.attacks import AttackOrchestrator
    
    orchestrator = AttackOrchestrator(
        interface="wlan0mon",
        simulate_mode=True,
        battery_saver=False
    )
    
    orchestrator.register_default_attacks()
    orchestrator.load_plugin('wifi_attacks')
    
    tests = [
        ('wifi_deauth_scapy', {'target_bssid': '00:11:22:33:44:55', 'client_mac': 'AA:BB:CC:DD:EE:FF', 'count': 10}),
        ('wifi_deauth_aireplay', {'target_bssid': '00:11:22:33:44:55', 'count': 5}),
        ('wifi_beacon_flood', {'count': 15, 'channel': 6}),
        ('wifi_rogue_ap', {'ssid': 'Test_WiFi', 'channel': 11, 'duration': 5}),
        ('wifi_channel_hop', {'duration': 10, 'hop_interval': 1.0, 'band': 'auto'}),
    ]
    
    for attack_name, kwargs in tests:
        attack_func = orchestrator.attack_vectors[attack_name]
        result = attack_func(orchestrator, **kwargs)
        assert result is True, f"{attack_name} failed"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
