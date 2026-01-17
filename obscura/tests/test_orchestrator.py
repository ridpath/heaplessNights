"""
Test suite for Autonomous Orchestrator

Tests OODA loop implementation, trait-based targeting,
attack scoring, and chain generation.
"""

import os
import sys
import json
import pytest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from obscura.attacks import AttackOrchestrator
from obscura.orchestrator import (
    AutonomousOrchestrator, AttackPhase, TargetTrait, 
    AttackScore, AttackChain
)


@pytest.fixture
def mock_orchestrator():
    """Create a mock AttackOrchestrator for testing."""
    orchestrator = AttackOrchestrator(
        interface="wlan0",
        simulate_mode=True,
        battery_saver=False
    )
    orchestrator.register_default_attacks()
    return orchestrator


@pytest.fixture
def auto_orchestrator(mock_orchestrator):
    """Create an AutonomousOrchestrator for testing."""
    return AutonomousOrchestrator(
        attack_orchestrator=mock_orchestrator,
        simulate_mode=True
    )


@pytest.fixture
def test_traits_file():
    """Path to test_traits.json file."""
    return os.path.join(os.path.dirname(__file__), 'test_traits.json')


class TestTraitLoading:
    """Test trait file loading functionality."""
    
    def test_load_valid_traits(self, auto_orchestrator, test_traits_file):
        """Test loading valid traits file."""
        result = auto_orchestrator.load_traits_from_file(test_traits_file)
        assert result is True
        assert len(auto_orchestrator.trait_db) > 0
    
    def test_load_missing_file(self, auto_orchestrator):
        """Test loading non-existent file."""
        result = auto_orchestrator.load_traits_from_file('/nonexistent/file.json')
        assert result is False
    
    def test_load_invalid_json(self, auto_orchestrator, tmp_path):
        """Test loading invalid JSON."""
        invalid_file = tmp_path / "invalid.json"
        invalid_file.write_text("{invalid json")
        
        result = auto_orchestrator.load_traits_from_file(str(invalid_file))
        assert result is False


class TestObservePhase:
    """Test OBSERVE phase of OODA loop."""
    
    def test_observe_drone(self, auto_orchestrator):
        """Test observing a drone target."""
        target_data = {
            'device_type': 'drone',
            'vendor': 'DJI',
            'services': ['gps', 'wifi'],
            'protocols': ['wifi', 'gps'],
            'signal_strength': -45
        }
        
        target = auto_orchestrator.observe(target_data)
        
        assert isinstance(target, TargetTrait)
        assert target.device_type == 'drone'
        assert target.vendor == 'DJI'
        assert 'gps' in target.services
        assert target.signal_strength == -45
        assert auto_orchestrator.current_phase == AttackPhase.OBSERVE
    
    def test_observe_camera(self, auto_orchestrator):
        """Test observing a camera target."""
        target_data = {
            'device_type': 'camera',
            'vendor': 'Ring',
            'services': ['http', 'rtsp'],
            'dns_hosts': ['ring.com'],
            'signal_strength': -55
        }
        
        target = auto_orchestrator.observe(target_data)
        
        assert target.device_type == 'camera'
        assert target.vendor == 'Ring'
        assert 'rtsp' in target.services
        assert 'ring.com' in target.dns_hosts


class TestOrientPhase:
    """Test ORIENT phase of OODA loop."""
    
    def test_orient_drone_attacks(self, auto_orchestrator):
        """Test identifying attacks for drone target."""
        target = TargetTrait(
            device_type='drone',
            services=['gps', 'wifi']
        )
        
        attacks = auto_orchestrator.orient(target)
        
        assert isinstance(attacks, list)
        assert len(attacks) > 0
        assert 'gps_spoof' in attacks
        assert auto_orchestrator.current_phase == AttackPhase.ORIENT
    
    def test_orient_camera_attacks(self, auto_orchestrator):
        """Test identifying attacks for camera target."""
        target = TargetTrait(
            device_type='camera',
            services=['http', 'rtsp']
        )
        
        attacks = auto_orchestrator.orient(target)
        
        assert 'camera_jam' in attacks
        assert 'mjpeg_inject' in attacks or 'rtsp_inject' in attacks
    
    def test_orient_wifi_attacks(self, auto_orchestrator):
        """Test identifying attacks for Wi-Fi target."""
        target = TargetTrait(
            device_type='router',
            services=['http', 'dns']
        )
        
        attacks = auto_orchestrator.orient(target)
        
        assert 'wifi_deauth' in attacks
    
    def test_orient_bluetooth_attacks(self, auto_orchestrator):
        """Test identifying attacks for Bluetooth target."""
        target = TargetTrait(
            device_type='bluetooth',
            services=['bluetooth', 'a2dp']
        )
        
        attacks = auto_orchestrator.orient(target)
        
        assert 'bluetooth_jam' in attacks or 'ble_disrupt' in attacks


class TestDecidePhase:
    """Test DECIDE phase of OODA loop."""
    
    def test_decide_generates_chain(self, auto_orchestrator):
        """Test that decide phase generates attack chain."""
        target = TargetTrait(
            device_type='drone',
            services=['gps', 'wifi'],
            signal_strength=-45
        )
        
        attacks = ['gps_spoof', 'rf_jam', 'drone_jam']
        
        chain = auto_orchestrator.decide(target, attacks)
        
        assert isinstance(chain, AttackChain)
        assert len(chain.attacks) > 0
        assert len(chain.scores) > 0
        assert auto_orchestrator.current_phase == AttackPhase.DECIDE
    
    def test_attack_scoring_gps_spoof(self, auto_orchestrator):
        """Test GPS spoof scoring for drone."""
        target = TargetTrait(device_type='drone', services=['gps'], signal_strength=-45)
        
        score = auto_orchestrator._score_attack('gps_spoof', target)
        
        assert isinstance(score, AttackScore)
        assert score.score > 80.0
        assert score.confidence > 0.8
    
    def test_attack_scoring_camera_jam(self, auto_orchestrator):
        """Test camera jam scoring for camera."""
        target = TargetTrait(device_type='camera', services=['rtsp'], signal_strength=-50)
        
        score = auto_orchestrator._score_attack('camera_jam', target)
        
        assert score.score > 70.0
        assert score.confidence > 0.7
    
    def test_attack_scoring_signal_strength_bonus(self, auto_orchestrator):
        """Test signal strength affects scoring."""
        target_strong = TargetTrait(device_type='drone', signal_strength=-40)
        target_weak = TargetTrait(device_type='drone', signal_strength=-85)
        
        score_strong = auto_orchestrator._score_attack('gps_spoof', target_strong)
        score_weak = auto_orchestrator._score_attack('gps_spoof', target_weak)
        
        assert score_strong.score > score_weak.score
    
    def test_fallback_chains_generated(self, auto_orchestrator):
        """Test fallback chains are generated."""
        target = TargetTrait(device_type='camera')
        attacks = ['camera_jam', 'mjpeg_inject', 'rtsp_inject']
        
        chain = auto_orchestrator.decide(target, attacks)
        
        assert len(chain.fallback_chains) > 0


class TestActPhase:
    """Test ACT phase of OODA loop."""
    
    def test_act_executes_chain(self, auto_orchestrator):
        """Test executing attack chain."""
        target = TargetTrait(device_type='drone')
        attacks = ['gps_spoof', 'rf_jam']
        
        chain = auto_orchestrator.decide(target, attacks)
        
        result = auto_orchestrator.act(chain, max_attacks=2)
        
        assert isinstance(result, bool)
        assert chain.start_time is not None
        assert chain.end_time is not None
        assert len(chain.execution_log) > 0
        assert auto_orchestrator.current_phase == AttackPhase.ACT
    
    def test_act_respects_max_attacks(self, auto_orchestrator):
        """Test max_attacks limit is respected."""
        target = TargetTrait(device_type='drone')
        attacks = ['gps_spoof', 'rf_jam', 'drone_jam', 'camera_jam']
        
        chain = AttackChain(
            chain_id='test_chain',
            target_traits=target,
            attacks=attacks,
            scores=[]
        )
        
        auto_orchestrator.act(chain, max_attacks=2)
        
        assert len(chain.execution_log) <= 2
    
    def test_act_simulate_mode(self, auto_orchestrator):
        """Test execution in simulate mode."""
        auto_orchestrator.simulate_mode = True
        
        target = TargetTrait(device_type='camera')
        attacks = ['camera_jam']
        
        chain = AttackChain(
            chain_id='sim_chain',
            target_traits=target,
            attacks=attacks,
            scores=[]
        )
        
        auto_orchestrator.act(chain, max_attacks=1)
        
        assert len(chain.execution_log) == 1
        assert chain.execution_log[0]['attack'] == 'camera_jam'


class TestOODALoop:
    """Test full OODA loop execution."""
    
    def test_full_ooda_loop_drone(self, auto_orchestrator):
        """Test complete OODA loop for drone target."""
        target_data = {
            'device_type': 'drone',
            'vendor': 'DJI',
            'services': ['gps', 'wifi'],
            'protocols': ['wifi', 'gps'],
            'signal_strength': -45
        }
        
        chain = auto_orchestrator.run_ooda_loop(target_data, max_attacks=3)
        
        assert isinstance(chain, AttackChain)
        assert chain.target_traits.device_type == 'drone'
        assert len(chain.attacks) > 0
        assert len(chain.execution_log) > 0
    
    def test_full_ooda_loop_camera(self, auto_orchestrator):
        """Test complete OODA loop for camera target."""
        target_data = {
            'device_type': 'camera',
            'vendor': 'Ring',
            'services': ['http', 'rtsp'],
            'signal_strength': -50
        }
        
        chain = auto_orchestrator.run_ooda_loop(target_data, max_attacks=2)
        
        assert chain.target_traits.device_type == 'camera'
        assert any('camera' in attack or 'mjpeg' in attack or 'rtsp' in attack 
                  for attack in chain.attacks)


class TestExportFunctionality:
    """Test attack chain export functionality."""
    
    def test_export_chain_to_json(self, auto_orchestrator, tmp_path):
        """Test exporting chain to JSON."""
        target_data = {'device_type': 'drone', 'services': ['gps']}
        chain = auto_orchestrator.run_ooda_loop(target_data, max_attacks=1)
        
        output_file = tmp_path / "chain.json"
        result = auto_orchestrator.export_chain_to_json(chain, str(output_file))
        
        assert result is True
        assert output_file.exists()
        
        with open(output_file, 'r') as f:
            data = json.load(f)
        
        assert 'chain_id' in data
        assert 'device_type' in data
        assert 'attacks' in data
        assert 'scores' in data
    
    def test_export_chain_to_dot(self, auto_orchestrator, tmp_path):
        """Test exporting chain to DOT graph."""
        target_data = {'device_type': 'camera', 'services': ['rtsp']}
        chain = auto_orchestrator.run_ooda_loop(target_data, max_attacks=1)
        
        output_file = tmp_path / "chain.dot"
        result = auto_orchestrator.export_chain_to_dot(chain, str(output_file))
        
        assert result is True
        assert output_file.exists()
        
        content = output_file.read_text()
        assert 'digraph AttackChain' in content
        assert 'target' in content


class TestIntegrationWithTraits:
    """Integration tests using test_traits.json."""
    
    def test_load_and_execute_all_traits(self, auto_orchestrator, test_traits_file):
        """Test loading and executing against all trait types."""
        auto_orchestrator.load_traits_from_file(test_traits_file)
        
        with open(test_traits_file, 'r') as f:
            traits = json.load(f)
        
        for device_type, trait_data in list(traits.items())[:3]:
            target_data = trait_data.copy()
            target_data['device_type'] = device_type
            
            chain = auto_orchestrator.run_ooda_loop(target_data, max_attacks=2)
            
            assert chain is not None
            assert len(chain.attacks) > 0


def test_orchestrator_integration():
    """Integration test for orchestrator."""
    print("\n=== Orchestrator Integration Test ===\n")
    
    orchestrator = AttackOrchestrator(
        interface="wlan0",
        simulate_mode=True,
        battery_saver=False
    )
    orchestrator.register_default_attacks()
    
    auto_orch = AutonomousOrchestrator(
        attack_orchestrator=orchestrator,
        simulate_mode=True
    )
    
    test_targets = [
        {
            'device_type': 'drone',
            'vendor': 'DJI',
            'services': ['gps', 'wifi'],
            'signal_strength': -45
        },
        {
            'device_type': 'camera',
            'vendor': 'Ring',
            'services': ['http', 'rtsp'],
            'signal_strength': -50
        },
        {
            'device_type': 'router',
            'vendor': 'Netgear',
            'services': ['http', 'upnp'],
            'signal_strength': -40
        }
    ]
    
    for target_data in test_targets:
        print(f"Testing {target_data['device_type']}...")
        chain = auto_orch.run_ooda_loop(target_data, max_attacks=2)
        print(f"  Attacks: {', '.join(chain.attacks[:3])}")
        print(f"  Success: {chain.success}")
        print("")
    
    print("[+] Integration test completed\n")


if __name__ == '__main__':
    test_orchestrator_integration()
    pytest.main([__file__, '-v'])
