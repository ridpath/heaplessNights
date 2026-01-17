"""
Test suite for Reporting Module

Tests Markdown report generation, JSON logging, and MITRE ATT&CK mapping.
"""

import os
import sys
import json
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from obscura.reporting import AttackReporter
from obscura.orchestrator import AttackChain, TargetTrait, AttackScore


@pytest.fixture
def sample_chain():
    """Create a sample attack chain for testing."""
    target = TargetTrait(
        device_type='drone',
        vendor='DJI',
        services=['gps', 'wifi'],
        protocols=['wifi', 'gps'],
        signal_strength=-45,
        location={'lat': 37.7749, 'lon': -122.4194}
    )
    
    scores = [
        AttackScore(
            plugin_name='gps_spoof',
            score=90.0,
            confidence=0.9,
            reason='GPS spoofing highly effective against drones',
            requirements_met=True,
            mitre_id='T1499'
        ),
        AttackScore(
            plugin_name='rf_jam',
            score=75.0,
            confidence=0.75,
            reason='RF jamming can disrupt drone communications',
            requirements_met=True,
            mitre_id='T0809'
        )
    ]
    
    chain = AttackChain(
        chain_id='test_chain_001',
        target_traits=target,
        attacks=['gps_spoof', 'rf_jam'],
        scores=scores,
        fallback_chains=[['wifi_deauth']],
        success=True,
        start_time=1000.0,
        end_time=1010.5
    )
    
    chain.execution_log = [
        {
            'attack': 'gps_spoof',
            'success': True,
            'timestamp': 1005.0,
            'execution_time': 5.0
        },
        {
            'attack': 'rf_jam',
            'success': True,
            'timestamp': 1010.5,
            'execution_time': 5.5
        }
    ]
    
    return chain


@pytest.fixture
def reporter(tmp_path):
    """Create AttackReporter instance with temp directory."""
    return AttackReporter(output_dir=str(tmp_path / 'logs'))


class TestMarkdownReportGeneration:
    """Test Markdown report generation."""
    
    def test_generate_basic_report(self, reporter, sample_chain, tmp_path):
        """Test generating basic Markdown report."""
        output_file = reporter.generate_markdown_report(sample_chain)
        
        assert os.path.exists(output_file)
        
        with open(output_file, 'r') as f:
            content = f.read()
        
        assert '# Obscura Attack Chain Report' in content
        assert 'test_chain_001' in content
        assert 'SUCCESS' in content
        assert 'DJI' in content
        assert 'drone' in content
    
    def test_report_contains_attack_details(self, reporter, sample_chain):
        """Test that report contains attack details."""
        output_file = reporter.generate_markdown_report(sample_chain)
        
        with open(output_file, 'r') as f:
            content = f.read()
        
        assert 'gps_spoof' in content
        assert 'rf_jam' in content
        assert 'Score:' in content
        assert 'Confidence:' in content
    
    def test_report_contains_mitre_mapping(self, reporter, sample_chain):
        """Test that report contains MITRE ATT&CK mapping."""
        output_file = reporter.generate_markdown_report(sample_chain)
        
        with open(output_file, 'r') as f:
            content = f.read()
        
        assert 'MITRE ATT&CK' in content
        assert 'T1499' in content
        assert 'T0809' in content
    
    def test_report_contains_execution_log(self, reporter, sample_chain):
        """Test that report contains execution log."""
        output_file = reporter.generate_markdown_report(sample_chain)
        
        with open(output_file, 'r') as f:
            content = f.read()
        
        assert 'Execution Log' in content
        assert 'Status' in content
        assert 'Execution Time' in content
    
    def test_report_contains_fallback_chains(self, reporter, sample_chain):
        """Test that report includes fallback chains."""
        output_file = reporter.generate_markdown_report(sample_chain)
        
        with open(output_file, 'r') as f:
            content = f.read()
        
        assert 'Fallback Chains' in content
        assert 'wifi_deauth' in content
    
    def test_custom_output_path(self, reporter, sample_chain, tmp_path):
        """Test specifying custom output path."""
        custom_path = tmp_path / 'custom_report.md'
        
        output_file = reporter.generate_markdown_report(
            sample_chain, 
            output_file=str(custom_path)
        )
        
        assert output_file == str(custom_path)
        assert os.path.exists(custom_path)


class TestJSONLogging:
    """Test JSON logging functionality."""
    
    def test_save_json_log(self, reporter, sample_chain):
        """Test saving attack chain as JSON."""
        output_file = reporter.save_json_log(sample_chain)
        
        assert os.path.exists(output_file)
        assert output_file.endswith('.json')
        
        with open(output_file, 'r') as f:
            data = json.load(f)
        
        assert data['chain_id'] == 'test_chain_001'
        assert data['target']['device_type'] == 'drone'
        assert data['target']['vendor'] == 'DJI'
    
    def test_json_contains_attack_data(self, reporter, sample_chain):
        """Test that JSON contains attack data."""
        output_file = reporter.save_json_log(sample_chain)
        
        with open(output_file, 'r') as f:
            data = json.load(f)
        
        assert len(data['attacks']) == 2
        assert data['attacks'][0]['name'] == 'gps_spoof'
        assert data['attacks'][0]['score'] == 90.0
        assert data['attacks'][0]['mitre_id'] == 'T1499'
    
    def test_json_contains_execution_log(self, reporter, sample_chain):
        """Test that JSON contains execution log."""
        output_file = reporter.save_json_log(sample_chain)
        
        with open(output_file, 'r') as f:
            data = json.load(f)
        
        assert len(data['execution_log']) == 2
        assert data['execution_log'][0]['attack'] == 'gps_spoof'
        assert data['execution_log'][0]['success'] is True
    
    def test_json_contains_mitre_info(self, reporter, sample_chain):
        """Test that JSON includes MITRE info."""
        output_file = reporter.save_json_log(sample_chain)
        
        with open(output_file, 'r') as f:
            data = json.load(f)
        
        for attack in data['attacks']:
            if attack['mitre_id']:
                assert 'mitre_info' in attack
                if attack['mitre_info']:
                    assert 'id' in attack['mitre_info']
                    assert 'name' in attack['mitre_info']
                    assert 'tactic' in attack['mitre_info']


class TestMITREMatrixGeneration:
    """Test MITRE ATT&CK matrix generation."""
    
    def test_generate_mitre_matrix(self, reporter, sample_chain):
        """Test generating MITRE matrix from chains."""
        matrix = reporter.generate_mitre_matrix([sample_chain])
        
        assert 'tactics' in matrix
        assert 'techniques' in matrix
        assert 'total_tactics' in matrix
        assert 'total_techniques' in matrix
        assert 'coverage_summary' in matrix
    
    def test_mitre_matrix_tactics(self, reporter, sample_chain):
        """Test MITRE matrix tactics."""
        matrix = reporter.generate_mitre_matrix([sample_chain])
        
        assert matrix['total_tactics'] > 0
        assert 'Impact' in matrix['tactics']
    
    def test_mitre_matrix_techniques(self, reporter, sample_chain):
        """Test MITRE matrix techniques."""
        matrix = reporter.generate_mitre_matrix([sample_chain])
        
        assert matrix['total_techniques'] >= 2
        assert 'T1499' in matrix['techniques']
        assert 'T0809' in matrix['techniques']
    
    def test_mitre_matrix_multiple_chains(self, reporter, sample_chain):
        """Test MITRE matrix with multiple chains."""
        chain2 = AttackChain(
            chain_id='test_chain_002',
            target_traits=sample_chain.target_traits,
            attacks=['wifi_deauth'],
            scores=[
                AttackScore(
                    plugin_name='wifi_deauth',
                    score=80.0,
                    confidence=0.8,
                    reason='Test',
                    requirements_met=True,
                    mitre_id='T1498'
                )
            ],
            success=True
        )
        
        matrix = reporter.generate_mitre_matrix([sample_chain, chain2])
        
        assert matrix['total_techniques'] >= 3
        assert 'T1498' in matrix['techniques']


class TestCampaignReporting:
    """Test campaign-level reporting."""
    
    def test_generate_campaign_report(self, reporter, sample_chain):
        """Test generating campaign report."""
        output_file = reporter.generate_campaign_report([sample_chain])
        
        assert os.path.exists(output_file)
        
        with open(output_file, 'r') as f:
            content = f.read()
        
        assert 'Obscura Campaign' in content
        assert 'Total Chains:' in content
        assert 'Successful:' in content
    
    def test_campaign_report_chain_summary(self, reporter, sample_chain):
        """Test campaign report includes chain summary."""
        output_file = reporter.generate_campaign_report([sample_chain])
        
        with open(output_file, 'r') as f:
            content = f.read()
        
        assert 'Chain Summary' in content
        assert 'test_chain_001' in content
        assert 'drone' in content
    
    def test_campaign_report_mitre_coverage(self, reporter, sample_chain):
        """Test campaign report includes MITRE coverage."""
        output_file = reporter.generate_campaign_report([sample_chain])
        
        with open(output_file, 'r') as f:
            content = f.read()
        
        assert 'MITRE ATT&CK Coverage' in content
        assert 'Tactics' in content
        assert 'Techniques' in content
    
    def test_campaign_report_custom_name(self, reporter, sample_chain):
        """Test campaign report with custom name."""
        output_file = reporter.generate_campaign_report(
            [sample_chain],
            campaign_name='Test Campaign 2024'
        )
        
        with open(output_file, 'r') as f:
            content = f.read()
        
        assert 'Test Campaign 2024' in content


class TestMITREDatabase:
    """Test MITRE ATT&CK database."""
    
    def test_mitre_db_exists(self, reporter):
        """Test that MITRE database is populated."""
        assert len(reporter.MITRE_ATTACK_DB) > 0
    
    def test_mitre_db_structure(self, reporter):
        """Test MITRE database structure."""
        for attack, info in reporter.MITRE_ATTACK_DB.items():
            assert 'id' in info
            assert 'name' in info
            assert 'tactic' in info
            assert isinstance(info['id'], str)
            assert isinstance(info['name'], str)
            assert isinstance(info['tactic'], str)
    
    def test_common_attacks_mapped(self, reporter):
        """Test that common attacks are mapped."""
        common_attacks = [
            'gps_spoof', 'camera_jam', 'wifi_deauth', 
            'rogue_ap', 'bluetooth_jam'
        ]
        
        for attack in common_attacks:
            assert attack in reporter.MITRE_ATTACK_DB


def test_reporter_integration():
    """Integration test for reporter."""
    import tempfile
    
    with tempfile.TemporaryDirectory() as tmpdir:
        reporter = AttackReporter(output_dir=tmpdir)
        
        target = TargetTrait(
            device_type='camera',
            vendor='Ring',
            services=['http', 'rtsp'],
            signal_strength=-50
        )
        
        scores = [
            AttackScore(
                plugin_name='camera_jam',
                score=85.0,
                confidence=0.85,
                reason='RF jamming effective',
                requirements_met=True,
                mitre_id='T0885'
            )
        ]
        
        chain = AttackChain(
            chain_id='integration_test',
            target_traits=target,
            attacks=['camera_jam'],
            scores=scores,
            success=True,
            start_time=1000.0,
            end_time=1005.0
        )
        
        chain.execution_log = [
            {
                'attack': 'camera_jam',
                'success': True,
                'timestamp': 1005.0,
                'execution_time': 5.0
            }
        ]
        
        md_file = reporter.generate_markdown_report(chain)
        assert os.path.exists(md_file)
        
        json_file = reporter.save_json_log(chain)
        assert os.path.exists(json_file)
        
        campaign_file = reporter.generate_campaign_report([chain])
        assert os.path.exists(campaign_file)
        
        matrix = reporter.generate_mitre_matrix([chain])
        assert matrix['total_techniques'] >= 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
