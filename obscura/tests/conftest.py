"""
Pytest configuration and shared fixtures for Obscura test suite.

Provides common fixtures for testing attack plugins, orchestrator,
and hardware abstraction in both real and simulated modes.
"""

import os
import sys
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from obscura.attacks import AttackOrchestrator
from obscura.orchestrator import AutonomousOrchestrator


@pytest.fixture(scope="session", autouse=True)
def set_rf_lock():
    """Set RF_LOCK environment variable for all tests."""
    os.environ['OBSCURA_RF_LOCK'] = '1'
    yield
    if 'OBSCURA_RF_LOCK' in os.environ:
        del os.environ['OBSCURA_RF_LOCK']


@pytest.fixture(scope="session")
def fixtures_dir():
    """Path to fixtures directory containing .iq files and test data."""
    return Path(__file__).parent.parent / 'fixtures'


@pytest.fixture(scope="session")
def test_traits_file():
    """Path to test_traits.json file."""
    return Path(__file__).parent / 'test_traits.json'


@pytest.fixture
def mock_orchestrator():
    """Create a mock AttackOrchestrator in simulate mode."""
    orchestrator = AttackOrchestrator(
        interface="wlan0",
        simulate_mode=True,
        battery_saver=False
    )
    orchestrator.register_default_attacks()
    return orchestrator


@pytest.fixture
def auto_orchestrator(mock_orchestrator):
    """Create an AutonomousOrchestrator in simulate mode."""
    return AutonomousOrchestrator(
        attack_orchestrator=mock_orchestrator,
        simulate_mode=True
    )


@pytest.fixture
def wifi_orchestrator():
    """Create AttackOrchestrator configured for Wi-Fi testing."""
    orchestrator = AttackOrchestrator(
        interface="wlan0mon",
        simulate_mode=True,
        battery_saver=False
    )
    orchestrator.register_default_attacks()
    orchestrator.load_plugin('wifi_attacks')
    return orchestrator


@pytest.fixture
def ble_orchestrator():
    """Create AttackOrchestrator configured for BLE testing."""
    orchestrator = AttackOrchestrator(
        interface="hci0",
        simulate_mode=True,
        battery_saver=False
    )
    orchestrator.register_default_attacks()
    orchestrator.load_plugin('ble_attacks')
    return orchestrator


@pytest.fixture
def sdr_orchestrator():
    """Create AttackOrchestrator configured for SDR testing."""
    orchestrator = AttackOrchestrator(
        interface="hackrf0",
        simulate_mode=True,
        battery_saver=False
    )
    orchestrator.register_default_attacks()
    orchestrator.load_plugin('sdr_attacks')
    return orchestrator


@pytest.fixture
def camera_orchestrator():
    """Create AttackOrchestrator configured for camera testing."""
    orchestrator = AttackOrchestrator(
        interface="eth0",
        simulate_mode=True,
        battery_saver=False
    )
    orchestrator.register_default_attacks()
    orchestrator.load_plugin('camera_attacks')
    return orchestrator


@pytest.fixture
def satellite_orchestrator():
    """Create AttackOrchestrator configured for satellite testing."""
    orchestrator = AttackOrchestrator(
        interface="dvb0",
        simulate_mode=True,
        battery_saver=False
    )
    orchestrator.register_default_attacks()
    orchestrator.load_plugin('satellite_attacks')
    return orchestrator


@pytest.fixture
def mock_attack_context():
    """Create a mock attack context for testing attack functions."""
    class MockContext:
        def __init__(self):
            self.attack_log = []
            self.active_attacks = []
            self.generated_files = []
            self.simulate_mode = True
            self.interface = 'test_interface'
            self.attack_vectors = {}
    
    return MockContext()


@pytest.fixture
def temp_output_dir(tmp_path):
    """Create temporary directory for test output files."""
    output_dir = tmp_path / "test_output"
    output_dir.mkdir(exist_ok=True)
    return output_dir


@pytest.fixture
def sample_gps_iq_file(fixtures_dir):
    """Path to sample GPS L1 IQ file."""
    iq_file = fixtures_dir / 'gps_l1_sample.bin'
    if not iq_file.exists():
        pytest.skip(f"GPS IQ fixture not found: {iq_file}")
    return str(iq_file)


@pytest.fixture
def sample_adsb_iq_file(fixtures_dir):
    """Path to sample ADS-B IQ file."""
    iq_file = fixtures_dir / 'adsb_sample.bin'
    if not iq_file.exists():
        pytest.skip(f"ADS-B IQ fixture not found: {iq_file}")
    return str(iq_file)


@pytest.fixture
def sample_315mhz_iq_file(fixtures_dir):
    """Path to sample 315MHz garage door IQ file."""
    iq_file = fixtures_dir / '315mhz_garage.bin'
    if not iq_file.exists():
        pytest.skip(f"315MHz IQ fixture not found: {iq_file}")
    return str(iq_file)


@pytest.fixture
def sample_433mhz_iq_file(fixtures_dir):
    """Path to sample 433MHz alarm IQ file."""
    iq_file = fixtures_dir / '433mhz_alarm.bin'
    if not iq_file.exists():
        pytest.skip(f"433MHz IQ fixture not found: {iq_file}")
    return str(iq_file)


@pytest.fixture
def sample_jamming_iq_file(fixtures_dir):
    """Path to sample noise jamming IQ file."""
    iq_file = fixtures_dir / 'noise_jamming.bin'
    if not iq_file.exists():
        pytest.skip(f"Jamming IQ fixture not found: {iq_file}")
    return str(iq_file)


@pytest.fixture
def mock_sdr_hardware():
    """Mock SDR hardware detection."""
    return {
        'hackrf': False,
        'rtlsdr': False,
        'usrp': False,
        'limesdr': False,
        'bladerf': False
    }


@pytest.fixture
def mock_wifi_interface():
    """Mock Wi-Fi interface for testing."""
    interface = Mock()
    interface.name = 'wlan0mon'
    interface.mode = 'monitor'
    interface.channel = 6
    return interface


@pytest.fixture
def mock_ble_interface():
    """Mock BLE interface for testing."""
    interface = Mock()
    interface.name = 'hci0'
    interface.powered = True
    interface.scanning = False
    return interface


def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line(
        "markers", "hardware: tests that require actual hardware (skip by default)"
    )
    config.addinivalue_line(
        "markers", "slow: tests that take a long time to run"
    )
    config.addinivalue_line(
        "markers", "integration: integration tests requiring multiple components"
    )


def pytest_collection_modifyitems(config, items):
    """Auto-skip hardware tests unless --hardware flag is provided."""
    if not config.getoption("--hardware", default=False):
        skip_hardware = pytest.mark.skip(reason="need --hardware option to run")
        for item in items:
            if "hardware" in item.keywords:
                item.add_marker(skip_hardware)


def pytest_addoption(parser):
    """Add custom pytest command-line options."""
    parser.addoption(
        "--hardware",
        action="store_true",
        default=False,
        help="run tests that require actual hardware"
    )
    parser.addoption(
        "--wsl",
        action="store_true",
        default=False,
        help="run WSL-specific integration tests"
    )
