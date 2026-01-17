# Obscura Test Suite

Comprehensive test suite for the Obscura multi-vector adversarial orchestration framework.

## Test Structure

```
tests/
├── conftest.py              # Pytest configuration and shared fixtures
├── test_wifi.py             # Wi-Fi attack plugin tests
├── test_ble.py              # BLE attack plugin tests
├── test_sdr_attacks.py      # SDR attack plugin tests
├── test_orchestrator.py     # Autonomous orchestrator tests
├── test_traits.json         # Test trait definitions
└── README.md                # This file
```

## Running Tests

### Basic Usage

Run all tests:
```bash
pytest
```

Run specific test file:
```bash
pytest tests/test_wifi.py
```

Run specific test class:
```bash
pytest tests/test_wifi.py::TestWiFiPluginRegistration
```

Run specific test:
```bash
pytest tests/test_wifi.py::TestWiFiPluginRegistration::test_register_attack_returns_dict
```

### Test Markers

Skip hardware tests (default):
```bash
pytest
```

Include hardware tests:
```bash
pytest --hardware
```

Run only integration tests:
```bash
pytest -m integration
```

Skip slow tests:
```bash
pytest -m "not slow"
```

WSL-specific tests:
```bash
pytest -m wsl --wsl
```

### Output Options

Verbose output:
```bash
pytest -v
```

Show print statements:
```bash
pytest -s
```

Stop on first failure:
```bash
pytest -x
```

Show test coverage:
```bash
pytest --cov=obscura --cov-report=html
```

### Parallel Execution

Run tests in parallel (requires pytest-xdist):
```bash
pytest -n auto
```

## Test Fixtures

### Common Fixtures (from conftest.py)

- `set_rf_lock`: Sets OBSCURA_RF_LOCK environment variable
- `fixtures_dir`: Path to fixtures directory with .iq files
- `test_traits_file`: Path to test_traits.json
- `mock_orchestrator`: Mock AttackOrchestrator in simulate mode
- `auto_orchestrator`: AutonomousOrchestrator in simulate mode
- `wifi_orchestrator`: AttackOrchestrator with Wi-Fi plugin loaded
- `ble_orchestrator`: AttackOrchestrator with BLE plugin loaded
- `sdr_orchestrator`: AttackOrchestrator with SDR plugin loaded
- `camera_orchestrator`: AttackOrchestrator with camera plugin loaded
- `satellite_orchestrator`: AttackOrchestrator with satellite plugin loaded
- `mock_attack_context`: Mock context for testing attack functions
- `temp_output_dir`: Temporary directory for test outputs
- `sample_gps_iq_file`: Path to GPS L1 sample IQ file
- `sample_adsb_iq_file`: Path to ADS-B sample IQ file
- `sample_315mhz_iq_file`: Path to 315MHz sample IQ file
- `sample_433mhz_iq_file`: Path to 433MHz sample IQ file
- `sample_jamming_iq_file`: Path to noise jamming sample IQ file

## Test Categories

### Plugin Tests

**test_wifi.py**
- Wi-Fi plugin registration
- Deauth attacks (Scapy and aireplay-ng)
- Beacon flooding
- Rogue AP setup
- Channel hopping (2.4GHz, 5GHz, auto)

**test_ble.py**
- BLE plugin registration
- HID keyboard spoofing
- MAC address rotation
- GATT profile fuzzing
- Advertising channel jamming

**test_sdr_attacks.py**
- SDR hardware detection
- GPS spoofing via gps-sdr-sim
- ADS-B replay attacks
- RF replay from .iq files
- RF jamming (noise, tone, sweep)
- Frequency constants validation

### Orchestrator Tests

**test_orchestrator.py**
- Trait file loading
- OODA loop phases (Observe, Orient, Decide, Act)
- Attack scoring algorithms
- Attack chain generation
- Fallback chain generation
- Export to JSON and DOT formats
- Integration with trait database

## Fixtures Directory

The fixtures/ directory contains sample IQ files for testing SDR attacks:

- `315mhz_garage.bin`: 315MHz garage door opener signal
- `433mhz_alarm.bin`: 433MHz alarm system signal
- `gps_l1_sample.bin`: GPS L1 frequency sample
- `adsb_sample.bin`: ADS-B aircraft transponder signal
- `noise_jamming.bin`: White noise jamming waveform

These files are auto-generated if missing by `fixtures/generate_test_iq.py`.

## Safety Requirements

All tests run with OBSCURA_RF_LOCK=1 set automatically.
All attacks execute in simulate mode unless --hardware flag is used.
No actual RF emissions occur during normal test runs.

## WSL Testing

Tests are designed to work in WSL2 environment:

```bash
cd ~/obscura
pytest --wsl
```

Access WSL from Windows:
```
\\wsl.localhost\parrot
```

## Continuous Integration

For CI/CD pipelines:

```bash
pytest --cov=obscura --cov-report=xml --junitxml=test-results.xml
```

## Troubleshooting

**ImportError: No module named 'obscura'**
- Ensure you're in the project root directory
- Verify virtual environment is activated: `source .venv/bin/activate` (Linux) or `.venv\Scripts\activate` (Windows)

**Fixture files missing**
- Run: `python fixtures/generate_test_iq.py`
- Or: `pytest` will skip tests requiring missing fixtures

**Hardware tests failing**
- Hardware tests require actual SDR/Wi-Fi/BLE hardware
- Run without --hardware flag to skip hardware-dependent tests

**RF_LOCK errors**
- conftest.py sets this automatically
- If errors persist, manually set: `export OBSCURA_RF_LOCK=1`

## Writing New Tests

Template for new test file:

```python
"""
Test suite for NewPlugin

Description of what this plugin tests.
"""

import os
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from obscura.attack_plugins import new_plugin


class TestNewPluginRegistration:
    """Test plugin registration."""
    
    def test_register_attack_returns_dict(self):
        registration = new_plugin.register_attack()
        assert isinstance(registration, dict)


class TestNewPluginAttacks:
    """Test attack functions."""
    
    def test_attack_dry_run(self, mock_attack_context):
        result = new_plugin.some_attack(mock_attack_context)
        assert result is True


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
```

## Test Expectations

- All tests must pass in simulate mode without hardware
- Hardware tests must be marked with @pytest.mark.hardware
- All plugins must have registration tests
- All attack functions must have dry-run tests
- Integration tests must use orchestrator fixtures
