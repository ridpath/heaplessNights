# SDR Attack Fixtures

This directory contains test .iq files for SDR attack plugin testing and development.

## Files

### GPS L1 Signal
- **File**: `gps_l1_sample.bin`
- **Format**: 16-bit signed I/Q (complex int16)
- **Sample Rate**: 2.6 MSPS
- **Center Frequency**: 1575.42 MHz (GPS L1 C/A)
- **Duration**: 10 seconds
- **Description**: Simulated GPS L1 C/A signal with PRN code modulation and noise

### ADS-B Mode-S Signal
- **File**: `adsb_sample.bin`
- **Format**: 16-bit signed I/Q (complex int16)
- **Sample Rate**: 2.6 MSPS
- **Center Frequency**: 1090 MHz
- **Duration**: 10 seconds
- **Description**: Simulated ADS-B Mode-S bursts with realistic timing

### 315 MHz Garage Door Opener
- **File**: `315mhz_garage.bin`
- **Format**: 16-bit signed I/Q (complex int16)
- **Sample Rate**: 2.6 MSPS
- **Center Frequency**: 315 MHz
- **Duration**: 2 seconds
- **Description**: Simulated OOK (On-Off Keying) garage door opener signal

### 433 MHz Alarm System
- **File**: `433mhz_alarm.bin`
- **Format**: 16-bit signed I/Q (complex int16)
- **Sample Rate**: 2.6 MSPS
- **Center Frequency**: 433 MHz
- **Duration**: 2 seconds
- **Description**: Simulated FSK (Frequency Shift Keying) alarm system signal

### Noise Jamming
- **File**: `noise_jamming.bin`
- **Format**: 16-bit signed I/Q (complex int16)
- **Sample Rate**: 2.6 MSPS
- **Duration**: 5 seconds
- **Description**: White noise for jamming tests

## Regenerating Fixtures

To regenerate all fixture files:

```bash
cd fixtures/
python generate_test_iq.py
```

## Usage in Tests

```python
from pathlib import Path

fixtures_dir = Path(__file__).parent / 'fixtures'
gps_file = fixtures_dir / 'gps_l1_sample.bin'
adsb_file = fixtures_dir / 'adsb_sample.bin'
```

## Transmission Warning

These files are for testing in controlled environments only. Never transmit on GPS L1, ADS-B, or other regulated frequencies without proper authorization and shielding (Faraday cage).

## Format Details

All .iq files use the following format:
- Complex samples (I and Q)
- 16-bit signed integers (little-endian)
- Interleaved: I0, Q0, I1, Q1, I2, Q2, ...
- Compatible with hackrf_transfer, GNU Radio, and other SDR tools

## Compatibility

Compatible with:
- HackRF One (hackrf_transfer)
- RTL-SDR (rtl_sdr with conversion)
- USRP (GNU Radio, UHD)
- LimeSDR (SoapySDR, LimeSuite)
- BladeRF (bladeRF-cli)
- GNU Radio Companion (File Source block)
