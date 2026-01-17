"""
Hardware Abstraction Layer for Obscura

Provides unified hardware detection and fallback mechanisms for:
- SDR devices (HackRF, RTL-SDR, USRP, LimeSDR, BladeRF)
- Wi-Fi interfaces (monitor mode capable)
- BLE interfaces (Bluetooth Low Energy)
- Fallback to .iq recordings when no hardware is available
"""

import os
import subprocess
import re
import logging
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger("obscura.hardware")


@dataclass
class SDRDevice:
    """Represents an SDR device"""
    name: str
    device_type: str
    available: bool
    info: str = ""
    serial: Optional[str] = None


@dataclass
class WiFiInterface:
    """Represents a Wi-Fi interface"""
    name: str
    mac: str
    monitor_capable: bool
    monitor_active: bool
    driver: str = ""
    chipset: str = ""


@dataclass
class BLEInterface:
    """Represents a Bluetooth Low Energy interface"""
    name: str
    mac: str
    available: bool
    hci_version: str = ""


@dataclass
class HardwareProfile:
    """Complete hardware profile"""
    sdr_devices: List[SDRDevice] = field(default_factory=list)
    wifi_interfaces: List[WiFiInterface] = field(default_factory=list)
    ble_interfaces: List[BLEInterface] = field(default_factory=list)
    has_any_sdr: bool = False
    has_monitor_wifi: bool = False
    has_ble: bool = False
    fallback_mode: bool = False


def check_command_exists(command: str) -> bool:
    """Check if a command exists in PATH."""
    try:
        if os.name == 'nt':
            result = subprocess.run(['where', command], 
                                  capture_output=True, 
                                  text=True,
                                  timeout=3)
        else:
            result = subprocess.run(['which', command], 
                                  capture_output=True, 
                                  text=True,
                                  timeout=3)
        return result.returncode == 0
    except Exception:
        return False


def detect_hackrf() -> Optional[SDRDevice]:
    """Detect HackRF One devices."""
    if not check_command_exists('hackrf_info'):
        return None
    
    try:
        result = subprocess.run(['hackrf_info'], 
                              capture_output=True, 
                              text=True,
                              timeout=5)
        
        if result.returncode == 0 and 'Serial number' in result.stdout:
            serial_match = re.search(r'Serial number: (0x[0-9a-fA-F]+)', result.stdout)
            serial = serial_match.group(1) if serial_match else None
            
            return SDRDevice(
                name="HackRF One",
                device_type="hackrf",
                available=True,
                info=result.stdout.strip(),
                serial=serial
            )
    except Exception as e:
        logger.debug(f"HackRF detection error: {e}")
    
    return None


def detect_rtlsdr() -> Optional[SDRDevice]:
    """Detect RTL-SDR devices."""
    if not check_command_exists('rtl_test'):
        return None
    
    try:
        result = subprocess.run(['rtl_test', '-t'], 
                              capture_output=True, 
                              text=True,
                              timeout=3)
        
        if 'Found' in result.stdout or 'Realtek' in result.stdout:
            return SDRDevice(
                name="RTL-SDR",
                device_type="rtlsdr",
                available=True,
                info=result.stdout.strip()
            )
    except Exception as e:
        logger.debug(f"RTL-SDR detection error: {e}")
    
    return None


def detect_usrp() -> Optional[SDRDevice]:
    """Detect USRP devices."""
    if not check_command_exists('uhd_find_devices'):
        return None
    
    try:
        result = subprocess.run(['uhd_find_devices'], 
                              capture_output=True, 
                              text=True,
                              timeout=5)
        
        if 'USRP' in result.stdout or 'type:' in result.stdout:
            return SDRDevice(
                name="USRP",
                device_type="usrp",
                available=True,
                info=result.stdout.strip()
            )
    except Exception as e:
        logger.debug(f"USRP detection error: {e}")
    
    return None


def detect_limesdr() -> Optional[SDRDevice]:
    """Detect LimeSDR devices."""
    if not check_command_exists('LimeUtil'):
        return None
    
    try:
        result = subprocess.run(['LimeUtil', '--find'], 
                              capture_output=True, 
                              text=True,
                              timeout=5)
        
        if 'LimeSDR' in result.stdout or result.returncode == 0:
            return SDRDevice(
                name="LimeSDR",
                device_type="limesdr",
                available=True,
                info=result.stdout.strip()
            )
    except Exception as e:
        logger.debug(f"LimeSDR detection error: {e}")
    
    return None


def detect_bladerf() -> Optional[SDRDevice]:
    """Detect BladeRF devices."""
    if not check_command_exists('bladeRF-cli'):
        return None
    
    try:
        result = subprocess.run(['bladeRF-cli', '-p'], 
                              capture_output=True, 
                              text=True,
                              timeout=5)
        
        if result.returncode == 0 or 'bladeRF' in result.stdout.lower():
            return SDRDevice(
                name="BladeRF",
                device_type="bladerf",
                available=True,
                info=result.stdout.strip()
            )
    except Exception as e:
        logger.debug(f"BladeRF detection error: {e}")
    
    return None


def detect_all_sdr_devices() -> List[SDRDevice]:
    """Detect all available SDR devices."""
    devices = []
    
    detectors = [
        detect_hackrf,
        detect_rtlsdr,
        detect_usrp,
        detect_limesdr,
        detect_bladerf
    ]
    
    for detector in detectors:
        device = detector()
        if device:
            devices.append(device)
            logger.info(f"Detected SDR: {device.name} ({device.device_type})")
    
    return devices


def detect_wifi_interfaces() -> List[WiFiInterface]:
    """Detect Wi-Fi interfaces capable of monitor mode."""
    interfaces = []
    
    try:
        if check_command_exists('iw'):
            result = subprocess.run(['iw', 'dev'], 
                                  capture_output=True, 
                                  text=True,
                                  timeout=5)
            
            current_interface = None
            current_mac = None
            current_type = None
            
            for line in result.stdout.splitlines():
                line = line.strip()
                
                if line.startswith('Interface'):
                    if current_interface:
                        monitor_active = current_type == 'monitor'
                        interfaces.append(WiFiInterface(
                            name=current_interface,
                            mac=current_mac or "00:00:00:00:00:00",
                            monitor_capable=True,
                            monitor_active=monitor_active
                        ))
                    
                    current_interface = line.split()[1]
                    current_mac = None
                    current_type = None
                
                elif line.startswith('addr'):
                    current_mac = line.split()[1]
                
                elif line.startswith('type'):
                    current_type = line.split()[1]
            
            if current_interface:
                monitor_active = current_type == 'monitor'
                interfaces.append(WiFiInterface(
                    name=current_interface,
                    mac=current_mac or "00:00:00:00:00:00",
                    monitor_capable=True,
                    monitor_active=monitor_active
                ))
        
        elif check_command_exists('iwconfig'):
            result = subprocess.run(['iwconfig'], 
                                  capture_output=True, 
                                  text=True,
                                  timeout=5)
            
            for line in result.stdout.splitlines():
                if 'IEEE 802.11' in line or 'ESSID' in line:
                    iface_name = line.split()[0]
                    
                    ifconfig_result = subprocess.run(['ifconfig', iface_name], 
                                                    capture_output=True, 
                                                    text=True,
                                                    timeout=3)
                    
                    mac_match = re.search(r'ether ([0-9a-fA-F:]{17})', ifconfig_result.stdout)
                    mac = mac_match.group(1) if mac_match else "00:00:00:00:00:00"
                    
                    monitor_active = 'Mode:Monitor' in line
                    
                    interfaces.append(WiFiInterface(
                        name=iface_name,
                        mac=mac,
                        monitor_capable=True,
                        monitor_active=monitor_active
                    ))
        
        logger.info(f"Detected {len(interfaces)} Wi-Fi interface(s)")
        
    except Exception as e:
        logger.debug(f"Wi-Fi interface detection error: {e}")
    
    return interfaces


def detect_ble_interfaces() -> List[BLEInterface]:
    """Detect Bluetooth Low Energy interfaces."""
    interfaces = []
    
    try:
        if check_command_exists('hciconfig'):
            result = subprocess.run(['hciconfig'], 
                                  capture_output=True, 
                                  text=True,
                                  timeout=5)
            
            current_interface = None
            current_mac = None
            
            for line in result.stdout.splitlines():
                line = line.strip()
                
                if line.startswith('hci'):
                    if current_interface and current_mac:
                        interfaces.append(BLEInterface(
                            name=current_interface,
                            mac=current_mac,
                            available=True
                        ))
                    
                    current_interface = line.split(':')[0]
                    current_mac = None
                
                elif 'BD Address:' in line:
                    mac_match = re.search(r'BD Address: ([0-9A-Fa-f:]{17})', line)
                    if mac_match:
                        current_mac = mac_match.group(1)
            
            if current_interface and current_mac:
                interfaces.append(BLEInterface(
                    name=current_interface,
                    mac=current_mac,
                    available=True
                ))
        
        logger.info(f"Detected {len(interfaces)} BLE interface(s)")
        
    except Exception as e:
        logger.debug(f"BLE interface detection error: {e}")
    
    return interfaces


def find_iq_fixtures(fixtures_dir: Optional[Path] = None) -> List[Path]:
    """Find available .iq fixture files for fallback mode."""
    if fixtures_dir is None:
        fixtures_dir = Path(__file__).parent.parent / "fixtures"
    
    if not fixtures_dir.exists():
        return []
    
    iq_files = list(fixtures_dir.glob("*.iq")) + list(fixtures_dir.glob("*.bin"))
    
    logger.info(f"Found {len(iq_files)} .iq fixture file(s) for fallback mode")
    
    return iq_files


def get_hardware_profile(fixtures_dir: Optional[Path] = None) -> HardwareProfile:
    """
    Get complete hardware profile with detection and fallback.
    
    Args:
        fixtures_dir: Directory containing .iq fixture files for fallback
    
    Returns:
        HardwareProfile with all detected hardware and fallback status
    """
    logger.info("Starting hardware detection...")
    
    profile = HardwareProfile()
    
    profile.sdr_devices = detect_all_sdr_devices()
    profile.has_any_sdr = len(profile.sdr_devices) > 0
    
    profile.wifi_interfaces = detect_wifi_interfaces()
    profile.has_monitor_wifi = any(iface.monitor_capable for iface in profile.wifi_interfaces)
    
    profile.ble_interfaces = detect_ble_interfaces()
    profile.has_ble = len(profile.ble_interfaces) > 0
    
    if not profile.has_any_sdr:
        iq_files = find_iq_fixtures(fixtures_dir)
        if iq_files:
            logger.warning("No SDR hardware detected, enabling fallback mode with .iq fixtures")
            profile.fallback_mode = True
        else:
            logger.warning("No SDR hardware detected and no .iq fixtures available")
            profile.fallback_mode = True
    
    return profile


def print_hardware_summary(profile: HardwareProfile):
    """Print human-readable hardware summary."""
    print("\n" + "="*60)
    print("HARDWARE DETECTION SUMMARY")
    print("="*60)
    
    print("\n[SDR DEVICES]")
    if profile.sdr_devices:
        for device in profile.sdr_devices:
            print(f"  [+] {device.name} ({device.device_type})")
            if device.serial:
                print(f"      Serial: {device.serial}")
    else:
        print("  [-] No SDR devices detected")
    
    print("\n[WI-FI INTERFACES]")
    if profile.wifi_interfaces:
        for iface in profile.wifi_interfaces:
            status = "MONITOR" if iface.monitor_active else "MANAGED"
            print(f"  [+] {iface.name} ({iface.mac}) - {status}")
    else:
        print("  [-] No Wi-Fi interfaces detected")
    
    print("\n[BLE INTERFACES]")
    if profile.ble_interfaces:
        for iface in profile.ble_interfaces:
            print(f"  [+] {iface.name} ({iface.mac})")
    else:
        print("  [-] No BLE interfaces detected")
    
    print("\n[OPERATIONAL MODE]")
    if profile.fallback_mode:
        print("  [!] FALLBACK MODE: Using .iq fixtures (no hardware RF emission)")
    else:
        print("  [+] HARDWARE MODE: Live RF operations enabled")
    
    print("="*60 + "\n")


def get_preferred_sdr(profile: HardwareProfile, preferred_type: Optional[str] = None) -> Optional[SDRDevice]:
    """
    Get preferred SDR device.
    
    Args:
        profile: HardwareProfile
        preferred_type: Preferred SDR type (hackrf, rtlsdr, usrp, etc.)
    
    Returns:
        SDRDevice or None
    """
    if not profile.sdr_devices:
        return None
    
    if preferred_type:
        for device in profile.sdr_devices:
            if device.device_type == preferred_type:
                return device
    
    priority = ['hackrf', 'usrp', 'bladerf', 'limesdr', 'rtlsdr']
    for device_type in priority:
        for device in profile.sdr_devices:
            if device.device_type == device_type:
                return device
    
    return profile.sdr_devices[0]


def get_preferred_wifi_interface(profile: HardwareProfile) -> Optional[WiFiInterface]:
    """Get preferred Wi-Fi interface for monitor mode."""
    if not profile.wifi_interfaces:
        return None
    
    for iface in profile.wifi_interfaces:
        if iface.monitor_active:
            return iface
    
    for iface in profile.wifi_interfaces:
        if iface.monitor_capable:
            return iface
    
    return profile.wifi_interfaces[0]


def get_preferred_ble_interface(profile: HardwareProfile) -> Optional[BLEInterface]:
    """Get preferred BLE interface."""
    if not profile.ble_interfaces:
        return None
    
    return profile.ble_interfaces[0]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    profile = get_hardware_profile()
    print_hardware_summary(profile)
    
    preferred_sdr = get_preferred_sdr(profile)
    if preferred_sdr:
        print(f"\nPreferred SDR: {preferred_sdr.name}")
    
    preferred_wifi = get_preferred_wifi_interface(profile)
    if preferred_wifi:
        print(f"Preferred Wi-Fi: {preferred_wifi.name}")
    
    preferred_ble = get_preferred_ble_interface(profile)
    if preferred_ble:
        print(f"Preferred BLE: {preferred_ble.name}")
