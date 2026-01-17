<!--
Obscura cyber attack framework, AI-powered adversary automation, red team RF toolkit,
BLE exploit framework, Wi-Fi deauth tool, SDR jamming tool, GNSS spoofing tool,
ADS-B broadcast manipulation, satellite cyber attack simulation, AI auto-pwn orchestrator,
CTF cyber physical attack platform, IoT disruption offensive toolkit, multi-protocol MITM,
AI-driven exploit automation, offensive wireless security suite, advanced RF exploitation lab,
hackrf gnuradio cybersecurity, predictive adversary model, cyber autonomy toolchain,
security red team research tools, cyber-physical system exploitation,
experimental cyber weapons research for authorized labs,
extensible cyber attack plugins, covert sensor injection toolkit,
radio hacking automation, synthetic sensor generation attacks, github.com/ridpath, rf-hacking, sdr-exploitation, ai-security, iot-security,
ble-hacking, gps-spoofing, adsb-security, wireless-attacks,
offensive-security, cyber-physical-security, red-team-tool
-->

# Obscura - Autonomous Multi-Vector Adversarial Framework

<p align="center">
  <img src="https://img.shields.io/badge/status-alpha-yellow?style=for-the-badge" alt="Alpha">
  <img src="https://img.shields.io/badge/stability-experimental-orange?style=for-the-badge" alt="Experimental">
  <img src="https://img.shields.io/badge/license-MIT-blue?style=for-the-badge" alt="MIT License">
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=for-the-badge&logo=python" alt="Python 3.10+">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/HackRF-Supported-success?style=flat-square" alt="HackRF">
  <img src="https://img.shields.io/badge/RTL--SDR-Compatible-lightgrey?style=flat-square" alt="RTL-SDR">
  <img src="https://img.shields.io/badge/USRP-Research-blueviolet?style=flat-square" alt="USRP">
  <img src="https://img.shields.io/badge/BladeRF-Experimental-orange?style=flat-square" alt="BladeRF">
  <img src="https://img.shields.io/badge/GPS--SDR--SIM-Integrated-yellow?style=flat-square" alt="GPS-SDR-SIM">
</p>

> **WARNING - ALPHA RELEASE**: Highly experimental - Use ONLY in authorized RF-isolated labs, Faraday cages, or CTF environments  
> **FOR RED TEAMERS**: Built by operators, for operators - Autonomous attack chains with AI-driven decision making

---

---

## Scope & Design Goals

Obscura was built to explore adversarial behavior **across protocol boundaries**:

- Traditional IT wireless (Wi‑Fi, BLE)
- RF‑based systems (GNSS, ADS‑B, SDR‑driven protocols)
- IoT sensing and camera systems
- Cyber‑physical control surfaces
- Operator‑driven and autonomous attack chaining

Rather than focusing on a single exploit class, Obscura emphasizes:

- **Chaining** — combining weak signals into meaningful impact  
- **Repeatability** — deterministic execution for research and scoring  
- **Observability** — first‑class logging, evidence, and reporting  
- **Extensibility** — plugin‑based attack registration

---

## Key Capabilities

### Wireless (802.11)
- Targeted and broadcast deauthentication
- Rogue access point and Evil Twin workflows
- Handshake capture automation
- Channel‑aware attack execution

### Bluetooth / BLE
- GATT enumeration and manipulation
- Device disruption and interference
- HID‑style interaction research
- Pairing and bonding edge‑case testing

### SDR / RF
- GNSS signal simulation and deception (lab use only)
- ADS‑B/AIS replay and interference research
- Custom waveform execution via GNU Radio
- Replay attacks against simple RF devices

### IoT & Cameras
- RTSP/MJPEG stream interception
- ONVIF discovery and misuse testing
- Sensor data manipulation research
- Visual feed replacement (lab/CTF contexts)

### Orchestration & Chaining
- Operator‑driven attack selection
- Autonomous chain execution based on target traits
- Fallback logic and confidence scoring
- MITRE ATT&CK (Enterprise + ICS) mapping
---

## Installation

### Requirements
- Python 3.10+
- Linux recommended (Kali, Parrot, Ubuntu)
- Root or equivalent privileges for RF operations
- Compatible Wi‑Fi adapter for monitor mode (for wireless modules)

### Install
```bash
cd obscura
pip install -e .
```

Optional system tools (depending on use case):
```bash
sudo apt install aircrack-ng mdk4 hcxdumptool hostapd gnuradio hackrf rtl-sdr
```

---

## Safety Interlock (Mandatory)

RF‑capable modules require an explicit safety acknowledgment:

```bash
export OBSCURA_RF_LOCK=1
```

If this variable is not set, RF‑emitting modules will refuse to execute.

This is intentional and enforced.

---

## Operating Modes

### Interactive Shell
Manual operator control for research and demonstrations.

```bash
obscura --interactive --interface wlan0
```

### TUI (Terminal UI)
Live execution view with process tracking and attack status.

```bash
obscura --tui --config ~/.config/obscura/config.yaml
```

### Autonomous Execution
Trait‑driven attack chaining for competitions and repeatable testing.

```bash
obscura --auto --target traits.json --report-format html
```

### Simulation Mode
Dry‑run execution without RF emission or packet injection.

```bash
obscura --simulate --auto --target traits.json
```

---

## Configuration

Configuration files may be YAML or JSON and are auto‑loaded from standard locations:

- `~/.config/obscura/config.yaml`
- `./obscura.yaml`
- `./obscura.json`

A template can be generated:

```bash
obscura --generate-config ~/.config/obscura/config.yaml
```

Configuration is validated on startup and execution is refused if unsafe or invalid parameters are detected.

---

## Reporting & Evidence

Obscura treats reporting as a first‑class concern.

Supported outputs:
- Markdown
- HTML
- PDF (Linux/WSL)
- JSON (machine‑readable)
- ATT&CK Navigator layers
- STIX 2.1 bundles
- IOC exports (CSV, JSON, MISP)

Each execution records:
- Timeline
- Attack chain structure
- Confidence and outcome
- MITRE ATT&CK mappings
- Linked artifacts (pcaps, captures, logs)

---

## Plugin System

New attacks are added via lightweight plugins:

```python
def register_attack():
    return {
        "name": "custom_attack",
        "requirements": ["wifi_monitor"],
        "mitre_id": "T1498",
        "run": execute
    }
```

Plugins may be loaded dynamically or auto‑discovered at runtime.

---

## Legal & Usage Constraints

This software is **not** intended for use against live systems or networks without explicit authorization.

Permitted contexts:
- Security research labs
- Academic environments
- CTF competitions
- Client‑authorized red‑team engagements
- RF‑isolated testbeds

Prohibited contexts:
- Production networks
- Public RF environments
- Safety‑critical infrastructure
- Emergency, aviation, or maritime systems

Users are responsible for compliance with all applicable laws and regulations.

---

## Contributing

This project welcomes research‑focused contributions.

Preferred areas:
- New RF protocol research modules
- Additional wireless attack primitives
- Improved reporting and correlation
- Simulation fixtures for education and testing

All contributions must remain compatible with controlled environment use.

---

## License

MIT License. See `LICENSE` for details.


<!--
MITRE ATT&CK ICS mapping, cyber physical attack vectors, PLC sensor spoofing,
loss of view camera hijack, RF communications denial, satellite command spoof,
operational technology adversary tactics, wireless access disruption T0884,
SDR attack simulation platform, GPS deception tooling T0805, BLE protocol attack T0861,
radio frequency cyberattacks, ICS MITRE technique coverage mapping,
deepfake camera operator red team module, critical infrastructure DDoS avoidance,
high fidelity ICS attack simulation for cyber defense labs,
Advanced cyber-physical attack toolkit, wireless hacking framework, AI red team automation,
GPS spoofing scripts, RF jamming python, satellite spoofing tools, BLE exploit research,
ADS-B hacking, drone manipulation security testing, cognitive attack chain orchestration,
multi-vector cyber attack chaining, predictive adversary simulation engine,
SDR cyber lab testing toolkit, IoT sensor false data injection,
WiFi evil twin orchestrator, autonomous exploit delivery system,
cyber autonomy proof-of-concept, defense research lab tooling,
penetration testing RF frequencies, experimental red team modules,
satellite tracking security testing, Deepfake camera injection,
cybersecurity research tool RF IoT, AI-based fuzzing wireless,
advanced offensive security research platform, ridpath github, rf-hacking, sdr-exploitation, ai-security, iot-security,
ble-hacking, gps-spoofing, adsb-security, wireless-attacks,
offensive-security, cyber-physical-security, red-team-tool
-->
