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

![Status: Alpha](https://img.shields.io/badge/status-alpha-yellow)
![Stability: Experimental](https://img.shields.io/badge/stability-experimental-orange)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)
![Domain: RF/IoT/AI](https://img.shields.io/badge/domain-RF%20%7C%20IoT%20%7C%20AI-critical)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![HackRF support](https://img.shields.io/badge/HackRF-Supported-success)
![RTL--SDR support](https://img.shields.io/badge/RTL--SDR-Optional-lightgrey)
![USRP support](https://img.shields.io/badge/USRP-Research%20Only-blueviolet)
![BladeRF support](https://img.shields.io/badge/BladeRF-Experimental-orange)
![GPS-SDR-SIM](https://img.shields.io/badge/GPS--SDR--SIM-Integration-yellow)

> Alpha release - **unstable**, highly experimental modules  
> Use ONLY in authorized **Faraday cages**, RF controlled labs, or CTF exercises


## What is Obscura?

Obscura is an autonomous **adversarial orchestration engine** combining traditional wireless exploitation, satellite spoofing, IoT disruption, SDR interference, and **AI driven decision making** into a single modular system.

Built to bridge classic wireless attacks, SDR interference, IoT disruption, BLE exploitation, satellite spoofing, and AI-driven adversary simulation - all under a unified orchestration layer.


Targeted for:

• Red/Purple Team cyber ranges  
• Drone & satellite attack simulation  
• Wireless/IoT security labs  
• Future cyber & physical warfare research (legal only)

## Core Capabilities

| Module | Description |
|--------|-------------|
| Wi-Fi Attacks | Deauth, Rogue AP, Evil Twin, Hybrid ML bypass |
| Camera Exploits | RTSP hijack, MJPEG spoof, **deepfake operator feed** |
| BLE/Bluetooth | Disruption, HID spoof, **LLM fuzzing** modules |
| SDR/Radio | GPS spoof, ADS-B interference, RF replay tools |
| AI/LLM Stack | **Auto adversary reasoning**, strategy ranking |
| Satellite Exploits | GNSS & DVB spoofing, orbit aware targeting |
| Attack Graphing | DOT/SVG chain mapping with intelligence scoring |
| Live Shell | Interactive operator shell w/ real-time plugin control |

---
## Legal & Operational Safety

You **must** have explicit written authorization to use Obscura.  
RF emissions can be **illegal**, **dangerous**, or **air traffic impacting**.

Obscura is intended for:

• RF-isolated labs  
• Authorized cyber defense research  
• CTF and academic work  
• Threat modeling exercises

Developers assume **zero liability** for misuse.
---
## Plugin-Based Attack Architecture

Plugins register into the orchestrator at runtime:

```python
orchestrator.load_plugin("advanced_attacks")
orchestrator.load_all_plugins()
```
Attack plugins located in:

- `attack_plugins/`  
- Must expose: `run(context)` or `register_attack()`
---
## Getting Started

1. Install requirements:

```bash
pip install -e .
```

2. Launch the orchestrator:

If you installed using pyproject.toml, launch via:

obscura

Or with full path (e.g. pyenv):
```bash
sudo -E /home/kali/.pyenv/versions/3.11.9/bin/obscura

sudo -E preserves your environment variables
```
3️. Test RF modules individually before chaining
(e.g., monitor mode, HackRF drivers, GNURadio support)

---
<!--
MITRE ATT&CK ICS mapping, cyber physical attack vectors, PLC sensor spoofing,
loss of view camera hijack, RF communications denial, satellite command spoof,
operational technology adversary tactics, wireless access disruption T0884,
SDR attack simulation platform, GPS deception tooling T0805, BLE protocol attack T0861,
radio frequency cyberattacks, ICS MITRE technique coverage mapping,
deepfake camera operator red team module, critical infrastructure DDoS avoidance,
high fidelity ICS attack simulation for cyber defense labs
-->
| Technique | MITRE ID | Description | Status |
|----------|----------|-------------|--------|
| Wireless Network Deauth / Rogue AP | T0884 | Loss of availability via wireless disruption | Partially Supported |
| Spoof Command Message (PLC Sensor Input) | T0855 | Malicious sensor payload injection | Partially Supported |
| Modify Parameter (GPS / RF Injection) | T0805 | Change thresholds to affect control loops | Partially Supported |
| Exploit Wireless Protocol | T0861 | BLE spoof + jamming | Partially Supported |
| Jam Communication Channel | T0824 | SDR RF Denial (GPS/ADS-B) | Partially Supported |
| Loss of View | T0829 | Camera feed spoofing / deepfake | Partially Supported |
| Alarm Suppression | T0838 | Visual/telemetry masking on operators | Supported (Experimental) |
| Inhibit Response Function | T0809 | Prevent safety fallback via false confidence | Partially Supported |
| Modify Control Logic | T0880 | Targeted in future plugin roadmap | In Development |
---
## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Disclaimer
Obscura is intended solely for educational purposes and authorized penetration testing in controlled environments. Unauthorized use on live systems, networks, or RF frequencies without explicit permission is illegal and unethical. Always comply with local laws and regulations, including FCC guidelines for RF transmissions. The developers disclaim any liability for misuse or resulting damages.

<!--
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


