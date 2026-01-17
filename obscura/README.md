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

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Attack Capabilities](#attack-capabilities)
- [Operational Modes](#operational-modes)
- [Installation](#installation)
- [Configuration](#configuration)
- [Professional Reporting](#professional-reporting)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Advanced Usage](#advanced-usage)
- [Testing & Validation](#testing--validation)
- [Legal & Safety](#legal--safety)
- [Use Cases](#use-cases)
- [Contributing](#contributing)
- [Resources](#resources)
- [License](#license)

---

## Overview

**Obscura** is a full-spectrum adversarial orchestration engine that combines multiple attack vectors into a unified, AI-driven offensive platform. Unlike traditional single-purpose security tools, Obscura provides:

**Core Technologies**:
- Satellite & GNSS Spoofing (GPS/GLONASS/Galileo manipulation)
- Software Defined Radio (HackRF/USRP/BladeRF RF warfare)
- Wireless Exploitation (Wi-Fi/BLE/Zigbee/Z-Wave disruption)
- Camera/IoT Compromise (RTSP/MJPEG hijacking with deepfake injection)
- AI-Driven Autonomy (LLM-powered attack selection and chaining)
- Professional Reporting (Client-ready HTML/PDF reports with MITRE ATT&CK mapping)

**Target Audience**:
- Red Team operations and adversary emulation
- Penetration testing engagements (wireless + IoT + OT/ICS)
- CTF competitions requiring multi-vector attacks
- Security research labs and academic institutions
- Purple Team defensive posture validation

**Key Features**:
- Thread-safe process management with graceful termination
- Rich terminal user interface (TUI) with live attack monitoring
- YAML/JSON configuration system with auto-loading
- Multi-format report generation (Markdown/HTML/PDF/JSON)
- Plugin-based architecture for extensibility
- MITRE ATT&CK technique mapping (ICS + Enterprise)
- Autonomous OODA loop decision engine

---

## Quick Start

### Minimal Installation
```bash
# Clone repository
git clone https://github.com/ridpath/heaplessNights.git
cd obscura

# Install Python dependencies
pip install -e .

# Set RF safety interlock (REQUIRED)
export OBSCURA_RF_LOCK=1

# Launch interactive TUI
obscura --tui --interface wlan0

# Run autonomous attack chain with HTML report
obscura --auto --target traits.json --report-format html

# Generate configuration template
obscura --generate-config ~/.config/obscura/config.yaml
```

### Hardware Requirements

**Minimum (Wi-Fi Only)**:
- Wi-Fi adapter with monitor mode capability
  - Recommended: Alfa AWUS036ACH, TP-Link TL-WN722N v1, Panda PAU09
  - Alternative: Any Atheros AR9271 or Ralink RT3070 chipset

**Optional (Full Capabilities)**:
- HackRF One (RF attacks, GPS spoofing, ADS-B)
- RTL-SDR (receive-only RF analysis)
- USRP B200/B210 (research-grade SDR)
- BladeRF x40/x115 (experimental support)
- Bluetooth adapter (BLE exploitation)

**Cross-Platform Support**:
- Linux: Kali, Parrot, Ubuntu, Debian (full support)
- Windows: WSL2 required for RF operations
- macOS: Limited support (Wi-Fi attacks only)

---

## Attack Capabilities

### Wireless Attacks (Wi-Fi/802.11)

**Deauthentication & Denial of Service**:
- Targeted deauthentication floods (mdk4/aireplay-ng)
- Broadcast deauth (all clients on network)
- Management Frame Protection (MFP) bypass techniques
- Beacon flood DoS attacks
- Channel hopping deauth across 2.4/5GHz

**Access Point Attacks**:
- Rogue Access Point spawning
- Evil Twin with captive portal
- Karma attacks against cached SSIDs
- WPA/WPA2 handshake capture automation
- Enterprise network targeting (802.1X)

**Supported Tools**:
- aircrack-ng suite
- mdk4
- hcxdumptool/hcxtools
- hostapd (rogue AP)

### Camera & IoT Exploitation

**Video Stream Attacks**:
- RTSP stream hijacking
- MJPEG injection attacks
- Deepfake operator feed replacement (experimental)
- H.264/H.265 stream manipulation

**Target Platforms**:
- Hikvision cameras (default credentials, API exploits)
- Dahua cameras (authentication bypass)
- Axis cameras (UPnP exploitation)
- Generic ONVIF devices

**Discovery & Enumeration**:
- UPnP/SSDP network discovery
- RTSP port scanning (554, 8554)
- Default credential brute-forcing
- Shodan/ZoomEye integration ready

### Bluetooth & BLE Attacks

**BLE Exploitation**:
- BLE device jamming/disruption
- GATT service enumeration
- Characteristic read/write attacks
- Pairing/bonding manipulation

**Bluetooth Classic**:
- Bluetooth Classic disruption
- HID keyboard injection (Rubber Ducky-style)
- Profile fuzzing
- LLM-powered fuzzing modules (experimental)

**Supported Hardware**:
- Built-in Bluetooth adapters
- USB Bluetooth dongles
- Ubertooth One (advanced features)

### SDR & RF Warfare

**GNSS Attacks** (Requires SDR Hardware):
- GPS spoofing (GPS-SDR-SIM integration)
- GLONASS signal generation
- Galileo manipulation
- Multi-constellation attacks

**Aviation/Maritime**:
- ADS-B interference & replay attacks
- AIS (Automatic Identification System) spoofing
- Mode S transponder simulation

**Cellular** (Research Only):
- GSM jamming (research environments)
- LTE downgrade attacks
- IMSI catching simulation

**Custom RF**:
- GNU Radio flowgraph execution
- Custom waveform generation
- RF replay attacks (garage doors, key fobs, RKE)
- DVB-T satellite signal spoofing

**Supported SDR Platforms**:
- HackRF One (1MHz - 6GHz, TX/RX)
- RTL-SDR (RX only, 24-1766MHz)
- USRP B200/B210 (70MHz - 6GHz, TX/RX)
- BladeRF x40/x115 (300MHz - 3.8GHz, TX/RX)

### AI-Powered Orchestration

**Autonomous Features**:
- OODA loop decision engine (Observe, Orient, Decide, Act)
- Target trait analysis & vulnerability scoring
- Attack chain optimization with fallback strategies
- Real-time attack adaptation based on success/failure
- Historical success rate tracking

**Intelligence**:
- Device fingerprinting (vendor, model, firmware)
- Service enumeration correlation
- Signal strength proximity estimation
- Attack effectiveness prediction

**MITRE Mapping**:
- Automatic MITRE ATT&CK technique tagging
- ICS/OT + Enterprise technique coverage
- Tactic-based attack selection
- Kill chain visualization

### Professional Reporting

**Report Formats**:
- **Markdown**: Human-readable, version-control friendly
- **HTML**: Professional CSS styling with dark theme
- **PDF**: Publication-ready client deliverables (WeasyPrint)
- **JSON**: SIEM/automation integration, machine-readable
- **DOT/SVG**: Attack graph visualization

**Report Features**:
- Executive summary with success/failure metrics
- Target information (device type, vendor, services, location)
- Attack chain visualization with confidence scores
- MITRE ATT&CK technique mapping with clickable links
- Execution timeline with timestamps
- Color-coded status indicators
- Professional branding and styling

### OpSec-Grade Logging

**Enterprise Security Features**:
- **Encrypted Storage**: AES-256-GCM encryption with PBKDF2 key derivation
- **Sensitive Data Redaction**: Automatic IP, MAC, domain, credential scrubbing
- **Memory-Only Mode**: Zero disk footprint for covert operations
- **Async Logging**: High-throughput background logging (18,000+ logs/sec)
- **Log Compression**: gzip compression with automatic rotation
- **Session Management**: Full operator tracking and authorization chains
- **Evidence Chain of Custody**: SHA256 hashing and artifact linking
- **Secure Deletion**: Platform-specific secure deletion (shred on Linux, 3-pass overwrite)
- **Cross-Platform**: Works on Windows, Linux, macOS, WSL (Kali, Parrot, etc.)
- **Path Agnostic**: Relative paths by default, works in any directory

**Usage Example**:
```python
from obscura.opsec_logging import OpSecLogger

logger = OpSecLogger(
    log_dir='opsec_logs',
    encrypt=True,
    passphrase='your_secure_passphrase',
    redact=True,
    memory_only=False,
    async_logging=True,
    compress_logs=True,
    rotate_size_mb=10,
    operator='red_team_alpha'
)

session_id = logger.start_session(
    operation_name="Client Engagement 2024-01",
    target_network="192.168.0.0/16",
    client="Acme Corp",
    authorization="Written Authorization #2024-001"
)

logger.log_attack(
    chain_id='chain_001',
    attack_name='wifi_deauth',
    success=True,
    execution_time=2.5,
    target_info={'ap_ssid': 'TargetNetwork', 'channel': 6},
    log_data={'packets_sent': 100, 'clients_disconnected': 3}
)

artifact_id = logger.add_evidence(
    artifact_type='pcap',
    file_path='/captures/attack_001.pcap',
    description='Full packet capture during deauth attack',
    chain_id='chain_001'
)

logger.end_session(notes="Engagement completed successfully")
logger.export_session(session_id, 'session_report.enc')
```

**CTF Mode**:
```python
logger = OpSecLogger(ctf_mode=True, operator='team_alpha')

logger.capture_flag(
    flag_name='wifi_pwned',
    flag_value='FLAG{w1f1_cr4ck3d}',
    points=100,
    chain_id='chain_001'
)

scoreboard = logger.get_ctf_scoreboard()
print(f"Score: {scoreboard['total_score']} points")
print(f"Flags: {scoreboard['flags_captured']}")

logger.export_ctf_report('ctf_results.json')
```

### Cross-Platform Capabilities

**Supported Platforms**:
- **Windows** (native, full support)
- **Linux** (Ubuntu, Debian, Kali Linux, Parrot OS, etc.)
- **macOS** (native support)
- **WSL** (Windows Subsystem for Linux - all distributions)

**Platform-Specific Features**:

**1. Automatic Platform Detection**
```python
from obscura.opsec_logging import PLATFORM, IS_WSL, WSL_DISTRO, PlatformUtils

print(f"Platform: {PLATFORM}")
print(f"Running in WSL: {IS_WSL}")
if IS_WSL:
    print(f"WSL Distribution: {WSL_DISTRO}")  # Kali, Parrot, Ubuntu, etc.

is_admin = PlatformUtils.is_admin()
print(f"Elevated privileges: {is_admin}")
```

**2. Network Interface Enumeration**
```python
interfaces = PlatformUtils.get_network_interfaces()

for iface in interfaces:
    print(f"Interface: {iface['name']}")
    print(f"Status: {'UP' if iface['is_up'] else 'DOWN'}")
    for addr in iface['addresses']:
        print(f"  {addr['type']}: {addr['address']}")

logger.log_network_interfaces(chain_id='recon_001')
```

**3. Process Enumeration**
```python
all_processes = PlatformUtils.get_processes()

filtered = PlatformUtils.get_processes(filter_name='python')
for proc in filtered:
    print(f"PID {proc['pid']}: {proc['name']}")

logger.log_processes(filter_name='target_app')
```

**4. WSL Path Conversion**
```python
import os

if IS_WSL:
    wsl_path = os.path.expanduser("~/captures/attack.pcap")
    windows_path = PlatformUtils.wsl_to_windows_path(wsl_path)
    
    print(f"WSL path: {wsl_path}")
    print(f"Windows path: {windows_path}")
    
    win_path = "C:\\"
    wsl_converted = PlatformUtils.windows_to_wsl_path(win_path)
    
    logger.convert_path(os.path.expanduser("~"), to_windows=True)
```

**5. Hardware Acceleration Detection**
```python
hw_caps = PlatformUtils.detect_hardware_acceleration()

print(f"AES-NI: {hw_caps['aes_ni']}")
print(f"AVX2: {hw_caps['avx2']}")
print(f"SSE4: {hw_caps['sse4']}")
```

**6. Platform-Specific Secure Deletion**
```python
success = PlatformUtils.secure_delete('sensitive_file.log', passes=3)
```

**7. System Diagnostics**
```python
sys_info = logger.get_system_info()

print(f"Platform: {sys_info['platform']}")
print(f"Architecture: {sys_info['architecture']}")
print(f"WSL Distro: {sys_info.get('wsl_distro', 'N/A')}")
print(f"Admin: {sys_info['is_admin']}")
print(f"Hardware Accel: {sys_info['hardware_acceleration']}")

if 'system_entropy' in sys_info:
    print(f"System Entropy: {sys_info['system_entropy']} bits")
```

**Performance Across Platforms**:
- **Windows**: 18,000+ logs/sec (async mode)
- **Linux/Kali/Parrot**: 20,000+ logs/sec (async mode)
- **WSL**: 15,000+ logs/sec (async mode)
- **macOS**: 17,000+ logs/sec (async mode)

All features work seamlessly across platforms with automatic fallbacks when platform-specific libraries are unavailable.

### Professional Export Formats

**Industry-Standard Formats**:

**1. ATT&CK Navigator JSON**
- Import directly into MITRE ATT&CK Navigator
- Color-coded technique heatmap
- Attack score visualization
- Metadata and comments per technique

```python
from obscura.export_formats import ATTACKNavigatorExporter

navigator = ATTACKNavigatorExporter(
    name="Red Team Engagement 2024",
    description="Wireless exploitation assessment"
)

navigator.add_technique('T1595', 'Active Scanning', 85, 
                       comment='WiFi reconnaissance performed')
navigator.add_technique('T1498', 'Network DoS', 90,
                       comment='Deauthentication attack executed')

navigator.export('attack_layer.json')
```

**2. STIX 2.1 (Threat Intelligence Sharing)**
- Full STIX 2.1 bundle format
- Attack patterns with MITRE mappings
- Indicators of Compromise (IOCs)
- Relationships and kill chain phases

```python
from obscura.export_formats import STIXExporter

stix = STIXExporter(identity_name="Red Team Operations")

pattern_id = stix.add_attack_pattern(
    'T1595', 'Active Scanning',
    'Network reconnaissance via WiFi scanning',
    'Reconnaissance'
)

indicator_id = stix.add_indicator(
    "[ipv4-addr:value = '192.168.1.1']",
    'stix',
    'Target AP gateway address',
    ['network-activity']
)

stix.add_relationship(indicator_id, pattern_id, 'indicates')
stix.export('threat_intel.json')
```

**3. IOC Extraction (Automated)**
- Automatic extraction from attack logs
- IPv4/IPv6 addresses, MAC addresses, domains, URLs
- File hashes (MD5, SHA1, SHA256)
- WiFi SSIDs/BSSIDs, frequencies
- MITRE technique IDs

```python
from obscura.export_formats import IOCExtractor

extractor = IOCExtractor()
extractor.extract_from_chain(attack_chain)

iocs = extractor.get_iocs()
print(f"Found {len(iocs['ipv4'])} IPv4 addresses")
print(f"Found {len(iocs['mac'])} MAC addresses")
print(f"Found {len(iocs['ssid'])} WiFi networks")

extractor.export_json('iocs.json')
extractor.export_csv('iocs.csv')
extractor.export_stix('iocs_stix.json')
extractor.export_misp('iocs_misp.json')
```

**4. CSV Exports (Excel-Ready)**
- Attack timeline with success rates
- Evidence chain of custody
- Forensic reconstruction timeline
- Pivot table compatible

```python
from obscura.export_formats import CSVExporter

CSVExporter.export_attacks(attacks_list, 'attacks.csv')
CSVExporter.export_timeline(events_list, 'timeline.csv')
CSVExporter.export_evidence(evidence_list, 'evidence.csv')
```

**5. SQLite Database (Queryable)**
- Full relational schema
- Operations, chains, attacks, MITRE coverage
- IOC tracking with timestamps
- SQL analysis and correlation

```python
from obscura.export_formats import SQLiteExporter

db = SQLiteExporter('operation.db')
db.add_operation('OP_2024_001', 'Client Engagement', ...)
db.add_chain('chain_001', 'OP_2024_001', ...)
db.add_attack('chain_001', 'wifi_deauth', ...)
db.add_ioc('ipv4', '192.168.1.1', timestamp, 'chain_001')
db.close()
```

**6. MISP (Malware Information Sharing Platform)**
- MISP event format
- Threat intelligence sharing
- IOC attributes with to_ids flags
- MITRE ATT&CK galaxy tags

```python
from obscura.export_formats import MISPExporter

misp = MISPExporter(
    event_info="Red Team Wireless Assessment",
    distribution=0,
    threat_level=2
)

misp.add_attribute('ip-dst', '192.168.1.1', 'Network activity',
                  'Target gateway', to_ids=True)
misp.add_attack_pattern('T1498', 'Network DoS')
misp.export('misp_event.json')
```

**7. Elasticsearch/Kibana**
- NDJSON bulk format
- Kibana dashboard compatible
- Time-series analysis
- Real-time SIEM integration

```python
from obscura.export_formats import ElasticsearchExporter

ElasticsearchExporter.export_batch(
    attacks_list,
    'elasticsearch_bulk.ndjson',
    index_name='obscura-attacks'
)
```

**Artifact Linking & Correlation**:
```python
logger.link_artifact_to_chain(
    artifact_id='ARTIFACT_001',
    related_artifact_ids=['ARTIFACT_002', 'ARTIFACT_003'],
    relationship='captured_during_same_attack'
)

linked_artifacts = logger.get_artifact_chain('ARTIFACT_001')
for artifact in linked_artifacts:
    print(f"{artifact['artifact_type']}: {artifact['description']}")
```

---

## Operational Modes

### Mode 1: Interactive Shell

```bash
obscura --interactive --interface wlan0

# Shell commands:
obscura> list                    # Show available attacks
obscura> run wifi_deauth         # Execute specific attack
obscura> status                  # Check active processes
obscura> stop                    # Kill all attacks
obscura> exit                    # Quit interactive mode
```

**Use Cases**:
- Manual attack execution
- Real-time operator control
- Testing individual attack vectors
- Educational demonstrations

### Mode 2: Rich TUI (Terminal User Interface)

```bash
obscura --tui --config ~/.config/obscura/config.yaml

# Features:
# - Real-time hardware status (SDR/Wi-Fi/BLE availability)
# - Active attack monitoring with MITRE ATT&CK IDs
# - Process tracking (HackRF processes, attack processes)
# - Attack history with success/failure rates
# - Live log streaming with color-coded status
# - 1-second refresh rate (configurable)
```

**Dashboard Components**:
- Header: Uptime, packet count, attack count
- Hardware Status: SDR devices, Wi-Fi adapters, BLE interfaces
- Process Status: Active HackRF/attack processes
- Attack Progress: Real-time attack execution with elapsed time
- Attack History: Last 10 attacks with status indicators
- Logs: Last 15 log messages with timestamps

**Use Cases**:
- Live engagement monitoring
- Red Team operations center
- Training and demonstrations
- Multi-vector attack coordination

### Mode 3: Autonomous Mode (AI-Driven)

```bash
obscura --auto --target traits.json --report-format all

# AI decision factors:
# - Target device type (camera/router/IoT/ICS)
# - Signal strength & proximity
# - Available hardware (SDR/Wi-Fi/BLE detection)
# - Historical success rates
# - Attack prerequisites (monitor mode, root privileges)
```

**Attack Selection Algorithm**:
1. **Observe**: Analyze target traits (device_type, vendor, services, signal_strength)
2. **Orient**: Score all available attacks based on requirements and confidence
3. **Decide**: Select optimal attack chain with fallback strategies
4. **Act**: Execute attacks sequentially, adapt on failure

**Target Traits File** (traits.json):
```json
{
  "IoT_Camera": {
    "vendor": "Hikvision",
    "services": ["rtsp", "http", "onvif"],
    "protocols": ["TCP", "UDP"],
    "signal_strength": -45,
    "location": {"lat": 37.7749, "lon": -122.4194}
  },
  "WiFi_Router": {
    "vendor": "Ubiquiti",
    "model": "UniFi AP AC Pro",
    "services": ["ssh", "http", "https"],
    "protocols": ["TCP"],
    "signal_strength": -35,
    "channel": 36,
    "encryption": "WPA2-Enterprise"
  },
  "BLE_Sensor": {
    "vendor": "Texas Instruments",
    "device_type": "BLE_Beacon",
    "services": ["battery", "temperature"],
    "signal_strength": -60
  }
}
```

**Use Cases**:
- Rapid assessment engagements
- CTF competitions
- Automated penetration testing
- Proof-of-concept demonstrations

### Mode 4: Plugin System

```bash
obscura --load advanced_attacks,custom_exploits --interface wlan0

# Plugin structure:
# attack_plugins/
# ├── advanced_attacks.py
# ├── custom_exploits.py
# └── experimental_rf.py
```

**Plugin Development**:
```python
# attack_plugins/custom_exploit.py
def register_attack():
    return {
        'name': 'custom_exploit',
        'description': 'Custom attack module',
        'requirements': ['wifi_monitor'],
        'mitre_id': 'T1234',
        'run': execute_attack
    }

def execute_attack(context):
    target = context.get('target')
    interface = context.get('interface')
    
    # Attack implementation
    print(f"[*] Attacking {target} via {interface}")
    
    return True  # Success
```

**Use Cases**:
- Custom attack development
- Tool integration (Metasploit, Burp Suite, custom scripts)
- Proprietary exploit chains
- Research-specific attack vectors

---

## Installation

### Standard Installation (Kali/Parrot/Ubuntu)

```bash
# Clone repository
git clone https://github.com/ridpath/heaplessNights.git
cd obscura

# Install Python dependencies
pip install -e .

# For enhanced cross-platform features (optional but recommended)
pip install psutil cryptography keyring

# Install system tools (Wi-Fi)
sudo apt-get update
sudo apt-get install -y \
    aircrack-ng \
    mdk4 \
    hcxdumptool \
    hcxtools \
    hostapd \
    dnsmasq

# Install SDR tools (Optional - for RF attacks)
sudo apt-get install -y \
    gnuradio \
    gr-osmosdr \
    hackrf \
    gqrx-sdr \
    rtl-sdr \
    kalibrate-rtl

# Install BLE tools (Optional)
sudo apt-get install -y \
    bluez \
    bluez-tools \
    bluetooth

# Install PDF report generation (Linux/WSL - Optional)
sudo apt-get install -y \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info
pip install weasyprint

# Set RF safety interlock (REQUIRED)
echo 'export OBSCURA_RF_LOCK=1' >> ~/.bashrc
source ~/.bashrc

# Verify installation
obscura --show-hardware
```

**Note on Directory Structure**: Obscura uses relative paths by default and can be run from any directory. Log files and artifacts are created relative to your current working directory unless absolute paths are specified. All examples work on Windows, Linux, macOS, and WSL without modification.

### Windows Installation (WSL2)

```powershell
# Install WSL2 with Kali Linux
wsl --install -d kali-linux

# Inside WSL2:
wsl
cd ~
git clone https://github.com/ridpath/heaplessNights.git
cd obscura
pip install -e .

# Note: USB passthrough required for SDR hardware
# Use usbipd-win for USB device forwarding to WSL2
```

### macOS Installation

```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python@3.10
brew install libffi
brew install aircrack-ng

# Clone and install Obscura
git clone https://github.com/ridpath/heaplessNights.git
cd obscura
pip3 install -e .

# Note: SDR support limited on macOS (HackRF requires drivers)
# Wi-Fi attacks supported with compatible adapters
```

### Docker Installation (Isolated Environment)

```bash
# Build Docker image
docker build -t obscura:latest .

# Run with privileged mode (required for network manipulation)
docker run -it --privileged --net=host obscura:latest

# Mount config directory
docker run -it --privileged --net=host \
    -v ~/.config/obscura:/root/.config/obscura \
    obscura:latest
```

### Dependencies Matrix

| Category | Package | Required | Platform | Purpose |
|----------|---------|----------|----------|---------|
| **Python Core** | Python 3.10+ | Yes | All | Runtime |
| | scapy | Yes | All | Packet manipulation |
| | numpy | Yes | All | Data processing |
| | rich | Yes | All | TUI rendering |
| | pyyaml | Yes | All | Config management |
| | weasyprint | No | Linux/WSL | PDF generation |
| **Wi-Fi Tools** | aircrack-ng | Yes | Linux/macOS | WPA cracking, injection |
| | mdk4 | Yes | Linux | Wi-Fi DoS attacks |
| | hcxdumptool | No | Linux | Handshake capture |
| | hostapd | No | Linux | Rogue AP |
| **SDR Tools** | gnuradio | No | Linux | SDR framework |
| | hackrf | No | Linux/Windows | HackRF driver |
| | rtl-sdr | No | Linux/Windows | RTL-SDR driver |
| | gps-sdr-sim | No | Linux | GPS spoofing |
| **BLE Tools** | bluez | No | Linux | BLE stack |
| | gatttool | No | Linux | BLE GATT client |
| **Other** | git | Yes | All | Version control |

---

## Configuration

### Configuration File Structure

Obscura supports YAML and JSON configuration files with automatic loading from standard paths.

**Auto-Loading Paths** (priority order):
1. `~/.config/obscura/config.yaml`
2. `~/.config/obscura/config.json`
3. `~/.obscura.yaml`
4. `~/.obscura.json`
5. `./obscura.yaml` (project directory)
6. `./obscura.json` (project directory)

### Generate Template Configuration

```bash
# Generate YAML template
obscura --generate-config ~/.config/obscura/config.yaml

# Generate JSON template
obscura --generate-config ~/.config/obscura/config.json

# Edit configuration
nano ~/.config/obscura/config.yaml
```

### Example Configuration (YAML)

```yaml
# Interface Settings
interface: wlan0
simulate_mode: false
battery_saver: false

# Attack Parameters
signal_threshold: -120          # dBm (minimum signal strength)
jam_duration: 300               # seconds
deauth_duration: 120            # seconds

# Logging Configuration
log_level: INFO                 # DEBUG, INFO, WARNING, ERROR
log_file: obscura.log
max_log_size: 5242880           # 5MB in bytes

# Safety Interlocks
rf_safety_required: true        # Enforce OBSCURA_RF_LOCK check

# Hardware Preferences
sdr_preferred: hackrf           # hackrf, rtlsdr, usrp, bladerf
wifi_preferred: wlan0           # Preferred Wi-Fi interface
ble_preferred: hci0             # Preferred BLE interface

# Plugin Settings
auto_load_plugins: true
plugin_dir: attack_plugins

# Fixture/Fallback Settings
fixtures_dir: fixtures
fallback_mode: false            # Use .iq files when hardware unavailable

# TUI Settings
tui_enabled: true
tui_refresh_rate: 1.0           # seconds

# Reporting Configuration
mitre_mapping_enabled: true
reporting_enabled: true
report_format: html             # markdown, html, pdf, json, all
```

### Example Configuration (JSON)

```json
{
  "interface": "wlan0",
  "simulate_mode": false,
  "battery_saver": false,
  "signal_threshold": -120,
  "jam_duration": 300,
  "deauth_duration": 120,
  "log_level": "INFO",
  "log_file": "obscura.log",
  "max_log_size": 5242880,
  "rf_safety_required": true,
  "sdr_preferred": "hackrf",
  "wifi_preferred": "wlan0",
  "ble_preferred": "hci0",
  "tui_enabled": true,
  "tui_refresh_rate": 1.0,
  "auto_load_plugins": true,
  "plugin_dir": "attack_plugins",
  "fixtures_dir": "fixtures",
  "fallback_mode": false,
  "mitre_mapping_enabled": true,
  "reporting_enabled": true,
  "report_format": "html"
}
```

### Configuration Validation

```bash
# Obscura validates configuration on load
obscura --config ~/.config/obscura/config.yaml --validate

# Validation errors are reported:
# [ERROR] Configuration validation failed:
#   - jam_duration must be >= 1
#   - signal_threshold must be negative (dBm)
#   - Invalid log_level: VERBOSE
```

### Using Configuration in CLI

```bash
# Load specific config file
obscura --config /path/to/config.yaml --auto --target traits.json

# Config values override command-line defaults
obscura --config myconfig.yaml --tui --interface wlan0
```

---

## Professional Reporting

### Report Generation Commands

```bash
# Markdown (default, human-readable)
obscura --auto --target traits.json --report-format markdown

# HTML (professional styling)
obscura --auto --target traits.json --report-format html

# PDF (client deliverables, requires WeasyPrint)
obscura --auto --target traits.json --report-format pdf

# JSON (machine-readable, SIEM integration)
obscura --auto --target traits.json --report-format json

# All formats simultaneously
obscura --auto --target traits.json --report-format all
```

### Report Output Structure

```
logs/
├── attack_report_20260117_142530.md      # Markdown report
├── attack_report_20260117_142530.html    # HTML report
├── attack_report_20260117_142530.pdf     # PDF report
├── chain_20260117_142530.json            # JSON log
├── chain_20260117_142530.dot             # DOT graph
└── campaign_report_20260117_150000.md    # Multi-chain campaign report
```

### Report Components

**1. Executive Summary**:
- Attack chain ID and timestamp
- Overall success/failure status
- Total duration
- Attack count and success rate

**2. Target Information**:
- Device type and vendor
- Discovered services and protocols
- Signal strength measurements
- Geolocation data (if available)

**3. Attack Chain Details**:
- Attack sequence with ordering
- Confidence scores (0-100)
- MITRE ATT&CK technique IDs
- Execution status per attack
- Timing information

**4. MITRE ATT&CK Mapping**:
- Technique coverage table
- Tactic categorization
- ICS/OT vs Enterprise classification
- Clickable links to MITRE documentation

**5. Execution Log**:
- Chronological attack timeline
- Success/failure indicators
- Error messages and warnings
- Execution time per attack

### HTML Report Features

**Professional Styling**:
- Dark theme with gradient headers
- Responsive design (mobile-friendly)
- Color-coded status badges (green=success, red=failure)
- Progress bars for confidence visualization
- Hover effects on interactive elements

**Technical Details**:
- Embedded CSS (no external dependencies)
- Print-optimized layouts
- Cross-browser compatible (Chrome, Firefox, Safari, Edge)
- Accessible color schemes (WCAG AA compliant)

### PDF Report Requirements

**Linux/WSL**:
```bash
# Install GTK3 dependencies
sudo apt-get install -y \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info

# Install WeasyPrint
pip install weasyprint
```

**macOS**:
```bash
# Install GTK3 via Homebrew
brew install cairo pango gdk-pixbuf libffi
pip install weasyprint
```

**Windows**: PDF generation requires WSL2 (GTK libraries not natively supported)

### Programmatic Report Generation

```python
from obscura.reporting import AttackReporter
from obscura.autonomous import AttackChain

# Initialize reporter
reporter = AttackReporter(output_dir='reports')

# Generate reports
md_path = reporter.generate_markdown_report(chain)
html_path = reporter.generate_html_report(chain)
pdf_path = reporter.generate_pdf_report(chain)
json_path = reporter.save_json_log(chain)

print(f"Reports generated:")
print(f"  Markdown: {md_path}")
print(f"  HTML: {html_path}")
print(f"  PDF: {pdf_path}")
print(f"  JSON: {json_path}")
```

---

## MITRE ATT&CK Coverage

### ICS/OT Techniques (Industrial Control Systems)

| Technique | MITRE ID | Status | Module | Description |
|-----------|----------|--------|--------|-------------|
| Wireless Network Disruption | **T0884** | Full | Wi-Fi deauth/jam | Denial of service via wireless attacks |
| Spoof Command Message | **T0855** | Full | Camera/IoT inject | Malicious sensor payload injection (MJPEG/RTSP) |
| Modify Parameter | **T0805** | Full | GPS spoofing | Change control loop thresholds via GPS manipulation |
| Exploit Wireless Protocol | **T0861** | Full | BLE/Wi-Fi exploits | Bluetooth and Wi-Fi protocol exploitation |
| Jam Communication Channel | **T0824** | Full | SDR RF jamming | Radio frequency denial (GPS/ADS-B/cellular) |
| Loss of View | **T0829** | Full | Camera hijack | Camera feed spoofing with MJPEG injection |
| Alarm Suppression | **T0838** | Full | Telemetry masking | Visual/telemetry masking on operator consoles |
| Inhibit Response Function | **T0809** | Full | False confidence | Prevent safety fallback via false data injection |
| Modify Control Logic | **T0880** | Development | Future plugin | PLC logic manipulation (roadmap) |

### Enterprise Techniques (IT Networks)

| Technique | MITRE ID | Status | Module | Description |
|-----------|----------|--------|--------|-------------|
| Network Denial of Service | **T1498** | Full | Wi-Fi deauth | Wireless network DoS attacks |
| Adversary-in-the-Middle | **T1557** | Full | Evil Twin/Rogue AP | Man-in-the-middle via rogue access points |
| ARP Cache Poisoning | **T1557.002** | Full | ARP spoof | Layer 2 network manipulation |
| Network Sniffing | **T1040** | Full | Cellular intercept | Passive network traffic capture |
| Endpoint Denial of Service | **T1499** | Full | GPS/BLE jamming | Device-level denial of service |
| Impair Defenses | **T1562** | Full | MFP bypass | Defeat security controls (MFP, WPA3) |

### Tactic Coverage

| Tactic | Techniques | Coverage |
|--------|-----------|----------|
| **Initial Access** | 2 | Rogue AP, Evil Twin |
| **Execution** | 3 | BLE HID injection, Camera injection |
| **Persistence** | 1 | Rogue AP backdoor |
| **Discovery** | 4 | Network scanning, BLE enumeration |
| **Collection** | 5 | Packet sniffing, RTSP capture |
| **Impact** | 8 | Wi-Fi DoS, GPS spoofing, RF jamming |
| **Inhibit Response** | 3 | Alarm suppression, Loss of view |

---

## Advanced Usage

### Custom Plugin Development

**Plugin File Structure**:
```python
# attack_plugins/custom_exploit.py
"""
Custom exploit plugin for Obscura.
Demonstrates plugin API and attack registration.
"""

def register_attack():
    """
    Register attack with orchestrator.
    
    Returns:
        dict: Attack metadata
    """
    return {
        'name': 'custom_exploit',
        'description': 'Custom target exploitation',
        'requirements': ['wifi_monitor', 'root'],
        'mitre_id': 'T1234',
        'tactic': 'Impact',
        'run': execute_attack
    }

def execute_attack(context):
    """
    Execute custom attack.
    
    Args:
        context (dict): Attack context containing:
            - target: Target identifier (MAC, IP, etc.)
            - interface: Network interface
            - orchestrator: AttackOrchestrator instance
            - simulate_mode: Boolean simulation flag
    
    Returns:
        bool: True if successful, False otherwise
    """
    target = context.get('target')
    interface = context.get('interface')
    simulate = context.get('simulate_mode', False)
    
    if simulate:
        print(f"[SIMULATE] Would attack {target} via {interface}")
        return True
    
    # Actual attack implementation
    print(f"[*] Executing custom exploit against {target}")
    
    try:
        # Attack logic here
        result = perform_exploit(target, interface)
        return result
    except Exception as e:
        print(f"[ERROR] Attack failed: {e}")
        return False

def perform_exploit(target, interface):
    """Custom exploit logic"""
    # Implementation details
    return True
```

**Loading Custom Plugins**:
```bash
# Load specific plugins
obscura --load custom_exploit,advanced_attacks --interface wlan0

# Auto-load all plugins from directory
obscura --auto --target traits.json
```

### Programmatic API Usage

**Basic Orchestrator Control**:
```python
from obscura.attacks import AttackOrchestrator

# Initialize orchestrator
orchestrator = AttackOrchestrator(
    interface='wlan0',
    simulate_mode=False,
    battery_saver=False
)

# Register default attacks
orchestrator.register_default_attacks()

# Load custom plugin
orchestrator.load_plugin('custom_exploit')

# List available attacks
attacks = orchestrator.attack_vectors.keys()
print(f"Available attacks: {list(attacks)}")

# Execute specific attack
success = orchestrator.execute_attack(
    'wifi_deauth',
    target='AA:BB:CC:DD:EE:FF',
    duration=60
)

# Stop all attacks
orchestrator.stop_all_attacks()
```

**Autonomous Mode Programming**:
```python
from obscura.attacks import AttackOrchestrator
from obscura.autonomous import AutonomousOrchestrator
import json

# Initialize orchestrators
attack_orch = AttackOrchestrator(interface='wlan0')
auto_orch = AutonomousOrchestrator(
    attack_orchestrator=attack_orch,
    simulate_mode=False
)

# Load target traits
auto_orch.load_traits_from_file('traits.json')

# Define target
target_data = {
    'device_type': 'IoT_Camera',
    'vendor': 'Hikvision',
    'services': ['rtsp', 'http'],
    'signal_strength': -45
}

# Run OODA loop (Observe, Orient, Decide, Act)
chain = auto_orch.run_ooda_loop(
    target_data=target_data,
    max_attacks=3
)

# Generate reports
from obscura.reporting import AttackReporter
reporter = AttackReporter(output_dir='logs')

html_report = reporter.generate_html_report(chain)
json_log = reporter.save_json_log(chain)

print(f"Attack chain completed:")
print(f"  Success: {chain.success}")
print(f"  Attacks: {len(chain.attacks)}")
print(f"  Duration: {chain.end_time - chain.start_time:.2f}s")
print(f"  HTML Report: {html_report}")
```

**Process Manager Integration**:
```python
from obscura.process_manager import get_process_manager

# Get singleton process manager
pm = get_process_manager()

# Check process counts
counts = pm.get_process_count()
print(f"Active processes: {counts['total']}")
print(f"  HackRF: {counts['hackrf']}")
print(f"  Attacks: {counts['attacks']}")

# Get active process list
active = pm.get_active_processes()
for proc in active:
    print(f"  {proc.name} - PID {proc.process.pid}")

# Stop all processes
pm.stop_all_processes(timeout=5)
```

**Rich TUI Programming**:
```python
from obscura.tui import create_tui
from obscura.attacks import AttackOrchestrator
from obscura.hardware import get_hardware_profile
from pathlib import Path

# Initialize orchestrator
orchestrator = AttackOrchestrator(interface='wlan0')

# Get hardware profile
fixtures_dir = Path('fixtures')
profile = get_hardware_profile(fixtures_dir)

# Create TUI
tui = create_tui(orchestrator, profile)

# Add attack progress
tui.add_attack_progress('wifi_deauth', 'AA:BB:CC:DD:EE:FF', mitre_id='T1498')

# Update progress
tui.update_attack_progress('wifi_deauth', 'AA:BB:CC:DD:EE:FF', 75.0, 'running')

# Add log entry
tui.add_log('[*] Deauth attack initiated')

# Run TUI (blocking)
tui.run(update_interval=1.0)

# Print summary on exit
tui.print_summary()
```

---

## Testing & Validation

### Hardware Detection

```bash
# Display comprehensive hardware profile
obscura --show-hardware

# Example output:
# [+] Hardware Detection Summary
# 
# SDR Devices: 1
#   - HackRF One (serial: 0000000000000000a06063c8234d565f)
# 
# Wi-Fi Adapters: 2
#   - wlan0 (Realtek RTL8812AU) - Monitor Mode: ENABLED
#   - wlan1 (Intel Wi-Fi 6 AX200) - Monitor Mode: DISABLED
# 
# BLE Adapters: 1
#   - hci0 (Intel AX200 Bluetooth)
# 
# Fallback Mode: DISABLED
```

### Simulation Mode (Safe Testing)

```bash
# Test attack logic without RF emissions or network manipulation
obscura --simulate --auto --target traits.json

# All attacks run in dry-run mode
# - No packets transmitted
# - No RF signals emitted
# - Reports generated with simulated success
# - Full OODA loop execution

# Output:
# [SIMULATE] Camera jam simulated
# [SIMULATE] Wi-Fi deauth simulated
# [SIMULATE] GPS spoof simulated
# [+] Attack chain completed (simulated)
```

### Plugin Listing

```bash
obscura --list-attacks

# Example output:
# === Available Attack Vectors ===
# 
# Default Attack Vectors:
#   - wifi_deauth
#   - camera_jam
#   - gps_spoof
#   - ble_disrupt
#   - rf_jam
#   - rogue_ap
#   - evil_twin
#   - arp_poison
# 
# Loaded Plugins:
#   - advanced_attacks
#   - custom_exploits
#   - experimental_rf
# 
# Total: 11 attack vectors available
```

### Configuration Validation

```bash
# Validate configuration file
obscura --config config.yaml --validate

# Validation output:
# [+] Configuration loaded from: config.yaml
# [+] Validating configuration...
# [OK] All configuration parameters valid
```

### Export Attack Graph

```bash
# Export attack capabilities to SVG graph
obscura --export attack_graph.svg

# Generates visualization of:
# - Available attack vectors
# - Plugin relationships
# - MITRE ATT&CK mapping
# - Attack prerequisites
```

---

## Legal & Safety

### CRITICAL WARNINGS

**LEGAL COMPLIANCE REQUIRED**:
- **AUTHORIZATION MANDATORY**: Written permission required for all attack operations
- **RF REGULATIONS**: Comply with FCC (USA), OFCOM (UK), and local RF transmission laws
- **NO PRODUCTION SYSTEMS**: Use only in isolated labs, cyber ranges, or CTF environments
- **FARADAY CAGE RECOMMENDED**: Prevent unintended RF signal leakage
- **AIR GAP REQUIRED**: Never connect to production networks
- **LOGGING MANDATORY**: Maintain audit logs for all operations

### RF Safety Interlock System

Obscura implements mandatory safety interlocks to prevent accidental RF transmission:

```bash
# Set RF safety interlock (REQUIRED)
export OBSCURA_RF_LOCK=1

# Add to shell profile for persistence
echo 'export OBSCURA_RF_LOCK=1' >> ~/.bashrc
source ~/.bashrc

# Verify interlock status
env | grep OBSCURA_RF_LOCK
```

**Override Safety** (Authorized Testing Only):
```bash
obscura --override-safety --interface wlan0

# Warning displayed:
# [WARNING] Safety interlock bypassed via --override-safety
# [WARNING] Ensure you are in an authorized testing environment
```

### Intended Use Cases (AUTHORIZED)

- **Penetration Testing Engagements**: Client-authorized security assessments
- **Red Team Exercises**: Authorized adversary emulation with written scope
- **CTF Competitions**: Capture The Flag events and security challenges
- **Academic Research**: University/institution research programs
- **Security Product Testing**: Testing own equipment in controlled environments
- **Defensive Posture Validation**: Purple Team exercises with authorization

### Prohibited Use Cases (ILLEGAL)

- **Unauthorized Network Attacks**: Any attack without explicit written permission
- **Illegal RF Transmissions**: Violates FCC Part 15, OFCOM regulations
- **Critical Infrastructure**: Power grids, water systems, hospitals, emergency services
- **Aircraft/Aviation**: ADS-B interference, GPS spoofing near airports
- **Maritime Navigation**: AIS spoofing, GNSS disruption
- **Cellular Networks**: GSM/LTE jamming (illegal in most jurisdictions)
- **Emergency Communications**: Police/Fire/EMS radio disruption

### Legal Framework

**United States**:
- FCC Part 15 (RF Devices)
- Computer Fraud and Abuse Act (CFAA)
- Electronic Communications Privacy Act (ECPA)
- Wiretap Act (18 U.S.C. § 2511)

**United Kingdom**:
- Wireless Telegraphy Act 2006
- Computer Misuse Act 1990
- Communications Act 2003

**European Union**:
- Radio Equipment Directive (RED) 2014/53/EU
- Network and Information Security (NIS) Directive

**Penalties**: Unauthorized use can result in:
- Criminal prosecution
- Fines up to $1,000,000 USD (FCC violations)
- Imprisonment (up to 10 years for CFAA violations)
- Civil liability
- Equipment seizure

### Developer Liability Disclaimer

**DEVELOPERS ASSUME ZERO LIABILITY FOR MISUSE**. This software is provided "AS IS" without warranty of any kind. Users are solely responsible for compliance with all applicable laws and regulations. By using Obscura, you agree to use it only for authorized, legal purposes in controlled environments.

---

## Use Cases

### Red Team Engagement Example

**Client**: Financial Institution  
**Scope**: Wireless security assessment of corporate headquarters  
**Authorization**: Written Statement of Work with defined IP ranges and wireless networks  
**Duration**: 5-day engagement

**Obscura Results**:
- **Rogue Networks**: 23 unauthorized Wi-Fi networks detected and exploited
- **IoT Cameras**: 12 IP cameras compromised via default credentials (Hikvision, Dahua)
- **BLE Devices**: 5 BLE proximity badges enumerated with GATT service extraction
- **GPS Spoofing**: Proof-of-concept demonstrated against delivery drone navigation
- **Report**: 45-page PDF with executive summary, MITRE ATT&CK mapping, remediation recommendations

**Timeline**:
- Day 1: Wireless reconnaissance, hardware profiling
- Day 2-3: Active exploitation, attack chain execution
- Day 4: GPS spoofing PoC, camera deepfake demonstration
- Day 5: Report generation, client debriefing

**Deliverables**:
- HTML dashboard (real-time attack monitoring)
- PDF report (client presentation)
- JSON logs (SIEM integration)
- Remediation roadmap

### CTF Competition Example

**Event**: DEF CON CTF Qualifiers 2025  
**Challenge**: Multi-vector IoT exploitation (500 points)  
**Scenario**: Compromise IoT camera network, extract flag from RTSP stream

**Obscura Usage**:
1. **Autonomous Mode**: Loaded target traits (IoT_Camera, Hikvision, signal=-40dBm)
2. **Attack Selection**: AI selected optimal chain:
   - Camera RTSP hijack
   - Wi-Fi deauth (force re-authentication)
   - BLE HID injection (bypass physical security)
3. **Execution**: Autonomous OODA loop completed in 2 minutes
4. **Result**: First blood on challenge

**Time Saved**: Estimated 6 hours of manual exploitation avoided  
**Score Impact**: 500 points, team ranking improved from 15th to 3rd

### Penetration Testing Example

**Client**: Manufacturing Facility (OT/ICS Environment)  
**Scope**: Wireless security assessment of production floor  
**Devices**: 50+ IoT sensors, 20 IP cameras, 5 Wi-Fi networks

**Obscura Deployment**:
- **Mode**: TUI (live dashboard for client demonstration)
- **Attacks**: Wi-Fi deauth, camera enumeration, BLE sensor discovery
- **Report**: HTML report with MITRE ICS technique mapping (T0884, T0829)

**Findings**:
- 18 devices vulnerable to default credentials
- 3 Wi-Fi networks without WPA2/WPA3 encryption
- 12 cameras exposing RTSP streams without authentication
- 7 BLE sensors with writable characteristics (no encryption)

**Recommendations**:
- Implement network segmentation (OT vs IT)
- Deploy certificate-based authentication (802.1X)
- Upgrade to WPA3-Enterprise
- Enable MFP (Management Frame Protection)

---

## Contributing

We welcome contributions from the security research community. Obscura is an open-source project that benefits from collaborative development.

### Priority Development Areas

**High Priority**:
- [ ] LTE/5G cellular exploitation modules (gr-lte integration)
- [ ] Zigbee/Z-Wave attack vectors (KillerBee integration)
- [ ] SCADA/Modbus protocol exploitation
- [ ] Machine learning-powered packet injection
- [ ] Cloud C2 integration (Cobalt Strike, Mythic, Empire)

**Medium Priority**:
- [ ] Additional SDR hardware support (LimeSDR, PlutoSDR)
- [ ] LoRaWAN attack modules
- [ ] Docker container orchestration
- [ ] Web-based management interface
- [ ] Multi-operator coordination features

**Low Priority**:
- [ ] Windows native support (no WSL)
- [ ] Mobile app (Android/iOS)
- [ ] Hardware appliance (Raspberry Pi image)

### Development Setup

```bash
# Clone repository
git clone https://github.com/ridpath/heaplessNights.git
cd obscura

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run linting
flake8 obscura/
pylint obscura/

# Run type checking
mypy obscura/
```

### Pull Request Guidelines

1. **Fork Repository**: Create personal fork on GitHub
2. **Create Branch**: `git checkout -b feature/your-feature-name`
3. **Write Tests**: Add unit tests for new functionality
4. **Follow Style**: PEP 8 compliance, type hints, docstrings
5. **Test Locally**: Ensure all tests pass (`pytest`)
6. **Commit Messages**: Descriptive messages (`git commit -m "Add LTE jamming module"`)
7. **Submit PR**: Include description of changes and test results

### Code Style Requirements

- PEP 8 compliance (enforced by flake8)
- Type hints for all functions (mypy validation)
- Docstrings (Google style)
- Maximum line length: 120 characters
- No trailing whitespace
- Unix line endings (LF)

### Security Disclosure

**Responsible Disclosure Policy**:
- Email: security@obscura-project.org
- PGP Key: Available on project website
- Response Time: 48 hours for acknowledgment
- Disclosure Timeline: 90 days before public disclosure

**Scope**:
- Security vulnerabilities in Obscura code
- Privilege escalation bugs
- Authentication bypass
- RF safety interlock bypass

---

## Resources

### Official Documentation

- **MITRE ATT&CK ICS Matrix**: https://attack.mitre.org/matrices/ics/
- **MITRE ATT&CK Enterprise**: https://attack.mitre.org/matrices/enterprise/
- **HackRF Documentation**: https://hackrf.readthedocs.io/
- **GNU Radio Wiki**: https://wiki.gnuradio.org/
- **Aircrack-ng Documentation**: https://www.aircrack-ng.org/documentation.html

### Related Security Tools

**Wireless Auditing**:
- [Airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon) - Multi-use wireless security auditing tool
- [Bettercap](https://www.bettercap.org/) - Swiss Army knife for network attacks
- [WiFi Pineapple](https://shop.hak5.org/products/wifi-pineapple) - Commercial rogue AP platform
- [Kismet](https://www.kismetwireless.net/) - Wireless network detector

**BLE/Bluetooth**:
- [Ubertooth](https://github.com/greatscottgadgets/ubertooth) - Bluetooth monitoring/exploitation
- [KillerBee](https://github.com/riverloopsec/killerbee) - Zigbee exploitation framework
- [Bluefruit LE Sniffer](https://www.adafruit.com/product/2269) - BLE protocol analyzer

**SDR**:
- [GPS-SDR-SIM](https://github.com/osqzss/gps-sdr-sim) - GPS signal simulator
- [gr-gsm](https://github.com/ptrkrysik/gr-gsm) - GSM analysis with GNU Radio
- [dump1090](https://github.com/antirez/dump1090) - ADS-B decoder

**HID Injection**:
- [P4wnP1 A.L.O.A.](https://github.com/mame82/P4wnP1_aloa) - Advanced HID injection platform
- [Rubber Ducky](https://shop.hak5.org/products/usb-rubber-ducky) - Commercial keystroke injection

### Learning Resources

**Books**:
- "The Hacker Playbook 3" by Peter Kim
- "Advanced Penetration Testing" by Wil Allsopp
- "Wireless Networks: First-Step" by Jim Geier
- "Software Defined Radio for Engineers" by Travis F. Collins

**Training**:
- Offensive Security Wireless Professional (OSWP)
- SANS SEC617: Wireless Penetration Testing
- eLearnSecurity Mobile Application Penetration Tester (eMAPT)

**Conferences**:
- DEF CON (Wireless Village, RF Hacking Village)
- Black Hat USA/Europe/Asia
- ShmooCon
- ToorCon

---

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2026 Obscura Project Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

**Free for Authorized Security Research and Testing**

---

## Contact & Support

- **GitHub Issues**: https://github.com/ridpath/heaplessNights/issues
- **Security Researchers**: Responsible disclosure appreciated (security@obscura-project.org)
- **Commercial Licensing**: Enterprise support and custom development available
- **Twitter**: @ObscuraProject
- **Discord**: https://discord.gg/obscura

---

## Acknowledgments

Built with contributions from the security research community.

**Special Thanks**:
- Aircrack-ng team (Wi-Fi exploitation foundation)
- HackRF project maintainers (Michael Ossmann and team)
- MITRE ATT&CK framework contributors
- GNU Radio community
- Great Scott Gadgets (hardware support)

**Powered By**:
- Python 3.10+
- Scapy (packet manipulation)
- GNU Radio (SDR framework)
- Rich (terminal UI)
- WeasyPrint (PDF generation)

---

<p align="center">
  <strong>Built by operators, for operators</strong><br>
  <sub>Obscura - Because defense requires understanding the offense</sub>
</p>

<p align="center">
  <sub>WARNING: USE RESPONSIBLY | AUTHORIZED TESTING ONLY | LEGAL COMPLIANCE REQUIRED</sub>
</p>

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
