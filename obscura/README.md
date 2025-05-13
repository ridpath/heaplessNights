# Obscura

Obscura is a signal jamming tool. It provides capabilities to detect and jam Wi-Fi cameras, Bluetooth devices, and entire networks using techniques like deauthentication and SDR jamming with HackRF. Written in Python, it features a rich terminal-based UI for real-time monitoring and control.

## Features
- **Camera Jamming**: Detects and jams Wi-Fi cameras based on MAC address OUIs and traffic patterns.
- **Bluetooth Jamming**: Disrupts Bluetooth signals.
- **Network Deauthentication**: Performs deauth attacks on Wi-Fi networks, with support for Management Frame Protection (MFP) bypass using `mdk4`.
- **SDR Jamming**: Uses HackRF for broad-spectrum jamming.
- **Rich UI**: Displays detected devices, jamming status, and logs in a terminal interface.

## Installation

### Prerequisites
Obscura requires root privileges and specific system tools, typically available on Kali Linux or similar distributions.

#### System Dependencies
Install the required tools on Kali Linux:
```bash
sudo apt-get update
sudo apt-get install iw macchanger bluez aircrack-ng hackrf mdk4 libpcap0.8t64
aircrack-ng includes airmon-ng and aireplay-ng.

hackrf includes hackrf_transfer.

bluez provides hciconfig.

libpcap0.8t64 is required for packet capture.

Verify HackRF connectivity (if using SDR jamming):
hackrf_info

Python Dependencies
Create and activate a virtual environment (recommended):
bash

python3 -m venv jammer_venv
source jammer_venv/bin/activate

Install Python packages:
bash

pip install -r requirements.txt

Usage
Run Obscura with root privileges, specifying a wireless interface (e.g., wlan0):
bash

sudo python3 obscura.py --interface wlan0

Or, make the script executable:
bash

chmod +x obscura.py
sudo ./obscura.py --interface wlan0
```

## Controls
1: Toggle Camera Jamming (targets detected cameras).

2: Toggle Bluetooth Jamming (sends random Bluetooth packets).

3: Toggle Deauth Everything (attacks the strongest network for 2 minutes).

4: Toggle SDR Jamming (jams with HackRF for 5 minutes).

~: Enter Live Python Shell (for debugging or customization; type exit() to return).

n/p: Next/Previous Page (for camera and network tables).

q: Quit the application.

Jamming Modes
Camera Jamming: Continuously sends deauth packets to detected camera MACs.

Bluetooth Jamming: Sends random L2CAP packets via hci0.

Network Deauthentication: Targets a network’s BSSID and clients; uses mdk4 for MFP-enabled networks.

SDR Jamming: Transmits noise on a network’s channel using HackRF.

Example Output
Upon running, the UI displays:
Detected Cameras: MAC, SSID, vendor, jamming status, etc.

Wi-Fi Networks: BSSID, SSID, signal strength, channel, MFP status.

Stats: Packet counts, jamming status, uptime.

Progress: Real-time jamming feedback.

Notes
The script auto-detects interfaces if --interface is omitted.

Logs are saved to jammer_log.txt in the script’s directory.

Requires monitor mode; the script attempts to enable it automatically.

## Disclaimer
Obscura is intended for educational and authorized testing purposes only. Jamming signals may be illegal in some jurisdictions. Use responsibly and only in environments where you have explicit permission.



