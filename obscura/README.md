# 🛰 Obscura 

> ⚠️ **Alpha Release** — unstable features, experimental modules, and active development. Use in controlled/CTF/lab environments only.

**Obscura** is an autonomous, extensible adversarial operations framework designed for CTF teams, red teams, and research into next-generation cyber-physical attack vectors.

Built to bridge classic wireless attacks, SDR interference, IoT disruption, BLE exploitation, satellite spoofing, and AI-driven adversary simulation — all under a unified orchestration layer.


##  WARNING: This tool is for educational and authorized testing purposes only. Unauthorized use on networks, systems, or frequencies you do not own or have explicit permission to test is illegal and unethical. Use only in controlled environments like Faraday cages or with proper authorization. The developers are not responsible for any misuse or damage caused by this tool.



## Key Features

| Module                | Capability                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| Wi-Fi Attacks       | Deauth, Rogue AP, Evil Twin, Hybrid Deauth                                 |
| Camera Attacks     | RTSP injection, MJPEG spoof, deepfake replay, fingerprinting               |
| BLE/Bluetooth      | Disruption, LLM-based fuzzing, HID spoof, audio replay                     |
| SDR/Radio          | BLE jamming, GPS spoof, RF replay, ADS-B broadcast                         |
| AI/LLM Modules     | AutoRedTeam, Cognitive Dissonance Engine, Predictive Adversary             |
| Satellite Modules   | GNSS spoofing, satellite tracking, DVB stream hijack, Iridium analysis     |
| Multi-Protocol     | MITM chaining, replay amplification, synthetic sensor injections           |
| Attack Graphing    | Auto-generates DOT/SVG attack chain graphs from logs                       |
| Live Interaction   | Launch Python shell into orchestrator context                              |

---

## Status: Alpha Release

> This framework is under **active development**. Some features may be broken, incomplete, or require external dependencies.

Known limitations:

- Some attacks assume files exist at hardcoded paths (e.g., `/tmp/gan_live.mp4`)
- BLE/Bluetooth fuzzing may crash systems with fragile drivers
- Deep chaining assumes strict interface setup (`monitor` mode, firmware-specific tools)
- SDR attacks assume presence of `hackrf_transfer`, `gps-sdr-sim`, `rtl_power`, etc.
- No input validation for plugin APIs — plugins can fail silently

Use in safe, **controlled lab/CTF environments** only.

---

## Plugin-Based Architecture

The orchestrator supports dynamic plugin loading:

```python
orchestrator.load_plugin("advanced_attacks")
orchestrator.load_all_plugins()
```
## Getting Started
1. Install Dependencies
Run from the project root:

pip install -e .

2. Run the Orchestrator
If you installed using pyproject.toml, launch via:

obscura

Or with full path (e.g. pyenv):

sudo -E /home/kali/.pyenv/versions/3.11.9/bin/obscura

✅ sudo -E preserves your environment variables

## 🤝 Contributing

Contributions are welcome! To get started, follow these steps:

1. **Fork the Repository**  
   Click the "Fork" button in the top right of this page to copy the repo to your GitHub account. Then, clone your fork to your local machine:  

   ```bash
   git clone https://github.com/ridpath/obscura/obscura.git
   cd obscura
   ```

2. **Create a Feature Branch**  
   Create a new branch for your feature or bug fix:  

   ```bash
   git checkout -b feature/your-feature-name
   ```
Make Your Changes
Add new attacks, improve existing modules, or fix bugs.  
Please follow the existing coding style (e.g., snake_case, include docstrings).  

Keep attack modules modular and self-contained.

Test Your Changes
Ensure your changes:  
Do not break existing features.  

Work with optional module loaders (e.g., load_gnuradio(), load_cv2()).  

Are stable when run via AttackOrchestrator.

Commit & Push
Commit your changes with a descriptive message and push to your fork:  

   ```bash
   git add .
git commit -m "Add: New BLE spoof attack module"
git push origin feature/your-feature-name
   ```
Submit a Pull Request
Open a Pull Request (PR) on GitHub and include:  
A summary of what you added or changed.  

The modules affected.  

Testing status (e.g., "Tested on Ubuntu with HackRF").  

Any dependencies or setup notes.


###  Coding Standards
Please adhere to these conventions:  
Modular Attacks: Register new attack vectors using self.register_attack(...).  

Threading: Use threading.Thread or subprocess.Popen for long-running tasks.  

Dynamic Imports: Load heavy libraries dynamically (e.g., load_cv2(), load_gnuradio()).  

Hardcoding: Avoid hardcoding values unless necessary for testing.  

Comments: Add detailed comments for complex logic, especially RF or GNU Radio operations.

###  Adding New Plugins
To add a new attack plugin:  
Place your file in attack_plugins/your_attack.py.  

Expose a run(...) method or register the attack via the AttackOrchestrator.  

Use log_message() and self.attack_log.append(...) to document actions and results.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Disclaimer
Obscura is intended solely for educational purposes and authorized penetration testing in controlled environments. Unauthorized use on live systems, networks, or RF frequencies without explicit permission is illegal and unethical. Always comply with local laws and regulations, including FCC guidelines for RF transmissions. The developers disclaim any liability for misuse or resulting damages.

