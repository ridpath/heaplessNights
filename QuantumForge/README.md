<!--
QuantumForge malware research framework, in-memory loader, AES-HKDF encrypted payloads,
polymorphic fileless execution, cross-platform red team tooling, Windows reflective DLL,
Linux memfd_create shellcode loader, macOS mach_vm_allocate injection,
JPEG polyglot steganography payload, C2 over DNS-over-HTTPS,
anti-analysis stealth loader, CPUID anti-VM detection,
offensive tradecraft research loader, post-exploitation in memory only,
reflective injection AES loader, blue team evasion, APT style TTP emulation,
malware development research, cybersecurity education toolkit,
Fileless C2 payload framework, OT cyber range payload delivery,
DNS covert channel activation, process name spoofing, ridpath GitHub
-->

# QuantumForge  
**Cross-Platform In Memory Payload Orchestrator**  
*Polymorphic Loader | AES-HKDF Encryption | DNS-over-HTTPS C2 Activation*

![Status Alpha](https://img.shields.io/badge/status-alpha-yellow)
![Stealth Mode](https://img.shields.io/badge/stealth-fileless%2Fpolymorphic-purple)
![Platform Linux](https://img.shields.io/badge/Linux-supported-success)
![Platform Windows](https://img.shields.io/badge/Windows-research--mode-blue)
![Platform macOS](https://img.shields.io/badge/macOS-experimental-orange)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20Mapping-partial-critical)
![License MIT](https://img.shields.io/badge/license-MIT-blue)

> **Educational + authorized red-team engagements only**  
> Unauthorized usage may violate international laws.  
> *You are responsible for your actions.*

---

## DISCLAIMER

**For educational and authorized red team engagements only.**  
Use of this code without proper authorization may violate laws and ethical guidelines.  
**You are responsible for your actions.**

---

## Overview

**QuantumForge** is an advanced post-exploitation loader framework with the following goals:

- **Cross-platform compatibility** (Linux, macOS, Windows)
- **In-memory execution** only (no disk writes)
- **Polymorphic, self-modifying loader**
- **AES-256-CBC + HKDF** payload encryption
- **Modular second-stage loading**:
  - Shellcode
  - Reflective `.so`/`.dll` injection (stage2)
- **C2 trigger via DNS-over-HTTPS**
- **Beaconing via HTTPS POST**
- **Static and behavioral anti-analysis defenses**

---

## Supported Platforms

| Platform | Loader Artifact | Execution Vector | Second-Stage Support | Status |
|----------|----------------|------------------|---------------------|--------|
| Linux | quantum_server | memfd_create → dlopen FD | Shellcode, ELF, .so | Stable |
| Windows | quantum_loader_win.exe | Reflective DLL (planned) | Shellcode only | Planned |
| macOS | quantum_loader_mac | mach_vm_allocate | Shellcode | Experimental |

---

## Features

- **AES-256-CBC + HKDF** encryption (OpenSSL / Bcrypt / CCCrypt)
- **XOR-masked memory** post-decryption
- **Polymorphic payloads** with randomized NOP sleds (`junk.h`)
- **DNS-over-HTTPS activation trigger**
- **HTTPS beaconing** (base64-encoded POST)
- **Second-stage loader**:
  - Linux: `dlopen()` from `memfd_create`
  - Windows: Reflective loader (stub included)
  - macOS: Shellcode (Mach-O loader optional)
- **Self-delete & unlink** logic
- **Anti-debug, anti-vm, anti-sandbox** (RDTSC, sysctl, CPUID, etc)
- **JPEG polyglot** creation for social engineering
- **Section scrubbing + mprotect(PROT_NONE)** to erase decrypted data
- **Process name spoofing** (`[kworker]`, `svchost.exe`, `launchd`)

---

## Usage

1️. Build Linux Payload

```bash
./quantum_forge.sh cat.jpg payload.bin 00112233445566778899aabbccddeeff 0123456789abcdef
Output: cat.jpg (JPEG+ELF polyglot)
```
2️. Build Windows Payload
```powershell
.\quantum_forge_win.ps1 -Image "cat.jpg" -Payload "win_payload.bin" `
  -BaseKey "QuantumKey123456" -Salt "FixedSalt456" -IV "1234567890abcdef"
Output: cat.jpg (JPEG+EXE polyglot)
```
3️. Build macOS Payload
```bash
./quantum_forge_mac.sh cat.jpg payload_macos.bin QuantumKey123 FixedSalt456 1234567890abcdef
Output: cat.jpg (JPEG+Mach-O polyglot)
```
### Runtime Flags

Command-line options for modifying operational behavior:

| Flag | Description |
|------|-------------|
| --no-doh | Disable DNS-over-HTTPS activation trigger |
| --no-selfdelete | Prevent the loader from deleting itself post execution |
| --fallback-only | Serve payload locally on HTTP port 8080 only (no remote activation) |

These switches enable controlled execution during analysis or testing without fully enabling covert C2 workflows.

---

### C2 Trigger and Beaconing via DNS-over-HTTPS

QuantumForge uses **DNS-over-HTTPS (DoH)** for covert activation and HTTPS POST for beaconing.

Trigger activation remotely by setting a TXT record:
- c2.example.com TXT "C2_TRIGGER:1"

Once triggered, the loader retrieves second-stage data via:
- https://c2.example.com/beacon

Payloads are transmitted as:

• Base64-encoded shellcode  
• Encrypted binary blobs  
• Optional staged modules depending on OS capabilities  

This allows a **C2 channel without direct DNS visibility**, reducing network forensics exposure.

---

### Analysis Evasion Techniques

Integrated anti-analysis safeguards designed to hinder sandboxes, AV heuristics, and debugger assisted inspection:

| Category | Technique |
|----------|-----------|
| Instruction Polymorphism | Randomized instruction padding via compile-time injection |
| Section Name Mutation | Random string replacement for `.text` and executable sections |
| Memory Wiping | `mprotect(PROT_NONE)` and `scramble_self()` erase decrypted regions |
| Anti-Debugging | Detection of TracerPid, ptrace, and NtQueryInformationProcess |
| Anti-VM Detection | Vendor lookup in CPUID and hypervisor fingerprint checks |
| Anti-Sandbox Detection | High-resolution timing drift via RDTSC and sleep delta validation |

Memory is kept in a volatile state only long enough for execution to complete, reducing forensic recoverability.
<!--
QuantumForge DNS-over-HTTPS C2, fileless execution flags, stealth loader runtime options,
base64 beaconing encrypted payloads, C2 command activation DNS TXT trigger,
post-exploitation covert channel research, red team stealth techniques,
anti-debug CPUID checks, malware memory wiping protections,
advanced anti-sandbox timing evasion, encrypted payload command line options,
cybersecurity research loader, in-memory ELF/Mach-O execution,
fileless malware detection evasion, offensive security payload flags,
ridpath quantumforge project
-->

---
### Second-Stage Payload Compatibility Matrix

QuantumForge includes a modular payload-loading architecture designed to support fileless, memory-resident execution across multiple platforms. Coverage varies depending on OS APIs, loader maturity, and attack vector.

| Payload Type | Linux Support | Windows Support | macOS Support | Technical Notes |
|-------------|---------------|----------------|---------------|----------------|
| Raw Shellcode | Supported | Supported | Supported | Direct execution from allocated memory regions |
| ELF Executable | Supported | Not Supported | Not Supported | `exec_memfd()` memory execution on Linux |
| Shared Object (.so) | Supported | Not Supported | Not Supported | `dlopen()` on `/proc/self/fd/N` enables fileless library loading |
| Reflective DLL (.dll) | Not Supported | Planned | Not Supported | Windows stub included; reflective loader implementation pending |
| Mach-O dylib | Planned | Not Supported | Planned | Requires custom Mach-O loader + `mach_vm` injection routines |

> All payloads are decrypted, mapped, and executed entirely in memory to avoid disk forensics and IOC generation.
<!--
QuantumForge second-stage payload support,
in-memory shellcode execution Linux macOS Windows,
ELF fileless loader memfd_create dlopen reflective DLL,
Mach-O dylib injection cybersecurity research,
polymorphic payload delivery cross-platform,
advanced post-exploitation modular payload chaining,
fileless malware analysis evasion research,
C2 in-memory staging capability,
security red team tradecraft framework,
malware development research loader technology,
cross-OS exploit payload compatibility table, github.com/ridpath
-->

---
### Notes

Payload encryption is never stored in plaintext on disk.

All second-stage logic executes entirely in memory.

Polyglot payloads will open as JPEGs when inspected by analysts or tools.


## Authorized Use Only

Use of QuantumForge must be limited to systems and environments where you have explicit permission.  
Improper or malicious deployment is strictly prohibited.


---
## License

MIT License for research and educational use.


<!--
QuantumForge fileless agent, red team cybersecurity loader, DNS Covert C2 trigger,
memory resident payload Linux, AES-HKDF loader Windows, Mach-O shellcode injector,
Reflective loader cybersecurity, advanced malware research framework,
APT tradecraft emulation toolkit, anti-sandbox red team loader,
JPEG polyglot encrypted payload, cyber weapon research tool,
security testing of incident response detection bypass,
fileless post-exploitation demonstration, advanced cross-platform payload runner,
ridpath cybersecurity research project, memory encryption evasion,
C2 implant demonstration for defensive training, cybersecurity lab tooling
-->




