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
**Cross-Platform In-Memory Payload Loader**  
*Polymorphic Execution · Encrypted Payloads · Covert Activation Channels*

![Status Research](https://img.shields.io/badge/status-research-blue)
![Stealth Fileless](https://img.shields.io/badge/stealth-fileless%2Fpolymorphic-purple)
![Platform Linux](https://img.shields.io/badge/Linux-supported-success)
![Platform Windows](https://img.shields.io/badge/Windows-supported-blue)
![Platform macOS](https://img.shields.io/badge/macOS-supported-orange)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-mapped-critical)
![License MIT](https://img.shields.io/badge/license-MIT-blue)

> **For security research, malware analysis, and authorized red-team use only.**  
> Use against systems without explicit permission is illegal.

---

## Overview

**QuantumForge** is a cross-platform, memory-resident loader designed to study modern post-exploitation tradecraft and fileless execution techniques across Linux, Windows, and macOS.

The project focuses on:
- In-memory payload delivery
- Encrypted, staged execution
- Covert activation and beaconing
- Anti-analysis and forensic resistance

Rather than acting as a full command-and-control framework, QuantumForge intentionally concentrates on the loader problem: how second-stage code is decrypted, staged, executed, and erased without touching disk.

---

## Design Goals

- Memory-only execution with minimal forensic footprint  
- Platform-specific loaders rather than lowest-common-denominator abstractions  
- Cryptographic correctness over obfuscation theater  
- Tradecraft realism aligned with observed adversary techniques  
- Deterministic behavior suitable for analysis and lab testing  

---

## Core Capabilities

### Execution & Staging
- Fully in-memory payload decryption and execution
- Linux: memfd_create + execveat / dlopen
- Windows: reflective DLL loading
- macOS: mach_vm_allocate-based injection
- Optional JPEG polyglot payload container

### Cryptography
- AES-256-CBC payload encryption
- HKDF key derivation (RFC 5869)
- Constant-time comparisons
- Explicit memory wiping after use

### Activation & Beaconing
- DNS-over-HTTPS (DoH) activation trigger
- HTTPS POST beaconing with encoded payloads
- Configurable resolvers and fallback behavior

### Anti-Analysis
- Debugger and VM heuristics
- Timing-based sandbox checks
- Process name spoofing
- Memory region scrubbing and protection changes

---

## Supported Platforms

| Platform | Loader Strategy |
|--------|----------------|
| Linux | memfd_create, execveat, fileless .so loading |
| Windows | Reflective PE loading |
| macOS | Mach-O shellcode injection |

Implementation details are platform-specific by design.

---

## Building

### Quick Build
```bash
bash compile_all.sh
```

### CMake
```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Hardening flags and optional features are documented in `docs/builds.md`.

---

## Usage

### Test Mode (Safe Validation)
```bash
./quantumserver --test-mode --no-doh --no-selfdelete
```

This validates:
- Key derivation
- Payload decryption
- Memory handling  

without network activation or cleanup behavior.

### Runtime Flags (Selected)

| Flag | Description |
|-----|-------------|
| --test-mode | Disable C2 and self-deletion |
| --no-doh | Skip DNS-over-HTTPS activation |
| --no-selfdelete | Preserve loader for inspection |
| --stage-file <path> | Load local second stage |

Full flag reference is in `docs/usage.md`.

---

## MITRE ATT&CK Alignment

QuantumForge maps observed loader behaviors to MITRE ATT&CK (Enterprise) techniques related to:
- In-memory execution
- Obfuscated payloads
- Covert command activation
- Defense evasion


---

## Loader Internals

The internal execution flow of QuantumForge loaders across supported platforms.

### High-Level Flow

1. Loader initialization and environment checks
2. Anti-analysis and debugger heuristics
3. Key derivation and payload decryption
4. In-memory staging
5. Second-stage execution
6. Memory scrubbing and optional self-deletion

### Staging Philosophy

QuantumForge intentionally separates:
- **Activation** (when execution is allowed)
- **Decryption** (when plaintext exists in memory)
- **Execution** (when control is transferred)

Plaintext payloads exist only for the minimum required window.

### Platform-Specific Execution

#### Linux
- Payload mapped using `memfd_create`
- Executed via `execveat` or loaded via `dlopen`
- No filesystem artifacts are written

#### Windows
- Reflective PE loading
- Manual mapping of sections and IAT resolution
- Execution via in-memory entry point transfer

#### macOS
- Payload allocated with `mach_vm_allocate`
- Permissions updated with `vm_protect`
- Instruction pointer redirected into injected region

### Cleanup

After execution:
- Decrypted buffers are wiped
- Memory protections may be revoked
- Loader optionally unlinks itself


---
## Anti-Analysis Techniques

Analysis resistance techniques implemented in QuantumForge.

### Goals

- Increase cost of dynamic analysis
- Detect common sandbox and VM environments
- Disrupt automated detonation pipelines

### Debugger Detection

- TracerPid checks (Linux)
- `ptrace` self-attachment
- Windows debugger queries
- Timing inconsistencies

### Virtualization Heuristics

- CPUID vendor strings
- Hypervisor bit checks
- Environment artifact detection

### Sandbox Detection

- RDTSC timing drift
- Sleep delta validation
- Process tree inspection

### Memory Defense

- Section permission changes
- PROT_NONE / PAGE_NOACCESS after use
- Explicit buffer wiping
---
## Build and Hardening Options

Build-time options and hardening strategies.

### Build Systems

QuantumForge supports:
- Shell-based compilation
- CMake-based builds

### Hardening Flags

Common flags include:
- Stack protection
- Position-independent execution
- RELRO and NX stack
- Symbol visibility reduction

### Optional Features

- Static builds (Linux)
- Sanitizer builds (testing only)
- Coverage instrumentation

### Tradeoffs

Hardening may:
- Increase binary size
- Reduce portability
- Complicate debugging

Build profiles should match the intended analysis environment.
---
## Legal & Ethics

This project is intended for:
- Malware research and reverse engineering
- Authorized red-team exercises
- Controlled lab and CTF environments

Unauthorized use against third-party systems is illegal and unethical.

---

## License

MIT License.  
See LICENSE for details.
