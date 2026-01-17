# Linux Loader Enhancements

## Overview

This document describes the enhanced Linux loader capabilities implemented in `quantumserver.c` for QuantumForge. These enhancements provide advanced post-exploitation capabilities with complete memory-resident execution and EDR evasion.

## Implemented Features

### 1. EDR Hook Detection

**Function**: `check_edr_hooks()`

Detects EDR (Endpoint Detection and Response) instrumentation via:

- **LD_PRELOAD environment variable**: Checks if libraries are preloaded (common EDR technique)
- **LD_AUDIT environment variable**: Checks for audit hooks (used by security tools)
- **Memory maps scanning**: Searches `/proc/self/maps` for known EDR libraries:
  - CrowdStrike (`libcrowdstrike`)
  - Sysdig (`libsysdig`)
  - Generic EDR (`libedr`)
  - Falco (`falco`)
  - SentinelOne (`sentinel`)
  - Cylance (`cylance`)

**Behavior**: If EDR hooks detected and not in test mode, terminates immediately via `SIGKILL`.

**Test Mode**: Reports detected EDR components to stderr.

### 2. Enhanced ELF Loader (execveat)

**Function**: `load_elf_execveat()`

Modern ELF loader using `execveat` syscall:

- Creates anonymous memory file descriptor via `memfd_create`
- Writes ELF binary to memory-only file descriptor
- Executes via `execveat(fd, "", argv, envp, AT_EMPTY_PATH)`
- **No disk writes**: Entire process happens in memory
- Automatically scrubs decrypted payload from memory before execution
- Falls back to traditional `execve` if `execveat` unavailable

**Advantages over execve**:
- Cleaner syscall semantics
- Better support for executing from file descriptors
- More resistant to process monitoring

### 3. Enhanced SO Loader (dlopen from memfd)

**Function**: `load_so_payload()`

Advanced shared object loader:

- Creates memory-only file descriptor via `memfd_create`
- Writes SO binary to memfd
- Loads via `dlopen("/proc/self/fd/N", RTLD_NOW | RTLD_LOCAL)`
- Attempts to call `entry()` symbol if exists
- Falls back to `_init()` constructor if no explicit entry point
- Scrubs decrypted payload from memory after loading
- Properly closes handle and file descriptor

**Features**:
- Complete memory residency
- No disk artifacts
- Supports standard SO entry points
- Error handling with detailed test mode output

### 4. Comprehensive Memory Scrubbing

**Function**: `scrub_memory_region()`

Multi-pass memory sanitization:

1. **First pass**: Fill with `0xCC` (INT3 instruction)
2. **Second pass**: Fill with `0xAA` (alternating pattern)
3. **Third pass**: Zero out with `0x00`
4. **Protection**: Set memory region to `PROT_NONE` via `mprotect`

**Features**:
- Page-aligned scrubbing
- Automatic alignment calculation
- Makes memory region inaccessible after scrubbing
- Prevents memory dumping and forensic analysis

### 5. Enhanced Self-Delete Logic

**Function**: `unlink_self()`

Improved self-deletion with verification:

- Reads own path from `/proc/self/exe`
- Unlinks binary from filesystem via syscall
- **Verification**: Attempts to re-open deleted file
- Reports success/failure in test mode
- Respects `--no-selfdelete` flag
- Provides detailed error reporting

**Anti-Forensics**:
- Binary removed from filesystem while still running
- Process memory remains but no disk artifact
- Makes incident response and forensics more difficult

### 6. Integration with Anti-Analysis

All loaders integrate with existing anti-analysis framework:

- VM detection (CPUID checks)
- Debugger detection (TracerPid, ptrace)
- Parent process inspection
- Timing-based sandbox detection
- CPU count checks

**New**: EDR hook detection runs before other anti-analysis checks.

## Usage Examples

### Test Mode (Safe Testing)

```bash
./quantumserver --test-mode --no-doh --no-selfdelete
```

Output shows:
- EDR detection results
- Memory scrubbing operations
- Self-delete behavior (simulated)
- Anti-analysis check results

### Production Mode (ELF Execution)

```bash
./quantumserver --no-doh
```

Behavior:
- Checks for EDR hooks (terminates if found)
- Runs anti-analysis checks (terminates if VM/debugger)
- Decrypts payload
- Loads ELF via `execveat`
- Scrubs memory
- Self-deletes binary

### SO Loading Mode

```bash
./quantumserver --stage-file payload.so
```

Behavior:
- Loads SO file from disk
- Creates memfd and loads via dlopen
- Calls entry point or _init
- Scrubs memory
- Self-deletes

### EDR Testing

```bash
LD_PRELOAD=/fake/edr.so ./quantumserver --test-mode
LD_AUDIT=/fake/audit.so ./quantumserver --test-mode
```

Should detect and report EDR instrumentation.

## Testing

### Test Suite

Run complete test suite:

```bash
cd tests/
bash test_loader_linux.sh
```

### Manual Testing

1. **Build test payloads**:
   ```bash
   cd tests/
   make
   ```

2. **Create encrypted payload**:
   ```bash
   cd ..
   ./quantum_forge.sh --payload tests/test_payload --output encrypted_elf.bin
   ```

3. **Test loader**:
   ```bash
   ./quantumserver --stage-file encrypted_elf.bin --test-mode
   ```

### Verification: No Disk Writes

```bash
strace -e trace=open,openat,creat,write ./quantumserver --test-mode 2>&1 | grep -E '(tmp|var|home)'
```

Should show no writes to disk (except logs in test mode).

### Verification: Memory Scrubbing

```bash
gdb -batch -ex 'run --test-mode --no-doh' -ex 'info proc mappings' ./quantumserver
```

Memory regions should show PROT_NONE after scrubbing.

## Security Considerations

### Operational Security

- **Always test in isolated environment first**
- Use `--test-mode` to validate behavior without execution
- EDR detection will terminate process immediately (by design)
- Self-delete makes binary unrecoverable (ensure backup)

### Detection Surface

**Minimized**:
- No disk writes during payload execution
- Memory-only execution
- Process name spoofing (`[kworker/u64:2]`)
- Argument and environment scrubbing

**Remaining**:
- Process memory can still be dumped by root
- Network traffic (DoH, C2 beacon) is visible
- Syscall tracing can observe memfd_create, execveat
- SELinux/AppArmor may flag memory execution

### Anti-Forensics

- Binary self-deletes (no disk artifact)
- Memory scrubbed after decryption (no plaintext in RAM)
- File descriptors closed promptly
- No temporary files created

## Compatibility

### Kernel Requirements

- **memfd_create**: Linux 3.17+ (2014)
- **execveat**: Linux 3.19+ (2015)
- Falls back to execve on older kernels

### Tested Platforms

- Ubuntu 20.04+ (kernel 5.x)
- Debian 10+ (kernel 4.19+)
- CentOS 8+ (kernel 4.18+)
- WSL2 (Windows Subsystem for Linux)

### Known Limitations

- Requires glibc 2.27+ for full functionality
- SELinux may block memfd execution (requires permissive or policy)
- AppArmor may block execveat with AT_EMPTY_PATH
- Some container runtimes block memfd_create

## Architecture

```
quantumserver
    │
    ├── check_edr_hooks() ──> [terminates if EDR found]
    │
    ├── check_all_anti_analysis() ──> [terminates if VM/debugger]
    │
    ├── decrypt_payload()
    │
    ├── Loader Selection:
    │   ├── load_elf_execveat()
    │   │   ├── memfd_create()
    │   │   ├── write(payload)
    │   │   ├── scrub_memory_region()
    │   │   └── execveat(fd, AT_EMPTY_PATH)
    │   │
    │   └── load_so_payload()
    │       ├── memfd_create()
    │       ├── write(payload)
    │       ├── dlopen("/proc/self/fd/N")
    │       ├── dlsym(entry or _init)
    │       ├── call entry point
    │       ├── scrub_memory_region()
    │       └── dlclose()
    │
    └── unlink_self() ──> [self-delete + verify]
```

## Code Quality

- All syscalls use direct syscall() interface (not libc wrappers)
- Error handling with errno checking
- Test mode provides detailed diagnostic output
- Memory safety: bounds checking, null checks
- No heap corruption: careful malloc/free management

## Future Enhancements

Potential additions:

- Direct syscall via inline assembly (bypass libc hooks)
- ELF parsing and manual loading (bypass execve entirely)
- SO relocation and manual linking (bypass dlopen)
- Process hollowing (inject into existing process)
- PTRACE_SEIZE injection (inject into running process)

## References

- `man 2 memfd_create`
- `man 2 execveat`
- `man 3 dlopen`
- `man 2 mprotect`
- Linux syscall reference: https://syscalls.kerneltalks.com/
