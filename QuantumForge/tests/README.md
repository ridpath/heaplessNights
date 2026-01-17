# QuantumForge Linux Loader Tests

## Overview

This directory contains test payloads, scripts, and verification tools for the QuantumForge Linux loader enhancements.

## Test Files

### Source Code
- `test_payload.c` - Simple ELF executable for testing ELF loader
- `test_so.c` - Shared object with entry points for testing SO loader

### Scripts
- `test_loader_linux.sh` - Comprehensive test suite for all loader features
- `compile_test.sh` - Compilation verification and basic functionality tests
- `Makefile` - Build automation for test payloads

## Quick Start

### 1. Compile Test Payloads

```bash
make
```

This creates:
- `test_payload` - ELF executable
- `test_so.so` - Shared object library

### 2. Run Compilation Test

```bash
bash compile_test.sh
```

Verifies:
- Required libraries are available
- quantumserver compiles successfully
- Basic functionality works
- All enhanced functions are present

### 3. Run Full Test Suite

```bash
bash test_loader_linux.sh
```

Tests:
- EDR hook detection
- Self-delete functionality
- Memory scrubbing
- Command-line flags
- Anti-analysis checks
- No-disk-write verification

## Test Categories

### Test 1: EDR Hook Detection

Tests `check_edr_hooks()` function:

```bash
LD_PRELOAD=/fake/edr.so ../quantumserver --test-mode
LD_AUDIT=/fake/audit.so ../quantumserver --test-mode
```

**Expected**: Detection and warning/termination

### Test 2: Self-Delete Verification

Tests `unlink_self()` function:

```bash
cp ../quantumserver /tmp/test_binary
/tmp/test_binary --test-mode
ls /tmp/test_binary  # Should fail or show deletion message
```

**Expected**: Binary removed from filesystem

### Test 3: Memory Scrubbing

Tests `scrub_memory_region()`:

```bash
../quantumserver --test-mode --no-doh --no-selfdelete 2>&1 | grep "Scrubbed"
```

**Expected**: Memory scrubbing messages in test mode

### Test 4: SO Loader

Tests `load_so_payload()`:

1. Create encrypted SO payload:
   ```bash
   ../quantum_forge.sh --payload test_so.so --output encrypted.bin
   ```

2. Test loading:
   ```bash
   ../quantumserver --stage-file encrypted.bin --test-mode
   ```

**Expected**: SO loads and entry point executes

### Test 5: ELF Loader

Tests `load_elf_execveat()`:

1. Create encrypted ELF payload:
   ```bash
   ../quantum_forge.sh --payload test_payload --output encrypted_elf.bin
   ```

2. Test loading:
   ```bash
   ../quantumserver --stage-file encrypted_elf.bin --test-mode
   ```

**Expected**: ELF executes via execveat

### Test 6: Anti-Analysis Checks

Tests all anti-analysis functions:

```bash
../quantumserver --test-mode --no-doh --no-selfdelete
```

**Expected**: Reports VM/debugger detection status

### Test 7: No Disk Writes

Verifies memory-only execution:

```bash
strace -e trace=open,openat,creat,write ../quantumserver --test-mode 2>&1 | grep -v proc
```

**Expected**: No writes to disk (except logs in test mode)

## WSL Testing

### Setup on WSL

1. Access WSL environment:
   ```
   \\wsl.localhost\parrot
   ```

2. Navigate to QuantumForge:
   ```bash
   cd /path/to/QuantumForge/tests
   ```

3. Install dependencies:
   ```bash
   sudo apt-get update
   sudo apt-get install build-essential libssl-dev libcurl4-openssl-dev
   ```

### Run Tests in WSL

```bash
bash test_loader_linux.sh
```

All tests should pass on WSL2 with kernel 5.x+.

## Advanced Testing

### Memory Dump Analysis

Test memory scrubbing effectiveness:

```bash
gdb -batch -ex 'run --test-mode --no-doh' -ex 'generate-core-file core.dump' ./quantumserver
strings core.dump | grep -i "payload\|secret"
```

**Expected**: No plaintext payload data in core dump

### Syscall Tracing

Verify syscall usage:

```bash
strace -e trace=memfd_create,execveat,dlopen,mprotect,unlink ../quantumserver --test-mode
```

**Expected**: See memfd_create, execveat (or execve), mprotect(PROT_NONE)

### Process Monitoring

Monitor process behavior:

```bash
watch -n 0.1 'ps aux | grep quantumserver'
```

**Expected**: Process name changes to `[kworker/u64:2]`

### Network Monitoring

Verify DoH traffic (if enabled):

```bash
tcpdump -i any -n host 8.8.8.8 or host 1.1.1.1 &
../quantumserver --test-mode
```

**Expected**: DNS-over-HTTPS queries if not using --no-doh

## Troubleshooting

### Compilation Fails

**Error**: `fatal error: openssl/evp.h: No such file or directory`

**Solution**:
```bash
sudo apt-get install libssl-dev
```

**Error**: `fatal error: curl/curl.h: No such file or directory`

**Solution**:
```bash
sudo apt-get install libcurl4-openssl-dev
```

### execveat Fails

**Error**: `execveat failed: 38` (ENOSYS - Function not implemented)

**Cause**: Kernel < 3.19 doesn't support execveat

**Solution**: Falls back to execve automatically

### memfd_create Fails

**Error**: `memfd_create failed: 38`

**Cause**: Kernel < 3.17 doesn't support memfd_create

**Solution**: Upgrade kernel or use different loader

### SELinux/AppArmor Blocks Execution

**Error**: `execveat failed: 13` (EACCES - Permission denied)

**Cause**: Security policy blocks memory execution

**Solution**:
```bash
# Temporary - for testing only
sudo setenforce 0
# OR
sudo aa-complain /path/to/quantumserver
```

### EDR Detection False Positive

**Issue**: Legitimate LD_PRELOAD usage triggers detection

**Solution**: Use `--test-mode` to see detection details, or modify EDR check logic

## Test Results Interpretation

### Success Indicators

- ✓ All tests show `[+]` or `[*]` status
- ✓ No `[!]` error messages
- ✓ Binary self-deletes successfully
- ✓ Memory scrubbing messages appear
- ✓ No unexpected files created

### Failure Indicators

- ✗ Compilation errors
- ✗ Segmentation faults
- ✗ EDR detection on clean system
- ✗ Self-delete leaves binary on disk
- ✗ Files created in /tmp or /var

## Manual Verification Checklist

- [ ] Compiles without errors
- [ ] All symbols present (nm check)
- [ ] Test mode works without crashes
- [ ] EDR detection activates with LD_PRELOAD
- [ ] Self-delete removes binary
- [ ] Memory scrubbing executes
- [ ] SO loader works with test_so.so
- [ ] ELF loader works with test_payload
- [ ] No disk writes during execution
- [ ] Process name spoofing works
- [ ] Anti-analysis checks run

## Performance Benchmarks

Expected performance metrics:

- Compilation: < 5 seconds
- Test suite: < 30 seconds
- Single test run: < 3 seconds
- Memory overhead: < 10MB
- Startup time: < 100ms

## Security Testing

### Fuzzing

Test with malformed payloads:

```bash
dd if=/dev/urandom of=fuzz.bin bs=1024 count=10
../quantumserver --stage-file fuzz.bin --test-mode
```

**Expected**: Graceful failure, no crash

### Buffer Overflow Testing

Compile with AddressSanitizer:

```bash
gcc -o quantumserver ../quantumserver.c -fsanitize=address -g -lcrypto -lssl -lcurl -ldl
./quantumserver --test-mode
```

**Expected**: No memory errors reported

## Cleanup

Remove test artifacts:

```bash
make clean
rm -f compile.log
rm -f ../quantumserver
rm -f core.*
```

## Notes

- All tests require Linux kernel 3.17+ (memfd_create)
- execveat tests require kernel 3.19+
- Some tests require root privileges (self-delete verification)
- Test mode disables anti-analysis termination for safety
- WSL2 fully supported, WSL1 has limitations

## References

- Build scripts: `../quantum_forge.sh`
- Anti-analysis: `../anti_analysis.h`
