# QuantumForge Reflective DLL Loader Test

## Overview

This directory contains comprehensive tests for the Windows Reflective DLL Loader functionality in QuantumForge. The reflective loader allows DLLs to be loaded directly from memory without touching disk, a critical capability for fileless post-exploitation.

## Test Components

### 1. test_dll.c
A simple test DLL that:
- Implements DllMain entry point
- Creates a marker file at `C:\temp\reflective_dll_test.txt`
- Displays a message box on successful load
- Exports a test function

### 2. test_reflective_loader.c
Standalone test harness that:
- Reads a DLL file into memory
- Parses PE headers (DOS + NT headers)
- Maps sections to allocated memory
- Processes relocations
- Resolves imports via GetProcAddress
- Sets proper memory protections
- Calls DllMain with DLL_PROCESS_ATTACH
- Provides detailed logging of each step

### 3. build_and_test.bat
Automated build and test script that:
- Verifies Visual Studio compiler is available
- Builds test_dll.dll
- Builds test_reflective_loader.exe
- Executes the test
- Validates results

## Prerequisites

- Windows 10/11
- Visual Studio 2019 or later (with C/C++ development tools)
- Developer Command Prompt for Visual Studio

## Running Tests

### Quick Test
```cmd
cd tests
build_and_test.bat
```

### Manual Test Steps
```cmd
REM Open Visual Studio Developer Command Prompt

REM Build test DLL
cl.exe /LD test_dll.c /link /DLL /OUT:test_dll.dll user32.lib kernel32.lib

REM Build test loader
cl.exe /Fe:test_reflective_loader.exe test_reflective_loader.c /link kernel32.lib user32.lib

REM Run test
test_reflective_loader.exe test_dll.dll
```

## Expected Output

### Successful Test
```
[*] QuantumForge Reflective DLL Loader Test
[*] Loading DLL: test_dll.dll

[*] File size: XXXX bytes
[+] DLL loaded into memory

[+] DOS header valid (MZ signature found)
[+] PE header valid (PE signature found)
[+] Architecture: x64
[*] Image size: XXXX bytes
[+] Allocated memory at: 0xXXXXXXXXXXXX
[*] Copied PE headers (XXX bytes)
[*] Copying N sections:
[*]   .text -> 0xXXXXXXXXXXXX (XXX bytes)
[*]   .rdata -> 0xXXXXXXXXXXXX (XXX bytes)
[*]   .data -> 0xXXXXXXXXXXXX (XXX bytes)
[*] Processing relocations (delta: 0xXXXXXXXXXXXX)
[+] Relocations processed successfully
[*] Loaded module: KERNEL32.dll
[*] Loaded module: USER32.dll
[+] Imports resolved successfully
[*] Setting section protections:
[*]   .text -> PAGE_EXECUTE_READ
[*]   .rdata -> PAGE_READONLY
[*]   .data -> PAGE_READWRITE
[*] DllMain entry point: 0xXXXXXXXXXXXX
[*] Calling DllMain(DLL_PROCESS_ATTACH)...
[+] DllMain returned successfully
[+] Reflective DLL load complete!

[SUCCESS] Reflective DLL loader test passed!
```

### Message Box
A Windows message box will appear with:
- Title: "QuantumForge Test DLL"
- Message: "Test DLL loaded successfully via reflective loader!"

### Output File
File created at `C:\temp\reflective_dll_test.txt` containing:
```
Reflective DLL Load Successful!
```

## Verification Checklist

The test validates the following components:

- [x] **PE Header Parsing**: DOS header (MZ) and NT header (PE) validation
- [x] **Section Mapping**: All sections (.text, .rdata, .data, etc.) copied correctly
- [x] **Import Resolution**: All imported functions resolved via GetProcAddress
- [x] **Relocation Processing**: Base relocation applied for ASLR compatibility
- [x] **Memory Protection**: Correct page protections set (RX, RW, R)
- [x] **DllMain Execution**: Entry point called successfully with DLL_PROCESS_ATTACH
- [x] **Memory Scrubbing**: Original buffer zeroed after load (via SecureZeroMemory)

## Implementation Details

### Reflective DLL Loading Process

1. **Validation**: Check DOS and PE signatures
2. **Allocation**: VirtualAlloc with image size
3. **Header Copy**: Copy PE headers to allocated memory
4. **Section Mapping**: Copy each section to its virtual address
5. **Relocation**: Apply base relocations if delta != 0
6. **Import Resolution**: Resolve all imports via LoadLibrary + GetProcAddress
7. **Protection**: Set section memory protections (RX/RW/R)
8. **Execution**: Call DllMain(DLL_PROCESS_ATTACH)
9. **Cleanup**: Scrub original buffer

### Key Functions

- `reflective_dll_load()`: Main loader entry point
- `resolve_imports()`: IAT resolution
- `process_relocations()`: Base relocation processing

### BCrypt Integration

The main loader uses BCryptDecrypt for AES-256-CBC decryption of the payload before reflective loading. This is already implemented in quantum_loader_win.c.

## Troubleshooting

### "cl.exe not found"
- Run from Visual Studio Developer Command Prompt
- Or execute: `"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"`

### "Test DLL build failed"
- Ensure Visual Studio C++ tools are installed
- Check for missing dependencies (user32.lib, kernel32.lib)

### "DllMain returned FALSE"
- Check Windows Event Viewer for detailed error
- Verify all imports were resolved correctly
- Ensure test_dll.c compiled successfully

### No message box appears
- Check if message box was blocked by Windows settings
- Verify DllMain is being called (check console output)
- Check C:\temp\reflective_dll_test.txt as alternative confirmation

## Integration with QuantumForge

This reflective loader is integrated into the main `quantum_loader_win.c` loader. The `load_second_stage()` function automatically detects PE/DLL format and uses reflective loading when appropriate, falling back to shellcode execution for raw payloads.

## Security Considerations

- Memory is allocated as PAGE_EXECUTE_READWRITE during loading
- Final protections are properly set (RX/RW/R) based on section characteristics
- Original DLL buffer is scrubbed with SecureZeroMemory after load
- No disk writes occur during the entire process
- Anti-analysis checks are performed before loading (in main loader)

## Exit Codes

- `0`: Test passed successfully
- `1`: Test failed (check console output for details)
