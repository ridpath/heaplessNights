# QuantumForge Polyglot Builder Implementation

## Overview

The QuantumForge polyglot builder creates executable files disguised as valid image files (JPEG, PNG, BMP). These files:
- Open correctly in image viewers
- Can be executed as binaries
- Support EXIF metadata embedding
- Validate image integrity automatically

## Implementation Details

### Supported Formats

1. **JPEG**: Uses JFIF header (0xFFD8FFE0) + JFIF APP0 marker
2. **PNG**: Uses PNG signature (0x89504E470D0A1A0A)
3. **BMP**: Uses BMP header (0x424D) with proper DIB header structure

### CLI Flags

All three builder scripts (quantum_forge.sh, quantum_forge_mac.sh, quantum_forge_win.ps1) support:

- `--no-polyglot` / `-NoPolyglot`: Build binary only, skip polyglot creation
- `--no-exif` / `-NoExif`: Skip EXIF metadata embedding
- `--format <fmt>` / `-Format <fmt>`: Choose image format (jpg, png, bmp)
- `--help` / `-Help`: Show usage information

### Usage Examples

#### Linux (quantum_forge.sh)
```bash
# JPEG polyglot (default)
./quantum_forge.sh output.jpg payload.bin <base_key> <iv>

# PNG polyglot
./quantum_forge.sh output.png payload.bin <base_key> <iv> --format png

# BMP polyglot
./quantum_forge.sh output.bmp payload.bin <base_key> <iv> --format bmp

# Binary only (no polyglot)
./quantum_forge.sh output.bin payload.bin <base_key> <iv> --no-polyglot

# Without EXIF metadata
./quantum_forge.sh output.jpg payload.bin <base_key> <iv> --no-exif
```

#### macOS (quantum_forge_mac.sh)
```bash
# JPEG polyglot (default)
./quantum_forge_mac.sh output.jpg payload.bin <base_key> <salt> <iv>

# PNG polyglot
./quantum_forge_mac.sh output.png payload.bin <base_key> <salt> <iv> --format png

# BMP polyglot
./quantum_forge_mac.sh output.bmp payload.bin <base_key> <salt> <iv> --format bmp
```

#### Windows (quantum_forge_win.ps1)
```powershell
# JPEG polyglot (default)
.\quantum_forge_win.ps1 -Output output.jpg -Payload payload.bin -BaseKey $key -Salt $salt -IV $iv

# PNG polyglot
.\quantum_forge_win.ps1 -Output output.png -Payload payload.bin -BaseKey $key -Salt $salt -IV $iv -Format png

# BMP polyglot
.\quantum_forge_win.ps1 -Output output.bmp -Payload payload.bin -BaseKey $key -Salt $salt -IV $iv -Format bmp

# Binary only
.\quantum_forge_win.ps1 -Output output.exe -Payload payload.bin -BaseKey $key -Salt $salt -IV $iv -NoPolyglot
```

## Validation

Each builder script automatically validates:
1. **Magic Bytes**: Verifies correct image format signature
2. **File Type**: Uses `file` command to check detected type (if available)
3. **EXIF Metadata**: Embeds and verifies metadata when enabled

### Image Integrity Checks

The scripts perform the following checks:

- **JPEG**: Validates 0xFFD8 magic bytes at start
- **PNG**: Validates 8-byte PNG signature (0x89504E470D0A1A0A)
- **BMP**: Validates 0x424D magic bytes at start

### EXIF Metadata

When EXIF embedding is enabled (default), the following metadata is added:
- Model: "QuantumLoader" (Linux/Windows) or "QuantumMac" (macOS)
- Artist: "InvisibleThread"
- Comment: "Secure Payload"

## Extraction

Use the provided extraction scripts to recover the executable payload:

### Linux/macOS
```bash
./extract_polyglot.sh input.jpg output_binary
```

### Windows
```powershell
.\extract_polyglot.ps1 -Input input.jpg -Output output_binary.exe
```

The extraction scripts:
1. Detect image format automatically
2. Locate executable payload offset
3. Extract and validate payload
4. Make payload executable (Linux/macOS)

## Testing

Comprehensive test suites are provided:

### Linux/macOS
```bash
cd tests
./test_polyglot.sh
```

### Windows
```powershell
cd tests
.\test_polyglot.ps1
```

Test coverage:
- JPEG polyglot creation and validation
- PNG polyglot creation and validation
- BMP polyglot creation and validation
- Binary-only mode (no polyglot)
- EXIF-free mode
- Magic byte verification
- Image viewer compatibility (when ImageMagick available)

## Technical Notes

### Polyglot Structure

```
[Image Header] + [Encrypted Payload Binary] + [Optional EXIF Data]
```

The image header is minimal but valid, allowing image viewers to recognize the format. The encrypted binary follows immediately after.

### Image Viewer Compatibility

Polyglots are designed to:
- Pass basic format validation in most image viewers
- Not crash viewers (graceful degradation)
- Appear as 1x1 pixel images (minimal visual footprint)

Tested with:
- Windows Photo Viewer
- macOS Preview
- ImageMagick (identify, display)
- GIMP
- Web browsers (Firefox, Chrome)

### Security Considerations

1. **AES-256-CBC Encryption**: All payloads encrypted before embedding
2. **HKDF Key Derivation**: Keys derived using HKDF-SHA256
3. **Memory-Resident Execution**: Loader never writes decrypted payload to disk
4. **Anti-Analysis**: Polymorphic code generation, section scrubbing

## Implementation Status

- [x] CLI flag parsing (--polyglot, --no-exif, --format)
- [x] JPEG polyglot with JFIF header
- [x] PNG polyglot with valid signature
- [x] BMP polyglot with DIB header
- [x] EXIF metadata embedding (optional)
- [x] Magic byte validation
- [x] File type detection
- [x] Cross-platform support (Linux, macOS, Windows)
- [x] Extraction utilities
- [x] Test suites

## Files Modified/Created

### Modified
- quantum_forge.sh (Linux builder)
- quantum_forge_mac.sh (macOS builder)
- quantum_forge_win.ps1 (Windows builder)

### Created
- extract_polyglot.sh (Linux/macOS extraction)
- extract_polyglot.ps1 (Windows extraction)
- tests/test_polyglot.sh (Linux/macOS test suite)
- tests/test_polyglot.ps1 (Windows test suite)
- POLYGLOT_IMPLEMENTATION.md (this file)
