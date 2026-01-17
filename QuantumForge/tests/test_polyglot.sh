#!/bin/bash

set -e

echo "===== QuantumForge Polyglot Builder Test ====="
echo ""

TEST_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$TEST_DIR")"
cd "$ROOT_DIR"

BASE_KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
IV="0123456789abcdef0123456789abcdef"
SALT="testsalt12345678"

echo "[*] Creating test payload..."
cat > test_payload.bin <<'EOF'
#!/bin/bash
echo "Polyglot test payload executed successfully!"
exit 0
EOF
chmod +x test_payload.bin

echo ""
echo "===== Test 1: JPEG Polyglot (Default) ====="
./quantum_forge.sh test_output.jpg test_payload.bin "$BASE_KEY" "$IV"

if [ -f test_output.jpg ]; then
    echo "[+] JPEG polyglot created"
    
    MAGIC=$(xxd -p -l 2 test_output.jpg)
    if [ "$MAGIC" == "ffd8" ]; then
        echo "[+] JPEG magic bytes correct"
    else
        echo "[!] JPEG magic bytes incorrect: $MAGIC"
        exit 1
    fi
    
    if command -v file &> /dev/null; then
        FILE_TYPE=$(file test_output.jpg)
        echo "[*] File type: $FILE_TYPE"
    fi
    
    if command -v exiftool &> /dev/null; then
        echo "[*] EXIF data:"
        exiftool test_output.jpg | grep -E "(Model|Artist|Comment)" || echo "No EXIF data found"
    fi
else
    echo "[!] JPEG polyglot creation failed"
    exit 1
fi

echo ""
echo "===== Test 2: PNG Polyglot ====="
./quantum_forge.sh test_output.png test_payload.bin "$BASE_KEY" "$IV" --format png

if [ -f test_output.png ]; then
    echo "[+] PNG polyglot created"
    
    MAGIC=$(xxd -p -l 8 test_output.png)
    if [ "$MAGIC" == "89504e470d0a1a0a" ]; then
        echo "[+] PNG magic bytes correct"
    else
        echo "[!] PNG magic bytes incorrect: $MAGIC"
        exit 1
    fi
else
    echo "[!] PNG polyglot creation failed"
    exit 1
fi

echo ""
echo "===== Test 3: BMP Polyglot ====="
./quantum_forge.sh test_output.bmp test_payload.bin "$BASE_KEY" "$IV" --format bmp

if [ -f test_output.bmp ]; then
    echo "[+] BMP polyglot created"
    
    MAGIC=$(xxd -p -l 2 test_output.bmp)
    if [ "$MAGIC" == "424d" ]; then
        echo "[+] BMP magic bytes correct"
    else
        echo "[!] BMP magic bytes incorrect: $MAGIC"
        exit 1
    fi
else
    echo "[!] BMP polyglot creation failed"
    exit 1
fi

echo ""
echo "===== Test 4: No Polyglot (Binary Only) ====="
./quantum_forge.sh test_output.bin test_payload.bin "$BASE_KEY" "$IV" --no-polyglot

if [ -f test_output.bin ]; then
    echo "[+] Binary created (no polyglot)"
    
    MAGIC=$(xxd -p -l 2 test_output.bin)
    if [ "$MAGIC" != "ffd8" ]; then
        echo "[+] Correctly created as binary (not image)"
    else
        echo "[!] Binary has image magic bytes"
        exit 1
    fi
else
    echo "[!] Binary creation failed"
    exit 1
fi

echo ""
echo "===== Test 5: No EXIF ====="
./quantum_forge.sh test_output_noexif.jpg test_payload.bin "$BASE_KEY" "$IV" --no-exif

if [ -f test_output_noexif.jpg ]; then
    echo "[+] JPEG created without EXIF"
    
    if command -v exiftool &> /dev/null; then
        EXIF_COUNT=$(exiftool test_output_noexif.jpg | grep -c -E "(Model|Artist|Comment)" || echo "0")
        if [ "$EXIF_COUNT" == "0" ]; then
            echo "[+] No custom EXIF tags found (as expected)"
        fi
    fi
else
    echo "[!] No-EXIF creation failed"
    exit 1
fi

echo ""
echo "===== Test 6: Image Viewer Validation ====="
if command -v identify &> /dev/null; then
    echo "[*] Testing with ImageMagick identify..."
    identify test_output.jpg 2>&1 && echo "[+] JPEG opens in ImageMagick" || echo "[!] JPEG failed to open"
    identify test_output.png 2>&1 && echo "[+] PNG opens in ImageMagick" || echo "[!] PNG failed to open"
    identify test_output.bmp 2>&1 && echo "[+] BMP opens in ImageMagick" || echo "[!] BMP failed to open"
else
    echo "[!] ImageMagick not installed, skipping viewer validation"
    echo "[*] To fully validate, open images manually in an image viewer"
fi

echo ""
echo "===== Cleanup ====="
rm -f test_payload.bin test_output.jpg test_output.png test_output.bmp test_output.bin test_output_noexif.jpg

echo ""
echo "===== All Tests Passed ====="
