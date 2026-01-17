#!/bin/bash

set -e

if [ $# -lt 2 ]; then
    echo "Usage: $0 <polyglot_image> <output_binary>"
    echo ""
    echo "Extract executable payload from polyglot image"
    exit 1
fi

INPUT="$1"
OUTPUT="$2"

if [ ! -f "$INPUT" ]; then
    echo "Error: Input file not found: $INPUT"
    exit 1
fi

echo "[*] Analyzing polyglot: $INPUT"

MAGIC=$(xxd -p -l 8 "$INPUT")

case "$MAGIC" in
    ffd8*)
        echo "[*] Detected JPEG polyglot"
        OFFSET=$(strings -t d "$INPUT" | grep -m1 "ELF" | awk '{print $1}')
        if [ -z "$OFFSET" ]; then
            OFFSET=20
        fi
        ;;
    89504e470d0a1a0a*)
        echo "[*] Detected PNG polyglot"
        OFFSET=$(strings -t d "$INPUT" | grep -m1 "ELF" | awk '{print $1}')
        if [ -z "$OFFSET" ]; then
            OFFSET=8
        fi
        ;;
    424d*)
        echo "[*] Detected BMP polyglot"
        OFFSET=$(strings -t d "$INPUT" | grep -m1 "ELF" | awk '{print $1}')
        if [ -z "$OFFSET" ]; then
            OFFSET=54
        fi
        ;;
    *)
        echo "[!] Unknown format, attempting raw extraction"
        OFFSET=$(strings -t d "$INPUT" | grep -m1 "ELF" | awk '{print $1}')
        if [ -z "$OFFSET" ]; then
            echo "[!] Could not find ELF header"
            exit 1
        fi
        ;;
esac

echo "[*] Extracting payload from offset: $OFFSET"
dd if="$INPUT" of="$OUTPUT" bs=1 skip=$OFFSET 2>/dev/null

if [ -f "$OUTPUT" ]; then
    chmod +x "$OUTPUT"
    
    FILE_TYPE=$(file "$OUTPUT")
    echo "[*] Extracted payload type: $FILE_TYPE"
    
    if echo "$FILE_TYPE" | grep -q "ELF"; then
        echo "[+] Successfully extracted ELF binary"
    elif echo "$FILE_TYPE" | grep -q "Mach-O"; then
        echo "[+] Successfully extracted Mach-O binary"
    else
        echo "[!] Warning: Extracted file may not be a valid executable"
    fi
    
    echo "[+] Payload extracted to: $OUTPUT"
else
    echo "[!] Extraction failed"
    exit 1
fi
