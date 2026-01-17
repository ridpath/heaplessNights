from obscura.opsec_logging import (
    PLATFORM, IS_WSL, WSL_DISTRO, IS_WINDOWS, IS_LINUX, IS_MACOS,
    PSUTIL_AVAILABLE, CRYPTO_AVAILABLE, KEYRING_AVAILABLE
)

print("="*60)
print("Obscura OpSec - System Capabilities")
print("="*60)
print(f"Platform: {PLATFORM}")
print(f"Windows: {IS_WINDOWS}")
print(f"Linux: {IS_LINUX}")
print(f"macOS: {IS_MACOS}")
print(f"WSL: {IS_WSL}")
if IS_WSL:
    print(f"WSL Distro: {WSL_DISTRO}")
print()
print("Library Support:")
print(f"  psutil (enhanced features): {PSUTIL_AVAILABLE}")
print(f"  cryptography (encryption): {CRYPTO_AVAILABLE}")
print(f"  keyring (key storage): {KEYRING_AVAILABLE}")
print("="*60)
