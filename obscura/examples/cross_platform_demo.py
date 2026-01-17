"""
Cross-Platform OpSec Demo
Demonstrates all platform-specific features across Windows/Linux/macOS/WSL/Kali/Parrot OS
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from obscura.opsec_logging import (
    OpSecLogger, PlatformUtils,
    PLATFORM, IS_WINDOWS, IS_LINUX, IS_MACOS, IS_WSL, WSL_DISTRO
)


def demonstrate_platform_detection():
    """Show platform detection capabilities"""
    print("\n" + "="*70)
    print("Platform Detection")
    print("="*70)
    
    print(f"Platform: {PLATFORM}")
    print(f"Is Windows: {IS_WINDOWS}")
    print(f"Is Linux: {IS_LINUX}")
    print(f"Is macOS: {IS_MACOS}")
    print(f"Is WSL: {IS_WSL}")
    
    if IS_WSL:
        print(f"WSL Distribution: {WSL_DISTRO}")
        print("\nThis is running in WSL - full compatibility with:")
        print("  - Kali Linux")
        print("  - Parrot OS")
        print("  - Ubuntu")
        print("  - Debian")
        print("  - Any other WSL distribution")
    
    print(f"\nRunning with admin/root privileges: {PlatformUtils.is_admin()}")


def demonstrate_network_enumeration():
    """Show network interface detection"""
    print("\n" + "="*70)
    print("Network Interface Enumeration")
    print("="*70)
    
    interfaces = PlatformUtils.get_network_interfaces()
    print(f"Found {len(interfaces)} network interface(s)\n")
    
    for idx, iface in enumerate(interfaces, 1):
        print(f"Interface {idx}: {iface.get('name', 'unknown')}")
        
        if 'is_up' in iface:
            status = "UP" if iface['is_up'] else "DOWN"
            print(f"  Status: {status}")
        
        if 'addresses' in iface:
            for addr in iface['addresses']:
                addr_type = addr.get('type', 'unknown').upper()
                addr_val = addr.get('address', 'N/A')
                print(f"  {addr_type}: {addr_val}")
        
        print()


def demonstrate_process_enumeration():
    """Show process enumeration"""
    print("="*70)
    print("Process Enumeration")
    print("="*70)
    
    processes = PlatformUtils.get_processes()
    print(f"Detected {len(processes)} running processes\n")
    
    if processes and isinstance(processes[0], dict) and 'pid' in processes[0]:
        print("Sample processes:")
        for proc in processes[:10]:
            print(f"  PID {proc['pid']}: {proc.get('name', 'unknown')}")
    else:
        print("Process list available via shell fallback")


def demonstrate_wsl_path_conversion():
    """Show WSL path conversion"""
    print("\n" + "="*70)
    print("WSL Path Conversion")
    print("="*70)
    
    if not IS_WSL:
        print("Not running in WSL - path conversion not applicable")
        return
    
    print("Converting WSL paths to Windows paths:\n")
    
    import os
    home_dir = os.path.expanduser("~")
    test_paths = [
        home_dir + "/documents",
        "/mnt/c",
        os.path.join(home_dir, "test.txt")
    ]
    
    for wsl_path in test_paths:
        win_path = PlatformUtils.wsl_to_windows_path(wsl_path)
        print(f"  {wsl_path}")
        print(f"  -> {win_path}\n")
    
    print("Converting Windows paths to WSL paths:\n")
    
    win_paths = [
        "C:\\",
        "D:\\"
    ]
    
    for win_path in win_paths:
        wsl_path = PlatformUtils.windows_to_wsl_path(win_path)
        print(f"  {win_path}")
        print(f"  -> {wsl_path}\n")


def demonstrate_hardware_capabilities():
    """Show hardware acceleration detection"""
    print("="*70)
    print("Hardware Capabilities")
    print("="*70)
    
    hw_caps = PlatformUtils.detect_hardware_acceleration()
    
    print("CPU Features:")
    print(f"  AES-NI (Hardware AES): {hw_caps.get('aes_ni', False)}")
    print(f"  AVX2 (Advanced Vector Extensions): {hw_caps.get('avx2', False)}")
    print(f"  SSE4 (Streaming SIMD Extensions): {hw_caps.get('sse4', False)}")
    
    if IS_LINUX:
        entropy = PlatformUtils.get_system_entropy()
        if entropy > 0:
            print(f"\nSystem Entropy: {entropy} bits")
            if entropy < 1000:
                print("  WARNING: Low entropy may affect cryptographic operations")


def demonstrate_opsec_logger_integration():
    """Show OpSecLogger with platform-specific features"""
    print("\n" + "="*70)
    print("OpSecLogger Cross-Platform Integration")
    print("="*70)
    
    import tempfile
    import os
    
    log_dir = os.path.join(tempfile.gettempdir(), 'obscura_demo_logs')
    
    logger = OpSecLogger(
        log_dir=log_dir,
        encrypt=False,
        operator=f"demo_{PLATFORM.lower()}",
        async_logging=True,
        enable_metrics=True
    )
    
    session_id = logger.start_session(
        operation_name=f"Cross-Platform Demo - {PLATFORM}",
        target_network="demo_network",
        client="Demo Client"
    )
    
    print(f"\nSession started: {session_id}")
    
    print("\nLogging network interfaces...")
    interfaces = logger.log_network_interfaces()
    print(f"  Logged {len(interfaces)} interface(s)")
    
    print("\nLogging running processes...")
    processes = logger.log_processes()
    print(f"  Logged {len(processes)} process(es)")
    
    print("\nGetting system info...")
    sys_info = logger.get_system_info()
    print(f"  Platform: {sys_info['platform']}")
    print(f"  Architecture: {sys_info['architecture']}")
    print(f"  Admin: {sys_info['is_admin']}")
    
    if IS_WSL:
        print(f"  WSL Distro: {sys_info['wsl_distro']}")
        
        print("\nTesting path conversion within logger...")
        import os
        test_path = os.path.expanduser("~")
        converted = logger.convert_path(test_path, to_windows=True)
        print(f"  {test_path} -> {converted}")
    
    print("\nRunning health check...")
    health = logger.healthcheck()
    print(f"  Status: {health['status']}")
    
    print("\nGetting performance metrics...")
    metrics = logger.get_metrics()
    print(f"  Throughput: {metrics.get('throughput_logs_per_sec', 0):.2f} logs/sec")
    print(f"  Total logs: {metrics.get('total_logs', 0)}")
    
    logger.end_session("Cross-platform demo completed")
    logger.shutdown_async_logging()
    
    print(f"\n[+] OpSecLogger cross-platform demo completed successfully!")


def main():
    """Run all demonstrations"""
    print("\n" + "#"*70)
    print("# Obscura OpSec - Cross-Platform Demonstration")
    print(f"# Platform: {PLATFORM} | WSL: {IS_WSL} | Distro: {WSL_DISTRO or 'N/A'}")
    print("#"*70)
    
    demonstrate_platform_detection()
    demonstrate_network_enumeration()
    demonstrate_process_enumeration()
    demonstrate_wsl_path_conversion()
    demonstrate_hardware_capabilities()
    demonstrate_opsec_logger_integration()
    
    print("\n" + "#"*70)
    print("# All demonstrations completed successfully!")
    print("# System is fully compatible with:")
    print("#   - Windows (native)")
    print("#   - Linux (Ubuntu, Debian, Kali, Parrot OS, etc.)")
    print("#   - macOS")
    print("#   - WSL (any distribution)")
    print("#"*70 + "\n")


if __name__ == '__main__':
    main()
