"""
Cross-Platform Testing Suite for OpSec Logging
Tests Windows, Linux, macOS, WSL, Kali, Parrot OS compatibility
"""

import os
import sys
import tempfile
import platform
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from obscura.opsec_logging import (
    OpSecLogger, PlatformUtils, 
    PLATFORM, IS_WINDOWS, IS_LINUX, IS_MACOS, IS_WSL, WSL_DISTRO,
    PSUTIL_AVAILABLE
)


def print_section(title):
    """Print test section header"""
    print(f"\n{'='*70}")
    print(f"{title}")
    print('='*70)


def test_platform_detection():
    """Test platform detection across all environments"""
    print_section("Test 1: Platform Detection")
    
    print(f"[+] Platform: {PLATFORM}")
    print(f"[+] Is Windows: {IS_WINDOWS}")
    print(f"[+] Is Linux: {IS_LINUX}")
    print(f"[+] Is macOS: {IS_MACOS}")
    print(f"[+] Is WSL: {IS_WSL}")
    
    if IS_WSL:
        print(f"[+] WSL Distribution: {WSL_DISTRO}")
        assert WSL_DISTRO is not None, "WSL distro detection failed"
    
    assert PLATFORM in ['Windows', 'Linux', 'Darwin'], f"Unknown platform: {PLATFORM}"
    print(f"[+] Platform detection: PASSED")
    
    return True


def test_privilege_detection():
    """Test admin/root privilege detection"""
    print_section("Test 2: Privilege Detection")
    
    is_admin = PlatformUtils.is_admin()
    print(f"[+] Running as admin/root: {is_admin}")
    
    if not is_admin:
        print(f"[!] Not running with elevated privileges (this is OK for testing)")
    else:
        print(f"[+] Elevated privileges detected")
    
    print(f"[+] Privilege detection: PASSED")
    return True


def test_network_interface_detection():
    """Test network interface enumeration"""
    print_section("Test 3: Network Interface Detection")
    
    interfaces = PlatformUtils.get_network_interfaces()
    print(f"[+] Found {len(interfaces)} network interface(s)")
    
    for idx, iface in enumerate(interfaces[:5], 1):
        print(f"    Interface {idx}: {iface.get('name', 'unknown')}")
        if 'addresses' in iface:
            for addr in iface['addresses'][:3]:
                print(f"      - {addr.get('type', 'unknown')}: {addr.get('address', 'N/A')}")
    
    if not PSUTIL_AVAILABLE:
        print(f"[!] psutil not available, using fallback detection")
    
    assert len(interfaces) > 0, "No interfaces detected"
    print(f"[+] Network interface detection: PASSED")
    
    return True


def test_process_enumeration():
    """Test process enumeration"""
    print_section("Test 4: Process Enumeration")
    
    processes = PlatformUtils.get_processes()
    print(f"[+] Enumerated {len(processes)} process(es)")
    
    if PSUTIL_AVAILABLE and processes:
        for idx, proc in enumerate(processes[:5], 1):
            if 'pid' in proc:
                print(f"    Process {idx}: PID={proc['pid']} Name={proc.get('name', 'unknown')}")
    
    if not PSUTIL_AVAILABLE:
        print(f"[!] psutil not available, using fallback detection")
    
    assert len(processes) > 0, "No processes detected"
    print(f"[+] Process enumeration: PASSED")
    
    return True


def test_wsl_path_conversion():
    """Test WSL path conversion"""
    print_section("Test 5: WSL Path Conversion")
    
    if not IS_WSL:
        print(f"[!] Not running in WSL, skipping path conversion tests")
        print(f"[+] WSL path conversion: SKIPPED (not WSL)")
        return True
    
    import os
    home_dir = os.path.expanduser("~")
    wsl_path = os.path.join(home_dir, "test.txt")
    win_path = PlatformUtils.wsl_to_windows_path(wsl_path)
    print(f"[+] WSL -> Windows: {wsl_path} -> {win_path}")
    
    test_win_path = "C:\\"
    converted_wsl = PlatformUtils.windows_to_wsl_path(test_win_path)
    print(f"[+] Windows -> WSL: {test_win_path} -> {converted_wsl}")
    
    assert converted_wsl is not None, "Windows to WSL conversion failed"
    print(f"[+] WSL path conversion: PASSED")
    
    return True


def test_hardware_acceleration():
    """Test hardware acceleration detection"""
    print_section("Test 6: Hardware Acceleration Detection")
    
    hw_caps = PlatformUtils.detect_hardware_acceleration()
    print(f"[+] AES-NI: {hw_caps.get('aes_ni', False)}")
    print(f"[+] AVX2: {hw_caps.get('avx2', False)}")
    print(f"[+] SSE4: {hw_caps.get('sse4', False)}")
    
    if not any(hw_caps.values()):
        print(f"[!] No hardware acceleration detected (may be expected on some platforms)")
    
    print(f"[+] Hardware acceleration detection: PASSED")
    return True


def test_system_entropy():
    """Test system entropy checking (Linux only)"""
    print_section("Test 7: System Entropy")
    
    entropy = PlatformUtils.get_system_entropy()
    
    if entropy > 0:
        print(f"[+] Available entropy: {entropy} bits")
        assert entropy > 100, "Low system entropy detected"
    else:
        print(f"[!] Entropy check not available (non-Linux platform)")
    
    print(f"[+] System entropy check: PASSED")
    return True


def test_secure_deletion():
    """Test platform-specific secure deletion"""
    print_section("Test 8: Secure File Deletion")
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        test_file = f.name
        f.write("SENSITIVE DATA TO BE SECURELY DELETED" * 100)
    
    assert os.path.exists(test_file), "Test file not created"
    file_size = os.path.getsize(test_file)
    print(f"[+] Created test file: {test_file} ({file_size} bytes)")
    
    success = PlatformUtils.secure_delete(test_file, passes=3)
    
    assert not os.path.exists(test_file), "File still exists after secure deletion"
    print(f"[+] File securely deleted: {success}")
    print(f"[+] Secure deletion: PASSED")
    
    return True


def test_opsec_logger_cross_platform():
    """Test OpSecLogger with platform-specific features"""
    print_section("Test 9: OpSecLogger Cross-Platform Features")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        logger = OpSecLogger(
            log_dir=tmpdir,
            encrypt=False,
            operator=f"test_operator_{PLATFORM.lower()}"
        )
        
        session_id = logger.start_session(
            f"Cross-Platform Test on {PLATFORM}",
            "test_network",
            f"Test Client - {PLATFORM}"
        )
        print(f"[+] Session started: {session_id}")
        
        if PSUTIL_AVAILABLE:
            interfaces = logger.log_network_interfaces()
            print(f"[+] Logged {len(interfaces)} network interface(s)")
            
            processes = logger.log_processes()
            print(f"[+] Logged {len(processes)} process(es)")
        
        sys_info = logger.get_system_info()
        print(f"[+] Platform: {sys_info['platform']}")
        print(f"[+] Architecture: {sys_info['architecture']}")
        print(f"[+] Admin privileges: {sys_info['is_admin']}")
        print(f"[+] Hardware accel: {sys_info['hardware_acceleration']}")
        
        if IS_WSL:
            print(f"[+] WSL Distro: {sys_info['wsl_distro']}")
        
        health = logger.healthcheck()
        assert health['status'] in ['healthy', 'degraded'], f"Unexpected health status: {health['status']}"
        print(f"[+] Health status: {health['status']}")
        
        logger.end_session("Cross-platform test completed")
        print(f"[+] Session ended successfully")
    
    print(f"[+] OpSecLogger cross-platform: PASSED")
    return True


def test_metrics_and_performance():
    """Test metrics collection on current platform"""
    print_section("Test 10: Metrics & Performance")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        logger = OpSecLogger(
            log_dir=tmpdir,
            encrypt=False,
            async_logging=True,
            enable_metrics=True
        )
        
        session_id = logger.start_session("Performance Test", "test", "test")
        
        for i in range(100):
            logger.log_attack(
                chain_id=f"perf_test_{i}",
                attack_name="test_attack",
                success=True,
                execution_time=0.001,
                target_info={'index': i},
                log_data={'data': 'test'}
            )
        
        metrics = logger.get_metrics()
        print(f"[+] Total logs: {metrics.get('total_logs', 0)}")
        print(f"[+] Throughput: {metrics.get('throughput_logs_per_sec', 0):.2f} logs/sec")
        print(f"[+] Avg log time: {metrics.get('avg_log_time_ms', 0):.2f} ms")
        
        assert metrics['total_logs'] >= 100, "Not all logs recorded"
        
        logger.end_session()
        logger.shutdown_async_logging()
    
    print(f"[+] Metrics & performance: PASSED")
    return True


def run_all_tests():
    """Run all cross-platform tests"""
    print(f"\n{'#'*70}")
    print(f"# Cross-Platform OpSec Logging Test Suite")
    print(f"# Platform: {PLATFORM} | WSL: {IS_WSL} | Distro: {WSL_DISTRO or 'N/A'}")
    print(f"# psutil Available: {PSUTIL_AVAILABLE}")
    print(f"{'#'*70}\n")
    
    tests = [
        test_platform_detection,
        test_privilege_detection,
        test_network_interface_detection,
        test_process_enumeration,
        test_wsl_path_conversion,
        test_hardware_acceleration,
        test_system_entropy,
        test_secure_deletion,
        test_opsec_logger_cross_platform,
        test_metrics_and_performance
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            failed += 1
            print(f"\n[FAILED] {test.__name__}: {e}")
            import traceback
            traceback.print_exc()
    
    print(f"\n{'='*70}")
    print(f"Test Results: {passed} PASSED, {failed} FAILED out of {len(tests)} tests")
    print(f"{'='*70}\n")
    
    return failed == 0


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
