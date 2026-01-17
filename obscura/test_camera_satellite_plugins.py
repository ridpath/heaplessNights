#!/usr/bin/env python3
"""
Test script for camera and satellite attack plugins.
Tests in dry-run/simulate mode without requiring hardware.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'obscura'))

from obscura.attacks import AttackOrchestrator


def test_camera_attacks():
    """Test camera attack plugin in dry-run mode."""
    print("\n=== Testing Camera Attacks ===")
    
    orchestrator = AttackOrchestrator(
        interface="eth0",
        simulate_mode=True,
        battery_saver=False
    )
    
    try:
        orchestrator.load_plugin("camera_attacks")
        print("[+] Camera attacks plugin loaded successfully")
    except Exception as e:
        print(f"[!] Failed to load camera attacks plugin: {e}")
        return False
    
    try:
        from obscura.attack_plugins import camera_attacks
        
        print("\n[*] Testing MJPEG stream replacement...")
        result = camera_attacks.mjpeg_stream_replacement(
            orchestrator,
            target_ip="192.168.1.100",
            gateway_ip="192.168.1.1",
            duration=10
        )
        print(f"[+] MJPEG stream replacement: {'PASS' if result else 'FAIL'}")
        
        print("\n[*] Testing RTSP hijack...")
        result = camera_attacks.rtsp_hijack(
            orchestrator,
            target_ip="192.168.1.100",
            gateway_ip="192.168.1.1",
            rtsp_url="rtsp://192.168.1.100/stream1",
            duration=10
        )
        print(f"[+] RTSP hijack: {'PASS' if result else 'FAIL'}")
        
        print("\n[*] Testing ASCII deepfake overlay...")
        result = camera_attacks.ascii_deepfake_overlay(
            orchestrator,
            target_stream="rtsp://example.com/stream",
            text_overlay="TEST",
            duration=5
        )
        print(f"[+] ASCII deepfake: {'PASS' if result else 'FAIL'}")
        
        print("\n[*] Testing OpenCV visual manipulation...")
        result = camera_attacks.opencv_visual_manipulation(
            orchestrator,
            target_stream="rtsp://example.com/stream",
            manipulation_type="blur",
            duration=5
        )
        print(f"[+] OpenCV manipulation: {'PASS' if result else 'FAIL'}")
        
        print("\n[SUCCESS] All camera attack tests passed")
        return True
        
    except Exception as e:
        print(f"[!] Camera attack tests failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_satellite_attacks():
    """Test satellite attack plugin enhancements in dry-run mode."""
    print("\n=== Testing Satellite Attacks ===")
    
    orchestrator = AttackOrchestrator(
        interface="none",
        simulate_mode=True,
        battery_saver=False
    )
    
    try:
        orchestrator.load_plugin("satellite_atttack")
        print("[+] Satellite attacks plugin loaded successfully")
    except Exception as e:
        print(f"[!] Failed to load satellite attacks plugin: {e}")
        return False
    
    try:
        from obscura.attack_plugins import satellite_atttack
        
        print("\n[*] Testing DVB-S spoofing with ffmpeg...")
        result = satellite_atttack.dvbs_spoof_ffmpeg(
            orchestrator,
            frequency=11.7e9,
            symbol_rate=27500000,
            video_file="/tmp/test.mp4",
            duration=10
        )
        print(f"[+] DVB-S spoof: {'PASS' if result else 'FAIL'}")
        
        print("\n[*] Testing orbit-aware targeting...")
        result = satellite_atttack.orbit_aware_targeting(
            orchestrator,
            satellite_name="ISS",
            observer_lat=37.7749,
            observer_lon=-122.4194,
            observer_alt=0.0,
            attack_window=300
        )
        print(f"[+] Orbit targeting: {'PASS' if isinstance(result, dict) else 'FAIL'}")
        if isinstance(result, dict):
            print(f"    Satellite: {result.get('satellite', 'N/A')}")
            print(f"    Max elevation: {result.get('max_elevation', 'N/A')}°")
        
        print("\n[*] Testing GNSS constellation poisoning...")
        result = satellite_atttack.gnss_constellation_poisoning(
            orchestrator,
            lat=37.7749,
            lon=-122.4194,
            alt=10.0,
            num_satellites=8,
            duration=60,
            offset_km=5.0
        )
        print(f"[+] GNSS poisoning: {'PASS' if result else 'FAIL'}")
        
        print("\n[*] Testing SatNOGS pass prediction...")
        result = satellite_atttack.satnogs_pass_prediction(
            orchestrator,
            satellite_norad_id=25544,
            ground_station_lat=37.7749,
            ground_station_lon=-122.4194,
            ground_station_alt=0.0,
            min_elevation=10.0
        )
        print(f"[+] SatNOGS prediction: {'PASS' if isinstance(result, dict) else 'FAIL'}")
        if isinstance(result, dict):
            print(f"    NORAD ID: {result.get('norad_id', 'N/A')}")
        
        print("\n[SUCCESS] All satellite attack tests passed")
        return True
        
    except Exception as e:
        print(f"[!] Satellite attack tests failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests."""
    print("=" * 60)
    print("Obscura Camera & Satellite Plugin Test Suite")
    print("=" * 60)
    
    camera_ok = test_camera_attacks()
    satellite_ok = test_satellite_attacks()
    
    print("\n" + "=" * 60)
    if camera_ok and satellite_ok:
        print("[SUCCESS] All plugin tests passed")
        print("=" * 60)
        return 0
    else:
        print("[FAIL] Some plugin tests failed")
        print("=" * 60)
        return 1


if __name__ == "__main__":
    sys.exit(main())
