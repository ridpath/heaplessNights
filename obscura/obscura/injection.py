import os
import socket
import time
import threading
import subprocess
import scapy.all as scapy
from scapy.layers.dot11 import Dot11, Dot11ProbeReq
from .utils import log_message


def start_mdns_listener(interface, ui, orchestrator):
    """Start an mDNS listener using Zeroconf to discover network services."""
    from zeroconf import Zeroconf, ServiceBrowser, ServiceListener

    class MDNSListener(ServiceListener):
        def add_service(self, zeroconf, type_, name):
            try:
                info = zeroconf.get_service_info(type_, name)
                if info and info.addresses:
                    addr = socket.inet_ntoa(info.addresses[0])
                    msg = f"mDNS: {name} @ {addr}:{info.port}"
                    log_message(msg, ui=ui)
                    if ui:
                        ui.notify(f"[green]{msg}[/]")
                    if "camera" in name.lower():
                        log_message(f"Potential camera detected: {name}", ui=ui)
            except Exception as e:
                log_message(f"[ERROR] mDNS resolution failed: {e}", ui=ui)

        def remove_service(self, zeroconf, type_, name):
            log_message(f"mDNS service removed: {name}", ui=ui)

        def update_service(self, zeroconf, type_, name):
            log_message(f"mDNS service updated: {name}", ui=ui)

    log_message("Starting mDNS listener...", ui=ui)
    zeroconf = Zeroconf()
    listener = MDNSListener()
    ServiceBrowser(zeroconf, "_services._dns-sd._udp.local.", listener)

    def mdns_loop():
        try:
            while orchestrator.running.is_set():
                time.sleep(1)
        except Exception as e:
            log_message(f"[ERROR] mDNS thread error: {e}", ui=ui)
        finally:
            log_message("Stopping mDNS listener", ui=ui)
            zeroconf.close()

    threading.Thread(target=mdns_loop, daemon=True).start()
    log_message("mDNS listener running", ui=ui)


def start_ssdp_listener(interface, ui, orchestrator):
    """Start an SSDP listener via multicast socket to discover UPnP devices."""
    log_message("Starting SSDP listener...", ui=ui)
    MCAST_GRP = '239.255.255.250'
    MCAST_PORT = 1900

    def ssdp_loop():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, 'SO_REUSEPORT'):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.bind(('', MCAST_PORT))

            mreq = socket.inet_aton(MCAST_GRP) + socket.inet_aton("0.0.0.0")
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            while orchestrator.running.is_set():
                try:
                    data, addr = sock.recvfrom(1024)
                    msg = data.decode(errors='ignore')
                    lines = msg.splitlines()
                    for line in lines:
                        if line.lower().startswith("location:"):
                            location = line.split(":", 1)[1].strip()
                            log_message(f"SSDP LOCATION: {location} from {addr[0]}", ui=ui)
                        elif line.lower().startswith("st:"):
                            service_type = line.split(":", 1)[1].strip()
                            log_message(f"SSDP ST: {service_type} from {addr[0]}", ui=ui)
                    if ui:
                        ui.notify(f"[cyan]SSDP: {addr[0]}[/]")
                except Exception as e:
                    log_message(f"[ERROR] SSDP recv error: {e}", ui=ui)
        except Exception as e:
            log_message(f"[ERROR] SSDP listener setup failed: {e}", ui=ui)

    threading.Thread(target=ssdp_loop, daemon=True).start()
    log_message("SSDP listener running", ui=ui)


def crack_handshake(cap_file, bssid, ui, wordlist="/usr/share/wordlists/rockyou.txt"):
    """Use aircrack-ng to brute-force a captured handshake with a specified wordlist."""
    log_message(f"Cracking handshake for {bssid} with wordlist {wordlist}", ui=ui)

    if not os.path.isfile(cap_file):
        log_message(f"[ERROR] Capture file not found: {cap_file}", ui=ui)
        return None

    if not os.path.isfile(wordlist):
        log_message(f"[ERROR] Wordlist not found: {wordlist}", ui=ui)
        return None

    try:
        result = subprocess.run(
            ["aircrack-ng", cap_file, "-b", bssid, "-w", wordlist],
            capture_output=True, text=True
        )
        if "KEY FOUND" in result.stdout:
            key = result.stdout.split("KEY FOUND!")[1].split("]")[0].strip("[ ")
            log_message(f"[SUCCESS] Handshake cracked: {bssid} = {key}", ui=ui)
            return key
        else:
            log_message(f"[INFO] No key found for {bssid}", ui=ui)
            return None
    except Exception as e:
        log_message(f"[ERROR] Handshake cracking failed: {e}", ui=ui)
        return None


def send_probe_request(interface, source_mac="00:11:22:33:44:55"):
    """Send a Wi-Fi probe request with a specified source MAC to elicit network responses."""
    log_message(f"Sending probe request from {source_mac}...", ui=None)

    pkt = scapy.RadioTap() / Dot11(
        type=0, subtype=4,
        addr1="ff:ff:ff:ff:ff:ff",
        addr2=source_mac,
        addr3="ff:ff:ff:ff:ff:ff"
    ) / Dot11ProbeReq()

    try:
        scapy.sendp(pkt, iface=interface, count=3, inter=0.1, verbose=0)
        log_message("Probe request sent successfully", ui=None)
    except Exception as e:
        log_message(f"[ERROR] Failed to send probe request: {e}", ui=None)
