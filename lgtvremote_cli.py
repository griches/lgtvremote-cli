#!/usr/bin/env python3
"""
lgtvremote-cli — Command-line interface for controlling LG webOS TVs.

Communicates over WebSocket (SSAP protocol) on port 3001.
Supports discovery, pairing, remote control, app launching, and Wake-on-LAN.

Zero dependencies — uses only the Python standard library.
"""

import argparse
import hashlib
import base64
import json
import os
import pathlib
import random
import socket
import struct
import ssl
import sys
import textwrap
import time
import urllib.parse
import uuid
from typing import Any, Optional

__version__ = "1.5.0"

# ---------------------------------------------------------------------------
# Minimal WebSocket client (RFC 6455) — no external dependencies
# ---------------------------------------------------------------------------

class WebSocket:
    """Minimal WebSocket client using only the standard library."""

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._closed = False

    @classmethod
    def connect(cls, url: str, timeout: float = 10.0) -> "WebSocket":
        """Connect to a WebSocket URL (ws:// or wss://)."""
        if url.startswith("wss://"):
            scheme, default_port, use_ssl = "wss", 3001, True
            rest = url[6:]
        elif url.startswith("ws://"):
            scheme, default_port, use_ssl = "ws", 80, False
            rest = url[5:]
        else:
            raise ValueError(f"Unsupported URL scheme: {url}")

        # Parse host:port/path
        if "/" in rest:
            host_port, path = rest.split("/", 1)
            path = "/" + path
        else:
            host_port = rest
            path = "/"

        if ":" in host_port:
            host, port_str = host_port.rsplit(":", 1)
            port = int(port_str)
        else:
            host, port = host_port, default_port

        # Create TCP socket
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        raw_sock.connect((host, port))

        if use_ssl:
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            sock = ssl_ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock

        # WebSocket handshake
        ws_key = base64.b64encode(random.randbytes(16)).decode()
        handshake = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        )
        sock.sendall(handshake.encode())

        # Read response headers
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed during handshake")
            response += chunk

        status_line = response.split(b"\r\n")[0].decode()
        if "101" not in status_line:
            raise ConnectionError(f"WebSocket handshake failed: {status_line}")

        ws = cls(sock)

        # If there's leftover data after headers, buffer it
        header_end = response.index(b"\r\n\r\n") + 4
        ws._recv_buffer = response[header_end:]

        return ws

    def send(self, message: str):
        """Send a text message."""
        if self._closed:
            raise ConnectionError("WebSocket is closed")
        self._send_frame(0x1, message.encode())

    def recv(self, timeout: Optional[float] = None) -> str:
        """Receive a text message. Returns the decoded string."""
        if self._closed:
            raise ConnectionError("WebSocket is closed")

        old_timeout = self._sock.gettimeout()
        if timeout is not None:
            self._sock.settimeout(timeout)
        try:
            opcode, data = self._recv_frame()
        finally:
            self._sock.settimeout(old_timeout)

        if opcode == 0x1:  # Text
            return data.decode()
        elif opcode == 0x2:  # Binary
            return data.decode()
        elif opcode == 0x8:  # Close
            self._closed = True
            raise ConnectionError("WebSocket closed by server")
        elif opcode == 0x9:  # Ping
            self._send_frame(0xA, data)  # Pong
            return self.recv(timeout)
        elif opcode == 0xA:  # Pong
            return self.recv(timeout)
        else:
            return data.decode()

    def close(self):
        """Close the WebSocket connection."""
        if not self._closed:
            try:
                self._send_frame(0x8, b"")
            except OSError:
                pass
            self._closed = True
            try:
                self._sock.close()
            except OSError:
                pass

    def _send_frame(self, opcode: int, data: bytes):
        """Send a WebSocket frame (always masked, as required for clients)."""
        frame = bytearray()
        frame.append(0x80 | opcode)  # FIN + opcode

        length = len(data)
        if length < 126:
            frame.append(0x80 | length)  # Mask bit + length
        elif length < 65536:
            frame.append(0x80 | 126)
            frame.extend(struct.pack("!H", length))
        else:
            frame.append(0x80 | 127)
            frame.extend(struct.pack("!Q", length))

        # Masking key
        mask = random.randbytes(4)
        frame.extend(mask)

        # Masked payload
        masked = bytearray(length)
        for i in range(length):
            masked[i] = data[i] ^ mask[i % 4]
        frame.extend(masked)

        self._sock.sendall(bytes(frame))

    def _read_bytes(self, n: int) -> bytes:
        """Read exactly n bytes from socket, using any buffered data first."""
        result = bytearray()

        # Use buffered data first
        if hasattr(self, "_recv_buffer") and self._recv_buffer:
            take = min(n, len(self._recv_buffer))
            result.extend(self._recv_buffer[:take])
            self._recv_buffer = self._recv_buffer[take:]
            n -= take

        while n > 0:
            chunk = self._sock.recv(min(n, 65536))
            if not chunk:
                raise ConnectionError("Connection closed")
            result.extend(chunk)
            n -= len(chunk)

        return bytes(result)

    def _recv_frame(self) -> tuple:
        """Receive a WebSocket frame. Returns (opcode, payload_data)."""
        header = self._read_bytes(2)
        opcode = header[0] & 0x0F
        masked = bool(header[1] & 0x80)
        length = header[1] & 0x7F

        if length == 126:
            length = struct.unpack("!H", self._read_bytes(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._read_bytes(8))[0]

        if masked:
            mask = self._read_bytes(4)
            data = bytearray(self._read_bytes(length))
            for i in range(length):
                data[i] ^= mask[i % 4]
            data = bytes(data)
        else:
            data = self._read_bytes(length)

        return opcode, data


# ---------------------------------------------------------------------------
# Config persistence
# ---------------------------------------------------------------------------
CONFIG_DIR = pathlib.Path.home() / ".config" / "lgtvremote"
CONFIG_FILE = CONFIG_DIR / "devices.json"


def _load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {"devices": {}, "default": None}


def _save_config(cfg: dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2) + "\n")


def _get_device(cfg: dict, ip: Optional[str]) -> Optional[dict]:
    if ip:
        return cfg["devices"].get(ip)
    if cfg.get("default"):
        return cfg["devices"].get(cfg["default"])
    if len(cfg["devices"]) == 1:
        return next(iter(cfg["devices"].values()))
    return None


def _get_device_ip(cfg: dict, tv: Optional[str]) -> Optional[str]:
    if tv:
        # Direct IP match
        if tv in cfg["devices"]:
            return tv
        # Name match (case-insensitive) — prefer paired devices over stale entries
        lower = tv.lower()
        best_ip = None
        for dev_ip, dev in cfg["devices"].items():
            if dev.get("name", "").lower() == lower:
                if dev.get("client_key"):
                    best_ip = dev_ip  # keep searching; last paired wins, but any paired beats unpaired
                elif best_ip is None:
                    best_ip = dev_ip
        if best_ip:
            return best_ip
        # Fall back to treating it as an IP anyway (for new/unknown devices)
        return tv
    if cfg.get("default"):
        return cfg["default"]
    if len(cfg["devices"]) == 1:
        return next(iter(cfg["devices"]))
    return None


def _migrate_device_ip(cfg: dict, new_ip: str, mac: Optional[str] = None,
                       wifi_mac: Optional[str] = None,
                       name: Optional[str] = None,
                       model: Optional[str] = None) -> Optional[str]:
    """If an existing device matches by MAC (or name+model), migrate it to the new IP.

    Returns the old IP if a migration happened, None otherwise.
    """
    if new_ip in cfg["devices"]:
        return None  # Already exists at this IP

    for old_ip, dev in list(cfg["devices"].items()):
        if old_ip == new_ip:
            continue
        # Match by MAC address (most reliable)
        if mac and dev.get("mac") and dev["mac"].upper() == mac.upper():
            pass
        elif wifi_mac and dev.get("wifi_mac") and dev["wifi_mac"].upper() == wifi_mac.upper():
            pass
        elif (name and model and dev.get("name") == name and dev.get("model") == model):
            pass
        else:
            continue

        # Found a match — migrate to new IP
        old_name = dev.get("name", old_ip)
        print(f"  IP changed: {old_name} moved from {old_ip} to {new_ip}")
        dev["ip"] = new_ip
        cfg["devices"][new_ip] = dev
        del cfg["devices"][old_ip]
        if cfg.get("default") == old_ip:
            cfg["default"] = new_ip
        return old_ip

    return None


# ---------------------------------------------------------------------------
# SSAP WebSocket protocol
# ---------------------------------------------------------------------------
REGISTRATION_PAYLOAD = {
    "manifest": {
        "manifestVersion": 1,
        "appVersion": "1.1",
        "signed": {
            "created": "20140509",
            "appId": "com.lge.test",
            "vendorId": "com.lge",
            "localizedAppNames": {
                "": "LG Remote App",
                "ko-KR": "\ub9ac\ubaa8\ucee8 \uc571",
                "zxx-XX": "\u041b\u0413 R\u044d\u043cot\u044d A\u041f\u041f",
            },
            "localizedVendorNames": {"": "LG Electronics"},
            "permissions": [
                "TEST_SECURE", "CONTROL_INPUT_TEXT", "CONTROL_MOUSE_AND_KEYBOARD",
                "READ_INSTALLED_APPS", "READ_LGE_SDX", "READ_NOTIFICATIONS",
                "SEARCH", "WRITE_SETTINGS", "WRITE_NOTIFICATION_ALERT",
                "CONTROL_POWER", "READ_CURRENT_CHANNEL", "READ_RUNNING_APPS",
                "READ_UPDATE_INFO", "UPDATE_FROM_REMOTE_APP", "READ_LGE_TV_INPUT_EVENTS",
                "READ_TV_CURRENT_TIME",
            ],
            "serial": "2f930e2d2cfe083771f68e4fe7bb07"
        },
        "permissions": [
            "LAUNCH", "LAUNCH_WEBAPP", "APP_TO_APP", "CLOSE",
            "TEST_OPEN", "TEST_PROTECTED", "CONTROL_AUDIO",
            "CONTROL_DISPLAY", "CONTROL_INPUT_JOYSTICK",
            "CONTROL_INPUT_MEDIA_RECORDING", "CONTROL_INPUT_MEDIA_PLAYBACK",
            "CONTROL_INPUT_TV", "CONTROL_MOUSE_AND_KEYBOARD",
            "CONTROL_INPUT_TEXT", "CONTROL_POWER",
            "READ_APP_STATUS", "READ_CURRENT_CHANNEL",
            "READ_INPUT_DEVICE_LIST", "READ_NETWORK_STATE",
            "READ_RUNNING_APPS", "READ_TV_CHANNEL_LIST",
            "WRITE_NOTIFICATION_TOAST", "READ_POWER_STATE",
            "READ_COUNTRY_INFO", "READ_SETTINGS",
            "CONTROL_TV_SCREEN", "CONTROL_TV_STANBY",
            "CONTROL_FAVORITE_GROUP", "CONTROL_USER_INFO",
            "CHECK_BLUETOOTH_DEVICE", "CONTROL_BLUETOOTH",
            "CONTROL_TIMER_INFO", "STB_INTERNAL_CONNECTION",
            "CONTROL_RECORDING", "READ_RECORDING_STATE",
            "WRITE_RECORDING_LIST", "READ_RECORDING_LIST",
            "READ_RECORDING_SCHEDULE", "WRITE_RECORDING_SCHEDULE",
        ],
        "signatures": [
            {
                "signatureVersion": 1,
                "signature": "eyJhbGdvcml0aG0iOiJSU0EtU0hBMjU2Iiwia2V5SWQiOiJ0ZXN0LXNpZ25pbmctY2VydCIsInNpZ25hdHVyZVZlcnNpb24iOjF9.hrVRgjCwXVvE2OOSpDZ58hR+59aFNwYDyjQgKk3auukd7pcegmE2CzPCa0bJ0ZsRAcKkCTJrWo5iDzNhMBWRyaMOv5zWSrthlf7G128qvIlpMT0YNY+n/FaOHE73uLrS/g7swl3/qH/BGFG2Hu4RlL48eb3lLKqTt2xKHdCs6Cd4RMfJPYnzgvI4BNrFUKsjkcu+WD4OO2A27Pq1n50cMchmcaXadJhGrOqH5YmHdOCj5NSHzJYrsW0HPlpuAx/ECMeIZYDh6RMqaFM2DXzdKX9NmmyqzJ3o/0lkk/N97gfVRLW5hA29yeAwaCViZNCP8iC9aO0q9fQojoa7NQnAtw==",
            }
        ],
    }
}


def _ws_connect(ip: str, client_key: Optional[str] = None, timeout: float = 10.0) -> tuple:
    """Connect and register with the TV. Returns (websocket, client_key)."""
    uri = f"wss://{ip}:3001"
    ws = WebSocket.connect(uri, timeout=timeout)

    # Register
    reg = dict(REGISTRATION_PAYLOAD)
    if client_key:
        reg["client-key"] = client_key
        pairing_type = "prompt"
    else:
        pairing_type = "pin"

    reg_msg = {
        "type": "register",
        "id": str(uuid.uuid4()),
        "payload": {**reg, "pairingType": pairing_type, "forcePairing": client_key is None},
    }

    ws.send(json.dumps(reg_msg, ensure_ascii=False, separators=(",", ":")))

    # Wait for registration response
    new_key = client_key
    registered = False
    start = time.monotonic()

    while time.monotonic() - start < timeout:
        try:
            raw = ws.recv(timeout=max(1, timeout - (time.monotonic() - start)))
        except (socket.timeout, TimeoutError):
            break
        except ConnectionError:
            break

        resp = json.loads(raw)
        resp_type = resp.get("type", "")
        payload = resp.get("payload", {})

        if resp_type == "registered":
            new_key = payload.get("client-key", client_key)
            registered = True
            break
        elif resp_type == "response" and "client-key" in payload:
            new_key = payload["client-key"]
            registered = True
            break
        elif resp_type == "error":
            error_msg = resp.get("error", "Unknown error")
            raise ConnectionError(f"Registration failed: {error_msg}")
        elif "pairingType" in payload and payload.get("pairingType") == "pin":
            if not client_key:
                raise ConnectionError("NEEDS_PIN")

    if not registered:
        raise ConnectionError("Registration timed out — is the TV on and reachable?")

    return ws, new_key


def _send_request(ws: WebSocket, uri: str, payload: Optional[dict] = None, subscribe: bool = False) -> dict:
    """Send an SSAP request and return the response payload."""
    msg_id = str(uuid.uuid4())
    msg = {
        "type": "subscribe" if subscribe else "request",
        "id": msg_id,
        "uri": uri,
    }
    if payload:
        msg["payload"] = payload

    ws.send(json.dumps(msg))

    # Wait for matching response
    start = time.monotonic()
    while time.monotonic() - start < 10:
        try:
            raw = ws.recv(timeout=5)
        except (socket.timeout, TimeoutError):
            break
        except ConnectionError:
            break
        resp = json.loads(raw)
        if resp.get("id") == msg_id:
            return resp.get("payload", {})
    return None


def _send_button(ws: WebSocket, uri: str, payload: Optional[dict] = None):
    """Send a button press (fire-and-forget)."""
    msg = {
        "type": "request",
        "id": str(uuid.uuid4()),
        "uri": uri,
    }
    if payload:
        msg["payload"] = payload
    ws.send(json.dumps(msg))


# ---------------------------------------------------------------------------
# Wake-on-LAN
# ---------------------------------------------------------------------------
def _send_wol(mac: str, ip: Optional[str] = None):
    """Send Wake-on-LAN magic packet."""
    mac_clean = mac.replace(":", "").replace("-", "").upper()
    if len(mac_clean) != 12 or not all(c in "0123456789ABCDEF" for c in mac_clean):
        print(f"Error: Invalid MAC address: {mac}", file=sys.stderr)
        return False

    mac_bytes = bytes.fromhex(mac_clean)
    packet = b"\xff" * 6 + mac_bytes * 16

    targets = ["255.255.255.255"]
    if ip:
        parts = ip.split(".")
        if len(parts) == 4:
            targets.insert(0, f"{parts[0]}.{parts[1]}.{parts[2]}.255")
            targets.append(ip)

    for port in (9, 7):
        for target in targets:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.sendto(packet, (target, port))
                s.close()
            except OSError:
                pass

    return True


# ---------------------------------------------------------------------------
# SSDP Discovery
# ---------------------------------------------------------------------------
def _ssdp_discover(timeout: float = 5.0) -> list[dict]:
    """Discover LG webOS TVs via SSDP."""
    search_target = "urn:lge-com:service:webos-second-screen:1"
    m_search = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 3\r\n"
        f"ST: {search_target}\r\n"
        "\r\n"
    )

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.settimeout(2.0)

    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack("b", 4))
    except OSError:
        pass

    devices = {}
    msg_bytes = m_search.encode()

    destinations = [
        ("239.255.255.250", 1900),
        ("255.255.255.255", 1900),
    ]

    for attempt in range(3):
        for dest in destinations:
            try:
                s.sendto(msg_bytes, dest)
            except OSError:
                pass

        end_time = time.monotonic() + 2.0
        while time.monotonic() < end_time:
            try:
                data, addr = s.recvfrom(4096)
                response = data.decode("utf-8", errors="replace")
                ip = addr[0]

                if ip in devices:
                    continue
                if "lge" not in response.lower() and search_target not in response:
                    continue

                name = ip
                location = None
                for line in response.split("\r\n"):
                    lower = line.lower()
                    if lower.startswith("dlnadevicename.lge.com:"):
                        raw_name = line.split(":", 1)[1].strip()
                        try:
                            from urllib.parse import unquote
                            name = unquote(raw_name)
                        except Exception:
                            name = raw_name
                    elif lower.startswith("location:"):
                        location = line.split(":", 1)[1].strip()

                devices[ip] = {"ip": ip, "name": name, "location": location}
            except socket.timeout:
                break
            except OSError:
                break

    s.close()
    return list(devices.values())


def _enrich_device(ip: str, location: Optional[str] = None) -> dict:
    """Fetch model name and MAC addresses from the TV.

    Tries the UPnP device description XML first (works on all webOS versions),
    then falls back to the HTTP API on port 3000 (newer webOS only).
    """
    import urllib.request
    info: dict[str, Any] = {}

    # 1. UPnP XML — available on all webOS versions via the Location URL
    upnp_url = location or f"http://{ip}:1787/"
    try:
        req = urllib.request.Request(upnp_url)
        with urllib.request.urlopen(req, timeout=3) as resp:
            xml = resp.read().decode("utf-8", errors="replace")

            # friendlyName
            fn_start = xml.find("<friendlyName>")
            fn_end = xml.find("</friendlyName>")
            if fn_start >= 0 and fn_end > fn_start:
                name = xml[fn_start + 14:fn_end].strip()
                if name:
                    info["name"] = name

            # modelNumber (e.g. OLED55B9PLA)
            mn_start = xml.find("<modelNumber>")
            mn_end = xml.find("</modelNumber>")
            if mn_start >= 0 and mn_end > mn_start:
                model = xml[mn_start + 13:mn_end].strip()
                if model:
                    info["model"] = model

            # Fallback: modelName (e.g. "LG Smart TV")
            if "model" not in info:
                mn2_start = xml.find("<modelName>")
                mn2_end = xml.find("</modelName>")
                if mn2_start >= 0 and mn2_end > mn2_start:
                    model2 = xml[mn2_start + 11:mn2_end].strip()
                    if model2:
                        info["model"] = model2

            # bluetoothMac field (some TVs include this)
            bt_start = xml.find("<bluetoothMac>")
            bt_end = xml.find("</bluetoothMac>")
            if bt_start >= 0 and bt_end > bt_start:
                bt_mac = xml[bt_start + 14:bt_end].strip()
                if bt_mac and bt_mac != "00:00:00:00:00:00":
                    # Bluetooth MAC is often WiFi MAC + 1, not useful for WOL
                    pass
    except Exception:
        pass

    # 2. Port 3000 HTTP API — newer webOS (5.0+) only
    if "model" not in info:
        try:
            req = urllib.request.Request(
                f"http://{ip}:3000/api/com.webos.service.tv.systemproperty/getSystemInfo",
                data=b'{"keys":["modelName","firmwareVersion"]}',
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read())
                if "modelName" in data:
                    info["model"] = data["modelName"]
        except Exception:
            pass

    if "mac" not in info:
        try:
            param = '{"category":"network","keys":["macAddress","wifiMacAddress"]}'
            from urllib.parse import quote
            url = f"http://{ip}:3000/system/lge/setting?reqParam={quote(param)}"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read())
                settings = data.get("settings", {})
                mac = settings.get("macAddress", "")
                wifi_mac = settings.get("wifiMacAddress", "")
                if mac and mac != "00:00:00:00:00:00":
                    info["mac"] = _format_mac(mac)
                if wifi_mac and wifi_mac != "00:00:00:00:00:00":
                    info["wifi_mac"] = _format_mac(wifi_mac)
        except Exception:
            pass

    return info


def _format_mac(mac: str) -> str:
    clean = mac.replace(":", "").replace("-", "").upper()
    if len(clean) != 12:
        return mac
    return ":".join(clean[i:i+2] for i in range(0, 12, 2))


def _fetch_macs_via_ws(ip: str, client_key: str) -> dict:
    """Fetch real MAC addresses via WebSocket (most reliable method).

    Tries multiple endpoints matching what the iOS app does:
    1. ssap://com.webos.service.connectionmanager/getinfo
    2. ssap://com.webos.service.connectionmanager/getStatus (older webOS)
    """
    macs: dict[str, str] = {}
    try:
        ws, _ = _ws_connect(ip, client_key, timeout=5)

        endpoints = [
            "ssap://com.webos.service.connectionmanager/getinfo",
            "ssap://com.webos.service.connectionmanager/getStatus",
        ]

        for endpoint in endpoints:
            if macs:
                break
            result = _send_request(ws, endpoint)
            if not result:
                continue

            # Format 1: {"wiredInfo": {"macAddress": "..."}, "wifiInfo": {"macAddress": "..."}}
            for section_key, mac_key in [("wiredInfo", "mac"), ("wifiInfo", "wifi_mac"),
                                          ("wired", "mac"), ("wifi", "wifi_mac")]:
                section = result.get(section_key, {})
                if isinstance(section, dict):
                    mac = section.get("macAddress", "")
                    if mac and mac != "00:00:00:00:00:00":
                        macs[mac_key] = _format_mac(mac)

            # Format 2: flat {"macAddress": "...", "wifiMacAddress": "..."}
            if "mac" not in macs:
                for key in ("macAddress", "wiredMacAddress"):
                    mac = result.get(key, "")
                    if mac and mac != "00:00:00:00:00:00":
                        macs["mac"] = _format_mac(mac)
                        break
            if "wifi_mac" not in macs:
                mac = result.get("wifiMacAddress", "")
                if mac and mac != "00:00:00:00:00:00":
                    macs["wifi_mac"] = _format_mac(mac)

        ws.close()
    except (ConnectionError, OSError, TimeoutError):
        pass
    return macs


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def _do_pair(ip: str, cfg: dict) -> bool:
    """Pair with a TV. Returns True on success. Saves client key and MACs to cfg."""
    name = cfg["devices"].get(ip, {}).get("name", ip)
    print(f"Pairing with {name} ({ip})...")

    try:
        ws = WebSocket.connect(f"wss://{ip}:3001", timeout=10)
    except (OSError, TimeoutError, ConnectionError) as e:
        print(f"  Could not connect: {e}")
        return False

    reg_msg = {
        "type": "register",
        "id": str(uuid.uuid4()),
        "payload": {
            **REGISTRATION_PAYLOAD,
            "pairingType": "PIN",
            "forcePairing": False,
        },
    }
    ws.send(json.dumps(reg_msg))

    pin_requested = False
    start = time.monotonic()
    while time.monotonic() - start < 60:
        try:
            raw = ws.recv(timeout=30)
        except (socket.timeout, TimeoutError, ConnectionError):
            break

        resp = json.loads(raw)
        resp_type = resp.get("type", "")
        payload = resp.get("payload", {})

        if resp_type == "registered" or "client-key" in payload:
            key = payload.get("client-key")
            if key:
                cfg["devices"][ip]["client_key"] = key
                _save_config(cfg)
                print("  Paired successfully!")
                ws.close()

                # Fetch real MAC addresses
                print("  Fetching MAC addresses...")
                macs = _fetch_macs_via_ws(ip, key)
                if macs:
                    cfg["devices"][ip].update(macs)
                    _save_config(cfg)
                    for k, v in macs.items():
                        label = "MAC (wired)" if k == "mac" else "MAC (wifi)"
                        print(f"  {label}: {v}")

                # Cache input labels
                print("  Fetching input labels...")
                try:
                    result = _connect_and_send(
                        ip, cfg, "ssap://tv/getExternalInputList",
                        wait_response=True,
                    )
                    if result and "devices" in result:
                        _cache_input_labels(ip, result["devices"])
                        count = len([d for d in result["devices"] if d.get("label", "").strip()])
                        print(f"  Cached {count} input label(s).")
                except (OSError, TimeoutError, ConnectionError):
                    pass  # Non-critical — labels will be cached on next 'inputs' call

                return True

        elif payload.get("pairingType") in ("PIN", "pin") and not pin_requested:
            pin = input("  Enter the PIN shown on your TV: ").strip()
            pin_msg = {
                "type": "request",
                "id": str(uuid.uuid4()),
                "uri": "ssap://pairing/setPin",
                "payload": {"pin": pin},
            }
            ws.send(json.dumps(pin_msg))
            pin_requested = True

        elif resp_type == "error":
            print(f"  Pairing failed: {resp.get('error', 'Unknown error')}")
            ws.close()
            return False

    print("  Pairing timed out.")
    ws.close()
    return False


def cmd_scan(args):
    """Scan the local network for LG webOS TVs, add them, and pair."""
    print("Scanning for LG webOS TVs...")
    devices = _ssdp_discover(timeout=args.timeout if hasattr(args, "timeout") else 5.0)
    if not devices:
        print("No TVs found. Ensure your TV is on and on the same network.")
        return

    cfg = _load_config()

    print(f"\nFound {len(devices)} TV(s):\n")
    for d in devices:
        ip = d["ip"]
        info = _enrich_device(ip, location=d.get("location"))
        name = info.get("name", d["name"])

        # Check if this TV was previously saved under a different IP
        _migrate_device_ip(cfg, ip, name=info.get("name") or name,
                           model=info.get("model"))

        # Auto-add the device
        device = cfg["devices"].get(ip, {"ip": ip})
        device["ip"] = ip
        if info.get("name"):
            device["name"] = info["name"]
        elif "name" not in device:
            device["name"] = name
        if info.get("model"):
            device["model"] = info["model"]
        cfg["devices"][ip] = device
        if not cfg.get("default"):
            cfg["default"] = ip
        _save_config(cfg)

        already_paired = bool(device.get("client_key"))
        print(f"  {device.get('name', ip)}")
        print(f"    IP: {ip}")
        if info.get("model"):
            print(f"    Model: {info['model']}")
        if already_paired:
            print(f"    Status: already paired")
            # Fetch MACs if missing
            if not device.get("mac") and not device.get("wifi_mac"):
                macs = _fetch_macs_via_ws(ip, device["client_key"])
                if macs:
                    device.update(macs)
                    _save_config(cfg)
            if device.get("mac"):
                print(f"    MAC: {device['mac']}")
            if device.get("wifi_mac"):
                print(f"    MAC (wifi): {device['wifi_mac']}")
        else:
            print(f"    Status: new — pairing required")

        print()

    # Offer to pair any unpaired devices
    unpaired = [ip for ip, d in cfg["devices"].items()
                if not d.get("client_key") and ip in {dev["ip"] for dev in devices}]
    if unpaired:
        for ip in unpaired:
            name = cfg["devices"][ip].get("name", ip)
            answer = input(f"Pair with {name} ({ip})? [Y/n] ").strip().lower()
            if answer in ("", "y", "yes"):
                _do_pair(ip, cfg)
            print()


def cmd_add(args):
    """Add a TV by IP address, enrich, and pair."""
    cfg = _load_config()
    ip = args.ip

    # Enrich first so we can detect IP changes via name+model
    info = {}
    if not args.no_enrich:
        print(f"Fetching device info from {ip}...")
        info = _enrich_device(ip)

    # Check if this TV was previously saved under a different IP
    _migrate_device_ip(cfg, ip, mac=args.mac, wifi_mac=args.wifi_mac,
                       name=info.get("name") or args.name,
                       model=info.get("model"))

    device = cfg["devices"].get(ip, {"ip": ip})
    device["ip"] = ip
    if args.name:
        device["name"] = args.name
    elif "name" not in device:
        device["name"] = ip
    if args.mac:
        device["mac"] = _format_mac(args.mac)
    if args.wifi_mac:
        device["wifi_mac"] = _format_mac(args.wifi_mac)

    if info:
        if info.get("name") and not args.name and device.get("name") == ip:
            device["name"] = info["name"]
        if info.get("model") and "model" not in device:
            device["model"] = info["model"]

    cfg["devices"][ip] = device
    if not cfg.get("default"):
        cfg["default"] = ip
    _save_config(cfg)

    name = device.get("name", ip)
    print(f"Added TV: {name} ({ip})")
    if device.get("model"):
        print(f"  Model: {device['model']}")

    # Auto-pair if not already paired
    if not device.get("client_key") and not args.no_enrich:
        print()
        _do_pair(ip, cfg)
    elif device.get("client_key") and not device.get("mac") and not device.get("wifi_mac"):
        # Already paired but missing MACs — fetch them
        print("Fetching MAC addresses...")
        macs = _fetch_macs_via_ws(ip, device["client_key"])
        if macs:
            device.update(macs)
            _save_config(cfg)
            for k, v in macs.items():
                label = "MAC (wired)" if k == "mac" else "MAC (wifi)"
                print(f"  {label}: {v}")


def cmd_remove(args):
    """Remove a saved TV."""
    cfg = _load_config()
    ip = _get_device_ip(cfg, args.tv)
    if not ip or ip not in cfg["devices"]:
        print(f"Error: No TV saved matching '{args.tv}'", file=sys.stderr)
        sys.exit(1)

    name = cfg["devices"][ip].get("name", ip)
    del cfg["devices"][ip]
    if cfg.get("default") == ip:
        cfg["default"] = next(iter(cfg["devices"]), None)
    _save_config(cfg)
    print(f"Removed TV: {name} ({ip})")


def cmd_list(args):
    """List saved TVs."""
    cfg = _load_config()
    if not cfg["devices"]:
        print("No TVs saved. Use 'lgtv add <ip>' or 'lgtv scan' to find TVs.")
        return

    default_ip = cfg.get("default")
    for ip, d in cfg["devices"].items():
        marker = " *" if ip == default_ip else ""
        name = d.get("name", ip)
        model = f" ({d['model']})" if d.get("model") else ""
        paired = " [paired]" if d.get("client_key") else ""
        print(f"  {name}{model} — {ip}{paired}{marker}")

    if default_ip:
        print(f"\n  * = default TV")


def cmd_set_default(args):
    """Set the default TV."""
    cfg = _load_config()
    ip = _get_device_ip(cfg, args.tv)
    if not ip or ip not in cfg["devices"]:
        print(f"Error: No TV saved matching '{args.tv}'. Use 'lgtv add <ip>' first.", file=sys.stderr)
        sys.exit(1)
    cfg["default"] = ip
    _save_config(cfg)
    name = cfg["devices"][ip].get("name", ip)
    print(f"Default TV set to: {name} ({ip})")


def cmd_pair(args):
    """Pair with a TV using PIN-based authentication."""
    cfg = _load_config()
    ip = _get_device_ip(cfg, args.tv)
    if not ip:
        print("Error: No TV specified and no default set. Use --tv <ip> or 'lgtv pair --tv <ip>'.", file=sys.stderr)
        sys.exit(1)

    if ip not in cfg["devices"]:
        cfg["devices"][ip] = {"ip": ip, "name": ip}

    if not _do_pair(ip, cfg):
        sys.exit(1)


def _connect_and_send(ip: str, cfg: dict, uri: str, payload: Optional[dict] = None,
                       subscribe: bool = False, wait_response: bool = True) -> Optional[dict]:
    """Connect, authenticate, send a command, return response."""
    device = cfg["devices"].get(ip, {})
    client_key = device.get("client_key")

    try:
        ws, new_key = _ws_connect(ip, client_key)
    except ConnectionError as e:
        if "NEEDS_PIN" in str(e):
            print("Error: TV requires pairing. Run 'lgtv pair' first.", file=sys.stderr)
            sys.exit(1)
        raise

    # Save key if new/updated
    if new_key and new_key != client_key:
        if ip not in cfg["devices"]:
            cfg["devices"][ip] = {"ip": ip, "name": ip}
        cfg["devices"][ip]["client_key"] = new_key
        _save_config(cfg)

    if wait_response:
        result = _send_request(ws, uri, payload, subscribe=subscribe)
    else:
        _send_button(ws, uri, payload)
        result = None

    ws.close()
    return result


def _run_command(args, uri: str, payload: Optional[dict] = None,
                 wait_response: bool = False, subscribe: bool = False) -> Optional[dict]:
    """Helper to run a single TV command."""
    cfg = _load_config()
    ip = _get_device_ip(cfg, args.tv)
    if not ip:
        print("Error: No TV specified and no default set. Use --tv <ip> or 'lgtv set-default <ip>'.", file=sys.stderr)
        sys.exit(1)

    try:
        return _connect_and_send(ip, cfg, uri, payload, subscribe=subscribe, wait_response=wait_response)
    except ConnectionError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except (OSError, TimeoutError) as e:
        print(f"Error: Could not connect to TV at {ip}: {e}", file=sys.stderr)
        sys.exit(1)


# --- Luna settings write (alert workaround) ---
# ssap://com.webos.service.settings/setSystemSettings returns "404 no such
# service or method" on most webOS firmware. The working path is to create an
# invisible alert whose button/onclose/onfail handlers all point at the luna
# settings service, then immediately close the alert — closing fires the
# embedded luna call. Confirmed working on webOS CX firmware.
_LUNA_SETTINGS_URI = "luna://com.webos.settingsservice/setSystemSettings"


def _luna_call(ws: WebSocket, uri: str, params: dict) -> bool:
    """Invoke any internal luna:// endpoint via the alert workaround.

    Returns True if the alert round-trip succeeded (alertId received).
    Write-only: the luna call's own result never comes back.
    """
    alert_payload = {
        "message": " ",
        "buttons": [{"label": "", "onClick": uri, "params": params}],
        "onclose": {"uri": uri, "params": params},
        "onfail": {"uri": uri, "params": params},
    }
    resp = _send_request(ws, "ssap://system.notifications/createAlert", alert_payload)
    alert_id = (resp or {}).get("alertId")
    if not alert_id:
        return False
    _send_request(ws, "ssap://system.notifications/closeAlert", {"alertId": alert_id})
    return True


def _luna_set(ws: WebSocket, category: str, settings: dict) -> bool:
    """Write system settings via the createAlert/closeAlert luna workaround."""
    return _luna_call(ws, _LUNA_SETTINGS_URI, {"category": category, "settings": settings})


def _run_luna_calls(args, calls: list) -> bool:
    """Run one or more (uri, params) luna calls over a single connection."""
    cfg = _load_config()
    ip = _get_device_ip(cfg, args.tv)
    if not ip:
        print("Error: No TV specified and no default set. Use --tv <ip> or 'lgtv set-default <ip>'.", file=sys.stderr)
        sys.exit(1)

    device = cfg["devices"].get(ip, {})
    client_key = device.get("client_key")

    try:
        ws, new_key = _ws_connect(ip, client_key)
    except ConnectionError as e:
        if "NEEDS_PIN" in str(e):
            print("Error: TV requires pairing. Run 'lgtv pair' first.", file=sys.stderr)
        else:
            print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except (OSError, TimeoutError) as e:
        print(f"Error: Could not connect to TV at {ip}: {e}", file=sys.stderr)
        sys.exit(1)

    if new_key and new_key != client_key:
        cfg["devices"].setdefault(ip, {"ip": ip, "name": ip})["client_key"] = new_key
        _save_config(cfg)

    ok = all(_luna_call(ws, uri, params) for uri, params in calls)
    ws.close()
    return ok


def _run_luna_set(args, category: str, settings: dict) -> bool:
    """Helper to run a luna settings write against the selected TV."""
    return _run_luna_calls(
        args, [(_LUNA_SETTINGS_URI, {"category": category, "settings": settings})]
    )


# --- Power ---
def cmd_on(args):
    """Turn on the TV via Wake-on-LAN."""
    cfg = _load_config()
    ip = _get_device_ip(cfg, args.tv)
    if not ip:
        print("Error: No TV specified and no default set.", file=sys.stderr)
        sys.exit(1)

    device = cfg["devices"].get(ip, {})
    macs = []
    if device.get("mac"):
        macs.append(device["mac"])
    if device.get("wifi_mac"):
        macs.append(device["wifi_mac"])

    if not macs:
        print("Error: No MAC address stored for this TV. Use 'lgtv add <ip> --mac <mac>'.", file=sys.stderr)
        sys.exit(1)

    for mac in macs:
        _send_wol(mac, ip)
    print(f"Wake-on-LAN sent to {device.get('name', ip)}")


def cmd_off(args):
    """Turn off the TV."""
    _run_command(args, "ssap://system/turnOff")
    print("TV powered off.")


def cmd_power(args):
    """Toggle TV power (off via WebSocket, on via WOL)."""
    cfg = _load_config()
    ip = _get_device_ip(cfg, args.tv)
    if not ip:
        print("Error: No TV specified and no default set.", file=sys.stderr)
        sys.exit(1)

    try:
        _connect_and_send(ip, cfg, "ssap://system/turnOff", wait_response=False)
        print("TV powered off.")
    except (ConnectionError, OSError, TimeoutError):
        device = cfg["devices"].get(ip, {})
        macs = [m for m in [device.get("mac"), device.get("wifi_mac")] if m]
        if macs:
            for mac in macs:
                _send_wol(mac, ip)
            print(f"TV appears off. Wake-on-LAN sent.")
        else:
            print("Error: TV unreachable and no MAC address for WOL.", file=sys.stderr)
            sys.exit(1)


def cmd_power_status(args):
    """Report the TV's real power state: on, standby, or off.

    Quick Start+ TVs accept WebSocket connections while the panel is off, so a
    successful connect alone can't distinguish on from standby — ask
    getPowerState and report what the TV says. Exit code 0 only when the panel
    is actually on.
    """
    cfg = _load_config()
    ip = _get_device_ip(cfg, args.tv)
    if not ip:
        print("Error: No TV specified and no default set.", file=sys.stderr)
        sys.exit(1)

    device = cfg["devices"].get(ip, {})
    client_key = device.get("client_key")

    try:
        ws, _ = _ws_connect(ip, client_key, timeout=3.0)
    except (ConnectionError, OSError, TimeoutError):
        status = {"power": "off", "ip": ip, "name": device.get("name", ip)}
        print(json.dumps(status))
        sys.exit(1)

    try:
        resp = _send_request(
            ws, "ssap://com.webos.service.tvpower/power/getPowerState"
        )
    finally:
        ws.close()

    state = (resp or {}).get("state", "")
    if state in ("Standby", "Active Standby", "Suspend"):
        power = "standby"
    else:
        # "Active", plus unknown states (e.g. Screen Off's audio-only mode) —
        # the socket answered and the TV didn't say standby, so call it on.
        power = "on"
    status = {"power": power, "ip": ip, "name": device.get("name", ip)}
    if state:
        status["state"] = state
    print(json.dumps(status))
    if power != "on":
        sys.exit(1)


# --- Volume ---
def cmd_volume_up(args):
    _run_command(args, "ssap://audio/volumeUp")
    print("Volume up.")

def cmd_volume_down(args):
    _run_command(args, "ssap://audio/volumeDown")
    print("Volume down.")

def cmd_mute(args):
    _run_command(args, "ssap://audio/setMute", {"mute": True})
    print("Muted.")

def cmd_unmute(args):
    _run_command(args, "ssap://audio/setMute", {"mute": False})
    print("Unmuted.")

# webOS rejects ssap://audio/setVolume when audio is routed to these outputs.
# Relative volumeUp / volumeDown still work via CEC.
_UNSUPPORTED_SETVOLUME_OUTPUTS = {
    "external_arc",
    "external_optical",
    "bt_soundbar",
    "soundbar",
    "lineout",
}

_SOUND_OUTPUT_DISPLAY = {
    "external_arc": "HDMI ARC",
    "external_optical": "Optical",
    "bt_soundbar": "Bluetooth soundbar",
    "soundbar": "soundbar",
    "lineout": "line out",
}


def cmd_set_volume(args):
    # Query current sound output first — the LG TV silently ignores setVolume
    # when audio is routed externally (e.g. via HDMI ARC to a Sonos), so warn
    # the user instead of pretending the command worked.
    status = _run_command(args, "ssap://audio/getVolume", wait_response=True)
    if status:
        sound_output = status.get("soundOutput") \
            or (status.get("volumeStatus") or {}).get("soundOutput")
        if sound_output in _UNSUPPORTED_SETVOLUME_OUTPUTS:
            print(
                "Error: Slider unavailable. TV audio is routed through external source.",
                file=sys.stderr,
            )
            sys.exit(1)

    _run_command(args, "ssap://audio/setVolume", {"volume": args.level})
    print(f"Volume set to {args.level}.")

def cmd_get_volume(args):
    result = _run_command(args, "ssap://audio/getVolume", wait_response=True)
    if result:
        vol = result.get("volume", result.get("volumeStatus", {}).get("volume", "?"))
        muted = result.get("mute", result.get("muteStatus", result.get("volumeStatus", {}).get("muteStatus", "?")))
        print(f"Volume: {vol}")
        print(f"Muted: {muted}")
    else:
        print("Could not get volume info.")


# --- Navigation ---
def cmd_nav(args):
    """Handle navigation button presses."""
    key_map = {
        "up": "UP", "down": "DOWN", "left": "LEFT", "right": "RIGHT",
        "ok": "ENTER", "enter": "ENTER", "select": "ENTER",
        "back": "BACK", "home": "HOME", "menu": "MENU",
    }

    button = args.button.lower()
    key = key_map.get(button)
    if not key:
        print(f"Error: Unknown button '{button}'. Valid: {', '.join(sorted(key_map))}", file=sys.stderr)
        sys.exit(1)

    cfg = _load_config()
    ip = _get_device_ip(cfg, args.tv)
    if not ip:
        print("Error: No TV specified and no default set.", file=sys.stderr)
        sys.exit(1)

    try:
        device = cfg["devices"].get(ip, {})
        client_key = device.get("client_key")
        ws, new_key = _ws_connect(ip, client_key)

        if new_key and new_key != client_key:
            if ip not in cfg["devices"]:
                cfg["devices"][ip] = {"ip": ip, "name": ip}
            cfg["devices"][ip]["client_key"] = new_key
            _save_config(cfg)

        # Get pointer input socket
        result = _send_request(ws, "ssap://com.webos.service.networkinput/getPointerInputSocket")
        sock_path = (result or {}).get("socketPath")
        if not sock_path:
            # Fallback for basic nav
            fallback_uris = {
                "ENTER": "ssap://com.webos.service.ime/sendEnterKey",
                "BACK": "ssap://com.webos.service.ime/deleteCharacters",
            }
            if key in fallback_uris:
                _send_button(ws, fallback_uris[key])
            ws.close()
            print(f"Sent: {button}")
            return

        # Connect to pointer socket
        pointer_ws = WebSocket.connect(sock_path, timeout=5)
        pointer_ws.send(f"type:button\nname:{key}\n\n")
        time.sleep(0.1)
        pointer_ws.close()
        ws.close()
        print(f"Sent: {button}")
    except ConnectionError as e:
        if "NEEDS_PIN" in str(e):
            print("Error: TV requires pairing. Run 'lgtv pair' first.", file=sys.stderr)
        else:
            print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except (OSError, TimeoutError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


# --- Channel ---
def cmd_channel_up(args):
    _run_command(args, "ssap://tv/channelUp")
    print("Channel up.")

def cmd_channel_down(args):
    _run_command(args, "ssap://tv/channelDown")
    print("Channel down.")

def cmd_set_channel(args):
    print("Channel selection is not supported. Use channel up/down instead.")


# --- Live TV ---

def cmd_livetv(args):
    """Switch to Live TV."""
    _run_command(args, "ssap://system.launcher/launch", {"id": "com.webos.app.livetv"})
    print("Switched to Live TV.")


def cmd_channels(args):
    print("Channel listing is not supported.")


# --- Media ---
def cmd_play(args):
    _run_command(args, "ssap://media.controls/play")
    print("Playing.")

def cmd_pause(args):
    _run_command(args, "ssap://media.controls/pause")
    print("Paused.")

def cmd_stop(args):
    _run_command(args, "ssap://media.controls/stop")
    print("Stopped.")

def cmd_rewind(args):
    _run_command(args, "ssap://media.controls/rewind")
    print("Rewinding.")

def cmd_fast_forward(args):
    _run_command(args, "ssap://media.controls/fastForward")
    print("Fast forwarding.")

def cmd_skip_forward(args):
    _run_command(args, "ssap://media.controls/skipForward")
    print("Skipped forward.")

def cmd_skip_back(args):
    _run_command(args, "ssap://media.controls/skipBackward")
    print("Skipped backward.")


# --- Input / HDMI ---

def _cache_input_labels(ip: str, devices: list):
    """Cache input labels from getExternalInputList response into device config."""
    cfg = _load_config()
    device = cfg["devices"].get(ip)
    if not device:
        return
    labels = {}
    for d in devices:
        input_id = d.get("id")
        label = d.get("label", "").strip()
        if input_id and label:
            labels[input_id] = label
    if labels:
        device["input_labels"] = labels
        _save_config(cfg)


def _resolve_input(args, name: str) -> str:
    """Resolve an input name/number/alias to an input ID."""
    upper = name.upper()
    # Numeric shorthand: 1 -> HDMI_1
    if upper.isdigit():
        return f"HDMI_{upper}"
    # Already a valid input ID
    if upper.startswith("HDMI_") or upper.startswith("COMP_"):
        return upper
    # Check cached input labels for a match (case-insensitive)
    cfg = _load_config()
    ip = _get_device_ip(cfg, args.tv)
    if ip:
        device = cfg["devices"].get(ip, {})
        labels = device.get("input_labels", {})
        lower = name.lower()
        for input_id, label in labels.items():
            if label.lower() == lower:
                return input_id
    # Fall back to HDMI_ prefix
    return f"HDMI_{upper}"


def cmd_input(args):
    """Switch TV input."""
    input_id = _resolve_input(args, args.input)

    _run_command(args, "ssap://tv/switchInput", {"inputId": input_id})
    print(f"Switched to {input_id}.")


def cmd_inputs(args):
    """List available inputs."""
    cfg = _load_config()
    ip = _get_device_ip(cfg, args.tv)
    result = _run_command(args, "ssap://tv/getExternalInputList", wait_response=True)
    if result and "devices" in result:
        # Cache labels for alias resolution
        if ip:
            _cache_input_labels(ip, result["devices"])

        print("Available inputs:\n")
        for d in result["devices"]:
            label = d.get("label", d.get("id", "?"))
            input_id = d.get("id", "?")
            connected = d.get("connected", False)
            status = " [connected]" if connected else ""
            print(f"  {input_id}: {label}{status}")
    else:
        print("Could not fetch input list.")


def cmd_input_alias(args):
    """Set or remove a custom alias for an input on this TV."""
    cfg = _load_config()
    ip = _get_device_ip(cfg, args.tv)
    if not ip:
        print("Error: No TV specified and no default set.", file=sys.stderr)
        sys.exit(1)
    device = cfg["devices"].get(ip)
    if not device:
        print(f"Error: No device found for {ip}.", file=sys.stderr)
        sys.exit(1)

    input_id = args.input_id.upper()
    if not input_id.startswith("HDMI_") and not input_id.startswith("COMP_"):
        input_id = f"HDMI_{input_id}"

    labels = device.get("input_labels", {})
    if args.alias:
        labels[input_id] = args.alias
        device["input_labels"] = labels
        _save_config(cfg)
        print(f"Set alias for {input_id}: {args.alias}")
    else:
        if input_id in labels:
            removed = labels.pop(input_id)
            device["input_labels"] = labels
            _save_config(cfg)
            print(f"Removed alias for {input_id} (was: {removed}).")
        else:
            print(f"No alias set for {input_id}.")


# --- Apps ---

KNOWN_APPS = {
    "netflix": "netflix",
    "youtube": "youtube.leanback.v4",
    "amazon": "amazon",
    "prime": "amazon",
    "primevideo": "amazon",
    "disney": "com.disney.disneyplus-prod",
    "disney+": "com.disney.disneyplus-prod",
    "disneyplus": "com.disney.disneyplus-prod",
    "hulu": "hulu",
    "hbo": "hbo-go-2",
    "hbomax": "hbo-go-2",
    "apple": "com.apple.tv",
    "appletv": "com.apple.tv",
    "spotify": "spotify-beehive",
    "plex": "plex",
    "crunchyroll": "crunchyroll",
    "twitch": "twitch",
    "vudu": "vudu",
    "livetv": "com.webos.app.livetv",
    "tv": "com.webos.app.livetv",
    "settings": "com.webos.app.settings",
    "browser": "com.webos.app.browser",
}


def cmd_launch(args):
    """Launch an app on the TV by name, shortcut, or app ID."""
    app = args.app
    app_id = KNOWN_APPS.get(app.lower())

    if not app_id:
        # Not a known shortcut — try matching against installed app names
        cfg = _load_config()
        ip = _get_device_ip(cfg, args.tv)
        if ip:
            result = _run_command(args, "ssap://com.webos.applicationManager/listApps", wait_response=True)
            if result and "apps" in result:
                app_lower = app.lower()
                # Exact title match first
                for a in result["apps"]:
                    if a.get("title", "").lower() == app_lower:
                        app_id = a["id"]
                        break
                # Substring match as fallback
                if not app_id:
                    matches = [a for a in result["apps"]
                               if app_lower in a.get("title", "").lower()]
                    if len(matches) == 1:
                        app_id = matches[0]["id"]
                    elif len(matches) > 1:
                        print(f"Multiple apps match '{app}':\n")
                        for m in matches:
                            print(f"  {m.get('title', '?')}")
                            print(f"    ID: {m['id']}")
                        print(f"\nBe more specific, or use the app ID directly.")
                        return

        # Fall back to using the input as a raw app ID
        if not app_id:
            app_id = app

    payload: dict[str, Any] = {"id": app_id}

    if args.params:
        params = {}
        for p in args.params:
            if "=" in p:
                k, v = p.split("=", 1)
                params[k] = v
        if params:
            payload["params"] = params

    _run_command(args, "ssap://system.launcher/launch", payload)
    print(f"Launched: {app_id}")


def cmd_apps(args):
    """List installed apps."""
    result = _run_command(args, "ssap://com.webos.applicationManager/listApps", wait_response=True)
    if result and "apps" in result:
        apps = sorted(result["apps"], key=lambda a: a.get("title", "").lower())
        print(f"Installed apps ({len(apps)}):\n")
        for a in apps:
            title = a.get("title", "?")
            app_id = a.get("id", "?")
            print(f"  {title}")
            print(f"    ID: {app_id}")
    else:
        print("Could not fetch app list.")


def cmd_app(args):
    """Get the currently running foreground app."""
    result = _run_command(args, "ssap://com.webos.applicationManager/getForegroundAppInfo", wait_response=True)
    if result:
        app_id = result.get("appId", "?")
        print(f"Foreground app: {app_id}")
    else:
        print("Could not get foreground app info.")


# --- YouTube deep link ---
# Port of the iOS PlayYouTubeVideoIntent (c4bc23f). Accepts a full watch URL,
# a youtu.be short link, a Shorts/live/embed link, or a bare 11-character id,
# and launches the YouTube app directly on that video via the leanback URL —
# unlike open-url, which leaves the routing to webOS.
_YT_ID_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")


def _is_youtube_video_id(candidate: str) -> bool:
    """YouTube ids are exactly 11 base64url characters."""
    return len(candidate) == 11 and all(c in _YT_ID_CHARS for c in candidate)


def _youtube_video_id(text: str) -> Optional[str]:
    """Pull the video id out of whatever the user hands over."""
    trimmed = text.strip()
    if not trimmed:
        return None
    if _is_youtube_video_id(trimmed):
        return trimmed

    # urlsplit needs a scheme; pasted links often arrive without one.
    normalized = trimmed if "://" in trimmed else "https://" + trimmed
    parts = urllib.parse.urlsplit(normalized)
    host = (parts.hostname or "").lower()
    if host not in ("youtu.be", "youtube.com") and not host.endswith(".youtube.com"):
        return None

    query = urllib.parse.parse_qs(parts.query)
    for v in query.get("v", []):
        if _is_youtube_video_id(v):
            return v

    path = [p for p in parts.path.split("/") if p]
    if host == "youtu.be" and path and _is_youtube_video_id(path[0]):
        return path[0]
    if (len(path) >= 2 and path[0].lower() in ("shorts", "live", "embed", "v")
            and _is_youtube_video_id(path[1])):
        return path[1]
    return None


def cmd_youtube(args):
    """Open a specific YouTube video on the TV."""
    video_id = _youtube_video_id(args.video)
    if not video_id:
        print("Error: Could not find a YouTube video id in that. Pass a watch URL, "
              "a youtu.be/Shorts/live link, or the 11-character video id.",
              file=sys.stderr)
        sys.exit(1)
    _run_command(args, "ssap://system.launcher/launch", {
        "id": "youtube.leanback.v4",
        "params": {"contentTarget": f"https://www.youtube.com/tv?v={video_id}"},
    })
    print(f"Playing YouTube video {video_id} on the TV.")


# --- Display/Settings (newer TVs only) ---
_SETTINGS_NOTE = "(may not work on older TVs)"


def _screen_off_with_fallback(args) -> bool:
    """Blank the panel, audio left on.

    tvpower/turnOffScreen is the real endpoint but older firmware doesn't have
    the service — those sets reach the same panel-off state via the luna
    energy-saving screen_off write, the identical fallback iOS uses.
    """
    result = _run_command(args, "ssap://com.webos.service.tvpower/power/turnOffScreen",
                          wait_response=True)
    if result and result.get("returnValue"):
        return True
    return _run_luna_set(args, "picture", {"energySaving": "screen_off"})


def cmd_screen_off(args):
    if _screen_off_with_fallback(args):
        print("Screen off (audio continues).")
    else:
        print("Error: TV did not accept the screen-off command.", file=sys.stderr)
        sys.exit(1)


def _parse_sleep_duration(text: str) -> Optional[int]:
    """'30' or '30m' -> 1800, '90s' -> 90, '1h' -> 3600, '1h30m' -> 5400."""
    spec = text.strip().lower()
    if spec.isdigit():
        return int(spec) * 60 or None
    total, number = 0, ""
    for ch in spec:
        if ch.isdigit():
            number += ch
        elif ch in "hms" and number:
            total += int(number) * {"h": 3600, "m": 60, "s": 1}[ch]
            number = ""
        else:
            return None
    if number:  # trailing bare number after a unit, e.g. "1h30"
        total += int(number) * 60
    return total or None


def cmd_screen_sleep(args):
    """Screen Sleep: blank the panel after a delay, keeping the audio on.

    Port of the apps' Screen Sleep feature — fall asleep to a programme, or
    run a music channel without the panel lit. The countdown runs in this
    process; Ctrl-C cancels it and the screen stays on.
    """
    seconds = _parse_sleep_duration(args.duration)
    if not seconds:
        print("Error: duration must be like 30, 45m, 90s or 1h30m.", file=sys.stderr)
        sys.exit(1)

    fire_at = time.strftime("%H:%M", time.localtime(time.time() + seconds))
    minutes = round(seconds / 60)
    print(f"Screen off at {fire_at} (in {minutes} minute{'s' if minutes != 1 else ''}), "
          "audio stays on. Ctrl-C to cancel.")
    try:
        time.sleep(seconds)
    except KeyboardInterrupt:
        print("\nCancelled — screen stays on.")
        sys.exit(0)

    if _screen_off_with_fallback(args):
        print("Screen off (audio continues). 'lgtv screen-on' wakes it.")
    else:
        print("Error: TV did not accept the screen-off command.", file=sys.stderr)
        sys.exit(1)


_PICTURE_MODES = ("vivid", "normal", "eco", "cinema", "sports", "game",
                  "filmMaker", "expert1", "expert2")


def cmd_picture_mode(args):
    # Case-insensitive match against the canonical webOS mode IDs
    mode = {m.lower(): m for m in _PICTURE_MODES}.get(args.mode.lower())
    if not mode:
        print(f"Error: mode must be one of {', '.join(_PICTURE_MODES)}.", file=sys.stderr)
        sys.exit(1)
    if _run_luna_set(args, "picture", {"pictureMode": mode}):
        print(f"Picture mode set to: {mode}")
    else:
        print("Error: TV did not accept the picture mode change.", file=sys.stderr)
        sys.exit(1)


# --- Picture levels (backlight/brightness/contrast/color) ---
# These four keys are the only ones ssap://settings/getSystemSettings accepts
# for reads in the "picture" category — other keys are rejected by the TV.
# Values come back as strings or ints depending on firmware.

def _get_picture_level(args, key: str):
    """Read a picture level via getSystemSettings and print it."""
    result = _run_command(args, "ssap://settings/getSystemSettings",
                          {"category": "picture", "keys": [key]},
                          wait_response=True)
    value = ((result or {}).get("settings") or {}).get(key)
    if value is None:
        print(f"Could not get {key}.")
        sys.exit(1)
    print(f"{key.capitalize()}: {value}")


def _set_picture_level(args, key: str, level: int):
    """Set a picture level (0-100) via the luna alert workaround."""
    if level < 0 or level > 100:
        print(f"Error: {key} must be 0-100.", file=sys.stderr)
        sys.exit(1)
    if _run_luna_set(args, "picture", {key: level}):
        print(f"{key.capitalize()} set to {level}.")
    else:
        print(f"Error: TV did not accept the {key} change.", file=sys.stderr)
        sys.exit(1)


def cmd_backlight(args):
    if args.level is None:
        _get_picture_level(args, "backlight")
    else:
        _set_picture_level(args, "backlight", args.level)


def cmd_brightness(args):
    if args.level is None:
        _get_picture_level(args, "brightness")
    else:
        _set_picture_level(args, "brightness", args.level)


def cmd_contrast(args):
    if args.level is None:
        _get_picture_level(args, "contrast")
    else:
        _set_picture_level(args, "contrast", args.level)


_TRUMOTION_MODES = ("off", "smooth", "clear", "user")


def cmd_trumotion(args):
    mode = args.mode.lower()
    if mode not in _TRUMOTION_MODES:
        print(f"Error: mode must be one of {', '.join(_TRUMOTION_MODES)}.", file=sys.stderr)
        sys.exit(1)
    if _run_luna_set(args, "picture", {"truMotionMode": mode}):
        print(f"TruMotion set to: {mode}")
    else:
        print("Error: TV did not accept the TruMotion change.", file=sys.stderr)
        sys.exit(1)


def cmd_sound_mode(args):
    _run_command(args, "ssap://com.webos.service.settings/setSystemSettings",
                 {"category": "sound", "settings": {"soundMode": args.mode}})
    print(f"Sound mode set to: {args.mode} {_SETTINGS_NOTE}")


_SOUND_OUTPUTS = ("tv_speaker", "external_arc", "external_optical", "bt_soundbar",
                  "headphone", "lineout", "tv_external_speaker", "tv_speaker_headphone")


def cmd_sound_output(args):
    if not args.output:
        # No output given — show the current one (reported in the volume status)
        result = _run_command(args, "ssap://audio/getVolume", wait_response=True)
        if result:
            sound_output = result.get("soundOutput") \
                or (result.get("volumeStatus") or {}).get("soundOutput", "?")
            print(f"Sound output: {sound_output}")
        else:
            print("Could not get sound output info.")
        return

    output = args.output.lower()
    if output not in _SOUND_OUTPUTS:
        print(f"Error: output must be one of {', '.join(_SOUND_OUTPUTS)}.", file=sys.stderr)
        sys.exit(1)
    _run_command(args, "ssap://com.webos.service.apiadapter/audio/changeSoundOutput",
                 {"output": output})
    print(f"Sound output set to: {output} {_SETTINGS_NOTE}")


def cmd_subtitles(args):
    _run_command(args, "ssap://com.webos.service.settings/setSystemSettings",
                 {"category": "caption", "settings": {"state": "toggle"}})
    print(f"Toggled subtitles. {_SETTINGS_NOTE}")


def cmd_audio_track(args):
    _run_command(args, "ssap://media.controls/changeAudioTrack")
    print(f"Cycled audio track. {_SETTINGS_NOTE}")


def cmd_screen_on(args):
    _run_command(args, "ssap://com.webos.service.tvpower/power/turnOnScreen")
    print("Screen on.")


_ENERGY_SAVING_MODES = ("auto", "off", "min", "med", "max", "screen_off")


def cmd_energy_saving(args):
    mode = args.mode.lower()
    if mode not in _ENERGY_SAVING_MODES:
        print(f"Error: mode must be one of {', '.join(_ENERGY_SAVING_MODES)}.", file=sys.stderr)
        sys.exit(1)
    if _run_luna_set(args, "picture", {"energySaving": mode}):
        print(f"Energy saving set to: {mode}")
    else:
        print("Error: TV did not accept the energy saving change.", file=sys.stderr)
        sys.exit(1)


# --- Panel auto-dimming (TPC / GSR) ---
# OLED models from 2020 (webOS 5) expose com.webos.service.oledepl; the calls
# are silent no-ops on older models and LCDs. The TV restores both protections
# after a power cycle, so re-run after powering the TV back on. Same endpoints
# bscpylgtv and ColorControl use.
_LUNA_TPC_URI = "luna://com.webos.service.oledepl/setTemporalPeakControl"
_LUNA_GSR_URI = "luna://com.webos.service.oledepl/setGlobalStressReduction"


def cmd_dimming(args):
    state = args.state.lower()
    if state not in ("on", "off"):
        print("Error: state must be 'on' or 'off'.", file=sys.stderr)
        sys.exit(1)
    enable = state == "on"

    # Default to both unless the user singled one out
    do_tpc = args.tpc or not args.gsr
    do_gsr = args.gsr or not args.tpc

    calls = []
    if do_tpc:
        calls.append((_LUNA_TPC_URI, {"enable": enable}))
    if do_gsr:
        calls.append((_LUNA_GSR_URI, {"enable": enable}))

    if _run_luna_calls(args, calls):
        which = "TPC and GSR" if do_tpc and do_gsr else ("TPC" if do_tpc else "GSR")
        print(f"Panel auto-dimming ({which}) {'enabled' if enable else 'disabled'}.")
        if not enable:
            print("Note: the TV restores dimming after a power cycle — re-run this "
                  "command after powering the TV back on. Increases burn-in risk "
                  "while static content stays on screen.")
    else:
        print("Error: TV did not accept the dimming change (needs a 2020+ LG OLED).",
              file=sys.stderr)
        sys.exit(1)


# --- Scenes ---
# Named presets that apply a batch of TV settings in one command, mirroring
# the iOS/Android apps' Scenes feature. Scenes are stored per TV in
# devices.json. Apply order matters: input switches and picture-mode switches
# both swap in stored picture values, so the input goes first (1.5s settle),
# then the picture mode (1s settle), then everything else in one batched luna
# write; sound output is unaffected by the swapping and fires immediately.

def _scene_config(args):
    """Load config and resolve the target device entry for scene commands."""
    cfg = _load_config()
    ip = _get_device_ip(cfg, args.tv)
    if not ip:
        print("Error: No TV specified and no default set. Use --tv <ip> or 'lgtv set-default <ip>'.", file=sys.stderr)
        sys.exit(1)
    device = cfg["devices"].setdefault(ip, {"ip": ip, "name": ip})
    return cfg, ip, device


def _find_scene(device: dict, name: str) -> Optional[dict]:
    for scene in device.get("scenes", []):
        if scene.get("name", "").lower() == name.lower():
            return scene
    return None


def _scene_summary(scene: dict) -> str:
    parts = []
    if scene.get("input"):
        parts.append(f"input={scene['input']}")
    if scene.get("picture_mode"):
        parts.append(f"picture-mode={scene['picture_mode']}")
    for key in ("backlight", "brightness", "contrast", "color"):
        if scene.get(key) is not None:
            parts.append(f"{key}={scene[key]}")
    if scene.get("energy_saving"):
        parts.append(f"energy-saving={scene['energy_saving']}")
    if scene.get("trumotion"):
        parts.append(f"trumotion={scene['trumotion']}")
    if scene.get("sound_output"):
        parts.append(f"sound-output={scene['sound_output']}")
    return ", ".join(parts)


def cmd_scene_set(args):
    """Create or replace a scene. Only the flags you pass are saved — a scene
    only applies the settings it includes."""
    cfg, ip, device = _scene_config(args)

    scene = {"name": args.name}

    if args.input:
        scene["input"] = _resolve_input(args, args.input)
    if args.picture_mode:
        mode = {m.lower(): m for m in _PICTURE_MODES}.get(args.picture_mode.lower())
        if not mode:
            print(f"Error: picture mode must be one of {', '.join(_PICTURE_MODES)}.", file=sys.stderr)
            sys.exit(1)
        scene["picture_mode"] = mode
    for key, value in (("backlight", args.backlight), ("brightness", args.brightness),
                       ("contrast", args.contrast), ("color", args.color)):
        if value is not None:
            if value < 0 or value > 100:
                print(f"Error: {key} must be 0-100.", file=sys.stderr)
                sys.exit(1)
            scene[key] = value
    if args.energy_saving:
        mode = args.energy_saving.lower()
        if mode not in _ENERGY_SAVING_MODES:
            print(f"Error: energy saving mode must be one of {', '.join(_ENERGY_SAVING_MODES)}.", file=sys.stderr)
            sys.exit(1)
        scene["energy_saving"] = mode
    if args.trumotion:
        mode = args.trumotion.lower()
        if mode not in _TRUMOTION_MODES:
            print(f"Error: trumotion mode must be one of {', '.join(_TRUMOTION_MODES)}.", file=sys.stderr)
            sys.exit(1)
        scene["trumotion"] = mode
    if args.sound_output:
        output = args.sound_output.lower()
        if output not in _SOUND_OUTPUTS:
            print(f"Error: sound output must be one of {', '.join(_SOUND_OUTPUTS)}.", file=sys.stderr)
            sys.exit(1)
        scene["sound_output"] = output

    if len(scene) == 1:
        print("Error: a scene needs at least one setting (e.g. --picture-mode cinema).", file=sys.stderr)
        sys.exit(1)

    scenes = device.setdefault("scenes", [])
    existing = _find_scene(device, args.name)
    if existing:
        scenes[scenes.index(existing)] = scene
        action = "Updated"
    else:
        scenes.append(scene)
        action = "Saved"
    _save_config(cfg)
    print(f"{action} scene '{args.name}' for {device.get('name', ip)}: {_scene_summary(scene)}")


def cmd_scene_list(args):
    cfg, ip, device = _scene_config(args)
    scenes = device.get("scenes", [])
    if not scenes:
        print(f"No scenes saved for {device.get('name', ip)}. Add one with 'lgtv scene set <name> ...'.")
        return
    for scene in scenes:
        print(f"{scene['name']}: {_scene_summary(scene)}")


def cmd_scene_remove(args):
    cfg, ip, device = _scene_config(args)
    scene = _find_scene(device, args.name)
    if not scene:
        print(f"Error: no scene named '{args.name}' for {device.get('name', ip)}.", file=sys.stderr)
        sys.exit(1)
    device["scenes"].remove(scene)
    _save_config(cfg)
    print(f"Removed scene '{scene['name']}'.")


def cmd_scene_run(args):
    """Apply a scene's settings in the order the TV needs."""
    cfg, ip, device = _scene_config(args)
    scene = _find_scene(device, args.name)
    if not scene:
        print(f"Error: no scene named '{args.name}' for {device.get('name', ip)}. "
              f"List scenes with 'lgtv scene list'.", file=sys.stderr)
        sys.exit(1)

    client_key = device.get("client_key")
    try:
        ws, new_key = _ws_connect(ip, client_key)
    except ConnectionError as e:
        if "NEEDS_PIN" in str(e):
            print("Error: TV requires pairing. Run 'lgtv pair' first.", file=sys.stderr)
        else:
            print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except (OSError, TimeoutError) as e:
        print(f"Error: Could not connect to TV at {ip}: {e}", file=sys.stderr)
        sys.exit(1)

    if new_key and new_key != client_key:
        device["client_key"] = new_key
        _save_config(cfg)

    try:
        settle = 0.0
        if scene.get("input"):
            _send_request(ws, "ssap://tv/switchInput", {"inputId": scene["input"]})
            settle = 1.5  # input switches settle slower than mode switches

        if scene.get("sound_output"):
            _send_request(ws, "ssap://com.webos.service.apiadapter/audio/changeSoundOutput",
                          {"output": scene["sound_output"]})

        if scene.get("picture_mode"):
            if settle:
                time.sleep(settle)
            _luna_set(ws, "picture", {"pictureMode": scene["picture_mode"]})
            settle = 1.0

        picture = {}
        for key in ("backlight", "brightness", "contrast", "color"):
            if scene.get(key) is not None:
                picture[key] = scene[key]
        if scene.get("energy_saving"):
            picture["energySaving"] = scene["energy_saving"]
        if scene.get("trumotion"):
            picture["truMotionMode"] = scene["trumotion"]
        if picture:
            if settle:
                time.sleep(settle)
            _luna_set(ws, "picture", picture)
    finally:
        ws.close()

    print(f"Applied scene '{scene['name']}' on {device.get('name', ip)}.")


def cmd_screenshot(args):
    result = _run_command(args, "ssap://tv/executeOneShot", wait_response=True)
    if not result or not result.get("imageUri"):
        print("Error: TV did not return an image URI.", file=sys.stderr)
        sys.exit(1)

    image_uri = result["imageUri"]
    output = args.output or f"screenshot-{time.strftime('%Y%m%d-%H%M%S')}.jpg"

    import urllib.request
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(image_uri, timeout=15, context=ssl_ctx) as resp:
            data = resp.read()
    except (OSError, urllib.error.URLError) as e:
        print(f"Error fetching screenshot from TV: {e}", file=sys.stderr)
        sys.exit(1)

    pathlib.Path(output).write_bytes(data)
    print(f"Saved {len(data)} bytes to {output}")



# --- Number key ---
def cmd_number(args):
    """Send a number key (0-9) press."""
    cfg = _load_config()
    ip = _get_device_ip(cfg, args.tv)
    if not ip:
        print("Error: No TV specified and no default set.", file=sys.stderr)
        sys.exit(1)

    num = args.digit
    if num < 0 or num > 9:
        print("Error: Digit must be 0-9.", file=sys.stderr)
        sys.exit(1)

    try:
        device = cfg["devices"].get(ip, {})
        ws, new_key = _ws_connect(ip, device.get("client_key"))

        if new_key and new_key != device.get("client_key"):
            cfg["devices"].setdefault(ip, {"ip": ip, "name": ip})["client_key"] = new_key
            _save_config(cfg)

        result = _send_request(ws, "ssap://com.webos.service.networkinput/getPointerInputSocket")
        sock_path = (result or {}).get("socketPath")
        if sock_path:
            pointer_ws = WebSocket.connect(sock_path, timeout=5)
            pointer_ws.send(f"type:button\nname:{num}\n\n")
            time.sleep(0.1)
            pointer_ws.close()

        ws.close()
        print(f"Sent number: {num}")
    except (ConnectionError, OSError, TimeoutError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


# --- Color buttons / picture color level ---
def cmd_color(args):
    """Color button press (red/green/yellow/blue), or get/set the picture
    color level when given an integer 0-100 (or no argument)."""
    # No argument — read the current picture color level
    if args.color is None:
        _get_picture_level(args, "color")
        return

    color = args.color.lower()

    # Integer argument — set the picture color level via luna
    if color.lstrip("-").isdigit():
        _set_picture_level(args, "color", int(color))
        return

    key_map = {
        "red": "RED", "green": "GREEN", "yellow": "YELLOW", "blue": "BLUE",
    }

    key = key_map.get(color)
    if not key:
        print(f"Error: Unknown color '{color}'. Valid: red, green, yellow, blue, or a level 0-100", file=sys.stderr)
        sys.exit(1)

    cfg = _load_config()
    ip = _get_device_ip(cfg, args.tv)
    if not ip:
        print("Error: No TV specified and no default set.", file=sys.stderr)
        sys.exit(1)

    try:
        device = cfg["devices"].get(ip, {})
        ws, new_key = _ws_connect(ip, device.get("client_key"))

        if new_key and new_key != device.get("client_key"):
            cfg["devices"].setdefault(ip, {"ip": ip, "name": ip})["client_key"] = new_key
            _save_config(cfg)

        result = _send_request(ws, "ssap://com.webos.service.networkinput/getPointerInputSocket")
        sock_path = (result or {}).get("socketPath")
        if sock_path:
            pointer_ws = WebSocket.connect(sock_path, timeout=5)
            pointer_ws.send(f"type:button\nname:{key}\n\n")
            time.sleep(0.1)
            pointer_ws.close()

        ws.close()
        print(f"Sent: {color} button")
    except ConnectionError as e:
        if "NEEDS_PIN" in str(e):
            print("Error: TV requires pairing. Run 'lgtv pair' first.", file=sys.stderr)
        else:
            print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except (OSError, TimeoutError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


# --- Service menus ---
def cmd_service(args):
    """Access service/advanced menus."""
    menu = args.menu.lower()
    menus = {
        "instart": ("com.webos.app.factorywin", {"id": "com.webos.app.factorywin", "params": {"irKey": "inStart"}}),
        "in-start": ("com.webos.app.factorywin", {"id": "com.webos.app.factorywin", "params": {"irKey": "inStart"}}),
        "ezadjust": ("com.webos.app.factorywin", {"id": "com.webos.app.factorywin", "params": {"irKey": "ezAdjust"}}),
        "ez-adjust": ("com.webos.app.factorywin", {"id": "com.webos.app.factorywin", "params": {"irKey": "ezAdjust"}}),
        "hotel": ("com.webos.app.installation", {"id": "com.webos.app.installation"}),
        "hidden": ("com.webos.app.tvhotkey", {"id": "com.webos.app.tvhotkey", "params": {"activateType": "mute-hidden-action"}}),
        "freesync": ("com.webos.app.tvhotkey", {"id": "com.webos.app.tvhotkey", "params": {"activateType": "freesync-info"}}),
    }

    if menu not in menus:
        print(f"Error: Unknown service menu '{menu}'.", file=sys.stderr)
        print(f"Available: {', '.join(sorted(set(m.replace('-', '') for m in menus)))}", file=sys.stderr)
        sys.exit(1)

    _, payload = menus[menu]
    _run_command(args, "ssap://system.launcher/launch", payload)
    print(f"Opened service menu: {menu}")
    print(f"Default password: 0413 (alternatives: 0000, 7777)")


# --- Enrich ---
def cmd_enrich(args):
    """Fetch and update device info (model, MAC addresses)."""
    cfg = _load_config()
    ip = _get_device_ip(cfg, args.tv)
    if not ip:
        print("Error: No TV specified and no default set.", file=sys.stderr)
        sys.exit(1)

    if ip not in cfg["devices"]:
        print(f"Error: No TV saved with IP {ip}. Use 'lgtv add {ip}' first.", file=sys.stderr)
        sys.exit(1)

    print(f"Enriching device info for {ip}...")
    device = cfg["devices"][ip]

    # Try UPnP/HTTP enrichment for name and model
    info = _enrich_device(ip)
    if info.get("name"):
        device["name"] = info["name"]
        print(f"  Name: {info['name']}")
    if info.get("model"):
        device["model"] = info["model"]
        print(f"  Model: {info['model']}")

    # Fetch real MAC addresses via WebSocket (most reliable)
    client_key = device.get("client_key")
    if client_key:
        print("  Fetching MAC addresses via WebSocket...")
        macs = _fetch_macs_via_ws(ip, client_key)
        if macs:
            device.update(macs)
            for k, v in macs.items():
                label = "MAC (wired)" if k == "mac" else "MAC (wifi)"
                print(f"  {label}: {v}")
        else:
            print("  Could not fetch MACs via WebSocket.")
    else:
        print("  TV not paired — pair first to fetch MAC addresses.")

    # Fall back to HTTP API MACs if WebSocket didn't find any
    if "mac" not in device and info.get("mac"):
        device["mac"] = info["mac"]
        print(f"  MAC (wired): {info['mac']}")
    if "wifi_mac" not in device and info.get("wifi_mac"):
        device["wifi_mac"] = info["wifi_mac"]
        print(f"  MAC (wifi): {info['wifi_mac']}")

    _save_config(cfg)
    print("Device info updated.")


# --- Raw command ---
def cmd_open_url(args):
    """Open a URL on the TV in the built-in webOS browser."""
    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    _run_command(args, "ssap://system.launcher/open", {"target": url})
    print(f"Opened URL: {url}")


def cmd_raw(args):
    """Send a raw SSAP command."""
    payload = None
    if args.payload:
        try:
            payload = json.loads(args.payload)
        except json.JSONDecodeError:
            print("Error: Invalid JSON payload.", file=sys.stderr)
            sys.exit(1)

    cfg = _load_config()
    ip = _get_device_ip(cfg, args.tv)
    if not ip:
        print("Error: No TV specified and no default set.", file=sys.stderr)
        sys.exit(1)

    try:
        client_key = cfg["devices"].get(ip, {}).get("client_key")
        ws, new_key = _ws_connect(ip, client_key)
        if new_key and new_key != client_key:
            cfg["devices"].setdefault(ip, {"ip": ip, "name": ip})["client_key"] = new_key
            _save_config(cfg)

        msg_id = str(uuid.uuid4())
        msg = {"type": "request", "id": msg_id, "uri": args.uri}
        if payload:
            msg["payload"] = payload
        ws.send(json.dumps(msg))

        start = time.monotonic()
        full_resp = None
        while time.monotonic() - start < 10:
            try:
                raw = ws.recv(timeout=5)
            except (socket.timeout, TimeoutError):
                break
            except ConnectionError:
                break
            resp = json.loads(raw)
            if resp.get("id") == msg_id:
                full_resp = resp
                break
        ws.close()
    except (ConnectionError, OSError, TimeoutError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if full_resp is None:
        print("Command sent (no response received).")
    else:
        print(json.dumps(full_resp, indent=2))


# ---------------------------------------------------------------------------
# TV Self-Test — port of the apps' field-diagnostics sweep (iOS ae3b001)
# ---------------------------------------------------------------------------
# Drives a full command sweep against the live TV and records what actually
# responds — for diagnosing TVs we don't own. Scope rules match the apps:
#   - Writes that would persistently alter the TV's setup (picture/sound/
#     energy settings) are recorded as skipped, not fired.
#   - Disruptive-but-transient commands (volume, mute, media keys) run as-is;
#     nothing is restored afterwards.
#   - Power runs strictly LAST: off, pause, then back on via Wake-on-LAN,
#     and the cycle is proven by reconnecting, not assumed.
# "Passed" means the TV acknowledged the command (returnValue true) —
# it does not prove the TV visibly reacted.

def _self_test_power_cycle(ip: str, device: dict, record) -> None:
    """Off, pause, WoL on, then prove the TV came back by reconnecting."""
    macs = [m for m in (device.get("mac"), device.get("wifi_mac")) if m]
    if not macs:
        record("Power: cycle", "skipped", None, "no MAC stored — run 'lgtv enrich'")
        return

    client_key = device.get("client_key")
    try:
        ws, _ = _ws_connect(ip, client_key, timeout=5.0)
        start = time.monotonic()
        resp = _send_request(ws, "ssap://system/turnOff")
        ws.close()
        ok = bool(resp and resp.get("returnValue"))
        record("Power: off", "passed" if ok else "failed",
               int((time.monotonic() - start) * 1000), None)
        if not ok:
            return
    except (ConnectionError, OSError, TimeoutError):
        record("Power: off", "failed", None, None)
        return

    print("  … TV off, waiting 8s before waking it")
    time.sleep(8)
    for mac in macs:
        _send_wol(mac, ip)
    record("Power: Wake-on-LAN sent", "fired", None, None)

    # Quick Start+ sets come back in seconds; a cold boot takes ~30s.
    start = time.monotonic()
    deadline = start + 60
    while time.monotonic() < deadline:
        try:
            ws, _ = _ws_connect(ip, client_key, timeout=3.0)
            ws.close()
            record("Power: back on (reconnected)", "passed",
                   int((time.monotonic() - start) * 1000), None)
            return
        except (ConnectionError, OSError, TimeoutError):
            time.sleep(3)
    record("Power: back on (reconnected)", "failed", None,
           "no reconnect within 60s — check Quick Start+ / WoL settings")


def cmd_self_test(args):
    """Run the full command sweep and print a pass/fail report."""
    cfg = _load_config()
    ip = _get_device_ip(cfg, args.tv)
    if not ip:
        print("Error: No TV specified and no default set.", file=sys.stderr)
        sys.exit(1)
    device = cfg["devices"].get(ip, {})

    results = []  # (name, outcome, latency_ms, note)
    marks = {"passed": "✅", "failed": "❌", "fired": "➤ ", "skipped": "⏭ "}

    def record(name, outcome, latency_ms, note):
        results.append((name, outcome, latency_ms, note))
        latency = f" ({latency_ms} ms)" if latency_ms is not None else ""
        suffix = f" — {note}" if note else ""
        print(f"  {marks[outcome]} {name}{latency}{suffix}")

    print(f"TV Self-Test: {device.get('name', ip)} ({ip})")
    print("Passed = the TV acknowledged the command, not that it visibly reacted.\n")

    try:
        ws, new_key = _ws_connect(ip, device.get("client_key"))
    except ConnectionError as e:
        if "NEEDS_PIN" in str(e):
            print("Error: TV requires pairing. Run 'lgtv pair' first.", file=sys.stderr)
        else:
            print(f"  {marks['failed']} Connection check — {e}")
        sys.exit(1)
    except (OSError, TimeoutError) as e:
        print(f"  {marks['failed']} Connection check — {e}")
        sys.exit(1)
    if new_key and new_key != device.get("client_key"):
        cfg["devices"].setdefault(ip, {"ip": ip, "name": ip})["client_key"] = new_key
        _save_config(cfg)
    record("Connection check", "passed", 0, None)

    def step(name, uri, payload=None):
        start = time.monotonic()
        resp = _send_request(ws, uri, payload)
        ms = int((time.monotonic() - start) * 1000)
        if resp is None:
            record(name, "failed", None, "no response")
        elif resp.get("returnValue"):
            record(name, "passed", ms, None)
        else:
            record(name, "failed", ms, resp.get("errorText"))
        time.sleep(0.6)  # don't flood the TV; a human can follow along

    # -- State reads --
    step("Read: volume state", "ssap://audio/getVolume")
    step("Read: input list", "ssap://tv/getExternalInputList")
    step("Read: app list", "ssap://com.webos.applicationManager/listApps")
    step("Read: channel list", "ssap://tv/getChannelList")
    step("Read: foreground app", "ssap://com.webos.applicationManager/getForegroundAppInfo")
    step("Read: power state", "ssap://com.webos.service.tvpower/power/getPowerState")

    # -- Navigation (pointer input socket) --
    start = time.monotonic()
    resp = _send_request(ws, "ssap://com.webos.service.networkinput/getPointerInputSocket")
    sock_path = (resp or {}).get("socketPath")
    if sock_path:
        record("Nav: pointer socket", "passed",
               int((time.monotonic() - start) * 1000), None)
        try:
            pointer_ws = WebSocket.connect(sock_path, timeout=5)
            for key in ("UP", "DOWN", "BACK"):
                pointer_ws.send(f"type:button\nname:{key}\n\n")
                record(f"Nav: {key}", "fired", None, None)
                time.sleep(0.6)
            pointer_ws.close()
        except (ConnectionError, OSError, TimeoutError) as e:
            record("Nav: button send", "failed", None, str(e))
    else:
        record("Nav: pointer socket", "failed", None, None)

    # -- Transient commands (not restored afterwards) --
    step("Volume up", "ssap://audio/volumeUp")
    step("Volume down", "ssap://audio/volumeDown")
    step("Mute on", "ssap://audio/setMute", {"mute": True})
    step("Mute off", "ssap://audio/setMute", {"mute": False})
    step("Media: play", "ssap://media.controls/play")
    step("Media: pause", "ssap://media.controls/pause")

    # -- Persistent writes are out of scope, same as the apps --
    for name in ("picture settings", "sound settings", "energy saving", "screen off"):
        record(f"Write: {name}", "skipped", None, "would alter the TV's setup")

    ws.close()

    # -- Power strictly last --
    if args.skip_power:
        record("Power: cycle", "skipped", None, "--skip-power")
    else:
        _self_test_power_cycle(ip, device, record)

    failed = sum(1 for _, outcome, _, _ in results if outcome == "failed")
    passed = sum(1 for _, outcome, _, _ in results if outcome == "passed")
    print(f"\n{passed} passed, {failed} failed, "
          f"{len(results) - passed - failed} fired/skipped.")
    if failed:
        sys.exit(1)


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lgtv",
        description="Control LG webOS TVs from the command line.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              lgtv scan                         # Find TVs on network
              lgtv add 192.168.1.100            # Add a TV
              lgtv pair                         # Pair with default TV
              lgtv off                          # Turn off TV
              lgtv on                           # Wake TV via WOL
              lgtv volume set 25                # Set volume to 25
              lgtv launch Netflix               # Launch app by name
              lgtv input 1                      # Switch to HDMI 1
              lgtv nav ok                       # Press OK button
              lgtv picture-mode game            # Set picture mode
              lgtv backlight 80                 # Set backlight level
              lgtv brightness                   # Show current brightness
              lgtv energy-saving off            # Set energy saving mode
              lgtv dimming off                  # Disable OLED auto-dimming (TPC+GSR)
              lgtv trumotion off                # Turn off motion smoothing
              lgtv sound-output bt_soundbar     # Route audio to BT soundbar
              lgtv scene run "Movie Night"      # Apply a saved scene preset
              lgtv play                         # Play media
              lgtv apps                         # List installed apps
              lgtv youtube https://youtu.be/ID  # Open a YouTube video on the TV
              lgtv screen-sleep 30              # Screen off in 30 min, audio stays on
              lgtv self-test                    # Sweep commands, report what responds
              lgtv open-url https://example.com  # Open URL on TV
              lgtv raw ssap://system/turnOff    # Send raw SSAP command
        """),
    )

    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--tv", metavar="TV", help="TV IP address or name (overrides default)")

    sub = parser.add_subparsers(dest="command", help="Command to run")

    # Device management
    sub.add_parser("scan", help="Scan network for LG TVs")

    p_add = sub.add_parser("add", help="Add a TV by IP address")
    p_add.add_argument("ip", help="TV IP address")
    p_add.add_argument("--name", help="Custom name for the TV")
    p_add.add_argument("--mac", help="Wired MAC address (for Wake-on-LAN)")
    p_add.add_argument("--wifi-mac", help="WiFi MAC address (for Wake-on-LAN)")
    p_add.add_argument("--no-enrich", action="store_true", help="Skip auto-fetching device info")

    p_rm = sub.add_parser("remove", help="Remove a saved TV")
    p_rm.add_argument("tv", help="TV IP address or name")

    sub.add_parser("list", help="List saved TVs")

    p_def = sub.add_parser("set-default", help="Set the default TV")
    p_def.add_argument("tv", help="TV IP address or name")

    sub.add_parser("pair", help="Pair with TV (PIN authentication)")
    sub.add_parser("enrich", help="Fetch/update device info (model, MACs)")

    # Power
    sub.add_parser("on", help="Turn on TV (Wake-on-LAN)")
    sub.add_parser("off", help="Turn off TV")
    sub.add_parser("power", help="Toggle TV power")
    sub.add_parser(
        "power-status",
        help="Report real power state: on, standby, or off (JSON output)",
    )

    # Volume
    vol = sub.add_parser("volume", help="Volume control")
    vol_sub = vol.add_subparsers(dest="vol_cmd")
    vol_sub.add_parser("up", help="Volume up")
    vol_sub.add_parser("down", help="Volume down")
    vol_sub.add_parser("mute", help="Mute")
    vol_sub.add_parser("unmute", help="Unmute")
    p_vs = vol_sub.add_parser("set", help="Set volume level")
    p_vs.add_argument("level", type=int, help="Volume level (0-100)")
    vol_sub.add_parser("get", help="Get current volume")

    # Navigation
    p_nav = sub.add_parser("nav", help="Navigation buttons (up/down/left/right/ok/back/home/menu)")
    p_nav.add_argument("button", help="Button: up, down, left, right, ok, back, home, menu")

    # Channel
    ch = sub.add_parser("channel", help="Channel control")
    ch_sub = ch.add_subparsers(dest="ch_cmd")
    ch_sub.add_parser("up", help="Channel up")
    ch_sub.add_parser("down", help="Channel down")
    p_cs = ch_sub.add_parser("set", help="Switch to channel number")
    p_cs.add_argument("number", type=int, help="Channel number")

    # Live TV
    p_livetv = sub.add_parser("livetv", help="Switch to Live TV tuner")
    sub.add_parser("channels", help="List available TV channels (not supported)")

    # Media
    sub.add_parser("play", help="Play")
    sub.add_parser("pause", help="Pause")
    sub.add_parser("stop", help="Stop playback")
    sub.add_parser("rewind", help="Rewind")
    sub.add_parser("ff", help="Fast forward")
    sub.add_parser("skip-forward", help="Skip forward / next track")
    sub.add_parser("skip-back", help="Skip backward / previous track")

    # Input
    p_input = sub.add_parser("input", help="Switch TV input (e.g., HDMI_1, 1, or a label like 'PS5')")
    p_input.add_argument("input", help="Input ID, number, or label (e.g., 1, HDMI_1, PS5)")
    sub.add_parser("inputs", help="List available inputs")
    p_alias = sub.add_parser("input-alias", help="Set or remove a custom label for an input")
    p_alias.add_argument("input_id", help="Input ID (e.g., HDMI_1 or just 1)")
    p_alias.add_argument("alias", nargs="?", default=None, help="Label to set (omit to remove)")

    # Apps
    p_launch = sub.add_parser("launch", help="Launch an app")
    p_launch.add_argument("app", help="App name or ID (e.g., netflix, youtube, com.webos.app.browser)")
    p_launch.add_argument("params", nargs="*", help="Optional params as key=value pairs")
    sub.add_parser("apps", help="List installed apps")
    sub.add_parser("app", help="Show currently running app")

    p_yt = sub.add_parser("youtube", help="Open a specific YouTube video on the TV")
    p_yt.add_argument("video", help="YouTube link (watch/youtu.be/Shorts/live) or 11-char video id")

    # Display/Settings (newer TVs only)
    _newer = " (newer TVs only)"
    sub.add_parser("screen-off", help="Turn off screen, audio continues" + _newer)
    sub.add_parser("screen-on", help="Turn screen back on" + _newer)
    p_sleep = sub.add_parser("screen-sleep",
                             help="Turn the screen off after a delay, audio continues (Ctrl-C cancels)")
    p_sleep.add_argument("duration", help="Delay: 30 (minutes), 45m, 90s or 1h30m")

    p_pic = sub.add_parser("picture-mode", help="Set picture mode")
    p_pic.add_argument("mode", help=f"Picture mode: {', '.join(_PICTURE_MODES)}")

    p_bl = sub.add_parser("backlight", help="Get or set backlight level (0-100)")
    p_bl.add_argument("level", nargs="?", type=int, default=None,
                      help="Level 0-100 (omit to show current)")

    p_br = sub.add_parser("brightness", help="Get or set brightness level (0-100)")
    p_br.add_argument("level", nargs="?", type=int, default=None,
                      help="Level 0-100 (omit to show current)")

    p_ct = sub.add_parser("contrast", help="Get or set contrast level (0-100)")
    p_ct.add_argument("level", nargs="?", type=int, default=None,
                      help="Level 0-100 (omit to show current)")

    p_tm = sub.add_parser("trumotion", help="Set TruMotion motion smoothing mode")
    p_tm.add_argument("mode", help=f"Mode: {', '.join(_TRUMOTION_MODES)}")

    p_snd = sub.add_parser("sound-mode", help="Set sound mode" + _newer)
    p_snd.add_argument("mode", help="Sound mode (e.g., standard, cinema, game)")

    p_so = sub.add_parser("sound-output", help="Get or set sound output device" + _newer)
    p_so.add_argument("output", nargs="?", default=None,
                      help=f"Output: {', '.join(_SOUND_OUTPUTS)} (omit to show current)")

    sub.add_parser("subtitles", help="Toggle subtitles" + _newer)
    sub.add_parser("audio-track", help="Cycle audio track" + _newer)

    p_eco = sub.add_parser("energy-saving", help="Set energy saving mode")
    p_eco.add_argument("mode", help=f"Mode: {', '.join(_ENERGY_SAVING_MODES)}")

    p_dim = sub.add_parser(
        "dimming",
        help="Toggle OLED panel auto-dimming (TPC/GSR) — 2020+ OLED models",
        description="Disable or restore the OLED panel's automatic dimming: TPC "
                    "(dims static scenes over time) and GSR (dims static logos/HUDs). "
                    "Disabling keeps full brightness at the cost of reduced burn-in "
                    "protection; the TV restores both after a power cycle.")
    p_dim.add_argument("state", help="'off' to disable dimming, 'on' to restore it")
    p_dim.add_argument("--tpc", action="store_true", help="Only change TPC")
    p_dim.add_argument("--gsr", action="store_true", help="Only change GSR")

    # Scenes — named presets applying a batch of TV settings, stored per TV
    p_scene = sub.add_parser("scene", help="Named presets that apply a batch of TV settings in one command")
    scene_sub = p_scene.add_subparsers(dest="scene_cmd", help="Scene command")
    p_sc_run = scene_sub.add_parser("run", help="Apply a saved scene")
    p_sc_run.add_argument("name", help="Scene name")
    p_sc_set = scene_sub.add_parser("set", help="Create or replace a scene (only the flags you pass are saved)")
    p_sc_set.add_argument("name", help="Scene name (e.g. 'Movie Night')")
    p_sc_set.add_argument("--input", help="HDMI input to switch to first (e.g. HDMI_1, 1, or an alias)")
    p_sc_set.add_argument("--picture-mode", help=f"Picture mode: {', '.join(_PICTURE_MODES)}")
    p_sc_set.add_argument("--backlight", type=int, help="Backlight/OLED light 0-100")
    p_sc_set.add_argument("--brightness", type=int, help="Brightness 0-100")
    p_sc_set.add_argument("--contrast", type=int, help="Contrast 0-100")
    p_sc_set.add_argument("--color", type=int, help="Color 0-100")
    p_sc_set.add_argument("--energy-saving", help=f"Energy saving: {', '.join(_ENERGY_SAVING_MODES)}")
    p_sc_set.add_argument("--trumotion", help=f"TruMotion: {', '.join(_TRUMOTION_MODES)}")
    p_sc_set.add_argument("--sound-output", help=f"Sound output: {', '.join(_SOUND_OUTPUTS)}")
    scene_sub.add_parser("list", help="List saved scenes for the selected TV")
    p_sc_rm = scene_sub.add_parser("remove", help="Remove a saved scene")
    p_sc_rm.add_argument("name", help="Scene name")

    p_shot = sub.add_parser("screenshot", help="Capture a 960x540 JPEG screenshot from the TV")
    p_shot.add_argument("output", nargs="?", help="Output file path (default: screenshot-<timestamp>.jpg)")

    p_st = sub.add_parser("self-test",
                          help="Sweep every safe command against the TV and report what responds")
    p_st.add_argument("--skip-power", action="store_true",
                      help="Skip the final power off/on cycle")

    # Number key
    p_num = sub.add_parser("number", help="Send number key (0-9)")
    p_num.add_argument("digit", type=int, help="Digit 0-9")

    # Color buttons / picture color level
    p_color = sub.add_parser("color", help="Color button (red/green/yellow/blue) or picture color level (0-100)")
    p_color.add_argument("color", nargs="?", default=None,
                         help="red, green, yellow, blue, or a level 0-100 (omit to show current level)")

    # Service menus
    p_svc = sub.add_parser("service", help="Open service/advanced menu (default password: 0413)")
    p_svc.add_argument("menu", help="Menu: instart, ezadjust, hotel, hidden, freesync")

    # Open URL
    p_url = sub.add_parser("open-url", help="Open a URL on the TV (YouTube URLs deep-link into app)")
    p_url.add_argument("url", help="URL to open (e.g., https://example.com or a YouTube link)")

    # Raw command
    p_raw = sub.add_parser("raw", help="Send a raw SSAP command")
    p_raw.add_argument("uri", help="SSAP URI (e.g., ssap://system/turnOff)")
    p_raw.add_argument("--payload", help="JSON payload")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    handlers = {
        "scan": cmd_scan,
        "add": cmd_add,
        "remove": cmd_remove,
        "list": cmd_list,
        "set-default": cmd_set_default,
        "pair": cmd_pair,
        "enrich": cmd_enrich,
        "on": cmd_on,
        "off": cmd_off,
        "power": cmd_power,
        "power-status": cmd_power_status,
        "livetv": cmd_livetv,
        "channels": cmd_channels,
        "play": cmd_play,
        "pause": cmd_pause,
        "stop": cmd_stop,
        "rewind": cmd_rewind,
        "ff": cmd_fast_forward,
        "skip-forward": cmd_skip_forward,
        "skip-back": cmd_skip_back,
        "input": cmd_input,
        "inputs": cmd_inputs,
        "input-alias": cmd_input_alias,
        "launch": cmd_launch,
        "apps": cmd_apps,
        "app": cmd_app,
        "youtube": cmd_youtube,
        "number": cmd_number,
        "color": cmd_color,
        "service": cmd_service,
        "open-url": cmd_open_url,
        "raw": cmd_raw,
        "nav": cmd_nav,
        "screen-off": cmd_screen_off,
        "screen-on": cmd_screen_on,
        "screen-sleep": cmd_screen_sleep,
        "self-test": cmd_self_test,
        "picture-mode": cmd_picture_mode,
        "backlight": cmd_backlight,
        "brightness": cmd_brightness,
        "contrast": cmd_contrast,
        "trumotion": cmd_trumotion,
        "sound-mode": cmd_sound_mode,
        "sound-output": cmd_sound_output,
        "subtitles": cmd_subtitles,
        "audio-track": cmd_audio_track,
        "energy-saving": cmd_energy_saving,
        "dimming": cmd_dimming,
        "screenshot": cmd_screenshot,
    }

    # Volume subcommands
    if args.command == "volume":
        vol_handlers = {
            "up": cmd_volume_up,
            "down": cmd_volume_down,
            "mute": cmd_mute,
            "unmute": cmd_unmute,
            "set": cmd_set_volume,
            "get": cmd_get_volume,
        }
        if not args.vol_cmd:
            parser.parse_args(["volume", "--help"])
        vol_handlers[args.vol_cmd](args)
        return

    # Channel subcommands
    if args.command == "channel":
        ch_handlers = {
            "up": cmd_channel_up,
            "down": cmd_channel_down,
            "set": cmd_set_channel,
        }
        if not args.ch_cmd:
            parser.parse_args(["channel", "--help"])
        ch_handlers[args.ch_cmd](args)
        return

    # Scene subcommands
    if args.command == "scene":
        scene_handlers = {
            "run": cmd_scene_run,
            "set": cmd_scene_set,
            "list": cmd_scene_list,
            "remove": cmd_scene_remove,
        }
        if not args.scene_cmd:
            parser.parse_args(["scene", "--help"])
        scene_handlers[args.scene_cmd](args)
        return

    handler = handlers.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
