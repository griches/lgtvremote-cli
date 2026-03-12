#!/usr/bin/env python3
"""
lgtvremote-cli — Command-line interface for controlling LG webOS TVs.

Communicates over WebSocket (SSAP protocol) on port 3001.
Supports discovery, pairing, remote control, app launching, and Wake-on-LAN.
"""

import argparse
import asyncio
import json
import os
import pathlib
import socket
import struct
import ssl
import sys
import textwrap
import time
import uuid
from typing import Any, Optional

try:
    import websockets
    import websockets.asyncio.client
except ImportError:
    print("Error: 'websockets' package is required. Install with: pip install websockets>=12.0", file=sys.stderr)
    sys.exit(1)

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
    # Single device shortcut
    if len(cfg["devices"]) == 1:
        return next(iter(cfg["devices"].values()))
    return None


def _get_device_ip(cfg: dict, ip: Optional[str]) -> Optional[str]:
    if ip:
        return ip
    if cfg.get("default"):
        return cfg["default"]
    if len(cfg["devices"]) == 1:
        return next(iter(cfg["devices"]))
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
            "localizedAppNames": {"": "LG Remote CLI"},
            "localizedVendorNames": {"": "LG Electronics"},
            "permissions": [
                "TEST_SECURE", "CONTROL_INPUT_TEXT", "CONTROL_MOUSE_AND_KEYBOARD",
                "READ_INSTALLED_APPS", "READ_LGE_SDX", "READ_NOTIFICATIONS",
                "SEARCH", "WRITE_SETTINGS", "WRITE_NOTIFICATION_ALERT",
                "CONTROL_POWER", "READ_CURRENT_CHANNEL", "READ_RUNNING_APPS",
                "READ_UPDATE_INFO", "UPDATE_FROM_REMOTE_APP", "READ_LGE_TV_INPUT_EVENTS",
                "READ_TV_CURRENT_TIME", "LAUNCH", "LAUNCH_WEBAPP", "CONTROL_AUDIO",
                "CONTROL_DISPLAY", "CONTROL_INPUT_JOYSTICK", "CONTROL_INPUT_MEDIA_RECORDING",
                "CONTROL_INPUT_MEDIA_PLAYBACK", "CONTROL_INPUT_TV", "READ_APP_STATUS",
                "READ_INPUT_DEVICE_LIST", "READ_NETWORK_STATE", "READ_TV_CHANNEL_LIST",
                "WRITE_NOTIFICATION_TOAST", "READ_POWER_STATE", "READ_COUNTRY_INFO",
            ],
            "serial": "2f930e2d2cfe083771f68e4fe7bb07"
        },
        "permissions": [
            "LAUNCH", "LAUNCH_WEBAPP", "APP_TO_APP", "CLOSE",
            "TEST_OPEN", "TEST_PROTECTED", "CONTROL_AUDIO",
            "CONTROL_DISPLAY", "CONTROL_INPUT_JOYSTICK",
            "CONTROL_INPUT_MEDIA_RECORDING", "CONTROL_INPUT_MEDIA_PLAYBACK",
            "CONTROL_INPUT_TV", "CONTROL_POWER", "READ_APP_STATUS",
            "READ_CURRENT_CHANNEL", "READ_INPUT_DEVICE_LIST",
            "READ_NETWORK_STATE", "READ_RUNNING_APPS",
            "READ_TV_CHANNEL_LIST", "WRITE_NOTIFICATION_TOAST",
            "READ_POWER_STATE", "READ_COUNTRY_INFO",
            "READ_SETTINGS", "CONTROL_TV_SCREEN",
            "CONTROL_TV_STANBY", "CONTROL_FAVORITE_GROUP",
            "CONTROL_USER_INFO", "CHECK_BLUETOOTH_DEVICE",
            "CONTROL_BLUETOOTH", "CONTROL_TIMER_INFO",
            "STB_INTERNAL_CONNECTION", "CONTROL_RECORDING",
            "READ_RECORDING_STATE", "WRITE_NOTIFICATION_ALERT",
            "CONTROL_INPUT_TEXT", "CONTROL_MOUSE_AND_KEYBOARD",
            "READ_INSTALLED_APPS", "CONTROL_INPUT_MEDIA_RECORDING",
        ]
    }
}


async def _ws_connect(ip: str, client_key: Optional[str] = None, timeout: float = 10.0) -> tuple:
    """Connect and register with the TV. Returns (websocket, client_key)."""
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    uri = f"wss://{ip}:3001"
    ws = await asyncio.wait_for(
        websockets.asyncio.client.connect(uri, ssl=ssl_ctx, additional_headers={}),
        timeout=timeout,
    )

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
        "payload": {**reg, "pairingType": pairing_type},
    }

    await ws.send(json.dumps(reg_msg))

    # Wait for registration response
    new_key = client_key
    registered = False
    start = time.monotonic()

    while time.monotonic() - start < timeout:
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=max(1, timeout - (time.monotonic() - start)))
        except asyncio.TimeoutError:
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
        # Pairing prompt shown on TV — for PIN flow, handle separately
        elif "pairingType" in payload and payload.get("pairingType") == "pin":
            if not client_key:
                raise ConnectionError("NEEDS_PIN")

    if not registered:
        raise ConnectionError("Registration timed out — is the TV on and reachable?")

    return ws, new_key


async def _send_request(ws, uri: str, payload: Optional[dict] = None, subscribe: bool = False) -> dict:
    """Send an SSAP request and return the response payload."""
    msg_id = str(uuid.uuid4())
    msg = {
        "type": "subscribe" if subscribe else "request",
        "id": msg_id,
        "uri": uri,
    }
    if payload:
        msg["payload"] = payload

    await ws.send(json.dumps(msg))

    # Wait for matching response
    start = time.monotonic()
    while time.monotonic() - start < 10:
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=5)
        except asyncio.TimeoutError:
            break
        resp = json.loads(raw)
        if resp.get("id") == msg_id:
            return resp.get("payload", {})
    return {}


async def _send_button(ws, uri: str, payload: Optional[dict] = None):
    """Send a button press (fire-and-forget)."""
    msg = {
        "type": "request",
        "id": str(uuid.uuid4()),
        "uri": uri,
    }
    if payload:
        msg["payload"] = payload
    await ws.send(json.dumps(msg))


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

    # Try to set multicast interface
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

                # Parse headers
                name = ip
                for line in response.split("\r\n"):
                    lower = line.lower()
                    if lower.startswith("dlnadevicename.lge.com:"):
                        raw_name = line.split(":", 1)[1].strip()
                        try:
                            from urllib.parse import unquote
                            name = unquote(raw_name)
                        except Exception:
                            name = raw_name

                devices[ip] = {"ip": ip, "name": name}
            except socket.timeout:
                break
            except OSError:
                break

    s.close()
    return list(devices.values())


def _enrich_device(ip: str) -> dict:
    """Fetch model name and MAC addresses from the TV's HTTP API."""
    import urllib.request
    info: dict[str, Any] = {}

    # Model name
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

    # MAC addresses
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


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def cmd_scan(args):
    """Scan the local network for LG webOS TVs."""
    print("Scanning for LG webOS TVs...")
    devices = _ssdp_discover(timeout=args.timeout if hasattr(args, "timeout") else 5.0)
    if not devices:
        print("No TVs found. Ensure your TV is on and on the same network.")
        return

    print(f"\nFound {len(devices)} TV(s):\n")
    for d in devices:
        print(f"  {d['name']}")
        print(f"    IP: {d['ip']}")

        # Enrich
        info = _enrich_device(d["ip"])
        if info.get("model"):
            print(f"    Model: {info['model']}")
        if info.get("mac"):
            print(f"    MAC (wired): {info['mac']}")
        if info.get("wifi_mac"):
            print(f"    MAC (wifi):  {info['wifi_mac']}")
        print()


def cmd_add(args):
    """Add a TV by IP address."""
    cfg = _load_config()
    ip = args.ip

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

    # Try to enrich
    if not args.no_enrich:
        print(f"Fetching device info from {ip}...")
        info = _enrich_device(ip)
        if info.get("model") and "model" not in device:
            device["model"] = info["model"]
        if info.get("mac") and "mac" not in device:
            device["mac"] = info["mac"]
        if info.get("wifi_mac") and "wifi_mac" not in device:
            device["wifi_mac"] = info["wifi_mac"]

    cfg["devices"][ip] = device
    if not cfg.get("default"):
        cfg["default"] = ip
    _save_config(cfg)

    name = device.get("name", ip)
    print(f"Added TV: {name} ({ip})")
    if device.get("model"):
        print(f"  Model: {device['model']}")
    if device.get("mac"):
        print(f"  MAC: {device['mac']}")


def cmd_remove(args):
    """Remove a saved TV."""
    cfg = _load_config()
    ip = args.ip
    if ip not in cfg["devices"]:
        print(f"Error: No TV saved with IP {ip}", file=sys.stderr)
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
    ip = args.ip
    if ip not in cfg["devices"]:
        print(f"Error: No TV saved with IP {ip}. Use 'lgtv add {ip}' first.", file=sys.stderr)
        sys.exit(1)
    cfg["default"] = ip
    _save_config(cfg)
    name = cfg["devices"][ip].get("name", ip)
    print(f"Default TV set to: {name} ({ip})")


def cmd_pair(args):
    """Pair with a TV using PIN authentication."""
    cfg = _load_config()
    ip = _get_device_ip(cfg, args.tv)
    if not ip:
        print("Error: No TV specified and no default set. Use --tv <ip> or 'lgtv set-default <ip>'.", file=sys.stderr)
        sys.exit(1)

    # Ensure device is saved
    if ip not in cfg["devices"]:
        cfg["devices"][ip] = {"ip": ip, "name": ip}

    async def do_pair():
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        uri = f"wss://{ip}:3001"
        print(f"Connecting to {ip}...")

        ws = await asyncio.wait_for(
            websockets.asyncio.client.connect(uri, ssl=ssl_ctx),
            timeout=10,
        )

        # Send PIN registration request
        reg_msg = {
            "type": "register",
            "id": str(uuid.uuid4()),
            "payload": {**REGISTRATION_PAYLOAD, "pairingType": "pin"},
        }
        await ws.send(json.dumps(reg_msg))

        print("A PIN should appear on your TV screen.")
        pin = input("Enter the PIN shown on TV: ").strip()

        # Send PIN
        pin_msg = {
            "type": "request",
            "id": str(uuid.uuid4()),
            "uri": "ssap://pairing/setPin",
            "payload": {"pin": pin},
        }
        await ws.send(json.dumps(pin_msg))

        # Wait for registration
        start = time.monotonic()
        while time.monotonic() - start < 15:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=10)
            except asyncio.TimeoutError:
                break
            resp = json.loads(raw)
            payload = resp.get("payload", {})
            if resp.get("type") == "registered" or "client-key" in payload:
                key = payload.get("client-key")
                if key:
                    cfg["devices"][ip]["client_key"] = key
                    _save_config(cfg)
                    print(f"Paired successfully! Client key saved.")
                    await ws.close()
                    return
            elif resp.get("type") == "error":
                print(f"Pairing failed: {resp.get('error', 'Unknown error')}", file=sys.stderr)
                await ws.close()
                sys.exit(1)

        print("Pairing timed out.", file=sys.stderr)
        await ws.close()
        sys.exit(1)

    asyncio.run(do_pair())


async def _connect_and_send(ip: str, cfg: dict, uri: str, payload: Optional[dict] = None,
                             subscribe: bool = False, wait_response: bool = True) -> Optional[dict]:
    """Connect, authenticate, send a command, return response."""
    device = cfg["devices"].get(ip, {})
    client_key = device.get("client_key")

    try:
        ws, new_key = await _ws_connect(ip, client_key)
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
        result = await _send_request(ws, uri, payload, subscribe=subscribe)
    else:
        await _send_button(ws, uri, payload)
        result = None

    await ws.close()
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
        return asyncio.run(_connect_and_send(ip, cfg, uri, payload, subscribe=subscribe, wait_response=wait_response))
    except ConnectionError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except (OSError, asyncio.TimeoutError) as e:
        print(f"Error: Could not connect to TV at {ip}: {e}", file=sys.stderr)
        sys.exit(1)


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

    # Try to connect — if it works, TV is on, so turn it off
    try:
        asyncio.run(_connect_and_send(ip, cfg, "ssap://system/turnOff", wait_response=False))
        print("TV powered off.")
    except (ConnectionError, OSError, asyncio.TimeoutError):
        # TV is off or unreachable — try WOL
        device = cfg["devices"].get(ip, {})
        macs = [m for m in [device.get("mac"), device.get("wifi_mac")] if m]
        if macs:
            for mac in macs:
                _send_wol(mac, ip)
            print(f"TV appears off. Wake-on-LAN sent.")
        else:
            print("Error: TV unreachable and no MAC address for WOL.", file=sys.stderr)
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

def cmd_set_volume(args):
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

    # Navigation keys are sent via the pointer socket as key events
    cfg = _load_config()
    ip = _get_device_ip(cfg, args.tv)
    if not ip:
        print("Error: No TV specified and no default set.", file=sys.stderr)
        sys.exit(1)

    async def do_nav():
        device = cfg["devices"].get(ip, {})
        client_key = device.get("client_key")
        ws, new_key = await _ws_connect(ip, client_key)

        if new_key and new_key != client_key:
            if ip not in cfg["devices"]:
                cfg["devices"][ip] = {"ip": ip, "name": ip}
            cfg["devices"][ip]["client_key"] = new_key
            _save_config(cfg)

        # Get pointer input socket
        result = await _send_request(ws, "ssap://com.webos.service.networkinput/getPointerInputSocket")
        sock_path = result.get("socketPath")
        if not sock_path:
            # Fallback: send as SSAP command for basic nav
            fallback_uris = {
                "ENTER": "ssap://com.webos.service.ime/sendEnterKey",
                "BACK": "ssap://com.webos.service.ime/deleteCharacters",
            }
            if key in fallback_uris:
                await _send_button(ws, fallback_uris[key])
            await ws.close()
            return

        # Connect to pointer socket
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        pointer_ws = await websockets.asyncio.client.connect(sock_path, ssl=ssl_ctx)

        await pointer_ws.send(f"type:button\nname:{key}\n\n")
        await asyncio.sleep(0.1)

        await pointer_ws.close()
        await ws.close()

    try:
        asyncio.run(do_nav())
        print(f"Sent: {button}")
    except (ConnectionError, OSError, asyncio.TimeoutError) as e:
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
    _run_command(args, "ssap://tv/openChannel", {"channelNumber": str(args.number)})
    print(f"Switched to channel {args.number}.")


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
def cmd_input(args):
    """Switch TV input."""
    input_id = args.input.upper()
    # Accept shorthand like "1" → "HDMI_1"
    if input_id.isdigit():
        input_id = f"HDMI_{input_id}"
    elif not input_id.startswith("HDMI_") and not input_id.startswith("COMP_"):
        input_id = f"HDMI_{input_id}"

    _run_command(args, "ssap://tv/switchInput", {"inputId": input_id})
    print(f"Switched to {input_id}.")


def cmd_inputs(args):
    """List available inputs."""
    result = _run_command(args, "ssap://tv/getExternalInputList", wait_response=True)
    if result and "devices" in result:
        print("Available inputs:\n")
        for d in result["devices"]:
            label = d.get("label", d.get("id", "?"))
            input_id = d.get("id", "?")
            connected = d.get("connected", False)
            icon = d.get("icon", "")
            status = " [connected]" if connected else ""
            print(f"  {input_id}: {label}{status}")
    else:
        print("Could not fetch input list.")


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
    """Launch an app on the TV."""
    app = args.app
    # Resolve friendly name
    app_id = KNOWN_APPS.get(app.lower(), app)
    payload: dict[str, Any] = {"id": app_id}

    # Handle params like key=value
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


# --- Screen/Display ---
def cmd_screen_off(args):
    _run_command(args, "ssap://com.webos.service.settings/setSystemSettings",
                 {"category": "display", "settings": {"screenOff": True}})
    print("Screen off.")


# --- Picture/Sound ---
def cmd_picture_mode(args):
    _run_command(args, "ssap://com.webos.service.settings/setSystemSettings",
                 {"category": "picture", "settings": {"pictureMode": args.mode}})
    print(f"Picture mode set to: {args.mode}")


def cmd_sound_mode(args):
    _run_command(args, "ssap://com.webos.service.settings/setSystemSettings",
                 {"category": "sound", "settings": {"soundMode": args.mode}})
    print(f"Sound mode set to: {args.mode}")


# --- Sleep Timer ---
def cmd_sleep(args):
    _run_command(args, "ssap://com.webos.service.settings/setSystemSettings",
                 {"category": "system", "settings": {"sleepTimer": args.minutes}})
    print(f"Sleep timer set to {args.minutes} minutes.")


# --- Info ---
def cmd_info(args):
    _run_command(args, "ssap://tv/showChannelInfo")
    print("Showing channel info.")


def cmd_subtitles(args):
    _run_command(args, "ssap://com.webos.service.settings/setSystemSettings",
                 {"category": "caption", "settings": {"state": "toggle"}})
    print("Toggled subtitles.")


def cmd_audio_track(args):
    _run_command(args, "ssap://media.controls/changeAudioTrack")
    print("Cycled audio track.")


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

    async def do_number():
        device = cfg["devices"].get(ip, {})
        ws, new_key = await _ws_connect(ip, device.get("client_key"))

        if new_key and new_key != device.get("client_key"):
            cfg["devices"].setdefault(ip, {"ip": ip, "name": ip})["client_key"] = new_key
            _save_config(cfg)

        result = await _send_request(ws, "ssap://com.webos.service.networkinput/getPointerInputSocket")
        sock_path = result.get("socketPath")
        if sock_path:
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            pointer_ws = await websockets.asyncio.client.connect(sock_path, ssl=ssl_ctx)
            key_name = f"{num}"
            await pointer_ws.send(f"type:button\nname:{key_name}\n\n")
            await asyncio.sleep(0.1)
            await pointer_ws.close()

        await ws.close()

    try:
        asyncio.run(do_number())
        print(f"Sent number: {num}")
    except (ConnectionError, OSError, asyncio.TimeoutError) as e:
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
    info = _enrich_device(ip)

    device = cfg["devices"][ip]
    if info.get("model"):
        device["model"] = info["model"]
        print(f"  Model: {info['model']}")
    if info.get("mac"):
        device["mac"] = info["mac"]
        print(f"  MAC (wired): {info['mac']}")
    if info.get("wifi_mac"):
        device["wifi_mac"] = info["wifi_mac"]
        print(f"  MAC (wifi):  {info['wifi_mac']}")

    if not info:
        print("  No additional info found. Is the TV on?")
    else:
        _save_config(cfg)
        print("Device info updated.")


# --- Raw command ---
def cmd_raw(args):
    """Send a raw SSAP command."""
    payload = None
    if args.payload:
        try:
            payload = json.loads(args.payload)
        except json.JSONDecodeError:
            print("Error: Invalid JSON payload.", file=sys.stderr)
            sys.exit(1)

    result = _run_command(args, args.uri, payload, wait_response=True)
    if result:
        print(json.dumps(result, indent=2))
    else:
        print("Command sent (no response data).")


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
              lgtv launch netflix               # Launch Netflix
              lgtv input 1                      # Switch to HDMI 1
              lgtv nav ok                       # Press OK button
              lgtv play                         # Play media
              lgtv apps                         # List installed apps
              lgtv raw ssap://system/turnOff    # Send raw SSAP command
        """),
    )

    parser.add_argument("--tv", metavar="IP", help="TV IP address (overrides default)")

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
    p_rm.add_argument("ip", help="TV IP address")

    sub.add_parser("list", help="List saved TVs")

    p_def = sub.add_parser("set-default", help="Set the default TV")
    p_def.add_argument("ip", help="TV IP address")

    sub.add_parser("pair", help="Pair with TV (PIN authentication)")
    sub.add_parser("enrich", help="Fetch/update device info (model, MACs)")

    # Power
    sub.add_parser("on", help="Turn on TV (Wake-on-LAN)")
    sub.add_parser("off", help="Turn off TV")
    sub.add_parser("power", help="Toggle TV power")

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

    # Media
    sub.add_parser("play", help="Play")
    sub.add_parser("pause", help="Pause")
    sub.add_parser("stop", help="Stop playback")
    sub.add_parser("rewind", help="Rewind")
    sub.add_parser("ff", help="Fast forward")
    sub.add_parser("skip-forward", help="Skip forward / next track")
    sub.add_parser("skip-back", help="Skip backward / previous track")

    # Input
    p_input = sub.add_parser("input", help="Switch TV input (e.g., HDMI_1 or just 1)")
    p_input.add_argument("input", help="Input ID: 1, 2, 3, 4, HDMI_1, HDMI_2, etc.")
    sub.add_parser("inputs", help="List available inputs")

    # Apps
    p_launch = sub.add_parser("launch", help="Launch an app")
    p_launch.add_argument("app", help="App name or ID (e.g., netflix, youtube, com.webos.app.browser)")
    p_launch.add_argument("params", nargs="*", help="Optional params as key=value pairs")
    sub.add_parser("apps", help="List installed apps")
    sub.add_parser("app", help="Show currently running app")

    # Display/Settings
    sub.add_parser("screen-off", help="Turn off screen (audio continues)")

    p_pic = sub.add_parser("picture-mode", help="Set picture mode")
    p_pic.add_argument("mode", help="Picture mode (e.g., standard, vivid, cinema, game)")

    p_snd = sub.add_parser("sound-mode", help="Set sound mode")
    p_snd.add_argument("mode", help="Sound mode (e.g., standard, cinema, game)")

    p_slp = sub.add_parser("sleep", help="Set sleep timer")
    p_slp.add_argument("minutes", type=int, help="Minutes until TV turns off (0 to cancel)")

    sub.add_parser("subtitles", help="Toggle subtitles")
    sub.add_parser("audio-track", help="Cycle audio track")
    sub.add_parser("info", help="Show channel/media info on screen")

    # Number key
    p_num = sub.add_parser("number", help="Send number key (0-9)")
    p_num.add_argument("digit", type=int, help="Digit 0-9")

    # Service menus
    p_svc = sub.add_parser("service", help="Open service/advanced menu")
    p_svc.add_argument("menu", help="Menu: instart, ezadjust, hotel, hidden, freesync")

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
        "play": cmd_play,
        "pause": cmd_pause,
        "stop": cmd_stop,
        "rewind": cmd_rewind,
        "ff": cmd_fast_forward,
        "skip-forward": cmd_skip_forward,
        "skip-back": cmd_skip_back,
        "input": cmd_input,
        "inputs": cmd_inputs,
        "launch": cmd_launch,
        "apps": cmd_apps,
        "app": cmd_app,
        "screen-off": cmd_screen_off,
        "picture-mode": cmd_picture_mode,
        "sound-mode": cmd_sound_mode,
        "sleep": cmd_sleep,
        "subtitles": cmd_subtitles,
        "audio-track": cmd_audio_track,
        "info": cmd_info,
        "number": cmd_number,
        "service": cmd_service,
        "raw": cmd_raw,
        "nav": cmd_nav,
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

    handler = handlers.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
