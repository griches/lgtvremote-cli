import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import lgtvremote_cli as cli


class FakeSocket:
    def __init__(self, mode="success", fresh=False):
        self.mode, self.fresh = mode, fresh
        self.sent = []
        self.closed = False
        self.responses = []

    def send(self, raw):
        message = json.loads(raw)
        self.sent.append(message)
        ident = message["id"]
        if message["type"] == "register":
            if self.mode == "silent":
                return
            if self.mode == "disconnect":
                self.responses.append(ConnectionError("connection lost"))
                return
            if self.mode in ("blacklist", "denied", "unrelated"):
                error = cli.BLACKLISTED_CERTIFICATE if self.mode != "denied" else "403 user denied access"
                self.responses.append({"type": "error", "id": "other" if self.mode == "unrelated" else ident, "error": error})
                if self.mode != "unrelated":
                    return
            if self.mode == "prompt-blacklist":
                self.responses.extend([{"type": "response", "id": ident, "payload": {"pairingType": "PROMPT"}},
                                       {"type": "error", "id": ident, "error": cli.BLACKLISTED_CERTIFICATE}])
                return
            if self.fresh:
                self.responses.append({"type": "response", "id": ident, "payload": {"pairingType": "PIN"}})
            else:
                self.responses.append({"type": "registered", "id": ident, "payload": {"client-key": "new-key"}})
        elif message.get("uri") == "ssap://pairing/setPin":
            self.responses.append({"type": "registered", "id": ident, "payload": {"client-key": "new-key"}})
        else:
            self.responses.append({"type": "response", "id": ident, "payload": {"returnValue": True}})

    def recv(self, timeout):
        if not self.responses:
            raise socket.timeout()
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return json.dumps(response)

    def close(self):
        self.closed = True


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = patch.object(cli, "CONFIG_DIR", Path(self.temp.name))
        self.file = patch.object(cli, "CONFIG_FILE", Path(self.temp.name) / "config.json")
        self.directory.start(); self.file.start()
        self.addCleanup(self.directory.stop); self.addCleanup(self.file.stop)
        self.cfg = {"devices": {"192.0.2.1": {"name": "TV", "client_key": "saved-key"}}, "default": "192.0.2.1"}

    def connect(self, sockets, **kwargs):
        with patch.object(cli.WebSocket, "connect", side_effect=sockets) as connect:
            result = cli._ws_connect("192.0.2.1", cfg=self.cfg, **kwargs)
            self.assertEqual(len(sockets), connect.call_count)
        return result

    def test_signed_success_keeps_existing_identity(self):
        ws = FakeSocket()
        self.connect([ws], client_key="saved-key")
        self.assertIn("signed", ws.sent[0]["payload"]["manifest"])
        self.assertFalse(self.cfg["devices"]["192.0.2.1"]["lg_uses_unsigned_registration"])

    def test_silent_and_blacklisted_fallback_fresh_and_saved_pairing(self):
        for mode in ("silent", "blacklist"):
            for fresh in (False, True):
                with self.subTest(mode=mode, fresh=fresh):
                    self.cfg["devices"]["192.0.2.1"].pop("lg_uses_unsigned_registration", None)
                    first, second = FakeSocket(mode), FakeSocket(fresh=fresh)
                    ws, key = self.connect([first, second], client_key=None if fresh else "saved-key", pin_provider=lambda: "12345678")
                    self.assertTrue(first.closed)
                    self.assertIs(ws, second)
                    payload = second.sent[0]["payload"]
                    self.assertNotIn("signed", payload["manifest"])
                    self.assertNotIn("signatures", payload["manifest"])
                    self.assertEqual(payload.get("client-key"), None if fresh else "saved-key")
                    self.assertEqual(payload["pairingType"], "PIN" if fresh else "PROMPT")
                    self.assertEqual(key, "new-key")
                    self.assertTrue(cli._load_config()["devices"]["192.0.2.1"]["lg_uses_unsigned_registration"])
                    # Representative commands use the authenticated socket unchanged.
                    for uri in ("ssap://audio/volumeUp", "ssap://system.launcher/launch", "ssap://com.webos.service.networkinput/getPointerInputSocket", "ssap://com.webos.service.ime/insertText", "ssap://system.notifications/createAlert"):
                        self.assertTrue(cli._send_request(ws, uri, {})["returnValue"])
                    remembered = FakeSocket()
                    self.connect([remembered], client_key=key)
                    self.assertNotIn("signed", remembered.sent[0]["payload"]["manifest"])

    def test_all_permissions_retained_without_mutating_old_payload(self):
        manifest = cli.REGISTRATION_PAYLOAD["manifest"]
        expected = set(manifest["permissions"] + manifest["signed"]["permissions"])
        unsigned = cli._registration_payload("saved", True)["manifest"]
        self.assertEqual(expected, set(unsigned["permissions"]))
        self.assertIn("signed", cli.REGISTRATION_PAYLOAD["manifest"])
        for permission in ("CONTROL_INPUT_TEXT", "CONTROL_MOUSE_AND_KEYBOARD", "WRITE_SETTINGS", "WRITE_NOTIFICATION_ALERT", "READ_INSTALLED_APPS"):
            self.assertIn(permission, unsigned["permissions"])

    def test_denial_and_transport_loss_never_trigger_compatibility_retry(self):
        for mode in ("denied", "disconnect", "prompt-blacklist"):
            with self.subTest(mode=mode):
                ws = FakeSocket(mode)
                with patch.object(cli.WebSocket, "connect", return_value=ws) as connect:
                    with self.assertRaises(ConnectionError):
                        cli._ws_connect("192.0.2.1", "saved", cfg=self.cfg, pin_provider=lambda: "12345678")
                    self.assertEqual(1, connect.call_count)
                self.assertTrue(ws.closed)

    def test_background_connection_never_submits_pin(self):
        ws = FakeSocket(fresh=True)
        with patch.object(cli.WebSocket, "connect", return_value=ws):
            with self.assertRaisesRegex(ConnectionError, "NEEDS_PIN"):
                cli._ws_connect("192.0.2.1", "saved", cfg=self.cfg)
        self.assertEqual(1, len(ws.sent))
        self.assertTrue(ws.closed)

    def test_unrelated_blacklist_is_ignored(self):
        ws = FakeSocket("unrelated")
        self.connect([ws], client_key="saved")
        self.assertFalse(ws.closed)

    def test_unsigned_failure_is_terminal(self):
        first, second = FakeSocket("blacklist"), FakeSocket("blacklist")
        with patch.object(cli.WebSocket, "connect", side_effect=[first, second]) as connect:
            with self.assertRaises(ConnectionError):
                cli._ws_connect("192.0.2.1", "saved", cfg=self.cfg)
            self.assertEqual(2, connect.call_count)
        self.assertTrue(first.closed and second.closed)

    def test_real_websocket_frames_recover_then_deliver_commands(self):
        pairs = [socket.socketpair(), socket.socketpair()]
        clients = [cli.WebSocket(pair[0]) for pair in pairs]
        servers = [cli.WebSocket(pair[1]) for pair in pairs]
        received, failures = [], []
        def television():
            try:
                for index, ws in enumerate(servers):
                    registration = json.loads(ws.recv(timeout=2))
                    received.append(registration)
                    ws.send(json.dumps({"type": "hello", "payload": {"protocolVersion": 2}}))
                    if index == 0:
                        ws.send(json.dumps({"type": "error", "id": registration["id"], "error": cli.BLACKLISTED_CERTIFICATE}))
                    else:
                        ws.send(json.dumps({"type": "registered", "id": registration["id"], "payload": {"client-key": "wire-key"}}))
                        for _ in range(3):
                            request = json.loads(ws.recv(timeout=2))
                            received.append(request)
                            ws.send(json.dumps({"type": "response", "id": request["id"], "payload": {"returnValue": True}}))
            except BaseException as error:
                failures.append(error)
        thread = threading.Thread(target=television, daemon=True)
        thread.start()
        try:
            ws, key = self.connect(clients, client_key="saved-key")
            self.assertEqual("wire-key", key)
            for uri in ("ssap://audio/volumeUp", "ssap://com.webos.service.networkinput/getPointerInputSocket", "ssap://system.notifications/createAlert"):
                self.assertTrue(cli._send_request(ws, uri, {})["returnValue"])
            thread.join(3)
            self.assertFalse(thread.is_alive())
            self.assertFalse(failures)
            self.assertEqual(5, len(received))
            self.assertNotIn("signed", received[1]["payload"]["manifest"])
        finally:
            for pair in pairs:
                for sock in pair: sock.close()

    def test_enrichment_retains_the_successful_mode_in_callers_config(self):
        first, second = FakeSocket("blacklist"), FakeSocket()
        with patch.object(cli.WebSocket, "connect", side_effect=[first, second]):
            cli._fetch_macs_via_ws("192.0.2.1", "saved-key", cfg=self.cfg)
        cli._save_config(self.cfg)
        self.assertTrue(cli._load_config()["devices"]["192.0.2.1"]["lg_uses_unsigned_registration"])

    def test_invalid_pin_is_rejected_and_socket_closed(self):
        ws = FakeSocket(fresh=True)
        with patch.object(cli.WebSocket, "connect", return_value=ws):
            with self.assertRaisesRegex(ConnectionError, "eight digits"):
                cli._ws_connect("192.0.2.1", cfg=self.cfg, pin_provider=lambda: "1234")
        self.assertTrue(ws.closed)
        self.assertEqual(1, len(ws.sent))

    def test_default_command_reloads_repaired_key_and_mode(self):
        from types import SimpleNamespace
        cli._save_config(self.cfg)
        repaired = cli._load_config()
        repaired["devices"]["192.0.2.1"].update(client_key="repaired-key", lg_uses_unsigned_registration=True)
        cli._save_config(repaired)
        ws = FakeSocket()
        with patch.object(cli.WebSocket, "connect", return_value=ws):
            cli._run_command(SimpleNamespace(tv=None), "ssap://audio/getVolume", wait_response=True)
        self.assertEqual("repaired-key", ws.sent[0]["payload"]["client-key"])
        self.assertNotIn("signed", ws.sent[0]["payload"]["manifest"])
        self.assertEqual("192.0.2.1", cli._load_config()["default"])

    def test_power_cycle_reconnect_uses_refreshed_registration_key(self):
        self.cfg["devices"]["192.0.2.1"]["mac"] = "02:00:00:00:00:01"
        self.cfg["devices"]["192.0.2.1"]["lg_uses_unsigned_registration"] = True
        cli._save_config(self.cfg)
        first, second = FakeSocket(), FakeSocket()
        with patch.object(cli.WebSocket, "connect", side_effect=[first, second]), \
             patch.object(cli.time, "sleep"), patch.object(cli, "_send_wol"):
            cli._self_test_power_cycle("192.0.2.1", self.cfg["devices"]["192.0.2.1"], lambda *args: None)
        self.assertEqual("saved-key", first.sent[0]["payload"]["client-key"])
        self.assertEqual("new-key", second.sent[0]["payload"]["client-key"])
        self.assertNotIn("signed", second.sent[0]["payload"]["manifest"])


if __name__ == "__main__":
    unittest.main()
