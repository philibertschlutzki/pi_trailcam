#!/usr/bin/env python3
"""Wildkamera Thumbnail Downloader - consolidated v4.10

Optimizations in this version (v4.10):
- Token buffering: Cmd=3 packets received during handshake/stabilization are buffered.
- Buffer validation debug: For buffered Cmd=3 packets, log full Base64 payload and decode/decrypt errors.
- Event handling: Cmd=9 (ARTEMISw events) are ACKed but routed into a separate event queue and can be filtered from the main flow.
- Login timing: Prefer waiting for token after sending Login (token may arrive only after Login request).
"""

import argparse
import asyncio
import base64
import json
import logging
import os
import socket
import struct
import subprocess
import sys
import time
from typing import Optional, Union, Set, Tuple, Callable, Any, Dict, List
from collections import deque

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

try:
    from bleak import BleakScanner, BleakClient

    BLE_AVAILABLE = True
except Exception:
    BLE_AVAILABLE = False


# --- CONFIG ---
TARGET_IP = "192.168.43.1"
TARGET_PORTS = [40611, 3333]
FIXED_LOCAL_PORT = 35281

DEFAULT_SSID = "KJK_E0FF"
DEFAULT_PASS = "85087127"

BLE_MAC = "C6:1E:0D:E0:32:E8"

# Login timing: give camera time after initial heartbeat/magic sequence.
LOGIN_DELAY_AFTER_STABILIZATION = 2.0


# --- CONSTANTS / PAYLOADS ---
LBCS_PAYLOAD = bytes.fromhex("f14100144c42435300000000000000004343434a4a000000")

MAGIC_BODY_1 = bytes.fromhex("000000000000")
MAGIC_BODY_2 = bytes.fromhex("0000")

HEARTBEAT_BODY_START = bytes.fromhex("415254454d49530002000000")
HEARTBEAT_PAYLOAD_END = bytes.fromhex(
    "000100190000004d7a6c423336582f49566f385a7a49357247396a31773d3d00"
)

PHASE2_KEY = b"a01bc23ed45fF56A"
PHASE2_STATIC_HEADER = bytes.fromhex(
    "0ccb9a2b5f951eb669dfaa375a6bbe3e76202e13c9d1aa3631be74e5"
)

ARTEMIS_NULL = b"ARTEMIS\x00"
ARTEMIS_W = b"ARTEMISw"

# Hello base64 blob
ARTEMIS_HELLO_B64 = (
    b"J8WWuQDPmYSLfu/gXAG+UqbBy55KP2iE25QPNofzn040+NI9g7zeXLkIpXpC07SXvosr"
    b"Wsc1m8mxnq6hMiKwePbKJUwvSvqZb6s0sl1sfziRb4nrHS3IjLjRVw2lxAUfPMOkSEVk"
    b"sh4L234p6VLtbnd4iq+8YcQJdk05GSR0cM4="
)


logger = logging.getLogger("CamClient")


class FlushFileHandler(logging.FileHandler):
    """FileHandler, der sofort flush+fsync macht (Crash-safe Logs)."""

    def emit(self, record):
        super().emit(record)
        try:
            self.flush()
            os.fsync(self.stream.fileno())
        except Exception:
            pass


def setup_logging(debug: bool):
    level = logging.DEBUG if debug else logging.INFO

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

    fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(level)
    sh.setFormatter(fmt)
    root.addHandler(sh)

    if debug:
        fh = FlushFileHandler("get_thumbnail_perp_debug.log", mode="w", encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        root.addHandler(fh)


def hexdump(data: bytes, max_len: int = 96) -> str:
    if not data:
        return ""
    if len(data) <= max_len:
        return data.hex()
    return data[:max_len].hex() + f"…(+{len(data)-max_len}b)"


def hexdump_full(data: bytes, width: int = 16) -> str:
    """Vollständiger Hexdump (ohne Trunkierung), zeilenweise."""

    if data is None:
        return ""

    out = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        out.append(f"{off:04x}: {chunk.hex()}")
    return "\n".join(out)


def build_artemis_frame(cmd_id: int, app_seq: int, body: bytes) -> bytes:
    return ARTEMIS_NULL + struct.pack("<III", cmd_id, app_seq, len(body)) + body


class BLEWorker:
    @staticmethod
    async def wake_camera(mac: str, scan_timeout: float = 20.0, connect_timeout: float = 10.0) -> bool:
        if not BLE_AVAILABLE:
            logger.error("BLE nicht verfügbar (bleak fehlt).")
            return False

        logger.info(f"Suche BLE {mac}…")
        try:
            dev = await BleakScanner.find_device_by_address(mac, timeout=scan_timeout)
            if not dev:
                logger.warning("BLE nicht gefunden (schon wach?).")
                return False

            async with BleakClient(dev, timeout=connect_timeout) as client:
                await client.write_gatt_char(
                    "00000002-0000-1000-8000-00805f9b34fb",
                    bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]),
                    response=True,
                )

            logger.info("✅ BLE Wakeup gesendet.")
            return True
        except Exception as e:
            logger.error(f"BLE Wakeup fehlgeschlagen: {e}")
            return False


class WiFiWorker:
    @staticmethod
    def connect(ssid, password):
        try:
            subprocess.run(
                ["sudo", "iwconfig", "wlan0", "power", "off"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if subprocess.run(["iwgetid", "-r"], capture_output=True, text=True).stdout.strip() == ssid:
                logger.info(f"WLAN bereits mit {ssid} verbunden.")
                return True
        except Exception:
            pass

        logger.info("Verbinde WLAN…")
        subprocess.run(["sudo", "nmcli", "c", "delete", ssid], capture_output=True)
        subprocess.run(["sudo", "nmcli", "d", "wifi", "rescan"], capture_output=True)
        time.sleep(3)

        res = subprocess.run(
            ["sudo", "nmcli", "d", "wifi", "connect", ssid, "password", password, "ifname", "wlan0"],
            capture_output=True,
        )
        return res.returncode == 0


class Session:
    TYPE_NAMES = {
        0x41: "DISC",
        0x42: "FRAG",
        0x43: "KEEPALIVE",
        0xD0: "DATA",
        0xD1: "ACK",
        0xE0: "ERR",
        0xF0: "DISC",
        0xF9: "PRE",
    }

    def __init__(self, debug: bool = False, raw_rx_window_seconds: float = 20.0, raw_rx_dump: bool = True):
        self.sock: Optional[socket.socket] = None
        self.active_port: Optional[int] = None

        self.global_seq = 0
        self.app_seq = 0

        self.debug = debug

        self.token: Optional[str] = None
        self.last_heartbeat_time = 0.0
        self.heartbeat_cnt = 0

        self._frag_buf = bytearray()

        # --- RAW window options (Debug) ---
        self.raw_dump_until: float = 0.0
        self.raw_rx_window_seconds = float(raw_rx_window_seconds)
        self.raw_rx_dump = bool(raw_rx_dump)

        # --- Event spam control (Debug) ---
        self._evt_last_log_ts: float = 0.0
        self._evt_suppressed: int = 0
        self._event_queue: deque = deque(maxlen=200)

        # --- Token buffer (Cmd=3) ---
        self._token_packet_buffer: deque = deque(maxlen=10)
        self._buffering_active = False

    def enable_token_buffering(self):
        """Aktiviert Token-Pufferung (sollte vor PreLogin gestartet werden)."""
        self._buffering_active = True
        self._token_packet_buffer.clear()
        if self.debug:
            logger.debug("🔓 Token-Pufferung aktiviert")

    def disable_token_buffering(self):
        """Deaktiviert Token-Pufferung."""
        self._buffering_active = False
        if self.debug:
            logger.debug("🔒 Token-Pufferung deaktiviert")

    def enable_raw_rx_dump(self, seconds: Optional[float] = None):
        secs = self.raw_rx_window_seconds if seconds is None else float(seconds)
        self.raw_dump_until = time.time() + secs
        if self.debug:
            logger.debug(f"🧾 RAW-RX-DUMP aktiv für {secs:.1f}s (bis {self.raw_dump_until})")

    def _raw_window_active(self) -> bool:
        return bool(self.debug and self.raw_dump_until and time.time() < self.raw_dump_until)

    @staticmethod
    def _parse_artemis_header_any(data: bytes) -> Optional[Tuple[int, bytes, int, int, int]]:
        """Findet ARTEMIS Header (ARTEMIS\x00 oder ARTEMISw) an beliebigem Offset.

        Returns: (offset, magic8, cmd_id, app_seq, alen)
        """

        if not data:
            return None

        for magic in (ARTEMIS_NULL, ARTEMIS_W):
            idx = data.find(magic)
            if idx < 0:
                continue

            base = idx + 8
            if len(data) < base + 12:
                return None

            try:
                cmd_id, app_seq, alen = struct.unpack("<III", data[base : base + 12])
                return idx, magic, cmd_id, app_seq, alen
            except Exception:
                return None

        return None

    @staticmethod
    def _extract_artemis_payload(data: bytes, offset: int, alen: int) -> bytes:
        start = offset + 20
        end = min(len(data), start + max(0, int(alen)))
        if start >= len(data) or end <= start:
            return b""
        return data[start:end]

    @staticmethod
    def _pad_b64(b64_part: bytes) -> bytes:
        if not b64_part:
            return b64_part
        if len(b64_part) % 4 != 0:
            b64_part += b"=" * (4 - (len(b64_part) % 4))
        return b64_part

    def _decrypt_artemis_json_any(self, data: bytes) -> Optional[Tuple[Dict[str, Any], int, int]]:
        """Robustes Decrypt: findet ARTEMIS Header an beliebigem Offset und entschlüsselt Base64(AES-ECB(JSON))."""

        hdr = self._parse_artemis_header_any(data)
        if hdr is None:
            return None

        off, _magic, cmd_id, app_seq, alen = hdr
        payload = self._extract_artemis_payload(data, off, alen)
        b64_part = payload.split(b"\x00")[0]
        if not b64_part:
            return None

        b64_part = self._pad_b64(b64_part)

        try:
            raw = base64.b64decode(b64_part)
        except Exception as e:
            if self.debug:
                logger.debug(
                    "❌ base64.b64decode failed "
                    f"(Cmd={cmd_id}, AppSeq={app_seq}, b64_len={len(b64_part)}): {e!r}"
                )
                try:
                    logger.debug(f"🧾 b64(full)={b64_part.decode('ascii', errors='replace')}")
                except Exception:
                    pass
            return None

        try:
            dec = unpad(AES.new(PHASE2_KEY, AES.MODE_ECB).decrypt(raw), AES.block_size)
        except Exception as e:
            if self.debug:
                logger.debug(
                    "❌ AES decrypt/unpad failed "
                    f"(Cmd={cmd_id}, AppSeq={app_seq}, raw_len={len(raw)}): {e!r}"
                )
            return None

        try:
            obj = json.loads(dec.decode("utf-8"))
        except Exception as e:
            if self.debug:
                logger.debug(
                    "❌ JSON decode failed "
                    f"(Cmd={cmd_id}, AppSeq={app_seq}, dec_len={len(dec)}): {e!r}"
                )
                logger.debug(f"🧾 dec(hex)={hexdump(dec, max_len=256)}")
            return None

        if not isinstance(obj, dict):
            return None

        return obj, cmd_id, app_seq

    def _try_parse_evt(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parst ARTEMISw-Events (z.B. {"evtId":4})."""

        hdr = self._parse_artemis_header_any(data)
        if hdr is None:
            return None

        off, magic, cmd_id, app_seq, alen = hdr
        if magic != ARTEMIS_W:
            return None

        payload = self._extract_artemis_payload(data, off, alen)
        raw = payload.split(b"\x00")[0]
        if not raw:
            return None

        try:
            s = raw.decode("utf-8", errors="strict")
            obj = json.loads(s)
            if isinstance(obj, dict) and "evtId" in obj:
                return {
                    "evtId": obj.get("evtId"),
                    "cmd_id": cmd_id,
                    "app_seq": app_seq,
                    "alen": alen,
                    "raw": obj,
                }
        except Exception:
            return None

        return None

    @staticmethod
    def _is_simple_ack_payload(data: bytes) -> bool:
        # z.B. f1 d0 00 07 d1 00 00 00 41 43 4b
        return bool(len(data) >= 11 and data[0] == 0xF1 and data[1] == 0xD0 and data[8:11] == b"ACK")

    @staticmethod
    def _parse_artemis_meta_any(data: bytes) -> Optional[Tuple[int, int, int, int]]:
        """Findet ARTEMIS Header an beliebigem Offset und parsed (cmd_id, app_seq, alen)."""

        hdr = Session._parse_artemis_header_any(data)
        if hdr is None:
            return None
        off, _magic, cmd_id, app_seq, alen = hdr
        return off, cmd_id, app_seq, alen

    def analyze_packet(self, data: bytes) -> str:
        if not data:
            return "EMPTY"

        if data[0] != 0xF1:
            return f"NON-F1(len={len(data)}) {hexdump(data, 32)}"

        if len(data) < 2:
            return f"F1-SHORT(len={len(data)})"

        pkt_type = data[1]
        tname = self.TYPE_NAMES.get(pkt_type, f"0x{pkt_type:02X}")

        if len(data) < 8:
            return f"F1 {tname} (short,len={len(data)}) {hexdump(data, 48)}"

        body_len = (data[2] << 8) | data[3]
        seq = data[7]
        info = f"RUDP {tname} Seq={seq} BodyLen={body_len}"

        hdr = self._parse_artemis_header_any(data)
        if hdr is not None:
            _off, magic, cmd_id, app_seq, alen = hdr
            tag = "ARTEMISw" if magic == ARTEMIS_W else "ARTEMIS"
            info += f" | {tag} Cmd={cmd_id} AppSeq={app_seq} ALen={alen}"

        return info

    def log_tx(self, pkt: bytes, desc: str = ""):
        if self.debug:
            logger.debug(f"📤 {self.analyze_packet(pkt)} {desc} | hex={hexdump(pkt)}")

    def log_rx(self, pkt: bytes, desc: str = ""):
        if self.debug:
            logger.debug(f"📥 {self.analyze_packet(pkt)} {desc} | hex={hexdump(pkt)}")

    def setup_network(self) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((TARGET_IP, 1))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception as e:
            logger.error(f"Lokale IP konnte nicht ermittelt werden: {e}")
            return False

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)

        try:
            self.sock.bind((local_ip, FIXED_LOCAL_PORT))
            logger.info(f"Socket: {local_ip}:{FIXED_LOCAL_PORT}")
        except OSError as e:
            logger.warning(f"FIXED_LOCAL_PORT {FIXED_LOCAL_PORT} belegt ({e}); Fallback auf Ephemeral-Port…")
            self.sock.bind((local_ip, 0))
            logger.info(f"Socket: {self.sock.getsockname()[0]}:{self.sock.getsockname()[1]}")

        self.sock.settimeout(0.15)
        return True

    def send_to(self, pkt: bytes, port: int, desc: str = ""):
        if not self.sock:
            return
        self.sock.sendto(pkt, (TARGET_IP, port))
        self.log_tx(pkt, desc=f"to={TARGET_IP}:{port} {desc}")

    def send_raw(self, pkt: bytes, desc: str = "", port: Optional[int] = None):
        if not self.sock:
            return
        p = port if port is not None else self.active_port
        if not p:
            return
        self.sock.sendto(pkt, (TARGET_IP, p))
        self.log_tx(pkt, desc=f"to={TARGET_IP}:{p} {desc}")

    def discovery(self, timeout: float = 2.0) -> bool:
        logger.info("Discovery…")
        for p in TARGET_PORTS:
            self.send_to(LBCS_PAYLOAD, p, desc="LBCS")

        start = time.time()
        while time.time() - start < timeout:
            try:
                data, addr = self.sock.recvfrom(2048)  # type: ignore[union-attr]
            except socket.timeout:
                continue
            except Exception:
                continue

            self.log_rx(data, desc=f"from={addr}")

            if not data or len(data) < 2 or data[0] != 0xF1:
                continue
            if addr[0] != TARGET_IP:
                continue

            self.active_port = addr[1]
            logger.info(f"✅ Discovery OK, active_port={self.active_port}")
            return True

        logger.error("❌ Discovery failed (no reply on candidate ports)")
        return False

    def next_seq(self) -> int:
        self.global_seq = (self.global_seq + 1) % 255
        if self.global_seq == 0:
            self.global_seq = 1
        return self.global_seq

    def build_packet(self, packet_type: int, payload: bytes, force_seq: Optional[int] = None):
        if force_seq is None:
            seq = self.next_seq()
        else:
            seq = force_seq
            self.global_seq = seq

        body_len = len(payload) + 4
        header = bytearray([0xF1, packet_type, (body_len >> 8) & 0xFF, body_len & 0xFF, 0xD1, 0x00, 0x00, seq])
        return bytes(header) + payload, seq

    def build_ack_10(self, rx_seq: int) -> bytes:
        payload = bytes([0x00, rx_seq])
        body_len = 6
        header = bytes([0xF1, 0xD1, (body_len >> 8) & 0xFF, body_len & 0xFF, 0xD1, 0x00, 0x00, rx_seq])
        return header + payload

    def encrypt_json(self, obj) -> bytes:
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        return AES.new(PHASE2_KEY, AES.MODE_ECB).encrypt(pad(raw, AES.block_size))

    def decrypt_payload(self, data: bytes):
        try:
            r = self._decrypt_artemis_json_any(data)
            if r is None:
                return None
            obj, _cmd_id, _app_seq = r
            return obj
        except Exception as e:
            if self.debug:
                logger.debug(f"Decrypt failed: {e}")
            return None

    def get_cmd_id(self, data: bytes) -> Optional[int]:
        hdr = self._parse_artemis_header_any(data)
        if hdr is None:
            return None
        _off, _magic, cmd_id, _app_seq, _alen = hdr
        return cmd_id

    def _extract_token_any(self, pkt: bytes) -> Optional[Tuple[str, int, int]]:
        """Extrahiert token aus beliebigem ARTEMIS-Frame (cmd_id egal)."""

        r = self._decrypt_artemis_json_any(pkt)
        if r is None:
            return None

        obj, cmd_id, app_seq = r

        if not isinstance(obj, dict) or "token" not in obj:
            return None

        tok = obj.get("token")
        if tok is None:
            return None

        return str(tok), int(cmd_id), int(app_seq)

    def _debug_dump_buffered_cmd3(self, pkt: bytes, idx: int):
        if not self.debug:
            return

        hdr = self._parse_artemis_header_any(pkt)
        if hdr is None:
            logger.debug(f"🧾 Buffer[{idx}] no ARTEMIS header")
            return

        off, magic, cmd_id, app_seq, alen = hdr
        payload = self._extract_artemis_payload(pkt, off, alen)
        b64_part = payload.split(b"\x00")[0]
        b64_part_padded = self._pad_b64(b64_part)

        tag = "ARTEMISw" if magic == ARTEMIS_W else "ARTEMIS"
        try:
            b64_str = b64_part_padded.decode("ascii", errors="replace")
        except Exception:
            b64_str = "<decode-error>"

        logger.debug(
            f"🧾 Buffer[{idx}] {tag} Cmd={cmd_id} AppSeq={app_seq} ALen={alen} "
            f"b64_len={len(b64_part_padded)} b64='{b64_str}'"
        )

        try:
            raw = base64.b64decode(b64_part_padded)
            logger.debug(f"✅ Buffer[{idx}] base64 decode ok raw_len={len(raw)}")
        except Exception as e:
            logger.debug(f"❌ Buffer[{idx}] base64 decode failed: {e!r}")
            return

        try:
            dec = unpad(AES.new(PHASE2_KEY, AES.MODE_ECB).decrypt(raw), AES.block_size)
            logger.debug(f"✅ Buffer[{idx}] AES decrypt ok dec_len={len(dec)}")
        except Exception as e:
            logger.debug(f"❌ Buffer[{idx}] AES decrypt/unpad failed: {e!r}")
            return

        try:
            j = dec.decode("utf-8")
            logger.debug(f"🧾 Buffer[{idx}] json(raw)={j}")
        except Exception as e:
            logger.debug(f"❌ Buffer[{idx}] utf-8 decode failed: {e!r}")

    def _check_buffered_tokens(self) -> bool:
        """Prüft gepufferte Pakete auf Token."""
        if not self._token_packet_buffer:
            return False

        if self.debug:
            logger.debug(f"🔍 Prüfe {len(self._token_packet_buffer)} gepufferte Pakete auf Token…")

        for i, pkt in enumerate(list(self._token_packet_buffer)):
            # v4.10: Debug the buffered payload end-to-end
            self._debug_dump_buffered_cmd3(pkt, i)

            t = self._extract_token_any(pkt)
            if t is not None:
                tok, cmd_id, app_seq = t
                self.token = str(tok)
                logger.info(
                    f"✅ TOKEN aus Puffer extrahiert (Cmd={cmd_id}, AppSeq={app_seq}, len={len(self.token)}): {self.token}"
                )
                return True

        return False

    def wait_for_token(self, timeout: float, phase: str) -> bool:
        """Wartet bis ein gültiges token empfangen wurde und speichert es in self.token."""

        # Check buffer first (in case token arrived early)
        if self._check_buffered_tokens():
            logger.info(f">>> Token bereits im Puffer vorhanden ({phase})")
            return True

        found: Dict[str, Any] = {"token": None, "cmd_id": None, "app_seq": None}

        def tok_ok(pkt: bytes) -> bool:
            t = self._extract_token_any(pkt)
            if t is None:
                return False
            tok, cmd_id, app_seq = t
            found["token"] = tok
            found["cmd_id"] = cmd_id
            found["app_seq"] = app_seq
            return True

        _pkt = self.pump(timeout=timeout, accept_predicate=tok_ok, filter_evt=True)
        if not found["token"]:
            return False

        self.token = str(found["token"])
        logger.info(
            f"✅ TOKEN OK ({phase}) cmd_id={found['cmd_id']} app_seq={found['app_seq']} token_len={len(self.token)}"
        )
        return True

    def send_heartbeat(self):
        if time.time() - self.last_heartbeat_time < 2.0:
            return

        self.heartbeat_cnt = (self.heartbeat_cnt + 1) % 255
        body = bytearray(HEARTBEAT_BODY_START) + bytearray([self.heartbeat_cnt]) + bytearray(HEARTBEAT_PAYLOAD_END)
        pkt, _ = self.build_packet(0xD0, bytes(body))
        self.send_raw(pkt, desc=f"Heartbeat cnt={self.heartbeat_cnt}")
        self.last_heartbeat_time = time.time()

    def send_prelogin(self):
        logger.info(">>> Pre-Login…")
        payload = {"utcTime": int(time.time()), "nonce": os.urandom(8).hex()}
        enc = AES.new(PHASE2_KEY, AES.MODE_ECB).encrypt(
            pad(json.dumps(payload, separators=(",", ":")).encode("utf-8"), AES.block_size)
        )
        pkt = struct.pack(">BBH", 0xF1, 0xF9, len(PHASE2_STATIC_HEADER + enc)
        ) + PHASE2_STATIC_HEADER + enc

        for p in TARGET_PORTS:
            self.send_to(pkt, p, desc="PreLogin")

        # Nur "pumpen" zum RX/ACK/Logging (nicht auf irgendein Paket "returnen")
        self.pump(timeout=1.0, accept_predicate=lambda _d: False)

    def _log_evt_rate_limited(self, evt: Dict[str, Any]):
        if not self.debug:
            return

        now = time.time()
        if now - self._evt_last_log_ts >= 1.0:
            if self._evt_suppressed:
                logger.debug(f"📰 EVT suppressed {self._evt_suppressed} packets")
                self._evt_suppressed = 0

            self._evt_last_log_ts = now
            logger.debug(
                f"📰 EVT evtId={evt.get('evtId')} (ARTEMISw Cmd={evt.get('cmd_id')} AppSeq={evt.get('app_seq')} ALen={evt.get('alen')})"
            )
        else:
            self._evt_suppressed += 1

    def pump(
        self,
        timeout: float,
        accept_cmd: Optional[Union[int, Set[int]]] = None,
        accept_predicate: Optional[Callable[[bytes], bool]] = None,
        filter_evt: bool = True,
    ) -> Optional[bytes]:
        """Empfängt Pakete, ack't wenn nötig und loggt in --debug alle Frames."""

        start = time.time()
        while time.time() - start < timeout:
            if self.active_port and self.global_seq > 1:
                self.send_heartbeat()

            try:
                data, addr = self.sock.recvfrom(65535)  # type: ignore[union-attr]
            except socket.timeout:
                continue
            except Exception:
                continue

            # Parse event early so RAW dump can reduce noise
            evt = self._try_parse_evt(data)

            if self.raw_rx_dump and self._raw_window_active():
                if evt is not None and filter_evt:
                    # avoid flooding debug logs with full hexdumps of event spam
                    logger.debug(f"🧾 RAW RX (event) from={addr[0]}:{addr[1]} len={len(data)}")
                else:
                    logger.debug(f"🧾 RAW RX from={addr[0]}:{addr[1]} len={len(data)}\n{hexdump_full(data)}")

                    meta = self._parse_artemis_meta_any(data)
                    if meta is not None:
                        off, cmd_id, app_seq, alen = meta
                        logger.debug(
                            f"🧩 ARTEMIS meta from={addr[0]}:{addr[1]} off=0x{off:x} cmd_id={cmd_id} app_seq={app_seq} alen={alen}"
                        )

            self.log_rx(data, desc=f"from={addr}")

            if not data or len(data) < 2:
                continue

            looks_artemis_frag = False
            if len(data) >= 8 and data[0] == 0xF1:
                pkt_type = data[1]
                rx_seq = data[7]

                if pkt_type == 0x42:
                    frag_payload = data[8:]
                    looks_artemis_frag = (ARTEMIS_NULL in frag_payload) or (ARTEMIS_NULL in self._frag_buf)

                # ACK data and artemis fragments (including events) to prevent retransmit storm
                if pkt_type == 0xD0 or (pkt_type == 0x42 and looks_artemis_frag):
                    is_ack_payload = self._is_simple_ack_payload(data)
                    if not is_ack_payload and self.active_port:
                        ack = self.build_ack_10(rx_seq)
                        self.send_raw(ack, desc=f"ACK(rx_seq={rx_seq})")

                if pkt_type == 0x42:
                    if looks_artemis_frag:
                        self._frag_buf += data[8:]
                        re = self._try_reassemble_artemis()
                        if re is None:
                            continue
                        data = re

                        if self.raw_rx_dump and self._raw_window_active():
                            meta = self._parse_artemis_meta_any(data)
                            if meta is not None:
                                off, cmd_id, app_seq, alen = meta
                                logger.debug(
                                    f"🧩 ARTEMIS(meta reassembled) from={addr[0]}:{addr[1]} off=0x{off:x} cmd_id={cmd_id} app_seq={app_seq} alen={alen}"
                                )
                    else:
                        if self.debug:
                            logger.debug("FRAG ohne ARTEMIS-Signatur (vermutlich LBCS/Discovery); skip reassembly/ack")

            # Token buffer: store Cmd=3 during handshake/stabilization
            if self._buffering_active:
                cmd_id = self.get_cmd_id(data)
                if cmd_id == 3:
                    self._token_packet_buffer.append(data)
                    if self.debug:
                        logger.debug(f"🔓 Cmd=3 Paket gepuffert (Buffer: {len(self._token_packet_buffer)} Pakete)")

            # Events: ACKed above but routed to separate queue; optionally filtered from main flow
            if evt is not None:
                self._event_queue.append(evt)
                self._log_evt_rate_limited(evt)
                if filter_evt:
                    continue

            if accept_predicate is not None:
                try:
                    if accept_predicate(data):
                        return data
                except Exception:
                    pass
                continue

            if accept_cmd is None:
                return data

            cmd_id = self.get_cmd_id(data)
            if cmd_id is None:
                continue

            if isinstance(accept_cmd, int):
                if cmd_id == accept_cmd:
                    return data
                if self.debug:
                    logger.debug(f"⚠️ Ignore Cmd {cmd_id} (warte auf {accept_cmd})")
            else:
                if cmd_id in accept_cmd:
                    return data
                if self.debug:
                    logger.debug(f"⚠️ Ignore Cmd {cmd_id} (warte auf {sorted(list(accept_cmd))})")

        return None

    def _try_reassemble_artemis(self) -> Optional[bytes]:
        idx = self._frag_buf.find(ARTEMIS_NULL)
        if idx < 0:
            if len(self._frag_buf) > 1024 * 1024:
                self._frag_buf.clear()
            return None

        if idx > 0:
            del self._frag_buf[:idx]

        if len(self._frag_buf) < 20:
            return None

        try:
            _cmd_id, _app_seq, blen = struct.unpack("<III", self._frag_buf[8:20])
        except Exception:
            del self._frag_buf[:1]
            return None

        total = 20 + blen
        if len(self._frag_buf) < total:
            return None

        payload = bytes(self._frag_buf[:total])
        del self._frag_buf[:total]

        # künstlicher RUDP Header
        rudp_hdr = bytes([0xF1, 0xD0, 0x00, 0x00, 0xD1, 0x00, 0x00, 0x00])
        return rudp_hdr + payload

    def hello_handshake(self) -> bool:
        logger.info(">>> Handshake Step 1: Hello (force seq 0)")

        # dynamische AppSeq, damit Hello nicht mit späteren Requests kollidiert
        self.app_seq += 1
        hello_body = build_artemis_frame(2, self.app_seq, ARTEMIS_HELLO_B64 + b"\x00")
        hello_pkt, _ = self.build_packet(0xD0, hello_body, force_seq=0)

        def hello_ok(pkt: bytes) -> bool:
            if self._is_simple_ack_payload(pkt):
                return True
            return self._parse_artemis_header_any(pkt) is not None

        self.send_raw(hello_pkt, desc="Hello")
        r = self.pump(timeout=2.2, accept_predicate=hello_ok, filter_evt=False)
        if r is not None:
            return True

        alt_ports = [p for p in TARGET_PORTS if p != self.active_port]
        if alt_ports:
            logger.warning("Keine Hello-Bestätigung via active_port; Fallback auf alternativen Port…")
            self.send_raw(hello_pkt, desc="Hello(fallback)", port=alt_ports[0])
            r = self.pump(timeout=2.2, accept_predicate=hello_ok, filter_evt=False)
            if r is not None:
                self.active_port = alt_ports[0]
                logger.info(f"✅ active_port auf {self.active_port} umgestellt (Hello-Fallback).")
                return True

        return False

    def run(self):
        if not self.setup_network():
            return
        if not self.discovery():
            return

        # Enable token buffering BEFORE PreLogin
        self.enable_token_buffering()

        self.send_prelogin()
        time.sleep(0.25)

        if not self.hello_handshake():
            logger.error("❌ Hello nicht bestätigt/keine Antwort")
            return

        logger.info(">>> Handshake Step 2: Magic 1 (force seq 3)")
        m1, _ = self.build_packet(0xD1, MAGIC_BODY_1, force_seq=3)
        self.send_raw(m1, desc="Magic1")
        time.sleep(0.05)

        logger.info(">>> Handshake Step 3: Magic 2 (force seq 1)")
        m2, _ = self.build_packet(0xD1, MAGIC_BODY_2, force_seq=1)
        self.send_raw(m2, desc="Magic2")
        time.sleep(0.05)

        logger.info(">>> Stabilisierung…")
        for _ in range(2):
            self.send_heartbeat()
            self.pump(timeout=0.5, accept_predicate=lambda _d: False)

        if LOGIN_DELAY_AFTER_STABILIZATION > 0:
            logger.info(f">>> Warte {LOGIN_DELAY_AFTER_STABILIZATION:.1f}s vor Login…")
            time.sleep(LOGIN_DELAY_AFTER_STABILIZATION)

        # Prefer token after login, but still check buffer once in case token arrived early
        logger.info(">>> Token-Check (nur Buffer) vor Login…")
        if self._check_buffered_tokens():
            logger.info(">>> Token bereits vorhanden; überspringe Login-Request.")
        else:
            logger.info(">>> Login…")
            self.app_seq += 1
            login_data = {
                "cmdId": 0,
                "usrName": "admin",
                "password": "admin",
                "needVideo": 0,
                "needAudio": 0,
                "utcTime": int(time.time()),
                "supportHeartBeat": True,
            }
            b64_body = base64.b64encode(self.encrypt_json(login_data)) + b"\x00"
            art = build_artemis_frame(0, self.app_seq, b64_body)

            pkt, _ = self.build_packet(0xD0, art)
            self.send_raw(pkt, desc="Login")

            if self.debug and self.raw_rx_dump:
                self.enable_raw_rx_dump()

            logger.info("⏳ Warte auf Token (Login-Response)…")
            if not self.wait_for_token(timeout=max(8.0, self.raw_rx_window_seconds), phase="login"):
                logger.error("❌ Login Timeout (kein Token empfangen)")
                return

        # Disable buffering after successful login
        self.disable_token_buffering()

        logger.info(">>> Request file list (Cmd 768)…")
        self.app_seq += 1
        req = {"cmdId": 768, "itemCntPerPage": 45, "pageNo": 0, "token": str(self.token)}
        b64_body = base64.b64encode(self.encrypt_json(req)) + b"\x00"
        art = build_artemis_frame(768, self.app_seq, b64_body)
        pkt, _ = self.build_packet(0xD0, art)
        self.send_raw(pkt, desc="Cmd768")

        pkt = self.pump(timeout=10.0, accept_cmd=768, filter_evt=True)
        if pkt:
            files = self.decrypt_payload(pkt)
            logger.info(f"Cmd768 response (preview): {str(files)[:200]}")
        else:
            logger.warning("Keine Cmd768 Antwort (Timeout).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true", help="Debug logging (inkl. Frame-Dumps)")
    parser.add_argument(
        "--raw-rx-window",
        type=float,
        default=20.0,
        help="RAW RX dump window nach Login-Request (Sekunden, default: 20.0).",
    )
    parser.add_argument(
        "--no-raw-rx",
        action="store_true",
        help="Deaktiviert RAW RX dump window (auch wenn --debug aktiv ist).",
    )
    parser.add_argument("--ble", action="store_true", help="Weckt die Kamera per BLE (aktiviert Wi-Fi-Modul)")
    parser.add_argument("--ble-mac", default=BLE_MAC, help="BLE MAC-Adresse der Kamera")
    parser.add_argument("--ble-wait", type=int, default=20, help="Wartezeit nach BLE-Wakeup (Sekunden)")
    parser.add_argument("--wifi", action="store_true", help="Verbinde zum Kamera-WLAN via nmcli")
    args = parser.parse_args()

    setup_logging(args.debug)

    if args.ble:
        asyncio.run(BLEWorker.wake_camera(args.ble_mac))
        time.sleep(max(0, args.ble_wait))

    if args.wifi:
        WiFiWorker.connect(DEFAULT_SSID, DEFAULT_PASS)

    Session(
        debug=args.debug,
        raw_rx_window_seconds=args.raw_rx_window,
        raw_rx_dump=(not args.no_raw_rx),
    ).run()
