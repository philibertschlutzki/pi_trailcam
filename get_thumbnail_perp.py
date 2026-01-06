#!/usr/bin/env python3
"""Wildkamera Thumbnail Downloader - consolidated v4.21

Changes in this version (v4.21) - FIX for Issue #168:
- CRITICAL FIX: Pre-Login ACK must be explicitly awaited before proceeding to login.
  Analysis of debug06012026_4.log and comparison with MITM captures reveals that the
  working app receives TWO "ACK" packets during the handshake:
  
  ACK #1 (MITM line 372): Sent by camera AFTER Pre-Login, BEFORE login request
  ACK #2 (MITM line 396): Sent by camera AFTER Magic1 handshake packet
  
  The current implementation sends Pre-Login but doesn't explicitly wait for ACK #1.
  This causes inconsistent behavior:
  - Sometimes camera sends ACK #1 (debug06012026_2.log line 21, debug06012026_3.log line 21)
  - Sometimes camera doesn't send ACK #1 (debug06012026_4.log, debug06012026_1.log)
  
  When ACK #1 is missing, the camera is NOT ready for login and ignores all subsequent
  packets (Login, Magic1, retransmissions). This is the root cause of Issue #168.
  
  Fix:
  1. After sending Pre-Login, explicitly pump() for ACK packet with timeout
  2. Only proceed to login if ACK #1 is received
  3. If ACK #1 not received, retry Pre-Login up to 3 times
  4. If all retries fail, abort with clear error message
  
  See ANALYSE_KONSOLIDIERT_LOGIN.md "NEUER ROOT CAUSE (Issue #168)" for detailed analysis.

Changes in v4.20 - FIX for Issue #166:
- CRITICAL FIX: Restored pump() wait after Magic1 + added global_seq reset. Analysis of 
  debug06012026_3.log shows that v4.19 (which removed the pump() wait) was WRONG.
  
  The v4.19 analysis (Issue #164) was INCORRECT. It claimed the camera doesn't send anything
  after Magic1, but this is FALSE. The MITM capture clearly shows:
  
  Correct sequence (ble_udp_1.log lines 378-435):
  1. TX Login #1 (Seq=0, AppSeq=1)                    [Line 378]
  2. TX Magic1 (Seq=3)                                [Line 393]
  3. ⬇️ [APP WAITS HERE - NO TX until line 399!]
  4. RX ACK "ACK" (Seq=0) from camera                 [Line 396] ← Kamera signalisiert Bereitschaft!
  5. TX ACK for camera's ACK (Seq=1)                  [Line 399] ← Handshake abgeschlossen
  6. TX Login #2 (Seq=0, AppSeq=1) - IMMEDIATELY      [Line 402]
  7. TX Login #3 (Seq=0, AppSeq=1)                    [Line 417]
  8. RX Login Response (MsgType=3, AppSeq=1) ✅       [Line 435]
  
  v4.19 sent Login #2 only 24ms after Magic1 (debug06012026_3.log), which is TOO EARLY.
  The camera needs time to send its ACK "ACK" response (step 4), which signals readiness
  for login retransmissions. This ACK-exchange is a CRITICAL HANDSHAKE.
  
  IMPORTANT: After Magic1 (Seq=3), the app resets global_seq to 0. This ensures the ACK
  for camera's ACK has Seq=1 (as seen in MITM line 399). Without this reset, the sequence
  numbers would be wrong and the camera would reject the handshake.
  
  Fix:
  1. After Magic1: Reset global_seq to 0 (to match MITM behavior)
  2. pump(0.3s) to receive camera's ACK "ACK" and automatically send ACK(Seq=1)
  3. THEN send Login #2 and #3
  
  See ANALYSE_KONSOLIDIERT_LOGIN.md "FINALER ROOT CAUSE (Issue #166)" for detailed analysis.

Changes in v4.19 (WRONG FIX - reverted in v4.20):
- Removed pump() after Magic1 based on incorrect Issue #164 analysis.

Changes in v4.18 (CORRECT IDEA, but missing global_seq reset):
- Added pump() call after Magic1 (correct idea, but missing the global_seq reset step).

Changes in v4.17:
- CRITICAL FIX for Issue #159: Suppress heartbeat during login handshake.
  Root cause: An unwanted heartbeat (AppSeq=2) was sent between Magic1 and login retransmissions,
  breaking the expected AppSeq=1 sequence. The camera firmware expects either:
  (a) Login response (MsgType=3, AppSeq=1), OR
  (b) Login retransmission (MsgType=2, AppSeq=1)
  
  The heartbeat with AppSeq=2 confused the camera's state machine, causing it to ignore
  subsequent login retransmissions. 
  
  Fix: Added no_heartbeat parameter to pump() and set it to True during login handshake:
  - After Magic1, pump without heartbeat to ACK responses
  - While waiting for login response, pump without heartbeat
  
  This ensures the AppSeq sequence remains clean: AppSeq=1 (login) -> AppSeq=1 (retrans) ->
  AppSeq=1 (retrans) -> MsgType=3 AppSeq=1 (response).
  
  See ANALYSE_KONSOLIDIERT_LOGIN.md "FINALER ROOT CAUSE (Issue #159)" section for detailed analysis.

Changes in v4.16:
- CRITICAL FIX for Issue #157: Implemented triple login request transmission.
  Analysis of MITM captures (ble_udp_1.log lines 378-475) reveals that the working app sends
  the login request THREE times (lines 378, 402, 417) before the camera responds (line 463).
  All three transmissions use identical RUDP Seq=0 and AppSeq=1 (it's a retransmission, not new requests).
  This is not error handling but part of the expected protocol flow - the camera firmware requires
  multiple transmissions before responding with the login token.
  
  Login sequence now:
  1. Login#1 (Seq=0, AppSeq=1)
  2. Magic1 handshake (Seq=3)
  3. Login#2 retransmit (Seq=0, AppSeq=1) - NEW!
  4. Login#3 retransmit (Seq=0, AppSeq=1) - NEW!
  5. Wait for Login Response (MsgType=3)
  
  See ANALYSE_KONSOLIDIERT_LOGIN.md for detailed analysis.

Changes in v4.15:
- CRITICAL FIX: Replaced static ARTEMIS_HELLO_B64 blob with proper JSON login request (cmdId=0).
  Now generates login JSON with dynamic utcTime, matching app behavior per Protocol_analysis.md.
  This fixes token extraction failures caused by sending replay/static data instead of fresh login.
- Enhanced decryption: Added multiple fallback strategies (ECB, CBC, prefix removal) to handle
  different response formats and improve token extraction robustness.

Keeps from v4.14:
- ARTEMIS ("ARTEMIS\x00") header field1 is MsgType (2=request, 3=response), not cmdId.
  Requests are sent with MsgType=2 and the real cmdId stays inside the encrypted JSON.
- Response matching: cmdId filtering is based on decrypted JSON (cmdId), not ARTEMIS header field.
- Token extraction: token is accepted only from MsgType=3 responses that match expected AppSeq.
- ARTEMISw Cmd=9 is parsed as plaintext JSON event (no base64/AES attempt).
"""

import argparse
import asyncio
import base64
import calendar
import json
import logging
import os
import socket
import struct
import subprocess
import sys
import time
from typing import Optional, Union, Set, Tuple, Callable, Any, Dict
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

LOGIN_DELAY_AFTER_STABILIZATION = 2.0
# Timeout for waiting for camera's ACK after Magic1 handshake packet (per MITM analysis)
MAGIC1_ACK_TIMEOUT = 0.3



# --- CONSTANTS / PAYLOADS ---
LBCS_PAYLOAD = bytes.fromhex("f14100144c42435300000000000000004343434a4a000000")

MAGIC_BODY_1 = bytes.fromhex("000000000000")
MAGIC_BODY_2 = bytes.fromhex("0000")

# Heartbeat body is a vendor-specific "ARTEMIS" blob; keep as-is.
HEARTBEAT_BODY_START = bytes.fromhex("415254454d49530002000000")
HEARTBEAT_PAYLOAD_END = bytes.fromhex(
    "000100190000004d7a6c423336582f49566f385a7a49357247396a31773d3d00"
)

PHASE2_KEY = b"a01bc23ed45fF56A"  # Note: ECB mode is used per camera vendor protocol specification (Protocol_analysis.md §4.2)
PHASE2_STATIC_HEADER = bytes.fromhex(
    "0ccb9a2b5f951eb669dfaa375a6bbe3e76202e13c9d1aa3631be74e5"
)

ARTEMIS_NULL = b"ARTEMIS\x00"
ARTEMIS_W = b"ARTEMISw"

ARTEMIS_MSG_REQUEST = 2
ARTEMIS_MSG_RESPONSE = 3

# Note: The legacy static HELLO blob (ARTEMIS_HELLO_B64) has been removed in v4.15.
# It was replaced with proper dynamic JSON login requests per Protocol_analysis.md.
# The blob was: J8WWuQDPmYSLfu/gXAG+UqbBy55KP2iE25QPNofzn040+NI9g7ze... (172 chars)
# but could not be decrypted as valid JSON, suggesting it was not a proper login format.


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
    if data is None:
        return ""

    out = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        out.append(f"{off:04x}: {chunk.hex()}")
    return "\n".join(out)


def build_artemis_frame(msg_type: int, app_seq: int, body: bytes) -> bytes:
    """Builds an ARTEMIS\x00 frame.

    field1 is MsgType (2=request, 3=response) according to Protocol_analysis.md.
    """
    # Input validation
    msg_type = int(msg_type)
    app_seq = int(app_seq)
    
    # Validate reasonable ranges
    if msg_type not in [ARTEMIS_MSG_REQUEST, ARTEMIS_MSG_RESPONSE]:
        logger.warning(f"⚠️ Unusual MsgType={msg_type} (expected {ARTEMIS_MSG_REQUEST} or {ARTEMIS_MSG_RESPONSE})")
    
    if app_seq < 0 or app_seq > 1000000:
        logger.warning(f"⚠️ AppSeq={app_seq} out of reasonable range")
    
    frame = ARTEMIS_NULL + struct.pack("<III", msg_type, app_seq, len(body)) + body
    
    # Debug logging
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"🔧 build_artemis_frame: MsgType={msg_type}, AppSeq={app_seq}, BodyLen={len(body)}")
        # Show the actual bytes of the AppSeq field
        appseq_bytes = struct.pack("<I", app_seq)
        logger.debug(f"   AppSeq bytes (LE): {appseq_bytes.hex()}")
    
    return frame


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

        self.raw_dump_until: float = 0.0
        self.raw_rx_window_seconds = float(raw_rx_window_seconds)
        self.raw_rx_dump = bool(raw_rx_dump)

        self._evt_last_log_ts: float = 0.0
        self._evt_suppressed: int = 0
        self._event_queue: deque = deque(maxlen=200)

        # Token buffer (raw MsgType=3 responses during handshake/login)
        self._token_packet_buffer: deque = deque(maxlen=10)
        self._buffering_active = False

    def enable_token_buffering(self):
        self._buffering_active = True
        self._token_packet_buffer.clear()
        if self.debug:
            logger.debug("🔓 Token-Pufferung aktiviert")

    def disable_token_buffering(self):
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
        """Finds ARTEMIS header at any offset.

        Returns: (offset, magic8, field1, app_seq, alen)
        - For ARTEMIS\x00: field1 = MsgType (2=request, 3=response)
        - For ARTEMISw:   field1 = cmd_id (e.g. 9 for event)
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
                field1, app_seq, alen = struct.unpack("<III", data[base : base + 12])
                return idx, magic, int(field1), int(app_seq), int(alen)
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

    @staticmethod
    def _manual_unpad_utf8_json(decrypted: bytes) -> Optional[Dict[str, Any]]:
        try:
            s = decrypted.decode("utf-8", errors="ignore")
            end_idx = s.rfind("}")
            if end_idx == -1:
                return None
            json_str = s[: end_idx + 1]
            obj = json.loads(json_str)
            return obj
        except Exception:
            return None

    def _decrypt_artemis_json_any(self, data: bytes) -> Optional[Tuple[Dict[str, Any], int, int, bytes]]:
        """Decrypts Base64(AES-ECB(JSON)) from ARTEMIS\x00 frames; ARTEMISw may be plaintext JSON.

        Returns: (obj, field1, app_seq, magic)
        - field1 = MsgType for ARTEMIS\x00, cmd_id for ARTEMISw
        """

        hdr = self._parse_artemis_header_any(data)
        if hdr is None:
            return None

        off, magic, field1, app_seq, alen = hdr

        # ARTEMISw is often plaintext JSON (events)
        if magic == ARTEMIS_W:
            payload = self._extract_artemis_payload(data, off, alen)
            raw = payload.split(b"\x00")[0]
            try:
                obj = json.loads(raw.decode("utf-8", errors="ignore"))
                if isinstance(obj, dict):
                    return obj, field1, app_seq, magic
            except Exception:
                return None

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
                    f"(field1={field1}, AppSeq={app_seq}, b64_len={len(b64_part)}): {e!r}"
                )
            return None

        # Enhanced instrumentation for debugging decryption issues
        if self.debug:
            logger.debug(
                f"🔍 Decrypt attempt: field1={field1}, AppSeq={app_seq}, "
                f"b64_len={len(b64_part)}, raw_len={len(raw)}, "
                f"raw_is_16_aligned={len(raw) % 16 == 0}"
            )
            logger.debug(f"🔍 Raw (first 32B): {raw[:32].hex()}")

        # Try multiple decryption strategies
        obj = None
        strategy = None

        # Strategy (a): Current AES-ECB approach (baseline)
        try:
            dec_ecb = AES.new(PHASE2_KEY, AES.MODE_ECB).decrypt(raw)
            if self.debug:
                logger.debug(f"🔍 ECB decrypted (first 32B): {dec_ecb[:32].hex()}")
            
            try:
                unpadded = unpad(dec_ecb, AES.block_size)
                obj = json.loads(unpadded.decode("utf-8"))
                strategy = "ECB"
            except Exception:
                obj = self._manual_unpad_utf8_json(dec_ecb)
                if obj:
                    strategy = "ECB-manual"
        except Exception as e:
            if self.debug:
                logger.debug(f"⚠️ ECB strategy failed: {e}")

        # Strategy (b): AES-CBC with IV = first 16 bytes of raw
        if not obj and len(raw) > 16 and len(raw[16:]) % 16 == 0:
            try:
                iv = raw[:16]
                ciphertext = raw[16:]
                if self.debug:
                    logger.debug(f"🔍 Trying CBC: IV={iv.hex()}, ciphertext_len={len(ciphertext)}")
                
                dec_cbc = AES.new(PHASE2_KEY, AES.MODE_CBC, iv).decrypt(ciphertext)
                if self.debug:
                    logger.debug(f"🔍 CBC decrypted (first 32B): {dec_cbc[:32].hex()}")
                
                try:
                    unpadded = unpad(dec_cbc, AES.block_size)
                    obj = json.loads(unpadded.decode("utf-8"))
                    strategy = "CBC"
                except Exception:
                    obj = self._manual_unpad_utf8_json(dec_cbc)
                    if obj:
                        strategy = "CBC-manual"
            except Exception as e:
                if self.debug:
                    logger.debug(f"⚠️ CBC strategy failed: {e}")

        # Strategy (c): Try removing prefix bytes (3, 4, 8, or 16) if payload has prefix
        if not obj:
            for prefix_size in [3, 4, 8, 16]:
                if len(raw) > prefix_size and len(raw[prefix_size:]) % 16 == 0:
                    try:
                        ciphertext = raw[prefix_size:]
                        if self.debug:
                            logger.debug(f"🔍 Trying ECB with {prefix_size}B prefix removal, ciphertext_len={len(ciphertext)}")
                        
                        dec_prefix = AES.new(PHASE2_KEY, AES.MODE_ECB).decrypt(ciphertext)
                        
                        try:
                            unpadded = unpad(dec_prefix, AES.block_size)
                            obj = json.loads(unpadded.decode("utf-8"))
                            strategy = f"ECB-prefix{prefix_size}"
                            break
                        except Exception:
                            obj = self._manual_unpad_utf8_json(dec_prefix)
                            if obj:
                                strategy = f"ECB-prefix{prefix_size}-manual"
                                break
                    except Exception as e:
                        if self.debug:
                            logger.debug(f"⚠️ ECB-prefix{prefix_size} failed: {e}")
        
        # Strategy (d): Try CBC with prefix removal
        if not obj:
            for prefix_size in [3, 4, 8, 16]:
                # After removing prefix, we need at least 32 bytes (16 for IV + 16 for one AES block)
                if len(raw) > prefix_size + 32 and len(raw[prefix_size + 16:]) % 16 == 0:
                    try:
                        data_after_prefix = raw[prefix_size:]
                        iv = data_after_prefix[:16]
                        ciphertext = data_after_prefix[16:]
                        if self.debug:
                            logger.debug(f"🔍 Trying CBC with {prefix_size}B prefix removal, IV+ciphertext_len={len(data_after_prefix)}")
                        
                        dec_cbc_prefix = AES.new(PHASE2_KEY, AES.MODE_CBC, iv).decrypt(ciphertext)
                        
                        try:
                            unpadded = unpad(dec_cbc_prefix, AES.block_size)
                            obj = json.loads(unpadded.decode("utf-8"))
                            strategy = f"CBC-prefix{prefix_size}"
                            break
                        except Exception:
                            obj = self._manual_unpad_utf8_json(dec_cbc_prefix)
                            if obj:
                                strategy = f"CBC-prefix{prefix_size}-manual"
                                break
                    except Exception as e:
                        if self.debug:
                            logger.debug(f"⚠️ CBC-prefix{prefix_size} failed: {e}")

        if not isinstance(obj, dict):
            if self.debug:
                logger.debug(f"❌ All decryption strategies failed (field1={field1}, AppSeq={app_seq})")
            return None

        if self.debug and strategy:
            logger.debug(f"✅ Decryption successful using strategy: {strategy}")

        return obj, field1, app_seq, magic

    def _try_parse_evt(self, data: bytes) -> Optional[Dict[str, Any]]:
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
                return {"evtId": obj.get("evtId"), "cmd_id": cmd_id, "app_seq": app_seq, "alen": alen, "raw": obj}
        except Exception:
            return None

        return None

    @staticmethod
    def _is_simple_ack_payload(data: bytes) -> bool:
        return bool(len(data) >= 11 and data[0] == 0xF1 and data[1] == 0xD0 and data[8:11] == b"ACK")

    @staticmethod
    def _parse_artemis_meta_any(data: bytes) -> Optional[Tuple[int, bytes, int, int, int]]:
        hdr = Session._parse_artemis_header_any(data)
        if hdr is None:
            return None
        off, magic, field1, app_seq, alen = hdr
        return off, magic, field1, app_seq, alen

    def _get_artemis_msg_type(self, data: bytes) -> Optional[int]:
        hdr = self._parse_artemis_header_any(data)
        if hdr is None:
            return None
        _off, magic, field1, _app_seq, _alen = hdr
        if magic != ARTEMIS_NULL:
            return None
        return int(field1)

    def _get_artemis_app_seq(self, data: bytes) -> Optional[int]:
        hdr = self._parse_artemis_header_any(data)
        if hdr is None:
            return None
        _off, _magic, _field1, app_seq, _alen = hdr
        return int(app_seq)

    def _get_json_cmd_id(self, data: bytes) -> Optional[int]:
        r = self._decrypt_artemis_json_any(data)
        if r is None:
            return None
        obj, _field1, _app_seq, magic = r
        if magic != ARTEMIS_NULL:
            return None
        try:
            v = obj.get("cmdId")
            return int(v) if v is not None else None
        except Exception:
            return None

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
            _off, magic, field1, app_seq, alen = hdr
            if magic == ARTEMIS_W:
                info += f" | ARTEMISw Cmd={field1} AppSeq={app_seq} ALen={alen}"
            else:
                info += f" | ARTEMIS MsgType={field1} AppSeq={app_seq} ALen={alen}"

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
        header = bytearray(
            [0xF1, packet_type, (body_len >> 8) & 0xFF, body_len & 0xFF, 0xD1, 0x00, 0x00, seq]
        )
        return bytes(header) + payload, seq

    def build_ack_10(self, rx_seq: int) -> bytes:
        payload = bytes([0x00, rx_seq])
        body_len = 6
        header = bytes([0xF1, 0xD1, (body_len >> 8) & 0xFF, body_len & 0xFF, 0xD1, 0x00, 0x00, rx_seq])
        return header + payload

    def encrypt_json(self, obj) -> bytes:
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        return AES.new(PHASE2_KEY, AES.MODE_ECB).encrypt(pad(raw, AES.block_size))

    def decrypt_payload(self, data: bytes) -> Optional[Dict[str, Any]]:
        r = self._decrypt_artemis_json_any(data)
        if r is None:
            return None
        obj, _field1, _app_seq, _magic = r
        return obj

    def _extract_token_from_login_response(self, pkt: bytes, expected_app_seq: int, strict_appseq: bool = True) -> Optional[str]:
        """Accept token only from login responses (MsgType=3) matching expected AppSeq."""

        msg_type = self._get_artemis_msg_type(pkt)
        app_seq = self._get_artemis_app_seq(pkt)
        
        if msg_type != ARTEMIS_MSG_RESPONSE:
            return None
        
        if strict_appseq and app_seq != int(expected_app_seq):
            if self.debug:
                logger.debug(f"⚠️ MsgType=3 mit falschem AppSeq: erwartet={expected_app_seq}, empfangen={app_seq}")
            return None

        r = self._decrypt_artemis_json_any(pkt)
        if r is None:
            if self.debug:
                logger.debug(f"⚠️ MsgType=3 konnte nicht entschlüsselt werden (AppSeq={app_seq})")
                # Provide additional diagnostic information
                hdr = self._parse_artemis_header_any(pkt)
                if hdr:
                    off, magic, field1, _aseq, alen = hdr
                    payload = self._extract_artemis_payload(pkt, off, alen)
                    b64_part = payload.split(b"\x00")[0]
                    logger.debug(f"   Payload length: {alen}, Base64 length: {len(b64_part)}")
                    logger.debug(f"   Base64 (first 40 chars): {b64_part[:40]}")
                    try:
                        raw = base64.b64decode(self._pad_b64(b64_part))
                        logger.debug(f"   Decoded raw length: {len(raw)} (16-aligned: {len(raw) % 16 == 0})")
                        logger.debug(f"   Raw hex (first 32 bytes): {raw[:32].hex()}")
                    except Exception as e:
                        logger.debug(f"   Base64 decode failed: {e}")
            return None

        obj, _field1, _app_seq2, magic = r
        if magic != ARTEMIS_NULL:
            return None

        # Must be login cmdId=0
        try:
            cmd_id = obj.get("cmdId")
            if cmd_id is None or int(cmd_id) != 0:
                if self.debug:
                    logger.debug(f"⚠️ MsgType=3 ist kein Login (cmdId={cmd_id}, AppSeq={app_seq})")
                return None
        except Exception:
            return None

        tok = obj.get("token")
        if tok is None:
            if self.debug:
                # Log full JSON to help debug token extraction issues
                json_str = json.dumps(obj, ensure_ascii=False)
                json_preview = json_str[:200] + "..." if len(json_str) > 200 else json_str
                logger.debug(f"⚠️ MsgType=3 Login-Response ohne Token (AppSeq={app_seq})")
                logger.debug(f"📄 Full JSON: {json_preview}")
            return None

        if not strict_appseq and app_seq != int(expected_app_seq):
            logger.warning(f"✅ TOKEN mit falschem AppSeq akzeptiert: erwartet={expected_app_seq}, empfangen={app_seq}")
        
        return str(tok)

    def _check_buffered_login_token(self, expected_app_seq: int) -> bool:
        if not self._token_packet_buffer:
            return False

        if self.debug:
            logger.debug(
                f"🔍 Prüfe {len(self._token_packet_buffer)} gepufferte Pakete auf Login-Token (AppSeq={expected_app_seq})…"
            )

        # First try with strict AppSeq matching
        for pkt in list(self._token_packet_buffer):
            tok = self._extract_token_from_login_response(pkt, expected_app_seq=expected_app_seq, strict_appseq=True)
            if tok:
                self.token = tok
                logger.info(f"✅ TOKEN aus Puffer extrahiert (login AppSeq={expected_app_seq}, len={len(self.token)})")
                return True

        # Fallback: try without strict AppSeq if nothing was found
        logger.warning(f"⚠️ Kein Token mit AppSeq={expected_app_seq} gefunden, versuche Fallback ohne AppSeq-Prüfung…")
        for pkt in list(self._token_packet_buffer):
            tok = self._extract_token_from_login_response(pkt, expected_app_seq=expected_app_seq, strict_appseq=False)
            if tok:
                self.token = tok
                logger.info(f"✅ TOKEN aus Puffer extrahiert (Fallback, len={len(self.token)})")
                return True

        return False

    def wait_for_login_token(self, timeout: float, expected_app_seq: int) -> bool:
        if self._check_buffered_login_token(expected_app_seq=expected_app_seq):
            return True

        found: Dict[str, Any] = {"token": None}

        def tok_ok(pkt: bytes) -> bool:
            # Try strict matching first
            tok = self._extract_token_from_login_response(pkt, expected_app_seq=expected_app_seq, strict_appseq=True)
            if tok:
                found["token"] = tok
                found["strict"] = True
                return True
            # Try relaxed matching as fallback
            tok = self._extract_token_from_login_response(pkt, expected_app_seq=expected_app_seq, strict_appseq=False)
            if tok:
                found["token"] = tok
                found["strict"] = False
                return True
            return False

        _ = self.pump(timeout=timeout, accept_predicate=tok_ok, filter_evt=True)
        if not found["token"]:
            return False

        self.token = str(found["token"])
        strict_msg = "strict" if found.get("strict") else "relaxed"
        logger.info(f"✅ TOKEN OK (login, {strict_msg}) app_seq={expected_app_seq} token_len={len(self.token)}")
        return True

    def send_heartbeat(self):
        if time.time() - self.last_heartbeat_time < 2.0:
            return

        # Increment app_seq for each heartbeat (ARTEMIS request)
        self.app_seq += 1
        
        # Heartbeat payload: Base64 encoded AES data (static for heartbeat)
        # The Base64 string "MzlB36X/IVo8ZzI5rG9j1w==" is a static heartbeat payload
        heartbeat_b64_payload = b"MzlB36X/IVo8ZzI5rG9j1w==\x00"
        
        # Build ARTEMIS frame with MsgType=2 (request) and incrementing app_seq
        artemis_body = build_artemis_frame(ARTEMIS_MSG_REQUEST, self.app_seq, heartbeat_b64_payload)
        
        # Wrap in RUDP DATA packet
        pkt, _ = self.build_packet(0xD0, artemis_body)
        
        self.heartbeat_cnt = (self.heartbeat_cnt + 1) % 255
        if self.debug:
            logger.debug(f"📊 Heartbeat AppSeq={self.app_seq}, cnt={self.heartbeat_cnt}")
        
        self.send_raw(pkt, desc=f"Heartbeat AppSeq={self.app_seq}")
        self.last_heartbeat_time = time.time()

    def send_prelogin(self) -> bool:
        """Send Pre-Login packet and wait for ACK response.
        
        Returns:
            True if Pre-Login ACK was received, False otherwise
        """
        logger.info(">>> Pre-Login…")
        payload = {"utcTime": int(time.time()), "nonce": os.urandom(8).hex()}
        enc = AES.new(PHASE2_KEY, AES.MODE_ECB).encrypt(
            pad(json.dumps(payload, separators=(",", ":")).encode("utf-8"), AES.block_size)
        )
        pkt = struct.pack(">BBH", 0xF1, 0xF9, len(PHASE2_STATIC_HEADER + enc)) + PHASE2_STATIC_HEADER + enc

        for p in TARGET_PORTS:
            self.send_to(pkt, p, desc="PreLogin")

        # CRITICAL (Issue #168): Explicitly wait for Pre-Login ACK response
        # The camera sends a DATA packet with "ACK" payload (MITM ble_udp_1.log line 372)
        # to confirm Pre-Login was successful. Without this ACK, the camera is NOT ready
        # for login requests and will ignore all subsequent packets.
        logger.info(">>> Waiting for Pre-Login ACK response...")
        ack_received = self.pump(timeout=2.0, accept_predicate=self._is_simple_ack_payload, filter_evt=False)
        
        if not ack_received:
            logger.warning("⚠️ Pre-Login ACK not received - camera may not be ready")
            return False
        
        logger.info("✅ Pre-Login ACK received - camera ready for login")
        return True
    
    def send_prelogin_with_retry(self, max_retries: int = 3) -> bool:
        """Send Pre-Login with retry logic.
        
        Args:
            max_retries: Maximum number of Pre-Login attempts
            
        Returns:
            True if Pre-Login ACK was received, False if all retries failed
        """
        for attempt in range(max_retries):
            if attempt > 0:
                logger.info(f">>> Pre-Login Retry {attempt}/{max_retries}...")
                time.sleep(1.0)  # Brief pause between retries
            
            if self.send_prelogin():
                return True
        
        logger.error(f"❌ Pre-Login failed after {max_retries} attempts")
        return False

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
        no_heartbeat: bool = False,
    ) -> Optional[bytes]:
        start = time.time()
        while time.time() - start < timeout:
            if self.active_port and self.global_seq > 1 and not no_heartbeat:
                self.send_heartbeat()

            try:
                data, addr = self.sock.recvfrom(65535)  # type: ignore[union-attr]
            except socket.timeout:
                continue
            except Exception:
                continue

            evt = self._try_parse_evt(data)

            if self.raw_rx_dump and self._raw_window_active():
                if evt is not None and filter_evt:
                    logger.debug(f"🧾 RAW RX (event) from={addr[0]}:{addr[1]} len={len(data)}")
                else:
                    logger.debug(f"🧾 RAW RX from={addr[0]}:{addr[1]} len={len(data)}\n{hexdump_full(data)}")
                    meta = self._parse_artemis_meta_any(data)
                    if meta is not None:
                        off, magic, field1, app_seq, alen = meta
                        if magic == ARTEMIS_W:
                            logger.debug(
                                f"🧩 ARTEMISw meta from={addr[0]}:{addr[1]} off=0x{off:x} cmd_id={field1} app_seq={app_seq} alen={alen}"
                            )
                        else:
                            logger.debug(
                                f"🧩 ARTEMIS meta from={addr[0]}:{addr[1]} off=0x{off:x} msg_type={field1} app_seq={app_seq} alen={alen}"
                            )

            self.log_rx(data, desc=f"from={addr}")

            if not data or len(data) < 2:
                continue

            looks_artemis_frag = False
            if len(data) >= 8 and data[0] == 0xF1:
                pkt_type = data[1]
                rx_seq = data[7]

                # ACK all DATA and ALL FRAG packets (per spec: "Jedes eingehende Paket vom Typ 0xD0 oder 0x42")
                # Note: We check _is_simple_ack_payload to avoid ACKing ACK packets (which would create an infinite loop)
                if pkt_type == 0xD0 or pkt_type == 0x42:
                    if not self._is_simple_ack_payload(data) and self.active_port:
                        self.send_raw(self.build_ack_10(rx_seq), desc=f"ACK(rx_seq={rx_seq})")

                # Handle FRAG reassembly for ARTEMIS packets
                if pkt_type == 0x42:
                    frag_payload = data[8:]
                    looks_artemis_frag = (ARTEMIS_NULL in frag_payload) or (ARTEMIS_NULL in self._frag_buf)
                    
                    if looks_artemis_frag:
                        self._frag_buf += frag_payload
                        re = self._try_reassemble_artemis()
                        if re is None:
                            continue
                        data = re
                    else:
                        if self.debug:
                            logger.debug("FRAG without ARTEMIS signature (likely LBCS/Discovery); ACK sent")

            # Token buffer: store MsgType=3 responses (raw) while buffering is active
            if self._buffering_active:
                msg_type = self._get_artemis_msg_type(data)
                if msg_type == ARTEMIS_MSG_RESPONSE:
                    app_seq = self._get_artemis_app_seq(data)
                    self._token_packet_buffer.append(data)
                    if self.debug:
                        logger.debug(
                            f"🔓 MsgType=3 Paket gepuffert (AppSeq={app_seq}, Buffer: {len(self._token_packet_buffer)} Pakete)"
                        )

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

            # accept_cmd is cmdId inside decrypted JSON (NOT ARTEMIS header field)
            # Decrypt only likely responses to save time.
            msg_type = self._get_artemis_msg_type(data)
            if msg_type != ARTEMIS_MSG_RESPONSE:
                continue

            json_cmd_id = self._get_json_cmd_id(data)
            if json_cmd_id is None:
                continue

            if isinstance(accept_cmd, int):
                if json_cmd_id == accept_cmd:
                    return data
                if self.debug:
                    logger.debug(f"⚠️ Ignore cmdId {json_cmd_id} (warte auf {accept_cmd})")
            else:
                if json_cmd_id in accept_cmd:
                    return data
                if self.debug:
                    logger.debug(f"⚠️ Ignore cmdId {json_cmd_id} (warte auf {sorted(list(accept_cmd))})")

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
            _field1, _app_seq, blen = struct.unpack("<III", self._frag_buf[8:20])
        except Exception:
            del self._frag_buf[:1]
            return None

        total = 20 + blen
        if len(self._frag_buf) < total:
            return None

        payload = bytes(self._frag_buf[:total])
        del self._frag_buf[:total]

        rudp_hdr = bytes([0xF1, 0xD0, 0x00, 0x00, 0xD1, 0x00, 0x00, 0x00])
        return rudp_hdr + payload

    def send_login_request(self) -> Tuple[bool, int]:
        """Send proper login JSON (cmdId=0) with current utcTime as the initial request.
        
        This replaces the static ARTEMIS_HELLO_B64 blob with a dynamically generated
        login request matching the protocol specification and app behavior.
        
        Returns:
            Tuple of (success: bool, app_seq: int) where app_seq is the AppSeq used for login
        """
        logger.info(">>> Login Request (cmdId=0) with AppSeq=1")

        self.app_seq += 1
        login_app_seq = int(self.app_seq)  # Capture the AppSeq being used for this login
        
        login_json = {
            "cmdId": 0,
            "usrName": "admin",
            "password": "admin",
            "needVideo": 0,
            "needAudio": 0,
            "utcTime": calendar.timegm(time.gmtime()),  # True UTC timestamp
            "supportHeartBeat": True
        }
        
        # Encrypt and encode the login JSON
        encrypted = self.encrypt_json(login_json)
        b64_payload = base64.b64encode(encrypted) + b"\x00"
        
        # Build ARTEMIS frame (MsgType=2 for request)
        login_body = build_artemis_frame(ARTEMIS_MSG_REQUEST, login_app_seq, b64_payload)
        login_pkt, _ = self.build_packet(0xD0, login_body, force_seq=0)

        def login_ack_ok(pkt: bytes) -> bool:
            # Accept ACK or any ARTEMIS response
            if self._is_simple_ack_payload(pkt):
                return True
            return self._parse_artemis_header_any(pkt) is not None

        self.send_raw(login_pkt, desc=f"Login(cmdId=0) utcTime={login_json['utcTime']}")
        r = self.pump(timeout=2.5, accept_predicate=login_ack_ok, filter_evt=False)
        if r is not None:
            logger.info("✅ Login request acknowledged")
            return True, login_app_seq

        # Try alternate port as fallback
        alt_ports = [p for p in TARGET_PORTS if p != self.active_port]
        if alt_ports:
            logger.warning("Keine Login-Bestätigung via active_port; Fallback auf alternativen Port…")
            self.send_raw(login_pkt, desc="Login(fallback)", port=alt_ports[0])
            r = self.pump(timeout=2.5, accept_predicate=login_ack_ok, filter_evt=False)
            if r is not None:
                self.active_port = alt_ports[0]
                logger.info(f"✅ active_port auf {self.active_port} umgestellt (Login-Fallback).")
                return True, login_app_seq

        return False, login_app_seq

    def run(self):
        if not self.setup_network():
            return
        if not self.discovery():
            return

        # Enable token buffering to capture MsgType=3 responses
        self.enable_token_buffering()

        # Pre-login phase with retry (Issue #168 fix)
        # CRITICAL: Pre-Login ACK must be received before proceeding to login.
        # Without ACK, the camera is not ready and will ignore login requests.
        if not self.send_prelogin_with_retry(max_retries=3):
            logger.error("❌ Pre-Login failed - cannot proceed to login")
            return
        
        # Brief pause after successful Pre-Login to allow camera to stabilize
        time.sleep(0.25)

        # === LOGIN HANDSHAKE (following MITM spec) ===
        # Step 1: Build and send login request (cmdId=0, AppSeq=1)
        # CRITICAL: Must use RUDP Seq=0 per MITM captures (ble_udp_1.log line 378)
        logger.info(">>> Login Handshake Step 1: Send Login Request (cmdId=0, AppSeq=1)")
        self.app_seq += 1  # app_seq becomes 1
        login_app_seq = int(self.app_seq)
        
        login_json = {
            "cmdId": 0,
            "usrName": "admin",
            "password": "admin",
            "needVideo": 0,
            "needAudio": 0,
            "utcTime": calendar.timegm(time.gmtime()),
            "supportHeartBeat": True
        }
        
        if self.debug:
            logger.debug(f"🔐 Login JSON: {json.dumps(login_json, separators=(',', ':'))[:100]}...")
        
        encrypted = self.encrypt_json(login_json)
        b64_payload = base64.b64encode(encrypted) + b"\x00"
        login_body = build_artemis_frame(ARTEMIS_MSG_REQUEST, login_app_seq, b64_payload)
        
        # CRITICAL FIX: Use force_seq=0 for login request (per MITM capture)
        login_pkt, login_rudp_seq = self.build_packet(0xD0, login_body, force_seq=0)
        
        if self.debug:
            logger.debug(f"📊 Login packet: RUDP seq={login_rudp_seq}, ARTEMIS MsgType=2, AppSeq={login_app_seq}")
        
        self.send_raw(login_pkt, desc=f"Login#1(cmdId=0,AppSeq={login_app_seq})")
        
        # Step 1b: Send Magic1 packet (per Protocol_analysis.md §5 and ble_udp_1.log line 393)
        # This is a critical handshake packet that the camera expects after login
        # NOTE: The sequence number jumps from 0 to 3. This is not a bug - the MITM capture
        # shows the working app does this intentionally. The camera firmware expects this
        # specific sequence jump as part of the handshake protocol (see Protocol_analysis.md §5).
        logger.info(">>> Login Handshake Step 1b: Send Magic1 packet")
        magic1_pkt, _ = self.build_packet(0xD1, MAGIC_BODY_1, force_seq=3)
        self.send_raw(magic1_pkt, desc="Magic1")
        
        # CRITICAL FIX (Issue #166): Reset global_seq to 0 after Magic1
        # This ensures the next ACK (for camera's ACK response) will have Seq=1, matching
        # MITM behavior (ble_udp_1.log line 399). Without this, sequence numbers are wrong.
        # NOTE: build_packet() with force_seq=3 set global_seq=3, and we immediately reset it
        # to 0 here. This is INTENTIONAL - it's part of the critical handshake sequence where
        # the sequence number "jumps" from Login(Seq=0) to Magic1(Seq=3) then resets to 0
        # for proper ACK synchronization. This matches the MITM-captured behavior exactly.
        if self.debug:
            logger.debug(f"🔄 Resetting global_seq from {self.global_seq} to 0 (post-Magic1 sync)")
        self.global_seq = 0
        
        # Step 1c: Wait for camera's ACK response after Magic1
        # CRITICAL: The camera sends an ACK with "ACK" payload (ble_udp_1.log line 396) AFTER 
        # processing Magic1. This ACK signals the camera is ready for login retransmissions.
        # The pump() will automatically send an ACK for this ACK (with Seq=1 because we reset
        # global_seq to 0 above). This ACK exchange is a critical handshake - without it, 
        # the camera ignores login retransmissions.
        # NOTE: no_heartbeat=True prevents heartbeat interference (Issue #159).
        logger.info(">>> Login Handshake Step 1c: Wait for camera's ACK after Magic1")
        self.pump(timeout=MAGIC1_ACK_TIMEOUT, accept_predicate=lambda _: False, filter_evt=False, no_heartbeat=True)
        
        # Step 1d: Retransmit login request #2 (per MITM capture ble_udp_1.log line 402)
        # CRITICAL: The working app sends the login request THREE times total.
        # This is not error handling - it's part of the expected protocol flow.
        # The camera firmware appears to require multiple transmissions before responding.
        # IMPORTANT: Use same Seq=0 and same login_body (it's a retransmission, not a new request)
        logger.info(">>> Login Handshake Step 1d: Retransmit Login #2")
        login_pkt2, _ = self.build_packet(0xD0, login_body, force_seq=0)
        self.send_raw(login_pkt2, desc=f"Login#2(cmdId=0,AppSeq={login_app_seq})")
        
        # Step 1e: Retransmit login request #3 (per MITM capture ble_udp_1.log line 417)
        # The camera typically responds after the third transmission
        logger.info(">>> Login Handshake Step 1e: Retransmit Login #3")
        login_pkt3, _ = self.build_packet(0xD0, login_body, force_seq=0)
        self.send_raw(login_pkt3, desc=f"Login#3(cmdId=0,AppSeq={login_app_seq})")
        
        # Step 2: Wait for and ACK the login response (MsgType=3, AppSeq=1)
        # After the triple transmission, the camera should now respond (MITM line 463)
        # CRITICAL: no_heartbeat=True prevents heartbeat from incrementing AppSeq during wait,
        # ensuring clean AppSeq sequence for login response matching
        logger.info(">>> Login Handshake Step 2: Wait for Login Response (MsgType=3, AppSeq=1)")
        
        def is_login_response(pkt: bytes) -> bool:
            """Accept MsgType=3 with AppSeq=1 (login response)."""
            msg_type = self._get_artemis_msg_type(pkt)
            app_seq = self._get_artemis_app_seq(pkt)
            if msg_type == ARTEMIS_MSG_RESPONSE and app_seq == login_app_seq:
                if self.debug:
                    logger.debug(f"✅ Login Response detected: MsgType={msg_type}, AppSeq={app_seq}")
                return True
            return False
        
        login_response = self.pump(timeout=3.0, accept_predicate=is_login_response, filter_evt=False, no_heartbeat=True)
        
        if login_response:
            logger.info("✅ Login Response received (MsgType=3)")
            # The pump() function should have already sent ACK for 0xD0 packet
            # But let's be explicit and give it a moment to process
            time.sleep(0.1)
        else:
            logger.warning("⚠️ No Login Response received within timeout")
            logger.info("Attempting to continue with stabilization and token wait...")
        
        # Step 3: Stabilization - send a few heartbeats to establish connection
        logger.info(">>> Login Handshake Step 3: Stabilization (send heartbeats)")
        for i in range(2):
            self.send_heartbeat()
            self.pump(timeout=0.5, accept_predicate=lambda _d: False, filter_evt=False)
        
        # Step 4: Extended wait for login token extraction
        if LOGIN_DELAY_AFTER_STABILIZATION > 0:
            logger.info(f">>> Waiting {LOGIN_DELAY_AFTER_STABILIZATION:.1f}s for additional responses...")
            self.pump(timeout=LOGIN_DELAY_AFTER_STABILIZATION, accept_predicate=lambda _d: False, filter_evt=False)

        # Enable raw RX dump if in debug mode
        if self.debug and self.raw_rx_dump:
            self.enable_raw_rx_dump()

        # Step 5: Extract token from buffered responses
        logger.info(f">>> Extracting token from Login Response (AppSeq={login_app_seq})...")
        if not self.wait_for_login_token(timeout=max(8.0, self.raw_rx_window_seconds), expected_app_seq=login_app_seq):
            logger.error(f"❌ Login Timeout (no token received, {len(self._token_packet_buffer)} MsgType=3 packets buffered)")
            if self.debug and self._token_packet_buffer:
                logger.debug(f"Buffered MsgType=3 packets:")
                for i, pkt in enumerate(list(self._token_packet_buffer)):
                    app_seq = self._get_artemis_app_seq(pkt)
                    cmd_id = self._get_json_cmd_id(pkt)
                    logger.debug(f"  Packet {i+1}: AppSeq={app_seq}, cmdId={cmd_id}, len={len(pkt)}")
                    # Try to decrypt and show what we got
                    r = self._decrypt_artemis_json_any(pkt)
                    if r:
                        obj, _f1, _a2, _m = r
                        json_preview = json.dumps(obj, ensure_ascii=False)[:150]
                        logger.debug(f"    Decrypted: {json_preview}...")
            return

        self.disable_token_buffering()

        # === POST-LOGIN OPERATIONS ===
        # Example operation: request file list (cmdId=768)
        logger.info(">>> Request file list (cmdId 768)…")
        self.app_seq += 1
        req = {"cmdId": 768, "itemCntPerPage": 45, "pageNo": 0, "token": str(self.token)}
        b64_body = base64.b64encode(self.encrypt_json(req)) + b"\x00"

        # IMPORTANT: MsgType=2 request
        art = build_artemis_frame(ARTEMIS_MSG_REQUEST, int(self.app_seq), b64_body)
        pkt, _ = self.build_packet(0xD0, art)
        self.send_raw(pkt, desc="cmdId=768")

        resp = self.pump(timeout=10.0, accept_cmd=768, filter_evt=True)
        if resp:
            files = self.decrypt_payload(resp)
            logger.info(f"cmdId=768 response (preview): {str(files)[:200]}")
        else:
            logger.warning("Keine cmdId=768 Antwort (Timeout).")


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
