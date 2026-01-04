#!/usr/bin/env python3
"""
Wildkamera Thumbnail Downloader - consolidated v4.3

Konsolidiert Fixes aus get_thumbnails.py + get_thumbnail_perp.py:
- Phase2 Pre-Login (F9) ist implementiert (war in get_thumbnail_perp.py nur Placeholder).
- Login wartet auf Cmd 3 (Result) und extrahiert token.
- ACK: 10 Bytes (Header 8 + Payload 2) und ACK für DATA (D0) + FRAG (42).
- Minimaler FRAG-Reassembler für ARTEMIS Frames.
- Discovery setzt active_port zuverlässig.
"""

import socket
import struct
import time
import json
import logging
import sys
import argparse
import subprocess
import asyncio
import base64
import os

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

# Hello base64 blob (wie vorher)
ARTEMIS_HELLO_B64 = (
    b"J8WWuQDPmYSLfu/gXAG+UqbBy55KP2iE25QPNofzn040+NI9g7zeXLkIpXpC07SXvosr"
    b"Wsc1m8mxnq6hMiKwePbKJUwvSvqZb6s0sl1sfziRb4nrHS3IjLjRVw2lxAUfPMOkSEVk"
    b"sh4L234p6VLtbnd4iq+8YcQJdk05GSR0cM4="
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("CamClient")


def build_artemis_frame(cmd_id: int, app_seq: int, body: bytes) -> bytes:
    # ARTEMIS\x00 + cmd(u32le) + seq(u32le) + len(u32le) + body
    return b"ARTEMIS\x00" + struct.pack("<III", cmd_id, app_seq, len(body)) + body


ARTEMIS_HELLO_BODY = build_artemis_frame(2, 1, ARTEMIS_HELLO_B64 + b"\x00")


class BLEWorker:
    @staticmethod
    async def wake_camera(mac: str, scan_timeout: float = 20.0, connect_timeout: float = 10.0) -> bool:
        if not BLE_AVAILABLE:
            logger.error("BLE nicht verfügbar (bleak fehlt).")
            return False

        logger.info(f"Suche BLE {mac}...")
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
            subprocess.run(["sudo", "iwconfig", "wlan0", "power", "off"],
                           check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if subprocess.run(["iwgetid", "-r"], capture_output=True, text=True).stdout.strip() == ssid:
                logger.info(f"WLAN bereits mit {ssid} verbunden.")
                return True
        except Exception:
            pass

        logger.info("Verbinde WLAN...")
        subprocess.run(["sudo", "nmcli", "c", "delete", ssid], capture_output=True)
        subprocess.run(["sudo", "nmcli", "d", "wifi", "rescan"], capture_output=True)
        time.sleep(3)

        res = subprocess.run(
            ["sudo", "nmcli", "d", "wifi", "connect", ssid, "password", password, "ifname", "wlan0"],
            capture_output=True,
        )
        return res.returncode == 0


class Session:
    def __init__(self, debug=False):
        self.sock = None
        self.active_port = None

        self.global_seq = 0
        self.app_seq = 0

        self.debug = debug

        self.token = None
        self.last_heartbeat_time = 0.0
        self.heartbeat_cnt = 0

        self._frag_buf = bytearray()

    def dlog(self, msg):
        if self.debug:
            logger.debug(msg)

    def setup_network(self):
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
        self.sock.bind((local_ip, FIXED_LOCAL_PORT))
        self.sock.settimeout(0.15)
        logger.info(f"Socket: {local_ip}:{FIXED_LOCAL_PORT}")
        return True

    def discovery(self, timeout=2.0):
        logger.info("Discovery...")
        for p in TARGET_PORTS:
            self.sock.sendto(LBCS_PAYLOAD, (TARGET_IP, p))

        start = time.time()
        while time.time() - start < timeout:
            try:
                data, addr = self.sock.recvfrom(2048)
            except socket.timeout:
                continue

            if not data or len(data) < 8 or data[0] != 0xF1:
                continue
            if addr[0] != TARGET_IP:
                continue

            self.active_port = addr[1]
            logger.info(f"✅ Discovery OK, active_port={self.active_port}")
            return True

        logger.error("❌ Discovery failed (no reply on candidate ports)")
        return False

    def next_seq(self):
        self.global_seq = (self.global_seq + 1) % 255
        if self.global_seq == 0:
            self.global_seq = 1
        return self.global_seq

    def build_packet(self, packet_type, payload, force_seq=None):
        if force_seq is None:
            seq = self.next_seq()
        else:
            seq = force_seq
            self.global_seq = seq

        body_len = len(payload) + 4
        header = bytearray([0xF1, packet_type, (body_len >> 8) & 0xFF, body_len & 0xFF,
                            0xD1, 0x00, 0x00, seq])
        return bytes(header) + payload, seq

    def build_ack_10(self, rx_seq: int) -> bytes:
        # 10 bytes total: header(8) + payload(2)
        payload = bytes([0x00, rx_seq])
        body_len = 6
        header = bytes([0xF1, 0xD1, (body_len >> 8) & 0xFF, body_len & 0xFF,
                        0xD1, 0x00, 0x00, rx_seq])
        return header + payload

    def send_raw(self, pkt: bytes):
        if not self.active_port:
            return
        self.sock.sendto(pkt, (TARGET_IP, self.active_port))

    def encrypt_json(self, obj):
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        return AES.new(PHASE2_KEY, AES.MODE_ECB).encrypt(pad(raw, AES.block_size))

    def decrypt_payload(self, data: bytes):
        # expects: RUDP(8) + ARTEMIS(8+12) + b64...
        try:
            if len(data) < 28:
                return None
            b64_part = data[28:].split(b"\x00")[0]
            if len(b64_part) % 4 != 0:
                b64_part += b"=" * (4 - len(b64_part) % 4)
            raw = base64.b64decode(b64_part)
            dec = unpad(AES.new(PHASE2_KEY, AES.MODE_ECB).decrypt(raw), AES.block_size)
            return json.loads(dec.decode("utf-8"))
        except Exception:
            return None

    def get_cmd_id(self, data: bytes):
        # cmd located at offset 16 (RUDP(8)+ARTEMIS(8))
        if len(data) > 20 and b"ARTEMIS\x00" in data[8:24]:
            try:
                return struct.unpack("<I", data[16:20])[0]
            except Exception:
                return None
        return None

    def send_heartbeat(self):
        if time.time() - self.last_heartbeat_time < 2.0:
            return
        self.heartbeat_cnt = (self.heartbeat_cnt + 1) % 255
        body = bytearray(HEARTBEAT_BODY_START) + bytearray([self.heartbeat_cnt]) + bytearray(HEARTBEAT_PAYLOAD_END)
        pkt, _ = self.build_packet(0xD0, bytes(body))
        self.send_raw(pkt)
        self.last_heartbeat_time = time.time()
        self.dlog(f"💓 Heartbeat cnt={self.heartbeat_cnt}")

    def send_prelogin(self):
        logger.info(">>> Pre-Login...")
        payload = {"utcTime": int(time.time()), "nonce": os.urandom(8).hex()}
        enc = AES.new(PHASE2_KEY, AES.MODE_ECB).encrypt(
            pad(json.dumps(payload, separators=(",", ":")).encode("utf-8"), AES.block_size)
        )
        # NOTE: Dieses Prelogin-Format ist aus get_thumbnails.py übernommen.
        pkt = struct.pack(">BBH", 0xF1, 0xF9, len(PHASE2_STATIC_HEADER + enc)) + PHASE2_STATIC_HEADER + enc
        self.send_raw(pkt)

        # Nicht streng prüfen, nur „Traffic“ konsumieren
        self.wait_for_cmd(timeout=2.0, cmd_accept=None)

    def _try_reassemble_artemis(self) -> bytes | None:
        # Suche nach ARTEMIS Header im Buffer
        idx = self._frag_buf.find(b"ARTEMIS\x00")
        if idx < 0:
            # Buffer begrenzen
            if len(self._frag_buf) > 1024 * 1024:
                self._frag_buf.clear()
            return None

        # Vorlauf verwerfen
        if idx > 0:
            del self._frag_buf[:idx]

        # Mindestlänge: ARTEMIS(8) + 3*4 = 20
        if len(self._frag_buf) < 20:
            return None

        try:
            cmd_id, app_seq, blen = struct.unpack("<III", self._frag_buf[8:20])
        except Exception:
            # Off-bytes -> ein Byte schieben
            del self._frag_buf[:1]
            return None

        total = 20 + blen
        if len(self._frag_buf) < total:
            return None

        payload = bytes(self._frag_buf[:total])
        del self._frag_buf[:total]

        # zu einem "DATA"-Packet formen, damit decrypt_payload() mit Offsets passt
        rudp_hdr = bytes([0xF1, 0xD0, 0x00, 0x00, 0xD1, 0x00, 0x00, 0x00])
        return rudp_hdr + payload

    def wait_for_cmd(self, timeout=5.0, cmd_accept=None):
        """
        cmd_accept:
          - None: akzeptiert alles (nur IO pumpen)
          - int: akzeptiert genau dieses Cmd
          - set/list/tuple: akzeptiert eines davon
        """
        start = time.time()
        while time.time() - start < timeout:
            if self.active_port and self.global_seq > 1:
                self.send_heartbeat()

            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception:
                continue

            if not data or len(data) < 2:
                continue

            # RUDP?
            if len(data) >= 8 and data[0] == 0xF1:
                pkt_type = data[1]
                rx_seq = data[7]

                # ACK für DATA/FRAG (außer wenn selbst ACK Payload)
                if pkt_type in (0xD0, 0x42):
                    is_ack_payload = (len(data) >= 11 and data[8:11] == b"ACK")
                    if not is_ack_payload and self.active_port:
                        self.sock.sendto(self.build_ack_10(rx_seq), (TARGET_IP, self.active_port))

                # FRAG -> in Buffer und ggf. reassemblen
                if pkt_type == 0x42:
                    self._frag_buf += data[8:]
                    re = self._try_reassemble_artemis()
                    if re is not None:
                        data = re
                        pkt_type = 0xD0  # virtuell "DATA"
                    else:
                        continue

                # Cmd extrahieren und filtern
                cmd_id = self.get_cmd_id(data)

                # Noise/Event Cmd 9 ignorieren (wie in euren Scripts)
                if cmd_id == 9:
                    continue

                if cmd_accept is None:
                    return data

                if isinstance(cmd_accept, int):
                    if cmd_id == cmd_accept:
                        return data
                else:
                    if cmd_id in set(cmd_accept):
                        return data

            # Non-RUDP: ignorieren
        return None

    def run(self):
        if not self.setup_network():
            return
        if not self.discovery():
            return

        # Pre-Login ist für viele Geräte nötig
        self.send_prelogin()

        # Hello/Handshake möglichst nahe am funktionierenden Script:
        logger.info(">>> Handshake Step 1: Hello (force seq 0)")
        hello_pkt, _ = self.build_packet(0xD0, ARTEMIS_HELLO_BODY, force_seq=0)
        self.send_raw(hello_pkt)
        if not self.wait_for_cmd(timeout=2.0, cmd_accept=None):
            logger.error("❌ Hello nicht bestätigt/keine Antwort")
            return

        logger.info(">>> Handshake Step 2: Magic 1 (force seq 3)")
        m1, _ = self.build_packet(0xD1, MAGIC_BODY_1, force_seq=3)
        self.send_raw(m1)
        time.sleep(0.05)

        logger.info(">>> Handshake Step 3: Magic 2 (force seq 1)")
        m2, _ = self.build_packet(0xD1, MAGIC_BODY_2, force_seq=1)
        self.send_raw(m2)
        time.sleep(0.05)

        # Stabilisierung
        logger.info(">>> Stabilisierung...")
        for _ in range(2):
            self.send_heartbeat()
            self.wait_for_cmd(timeout=0.5, cmd_accept=None)

        # Login
        logger.info(">>> Login...")
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
        self.send_raw(pkt)

        # Wichtig: Login-Response ist Result Cmd 3 (nicht Cmd 0)
        resp_pkt = self.wait_for_cmd(timeout=8.0, cmd_accept=3)
        if not resp_pkt:
            logger.error("❌ Login Timeout")
            return

        resp = self.decrypt_payload(resp_pkt)
        if not resp or "token" not in resp:
            logger.error(f"❌ Login Antwort ungültig: {resp}")
            return

        self.token = resp["token"]
        logger.info(f"✅ LOGIN OK! Token: {self.token}")

        # Optional: Beispiel-Request (Cmd 768) - ggf. fragmentiert
        logger.info(">>> Request file list (Cmd 768)...")
        self.app_seq += 1
        req = {"cmdId": 768, "itemCntPerPage": 45, "pageNo": 0, "token": str(self.token)}
        b64_body = base64.b64encode(self.encrypt_json(req)) + b"\x00"
        art = build_artemis_frame(768, self.app_seq, b64_body)
        pkt, _ = self.build_packet(0xD0, art)
        self.send_raw(pkt)

        pkt = self.wait_for_cmd(timeout=10.0, cmd_accept=768)
        if pkt:
            files = self.decrypt_payload(pkt)
            logger.info(f"Cmd768 response (preview): {str(files)[:200]}")
        else:
            logger.warning("Keine Cmd768 Antwort (Timeout).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true", help="Debug logging")
    parser.add_argument("--ble", action="store_true", help="Weckt die Kamera per BLE (aktiviert Wi-Fi-Modul)")
    parser.add_argument("--ble-mac", default=BLE_MAC, help="BLE MAC-Adresse der Kamera")
    parser.add_argument("--ble-wait", type=int, default=20, help="Wartezeit nach BLE-Wakeup (Sekunden)")
    parser.add_argument("--wifi", action="store_true", help="Verbinde zum Kamera-WLAN via nmcli")
    args = parser.parse_args()

    if args.ble:
        asyncio.run(BLEWorker.wake_camera(args.ble_mac))
        time.sleep(max(0, args.ble_wait))

    if args.wifi:
        WiFiWorker.connect(DEFAULT_SSID, DEFAULT_PASS)

    Session(debug=args.debug).run()
