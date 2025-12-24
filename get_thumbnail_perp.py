#!/usr/bin/env python3
"""
TrailCam Media Downloader
==========================
Interactive tool to download thumbnails and full-resolution images from trail camera.

Features:
- Progressive thumbnail download (configurable batch size)
- Interactive file selection for full downloads
- Robust error handling with retry logic
- Detailed logging and progress indicators
- Smart heartbeat (only sends when idle)

Usage:
  sudo ./get_thumbnails.py                    # Basic usage
  sudo ./get_thumbnails.py --batch-size 20    # Larger batches
  sudo ./get_thumbnails.py --debug            # Verbose logging
  sudo ./get_thumbnails.py --ble --wifi       # Full automated startup
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
import os
import threading
import base64
from pathlib import Path
from bleak import BleakScanner, BleakClient
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# --- CONFIG ---
TARGET_IP = "192.168.43.1"
TARGET_PORTS = [40611, 3333]
FIXED_LOCAL_PORT = 35281

DEFAULT_SSID = "KJK_E0FF"
DEFAULT_PASS = "85087127"
BLE_MAC = "C6:1E:0D:E0:32:E8"

# Output directory for thumbnails
THUMBNAIL_DIR = "thumbnails"

# --- CRYPTO & CONSTANTS ---
PHASE2_KEY = b"a01bc23ed45fF56A"
PHASE2_STATIC_HEADER = bytes.fromhex("0ccb9a2b5f951eb669dfaa375a6bbe3e76202e13c9d1aa3631be74e5")
LBCS_PAYLOAD = bytes.fromhex("f14100144c42435300000000000000004343434a4a000000")

ARTEMIS_HELLO = bytes.fromhex(
    "415254454d4953000200000001000000ad0000004a385757"
    "755144506d59534c66752f675841472b557162427935354b"
    "50326945323551504e6f667a6e3034302b4e493967377a65"
    "584c6b497058704330375358766f7372577363316d386d78"
    "6e7136684d694b776550624b4a5577765376715a62367330"
    "736c3173667a68335335307070307475324b657769305069"
    "4463765871584d3268506c4e6c6847536933465541762b50"
    "647935682f7278382b477437375468452b726431446d453d00"
)

MAGIC_BODY_1 = bytes.fromhex("000000000000") 
MAGIC_BODY_2 = bytes.fromhex("0000")         
HEARTBEAT_PAYLOAD = bytes.fromhex("00000000")

logger = logging.getLogger("CamClient")

def setup_logging(debug_mode):
    log_fmt = '[%(asctime)s.%(msecs)03d] %(message)s'
    date_fmt = '%H:%M:%S'
    logging.basicConfig(
        level=logging.DEBUG if debug_mode else logging.INFO, 
        format=log_fmt, 
        datefmt=date_fmt
    )

def hex_dump_str(data):
    """Create hex dump string for debugging"""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f"{b:02x}" for b in chunk)
        text_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{i:08x}  {hex_part:<47}  {text_part}")
    return "\n".join(lines)

def analyze_packet(data):
    """Analyze packet type for logging"""
    if len(data) == 4 and data == b'\x00\x00\x00\x00': 
        return "HEARTBEAT"
    if len(data) < 8 or data[0] != 0xF1:
        if data == b'\xf1\xe0\x00\x00': 
            return "ERROR (0xE0) - Session/Auth Fail"
        if data == b'\xf1\xf0\x00\x00': 
            return "FATAL (0xF0) - State Error"
        return f"UNKNOWN ({len(data)} bytes)"
    
    p_type = data[1]
    rudp_seq = data[7]
    base = f"RUDP(Type={p_type:02X}, Seq={rudp_seq})"
    
    if p_type == 0xD1:
        if len(data) >= 12: 
            return f"{base} -> ACK(Seq {data[9]})"
        return f"{base} -> CONTROL"
    if p_type == 0xD0:
        if len(data) >= 11 and data[8:11] == b'ACK': 
            return f"{base} -> TEXT ACK"
        if len(data) > 24 and data[8:15] == b'ARTEMIS':
            try:
                cmd = struct.unpack('<I', data[16:20])[0]
                seq = struct.unpack('<I', data[20:24])[0]
                return f"{base} -> ARTEMIS(Cmd={cmd}, AppSeq={seq})"
            except: 
                pass
    return base

class WiFiWorker:
    """Handles WiFi connection via NetworkManager"""
    
    @staticmethod
    def connect(ssid, password):
        """Connect to camera WiFi hotspot"""
        try:
            # Check if already connected
            result = subprocess.run(
                ["iwgetid", "-r"], 
                capture_output=True, 
                text=True
            )
            if result.stdout.strip() == ssid: 
                logger.info(f"✅ Bereits mit {ssid} verbunden")
                return True
        except: 
            pass
        
        logger.info(f"Verbinde mit WiFi: {ssid}")
        
        # Delete old profile to avoid stale configs
        subprocess.run(
            ["sudo", "nmcli", "c", "delete", ssid], 
            capture_output=True
        )
        
        # Force rescan
        subprocess.run(
            ["sudo", "nmcli", "d", "wifi", "rescan"], 
            capture_output=True
        )
        time.sleep(3)
        
        # Connect
        res = subprocess.run(
            ["sudo", "nmcli", "d", "wifi", "connect", ssid, 
             "password", password, "ifname", "wlan0"], 
            capture_output=True
        )
        
        # Disable power management
        subprocess.run(
            ["sudo", "iwconfig", "wlan0", "power", "off"], 
            check=False
        )
        
        if res.returncode == 0:
            logger.info("✅ WiFi verbunden")
            return True
        else:
            logger.error(f"❌ WiFi Fehler: {res.stderr.decode()}")
            return False

class BLEWorker:
    """Handles BLE wakeup of camera"""
    
    @staticmethod
    async def wake_camera(mac):
        """Send BLE wakeup command to camera"""
        logger.info(f"Suche BLE Gerät {mac}...")
        try:
            dev = await BleakScanner.find_device_by_address(mac, timeout=20.0)
            if not dev: 
                logger.error("❌ BLE Gerät nicht gefunden")
                return False
            
            logger.info(f"✅ Gerät gefunden, verbinde...")
            async with BleakClient(dev, timeout=10.0) as client:
                # Send wakeup command
                await client.write_gatt_char(
                    "00000002-0000-1000-8000-00805f9b34fb", 
                    bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]), 
                    response=True
                )
                logger.info("✅ BLE Wakeup gesendet")
                return True
        except Exception as e:
            logger.error(f"❌ BLE Fehler: {e}")
            return False

class SmartHeartbeatThread(threading.Thread):
    """Background thread for keepalive packets - only sends when idle"""
    
    def __init__(self, session):
        super().__init__()
        self.session = session
        self.running = True
        self.daemon = True

    def run(self):
        while self.running:
            try:
                # Only send heartbeat if no activity for 2+ seconds
                idle_time = time.time() - self.session.last_activity
                
                if idle_time > 2.0:
                    self.session.sock.sendto(
                        HEARTBEAT_PAYLOAD, 
                        (TARGET_IP, self.session.active_port)
                    )
                    if self.session.debug:
                        logger.debug("💓 Heartbeat gesendet")
                
                time.sleep(1.0)
            except: 
                pass
    
    def stop(self): 
        self.running = False

class MediaFile:
    """Represents a media file on the camera"""
    
    def __init__(self, data):
        self.file_type = data.get("fileType", 0)
        self.dir_num = data.get("mediaDirNum", 0)
        self.media_num = data.get("mediaNum", 0)
        self.timestamp = data.get("timestamp", 0)
        self.file_size = data.get("fileSize", 0)
        
    def __repr__(self):
        return f"MediaFile(dir={self.dir_num}, num={self.media_num}, size={self.file_size})"
    
    def thumbnail_filename(self):
        """Generate thumbnail filename"""
        return f"thumb_{self.dir_num}_{self.media_num}.jpg"
    
    def full_filename(self):
        """Generate full-resolution filename"""
        return f"IMG_{self.dir_num}_{self.media_num}.jpg"

class Session:
    """Main protocol handler for camera communication"""
    
    def __init__(self, debug=False, batch_size=10):
        self.sock = None
        self.active_port = None
        self.global_seq = 0 
        self.app_seq = 1
        self.debug = debug
        self.batch_size = batch_size
        self.heartbeat_thread = None
        self.last_activity = time.time()  # Track last network activity

    def log_packet(self, direction, data, addr=None):
        """Log packet for debugging"""
        if not self.debug: 
            return
        # Skip heartbeat ACKs to reduce noise
        if len(data) > 2 and data[1] == 0x42: 
            return
        
        desc = analyze_packet(data)
        logger.debug(f"{direction} {desc} ({len(data)} bytes)")
        
        # Show hex dump for important packets
        if "ARTEMIS" in desc or "Login" in desc or "UNKNOWN" in desc:
             logger.debug("\n" + hex_dump_str(data))

    def setup_network(self):
        """Initialize UDP socket"""
        try:
            # Get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((TARGET_IP, 1))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Create and bind socket
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((local_ip, FIXED_LOCAL_PORT))
            self.sock.settimeout(1.0) 
            
            logger.info(f"✅ Socket: {local_ip}:{FIXED_LOCAL_PORT}")
            return True
        except Exception as e:
            logger.error(f"❌ Network Setup: {e}")
            return False

    def next_seq(self):
        """Get next sequence number (wraps at 255)"""
        self.global_seq = (self.global_seq + 1) % 256
        if self.global_seq == 0: 
            self.global_seq = 1
        return self.global_seq

    def encrypt_json(self, json_obj):
        """Encrypt JSON payload with AES-ECB"""
        json_str = json.dumps(json_obj, separators=(',', ':'))
        cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
        return cipher.encrypt(pad(json_str.encode('utf-8'), AES.block_size))

    def decrypt_bytes(self, encrypted_data):
        """Decrypt AES-ECB payload to JSON"""
        try:
            cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
            decrypted = unpad(cipher.decrypt(encrypted_data), AES.block_size)
            return json.loads(decrypted.decode('utf-8').rstrip('\x00'))
        except Exception as e:
            if self.debug:
                logger.debug(f"Decrypt failed: {e}")
            return None

    def build_packet(self, p_type, payload):
        """Build RUDP packet with sequence number"""
        seq = self.next_seq()
        bl = len(payload) + 4
        header = bytearray([
            0xF1, p_type, 
            (bl >> 8) & 0xFF, bl & 0xFF, 
            0xD1, 0x00, 0x00, seq
        ])
        return header + payload, seq

    def build_cmd_packet(self, encrypted_payload):
        """Build ARTEMIS command packet"""
        b64_payload = base64.b64encode(encrypted_payload)
        self.app_seq += 1
        
        wrapper_header = (
            b'ARTEMIS\x00' + 
            struct.pack('<III', 2, self.app_seq, len(b64_payload) + 1)
        )
        
        return wrapper_header + b64_payload + b'\x00'

    def build_batch_ack(self, seq_list):
        """Build batch ACK for multiple RUDP sequences"""
        count = len(seq_list)
        payload = bytearray([(count >> 8) & 0xFF, count & 0xFF])
        
        for s in seq_list: 
            payload.extend([(s >> 8) & 0xFF, s & 0xFF])
        
        bl = len(payload) + 4
        return bytearray([
            0xF1, 0xD1, 
            (bl >> 8) & 0xFF, bl & 0xFF, 
            0xD1, 0x04, 0x00, 0x00
        ]) + payload

    def send_raw(self, pkt):
        """Send raw packet to camera"""
        self.log_packet("📤 [TX]", pkt)
        self.sock.sendto(pkt, (TARGET_IP, self.active_port))
        self.last_activity = time.time()  # Mark activity

    def send_ack(self, seq):
        """Send single sequence ACK"""
        ack_pkt, _ = self.build_packet(0xD1, bytearray([0x00, seq, 0x00, seq]))
        self.send_raw(ack_pkt)

    def send_reliable(self, p_type, payload, label="Packet", retries=5):
        """Send packet with retry until ACK received"""
        self.last_activity = time.time()  # Mark activity
        
        pkt, seq = self.build_packet(p_type, payload)
        
        if isinstance(payload, bytes) and len(payload) > 8 and payload[0] == 0xF1:
            pkt = payload
            seq = pkt[7]

        logger.info(f"Sende {label} (Seq {seq})...")
        
        for attempt in range(retries): 
            self.send_raw(pkt)
            start_wait = time.time()
            
            while time.time() - start_wait < 0.4:
                try:
                    data, addr = self.sock.recvfrom(4096)
                    self.log_packet("📥 [RX]", data, addr)
                    self.last_activity = time.time()  # Mark activity
                    
                    if len(data) > 8 and data[0] == 0xF1:
                        # Protocol ACK
                        if data[1] == 0xD1:
                            if (len(data) >= 10 and data[9] == seq) or data[7] == seq: 
                                return True
                        # Text ACK
                        elif data[1] == 0xD0:
                            if len(data) >= 11 and data[8:11] == b'ACK': 
                                return True
                except socket.timeout: 
                    pass
                except Exception as e:
                    if self.debug:
                        logger.debug(f"Receive error: {e}")
        
        logger.warning(f"⚠️  Kein ACK für {label} (Seq {seq})")
        return False

    def wait_for_data(self, timeout=8.0):
        """Wait for data packet and return decrypted JSON"""
        self.last_activity = time.time()  # Mark activity
        start = time.time()
        
        while time.time() - start < timeout:
            try:
                data, addr = self.sock.recvfrom(4096)
                self.log_packet("📥 [RX]", data, addr)
                self.last_activity = time.time()  # Mark activity
                
                # Check for error packets first
                if len(data) == 4:
                    if data == b'\xf1\xe0\x00\x00':
                        logger.error("❌ Session/Auth Fehler von Kamera")
                        return None
                    elif data == b'\xf1\xf0\x00\x00':
                        logger.error("❌ Fatal State Error von Kamera")
                        return None
                
                if len(data) > 8 and data[0] == 0xF1 and data[1] == 0xD0:
                    payload = data[8:]
                    
                    # ❗ CRITICAL FIX: Ignore TEXT ACK packets (don't send ACK back!)
                    if len(payload) == 3 and payload == b'ACK':
                        continue  # This is just protocol noise
                    
                    # Send ACK for real data packets
                    rx_seq = data[7]
                    self.send_ack(rx_seq)

                    # Try to decrypt ARTEMIS payload
                    if b'ARTEMIS' in payload and len(payload) > 20:
                        b64_data = payload[20:].rstrip(b'\x00')
                        try:
                            res = self.decrypt_bytes(base64.b64decode(b64_data))
                            if res: 
                                return res
                        except: 
                            pass
                    
                    # Try direct base64 decode
                    try:
                        res = self.decrypt_bytes(base64.b64decode(payload.rstrip(b'\x00')))
                        if res: 
                            return res
                    except: 
                        pass
                        
            except socket.timeout: 
                pass
            except Exception as e:
                if self.debug:
                    logger.debug(f"Wait error: {e}")
        
        return None

    def receive_thumbnail(self, timeout=5.0):
        """
        Receive a single thumbnail via RUDP.
        Returns raw JPEG bytes or None if timeout.
        """
        self.last_activity = time.time()  # Mark activity
        received_chunks = {}
        batch_seqs = []
        last_batch_time = time.time()
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                self.sock.settimeout(1.0)
                data, addr = self.sock.recvfrom(4096)
                self.last_activity = time.time()  # Mark activity
                
                # Only log every 10th packet to reduce noise
                if self.debug and len(received_chunks) % 10 == 0:
                    self.log_packet("📥 [RX]", data, addr)

                if len(data) > 8 and data[0] == 0xF1 and data[1] == 0xD0:
                    # Bulk transfer packet
                    if data[4] == 0xD1:
                        seq_16 = (data[6] << 8) | data[7]
                        
                        if seq_16 not in received_chunks:
                            received_chunks[seq_16] = data[8:]
                            batch_seqs.append(seq_16)
                        
                        # Send batch ACK periodically
                        if len(batch_seqs) >= 15 or \
                           (time.time() - last_batch_time > 0.08 and len(batch_seqs) > 0):
                            self.send_raw(self.build_batch_ack(batch_seqs))
                            batch_seqs = []
                            last_batch_time = time.time()
                    
                    # Check for end marker (small packet)
                    if len(data) < 30:
                        time.sleep(0.05)  # Small delay to catch last packets
                        break
                        
            except socket.timeout:
                # Timeout is expected, check if we have data
                if received_chunks:
                    break
            except Exception as e:
                if self.debug:
                    logger.debug(f"Receive error: {e}")
                break
        
        # Send final ACK if pending
        if batch_seqs:
            self.send_raw(self.build_batch_ack(batch_seqs))
        
        if not received_chunks:
            return None
        
        # Reassemble thumbnail
        thumbnail_data = b''
        for seq in sorted(received_chunks.keys()):
            thumbnail_data += received_chunks[seq]
        
        return thumbnail_data

    def get_thumbnails_batch(self, media_files):
        """
        Request thumbnails for a batch of media files.
        Returns dict mapping MediaFile -> thumbnail bytes.
        """
        if not media_files:
            return {}
        
        logger.info(f"Fordere {len(media_files)} Thumbnails an...")
        
        # Build thumbnail request
        thumbnail_reqs = []
        for mf in media_files:
            thumbnail_reqs.append({
                "fileType": mf.file_type,
                "dirNum": mf.dir_num,
                "mediaNum": mf.media_num
            })
        
        req_json = {
            "cmdId": 772,  # ❗ CRITICAL: 772 for thumbnails, not 1285!
            "thumbnailReqs": thumbnail_reqs
        }
        
        enc = self.encrypt_json(req_json)
        payload = self.build_cmd_packet(enc)
        pkt, _ = self.build_packet(0xD0, payload)
        
        self.send_raw(pkt)
        
        # Wait for cmdRet confirmation
        resp = self.wait_for_data(timeout=5.0)
        if not resp or resp.get("cmdId") != 772:
            logger.error("❌ Thumbnail Request fehlgeschlagen")
            return {}
        
        if resp.get("cmdRet") != 0:
            logger.error(f"❌ Thumbnail cmdRet: {resp.get('cmdRet')}")
            return {}
        
        logger.info("✅ Request bestätigt, empfange Thumbnails...")
        
        # Receive thumbnails sequentially
        results = {}
        for idx, mf in enumerate(media_files):
            sys.stdout.write(f"\r  Empfange {idx+1}/{len(media_files)}...")
            sys.stdout.flush()
            
            thumb_data = self.receive_thumbnail(timeout=5.0)
            
            if thumb_data and len(thumb_data) > 100:  # Sanity check for JPEG
                results[mf] = thumb_data
            else:
                logger.warning(f"\n⚠️  Thumbnail {mf.dir_num}:{mf.media_num} nicht empfangen")
        
        print()  # Newline after progress
        return results

    def download_full_image(self, media_file):
        """Download full-resolution image"""
        logger.info(f"Lade Vollbild: {media_file.full_filename()}")
        
        req_json = {
            "cmdId": 1285,  # Full download uses 1285
            "downloadReqs": [{
                "fileType": media_file.file_type,
                "dirNum": media_file.dir_num,
                "mediaNum": media_file.media_num
            }]
        }
        
        enc = self.encrypt_json(req_json)
        payload = self.build_cmd_packet(enc)
        pkt, _ = self.build_packet(0xD0, payload)
        
        self.send_raw(pkt)
        
        # Receive large file
        received_chunks = {}
        batch_seqs = []
        last_batch_time = time.time()
        
        while True:
            try:
                self.sock.settimeout(3.0)
                data, addr = self.sock.recvfrom(4096)
                self.last_activity = time.time()  # Mark activity
                
                if self.debug and len(received_chunks) % 50 == 0:
                    self.log_packet("📥 [RX]", data, addr)

                if len(data) > 8 and data[0] == 0xF1 and data[1] == 0xD0:
                    if data[4] == 0xD1:  # Bulk transfer
                        seq_16 = (data[6] << 8) | data[7]
                        
                        if seq_16 not in received_chunks:
                            received_chunks[seq_16] = data[8:]
                            batch_seqs.append(seq_16)
                        
                        # Batch ACK
                        if len(batch_seqs) >= 20 or \
                           (time.time() - last_batch_time > 0.1 and len(batch_seqs) > 0):
                            self.send_raw(self.build_batch_ack(batch_seqs))
                            batch_seqs = []
                            last_batch_time = time.time()
                            
                            sys.stdout.write(f"\rChunks: {len(received_chunks)}")
                            sys.stdout.flush()
            except socket.timeout:
                break
            except KeyboardInterrupt:
                logger.warning("\n⚠️  Download abgebrochen")
                return None
        
        print()  # Newline
        
        if not received_chunks:
            logger.error("❌ Kein Download empfangen")
            return None
        
        # Reassemble file
        full_data = b''
        for seq in sorted(received_chunks.keys()):
            full_data += received_chunks[seq]
        
        # Save to disk
        filename = media_file.full_filename()
        with open(filename, "wb") as f:
            f.write(full_data)
        
        logger.info(f"✅ Gespeichert: {filename} ({len(full_data)} bytes)")
        return filename

    def get_media_list(self, page=0, per_page=100):
        """Get list of media files from camera"""
        logger.info(f"Hole Medienliste (Seite {page}, {per_page} pro Seite)...")
        
        enc_list = self.encrypt_json({
            "cmdId": 768,
            "itemCntPerPage": per_page,
            "pageNo": page
        })
        payload = self.build_cmd_packet(enc_list)
        
        if self.send_reliable(0xD0, payload, "GetMediaList"):
            logger.info("Warte auf Dateiliste...")
            resp = self.wait_for_data(timeout=10.0)
            
            if resp and "mediaFiles" in resp:
                files = [MediaFile(f) for f in resp["mediaFiles"]]
                total = resp.get("totalItemCnt", len(files))
                logger.info(f"✅ {len(files)}/{total} Dateien geladen")
                return files
            else:
                logger.error("❌ Keine Dateiliste empfangen")
        
        return []

    def run_interactive(self):
        """Main interactive workflow"""
        # 1. Network setup
        if not self.setup_network():
            return
        
        # 2. Discovery
        logger.info("Starte Discovery...")
        for p in TARGET_PORTS:
            self.sock.sendto(LBCS_PAYLOAD, (TARGET_IP, p))
        
        start = time.time()
        while time.time() - start < 1.5:
            try:
                data, addr = self.sock.recvfrom(1024)
                if len(data) > 4 and data[0] == 0xF1:
                    self.active_port = addr[1]
                    logger.info(f"✅ Target Port: {self.active_port}")
                    break
            except:
                pass
        
        if not self.active_port:
            logger.error("❌ Discovery fehlgeschlagen")
            return

        # 3. Login (WITHOUT heartbeat yet!)
        logger.info("Login...")
        enc_login = self.encrypt_json({
            "utcTime": int(time.time()),
            "nonce": os.urandom(8).hex()
        })
        full_login = PHASE2_STATIC_HEADER + enc_login
        
        if not self.send_reliable(0xF9, full_login, "Login"):
            logger.warning("⚠️  Kein Login-ACK, versuche weiter...")
        
        time.sleep(0.5)

        # 4. Handshake
        logger.info("Handshake...")
        self.send_reliable(0xD0, ARTEMIS_HELLO, "Hello")
        self.send_reliable(0xD0, MAGIC_BODY_1, "Magic1")
        time.sleep(0.05)
        self.send_reliable(0xD0, MAGIC_BODY_2, "Magic2")
        time.sleep(0.5)
        
        # 5. NOW start SMART heartbeat (after handshake complete!)
        logger.info("Starte Smart Heartbeat...")
        self.heartbeat_thread = SmartHeartbeatThread(self)
        self.heartbeat_thread.start()

        # 6. Get media list
        all_files = self.get_media_list()
        if not all_files:
            logger.error("❌ Keine Dateien gefunden")
            if self.heartbeat_thread:
                self.heartbeat_thread.stop()
            return
        
        # 7. Create thumbnail directory
        Path(THUMBNAIL_DIR).mkdir(exist_ok=True)
        
        # 8. Progressive thumbnail download
        logger.info(f"\n{'='*60}")
        logger.info("THUMBNAIL DOWNLOAD")
        logger.info(f"{'='*60}")
        
        downloaded_thumbs = {}
        total_files = len(all_files)
        processed = 0
        
        while processed < total_files:
            batch = all_files[processed:processed + self.batch_size]
            logger.info(f"\n[Batch {processed//self.batch_size + 1}] "
                       f"Dateien {processed+1}-{min(processed+len(batch), total_files)} "
                       f"von {total_files}")
            
            batch_results = self.get_thumbnails_batch(batch)
            
            if not batch_results:
                logger.warning("⚠️  Batch fehlgeschlagen, breche ab")
                break
            
            # Save thumbnails
            for mf, thumb_data in batch_results.items():
                filename = os.path.join(THUMBNAIL_DIR, mf.thumbnail_filename())
                with open(filename, "wb") as f:
                    f.write(thumb_data)
                downloaded_thumbs[mf] = filename
            
            logger.info(f"  → {len(batch_results)}/{len(batch)} erfolgreich")
            processed += len(batch)
            
            # Small delay between batches
            time.sleep(0.2)
        
        if not downloaded_thumbs:
            logger.error("❌ Keine Thumbnails heruntergeladen")
            if self.heartbeat_thread:
                self.heartbeat_thread.stop()
            return
        
        logger.info(f"\n✅ {len(downloaded_thumbs)} Thumbnails in '{THUMBNAIL_DIR}/' gespeichert")
        
        # 9. Interactive full download selection
        logger.info(f"\n{'='*60}")
        logger.info("VOLLBILD DOWNLOAD")
        logger.info(f"{'='*60}")
        
        print("\nVerfügbare Dateien:")
        file_list = list(downloaded_thumbs.keys())
        for idx, mf in enumerate(file_list, 1):
            thumb_path = downloaded_thumbs[mf]
            print(f"  [{idx:2d}] {mf.thumbnail_filename()} "
                  f"(Dir: {mf.dir_num}, Media: {mf.media_num})")
        
        print("\nEingabe-Optionen:")
        print("  - Einzelne Nummern:  1,3,5")
        print("  - Bereiche:          1-10")
        print("  - Alle:              all")
        print("  - Abbruch:           q oder Enter\n")
        
        try:
            selection = input("Auswahl: ").strip()
        except (KeyboardInterrupt, EOFError):
            selection = "q"
        
        if not selection or selection.lower() == 'q':
            logger.info("Abbruch durch Benutzer")
            if self.heartbeat_thread:
                self.heartbeat_thread.stop()
            return
        
        # Parse selection
        selected_files = []
        
        if selection.lower() == 'all':
            selected_files = file_list
        else:
            parts = selection.split(',')
            for part in parts:
                part = part.strip()
                if '-' in part:
                    # Range
                    try:
                        start, end = map(int, part.split('-'))
                        for i in range(start, end + 1):
                            if 1 <= i <= len(file_list):
                                selected_files.append(file_list[i-1])
                    except:
                        logger.warning(f"⚠️  Ungültiger Bereich: {part}")
                else:
                    # Single number
                    try:
                        idx = int(part)
                        if 1 <= idx <= len(file_list):
                            selected_files.append(file_list[idx-1])
                    except:
                        logger.warning(f"⚠️  Ungültige Nummer: {part}")
        
        if not selected_files:
            logger.info("Keine Dateien ausgewählt")
            if self.heartbeat_thread:
                self.heartbeat_thread.stop()
            return
        
        # Download selected files
        logger.info(f"\nLade {len(selected_files)} Vollbilder herunter...")
        
        for idx, mf in enumerate(selected_files, 1):
            logger.info(f"\n[{idx}/{len(selected_files)}] {mf.full_filename()}")
            self.download_full_image(mf)
            time.sleep(0.3)  # Small delay between downloads
        
        logger.info(f"\n{'='*60}")
        logger.info("✅ FERTIG!")
        logger.info(f"{'='*60}")
        
        # Cleanup
        if self.heartbeat_thread:
            self.heartbeat_thread.stop()
        time.sleep(0.5)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="TrailCam Media Downloader - Interactive thumbnail and full image download"
    )
    parser.add_argument(
        "--wifi", 
        action="store_true", 
        help="Connect to camera WiFi before starting"
    )
    parser.add_argument(
        "--ble", 
        action="store_true", 
        help="Send BLE wakeup before WiFi connection"
    )
    parser.add_argument(
        "--debug", 
        action="store_true", 
        help="Enable verbose packet logging"
    )
    parser.add_argument(
        "--batch-size", 
        type=int, 
        default=10, 
        help="Number of thumbnails to request per batch (default: 10)"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.debug)
    
    # Root check
    if os.geteuid() != 0:
        logger.warning("⚠️  Bitte als root starten für BLE/WiFi Zugriff!")
    
    # BLE wakeup
    if args.ble:
        logger.info("BLE Wakeup...")
        success = asyncio.run(BLEWorker.wake_camera(BLE_MAC))
        if success:
            logger.info("Warte 15s auf WiFi Aktivierung...")
            time.sleep(15)
        else:
            logger.error("BLE Wakeup fehlgeschlagen, versuche trotzdem fortzufahren...")
    
    # WiFi connection
    if args.wifi:
        if not WiFiWorker.connect(DEFAULT_SSID, DEFAULT_PASS):
            logger.error("WiFi Verbindung fehlgeschlagen")
            sys.exit(1)
    
    # Run interactive session
    try:
        session = Session(debug=args.debug, batch_size=args.batch_size)
        session.run_interactive()
    except KeyboardInterrupt:
        logger.info("\n⚠️  Abbruch durch Benutzer")
    except Exception as e:
        logger.error(f"\n❌ Fehler: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
