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
import netifaces
from bleak import BleakScanner, BleakClient
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# --- CONFIG ---
TARGET_IP = "192.168.43.1"
TARGET_PORTS = [40611, 3333]
FIXED_LOCAL_PORT = 35281

DEFAULT_SSID = "KJK_E0FF"
DEFAULT_PASS = "85087127"
BLE_MAC = "C6:1E:0D:E0:32:E8"

# --- PAYLOADS ---
LBCS_PAYLOAD = bytes.fromhex("f14100144c42435300000000000000004343434a4a000000")

# ARTEMIS Hello (Session Start)
ARTEMIS_HELLO = bytes.fromhex(
    "f1d000c5d1000000415254454d495300"
    "0200000001000000ad0000004a385757"
    "755144506d59534c66752f675841472b"
    "557162427935354b5032694532355150"
    "4e6f667a6e3034302b4e493967377a65"
    "584c6b497058704330375358766f7372"
    "577363316d386d786e7136684d694b77"
    "6550624b4a5577765376715a62367330"
    "736c3173667a68326d7452736c56324e"
    "633674524b6f78472f516a2b70337947"
    "6c314343354152624a4a4b4742615863"
    "677137546e656b6e2b7974772b524c6c"
    "676f53414d4f633d00"
)

# Payload für 53-Byte Keep-Alive (aus traffic_port.log)
PAYLOAD_53 = bytes.fromhex("4d7a6c423336582f49566f385a7a49357247396a31773d3d00")

# Payload für 73-Byte Status-Request
PAYLOAD_73 = bytes.fromhex(
    "792b444462714d4e4e6e56354c446a7533786c45"
    "6853576c39706549356557623267686d72337756"
    "7945493d00"
)

# Crypto
PHASE2_KEY = b"a01bc23ed45fF56A"
PHASE2_STATIC_HEADER = bytes.fromhex("0ccb9a2b5f951eb669dfaa375a6bbe3e76202e13c9d1aa3631be74e5")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger("CamClient")

class BLEWorker:
    @staticmethod
    async def wake_camera(mac):
        logger.info(f"Suche BLE {mac}...")
        try:
            dev = await BleakScanner.find_device_by_address(mac, timeout=45.0)
            if not dev: 
                logger.warning("BLE Gerät nicht gefunden (vielleicht schon wach?).")
                return False
            async with BleakClient(dev, timeout=15.0) as client:
                await client.write_gatt_char("00000002-0000-1000-8000-00805f9b34fb", 
                                             bytearray([0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]), 
                                             response=True)
                logger.info("✅ BLE Wakeup gesendet.")
                return True
        except Exception as e:
            logger.error(f"BLE Error (Ignoriert): {e}")
            return False

class WiFiWorker:
    @staticmethod
    def connect(ssid, password):
        try:
            iw_out = subprocess.run(["iwgetid", "-r"], capture_output=True, text=True).stdout.strip()
            if iw_out == ssid:
                logger.info(f"WLAN bereits mit {ssid} verbunden.")
                return True
        except: pass
        
        logger.info("Verbinde WLAN...")
        subprocess.run(["sudo", "nmcli", "c", "delete", ssid], capture_output=True)
        subprocess.run(["sudo", "nmcli", "d", "wifi", "rescan"], capture_output=True)
        time.sleep(3)
        cmd = ["sudo", "nmcli", "d", "wifi", "connect", ssid, "password", password, "ifname", "wlan0"]
        res = subprocess.run(cmd, capture_output=True)
        if res.returncode == 0:
            logger.info("WLAN verbunden.")
            return True
        err_msg = res.stderr.decode('utf-8', errors='ignore').strip()
        logger.error(f"WLAN Fehler: {err_msg}")
        return False

class Session:
    def __init__(self):
        self.sock = None
        self.local_ip = None
        self.active_port = None
        self.running = True
        
        # RUDP State
        self.global_seq = 1 # Header-Sequenz
        self.cmd_cnt = 1    # Interner Body-Counter

    def setup_network(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((TARGET_IP, 1))
            self.local_ip = s.getsockname()[0]
            s.close()
        except:
            logger.error("❌ Netzwerk nicht bereit.")
            return False

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        try:
            self.sock.bind((self.local_ip, FIXED_LOCAL_PORT))
            logger.info(f"Socket gebunden an {self.local_ip}:{FIXED_LOCAL_PORT}")
        except:
            self.sock.bind((self.local_ip, 0))
            logger.info(f"Port belegt, nutze {self.sock.getsockname()[1]}")
        
        self.sock.settimeout(0.5) 
        return True

    def next_seq(self):
        s = self.global_seq
        self.global_seq = (self.global_seq + 1) % 255
        if self.global_seq == 0: self.global_seq = 1
        return s

    def build_packet(self, seq_to_use, is_status_req):
        # Erhöht internen Counter
        self.cmd_cnt = (self.cmd_cnt + 1) % 255
        
        pkt = bytearray()
        
        # Header (Länge berechnen)
        # 53 Byte Paket = Header Len 0x31 (49) + 4 = 53
        # 73 Byte Paket = Header Len 0x45 (69) + 4 = 73
        
        if is_status_req:
            # 73 Byte Paket (Status)
            pkt.extend(bytes.fromhex("f1d00045d10000")) 
        else:
            # 53 Byte Paket (Keep-Alive)
            pkt.extend(bytes.fromhex("f1d00031d10000"))
            
        pkt.append(seq_to_use) 
        
        # ARTEMIS Body
        pkt.extend(bytes.fromhex("415254454d495300")) 
        pkt.extend(bytes.fromhex("02000000"))         
        
        # Der magische Counter an Offset 20!
        pkt.append(self.cmd_cnt)
        
        if is_status_req:
            # Rest für 73-Byte Paket
            pkt.extend(bytes.fromhex("0000002d000000")) # Padding + Len 45
            pkt.extend(PAYLOAD_73)
        else:
            # Rest für 53-Byte Paket (Wichtig: "01" Byte nach Counter aus Log)
            pkt.extend(bytes.fromhex("00010019000000")) # Padding + Len 25
            pkt.extend(PAYLOAD_53)
            
        return pkt

    def build_ack(self, rx_seq):
        seq = self.next_seq()
        pkt = bytearray()
        pkt.extend(bytes.fromhex("f1d10008d10000"))
        pkt.append(seq)
        pkt.append(0x00)
        pkt.append(rx_seq)
        pkt.append(0x00)
        pkt.append(rx_seq)
        return pkt

    def discover(self):
        logger.info(f"Starte Discovery auf Ports {TARGET_PORTS}...")
        for attempt in range(3):
            for port in TARGET_PORTS:
                try: self.sock.sendto(LBCS_PAYLOAD, (TARGET_IP, port))
                except: pass
            
            start = time.time()
            while time.time() - start < 1.0:
                try:
                    data, addr = self.sock.recvfrom(4096)
                    if len(data) >= 4 and data[0] == 0xF1:
                        if data[1] == 0x42 or data[1] == 0xD0:
                            logger.info(f"✅ ANTWORT von {addr[0]}:{addr[1]}")
                            self.active_port = addr[1]
                            return True
                except: pass
        return False

    def login(self):
        if not self.active_port: return False
        
        payload = { "utcTime": int(time.time()), "nonce": os.urandom(8).hex() }
        json_str = json.dumps(payload, separators=(',', ':'))
        cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(json_str.encode('utf-8'), AES.block_size))
        
        pkt = struct.pack('>BBH', 0xF1, 0xF9, len(PHASE2_STATIC_HEADER + encrypted)) + \
              PHASE2_STATIC_HEADER + encrypted
        
        logger.info(f"Sende Login an {TARGET_IP}:{self.active_port}...")
        self.sock.sendto(pkt, (TARGET_IP, self.active_port))
        
        try:
            data, _ = self.sock.recvfrom(4096)
            if data:
                logger.info(f"✅ Login Antwort erhalten ({len(data)} bytes).")
                return True
        except:
            logger.warning("Keine Antwort, versuche trotzdem weiter...")
            return True
        return True

    def run(self):
        try:
            if self.setup_network():
                if self.discover():
                    if self.login():
                        
                        logger.info(">>> Sende ARTEMIS Hello...")
                        self.sock.sendto(ARTEMIS_HELLO, (TARGET_IP, self.active_port))
                        time.sleep(0.1)
                        
                        logger.info(">>> VERBINDUNG STABILISIERT (Dual RUDP Mode)...")
                        
                        last_send = 0
                        last_stats = time.time()
                        
                        # RUDP Variablen
                        pending_packet = None
                        pending_seq = 0
                        waiting_for_ack = False
                        last_tx_time = 0
                        retransmits = 0
                        
                        toggle_type = False # Wechselt zwischen 53 und 73 bytes
                        
                        rx_count = 0
                        tx_count = 0
                        
                        while self.running:
                            now = time.time()
                            
                            # --- 1. SENDEN (Stop-and-Wait ARQ) ---
                            if not waiting_for_ack:
                                # Senden alle 1.0s (schneller Takt)
                                if now - last_send > 1.0:
                                    pending_seq = self.next_seq()
                                    
                                    # Wechseln zwischen Keep-Alive (53) und Status (73)
                                    pending_packet = self.build_packet(pending_seq, toggle_type)
                                    toggle_type = not toggle_type
                                    
                                    try:
                                        self.sock.sendto(pending_packet, (TARGET_IP, self.active_port))
                                        tx_count += 1
                                        last_send = now
                                        last_tx_time = now
                                        waiting_for_ack = True
                                        retransmits = 0
                                    except OSError: break
                            
                            else:
                                # Warten auf ACK (Timeout 0.5s)
                                if now - last_tx_time > 0.5:
                                    if retransmits < 5:
                                        try:
                                            self.sock.sendto(pending_packet, (TARGET_IP, self.active_port))
                                            last_tx_time = now
                                            retransmits += 1
                                        except OSError: break
                                    else:
                                        waiting_for_ack = False # Give up

                            # --- 2. EMPFANGEN ---
                            try:
                                data, addr = self.sock.recvfrom(4096)
                                d_len = len(data)
                                
                                if d_len > 4 and data[0] == 0xF1:
                                    
                                    # DATEN von Kamera -> ACK senden
                                    if data[1] == 0xD0:
                                        rx_seq = data[7]
                                        ack_pkt = self.build_ack(rx_seq)
                                        self.sock.sendto(ack_pkt, (TARGET_IP, self.active_port))
                                        rx_count += 1
                                        
                                    # ACK von Kamera -> Pending löschen
                                    elif data[1] == 0xD1:
                                        if waiting_for_ack:
                                            # Payload ab Byte 8 prüfen
                                            if pending_seq in data[8:]:
                                                waiting_for_ack = False
                                                rx_count += 1
                                    
                            except socket.timeout:
                                pass
                            except OSError:
                                break
                            
                            # --- 3. STATUS ---
                            if now - last_stats > 5.0:
                                logger.info(f"♻️  Dual RUDP: TX: {tx_count} | RX: {rx_count} | Seq: {self.global_seq} | CmdCnt: {self.cmd_cnt}")
                                rx_count = 0
                                tx_count = 0
                                last_stats = now

                else:
                    logger.error("❌ Kamera nicht gefunden.")
        except KeyboardInterrupt:
            logger.info("Abbruch durch User.")
        finally:
            if self.sock: self.sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--wifi", action="store_true")
    parser.add_argument("--ble", action="store_true")
    args = parser.parse_args()

    if args.ble:
        asyncio.run(BLEWorker.wake_camera(BLE_MAC)) 
        logger.info("⏳ Warte 20s auf Kamera-WLAN (erzwungen)...")
        time.sleep(20) 
    
    if args.wifi:
        if not WiFiWorker.connect(DEFAULT_SSID, DEFAULT_PASS):
            sys.exit(1)

    Session().run()
