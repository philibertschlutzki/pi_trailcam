import socket
import struct
import time
import json
import base64
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# --- KONFIGURATION ---
CAMERA_IP = "192.168.43.1"
CAMERA_PORT = 40611
LOCAL_PORT = 5085

# --- DER GEFUNDENE SCHLÜSSEL ---
# Aus AESTool.java: "a01bc23ed45fF56A"
AES_KEY = b"a01bc23ed45fF56A"

class TrailCamController:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Binde an den Port, den die App auch nutzt (wichtig für Firewall/NAT)
        self.sock.bind(('', LOCAL_PORT))
        self.sock.settimeout(2.0)
        self.seq_num = 1
        self.running = True

    def encrypt_payload(self, json_data):
        """Verschlüsselt JSON mit AES-ECB (gemäß JADX Analyse)"""
        # 1. JSON String (Minified)
        json_str = json.dumps(json_data).replace(" ", "")
        
        # 2. AES-ECB Verschlüsselung
        # AESTool.java nutzt "Cipher.getInstance("AES")" -> Java Default ist ECB!
        cipher = AES.new(AES_KEY, AES.MODE_ECB)
        encrypted_bytes = cipher.encrypt(pad(json_str.encode('utf-8'), AES.block_size))
        
        # 3. Base64 Encode
        b64_str = base64.b64encode(encrypted_bytes).decode('utf-8')
        
        # 4. ARTEMIS Wrapper bauen
        wrapper = bytearray()
        wrapper.extend(b'ARTEMIS\x00')
        wrapper.extend(struct.pack('<I', 2))  # Padding (aus Dump)
        wrapper.extend(struct.pack('<I', len(b64_str))) # Länge
        wrapper.extend(struct.pack('<I', 45)) # Cmd ID (45 = Encrypted Login/Data)
        wrapper.extend(b64_str.encode('utf-8'))
        wrapper.extend(b'\x00')
        
        return wrapper

    def build_packet(self, cmd_byte, payload):
        """Baut den UDP Header (F1 D0...)"""
        pkt = bytearray()
        pkt.append(0xF1)     # Start
        pkt.append(cmd_byte) # Command
        pkt.extend(struct.pack('>H', len(payload))) # Länge (Big Endian)
        pkt.extend(b'\xD1\x00')                     # Magic
        pkt.extend(struct.pack('>H', self.seq_num)) # Sequenz (Big Endian)
        pkt.extend(payload)
        
        self.seq_num += 1
        return pkt

    def send_json_command(self, cmd_data):
        # Zeige CmdID an, falls vorhanden
        cid = cmd_data.get('cmdId', '?')
        print(f"[TX] Sende Cmd: {cid}")
        
        payload = self.encrypt_payload(cmd_data)
        packet = self.build_packet(0xD0, payload) # 0xD0 = Data Command
        self.sock.sendto(packet, (CAMERA_IP, CAMERA_PORT))

    def listen(self):
        print("[*] Listener gestartet...")
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                hex_str = data.hex()
                
                # Check Header Start Byte
                if hex_str.startswith("f1"):
                    cmd = data[1]
                    if cmd == 0xD1:
                        # ACK Paket (F1 D1...)
                        seq = data[6:8].hex()
                        print(f"\n[RX] ACK erhalten! (Seq: {seq})")
                    elif cmd == 0xD0:
                        # Datenpaket von der Kamera! Versuchen wir zu entschlüsseln
                        self.try_decrypt_response(data)
                    else:
                        print(f"[RX] OpCode {hex(cmd)} (Länge: {len(data)})")
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[!] Fehler im Listener: {e}")

    def try_decrypt_response(self, data):
        try:
            # Header überspringen (F1 D0 Len Len Mag Mag Seq Seq) = 8 Bytes
            raw = data[8:]
            
            # Suche nach dem ARTEMIS Header
            if b'ARTEMIS' in raw:
                # ARTEMIS\0 (8) + Pad(4) + Len(4) + ID(4) = 20 Bytes Header nach "ARTEMIS" Start
                start_idx = raw.find(b'ARTEMIS')
                payload_start = start_idx + 20 
                
                # Der Rest bis zum Null-Byte ist Base64
                # Wir nehmen einfach alles bis zum Ende, minus evtl. Null-Terminator
                b64_data = raw[payload_start:].split(b'\x00')[0]
                
                if not b64_data:
                    return

                encrypted_bytes = base64.b64decode(b64_data)
                
                # Entschlüsseln mit AES-ECB
                cipher = AES.new(AES_KEY, AES.MODE_ECB)
                decrypted = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)
                
                print(f"✅ [DECRYPTED]: {decrypted.decode('utf-8')}")
        except Exception as e:
            print(f"⚠️ Decrypt Fehler: {e}")

    def run(self):
        # 1. Wake Up (Stack wecken)
        print("--- PHASE 1: WAKE UP ---")
        self.sock.sendto(bytes.fromhex("f1e00000"), (CAMERA_IP, CAMERA_PORT))
        time.sleep(0.1)
        self.sock.sendto(bytes.fromhex("f1e10000"), (CAMERA_IP, CAMERA_PORT))
        time.sleep(0.5)

        # 2. Login
        print("--- PHASE 2: LOGIN ---")
        login_cmd = {
            "cmdId": 0,
            "usrName": "admin",
            "password": "admin",
            "needVideo": 0,
            "needAudio": 0,
            "utcTime": int(time.time()),
            "supportHeartBeat": True
        }
        self.send_json_command(login_cmd)
        time.sleep(1)

        # 3. Status abfragen (cmd 512 aus deinem Log)
        print("--- PHASE 3: STATUS ---")
        self.send_json_command({"cmdId": 512})

        # 4. Heartbeat Loop
        print("--- PHASE 4: HEARTBEAT ---")
        try:
            while True:
                time.sleep(3)
                self.send_json_command({"cmdId": 525})
        except KeyboardInterrupt:
            print("\n[*] Stoppe...")
            self.running = False

if __name__ == "__main__":
    ctl = TrailCamController()
    
    # Listener Thread starten
    t = threading.Thread(target=ctl.listen)
    t.start()
    
    # Hauptlogik starten
    ctl.run()
