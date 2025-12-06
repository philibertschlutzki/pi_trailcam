import socket
import json
import time
import logging
import config

class CameraClient:
    def __init__(self):
        self.ip = config.CAM_IP
        self.port = config.CAM_PORT # Sollte 40611 sein
        self.sock = None

    def _get_header(self):
        """Erstellt den 79-Byte Binär-Header aus den tcpdumps."""
        # Magic Bytes (0xEF 0xAA 0x55 0xAA)
        header = b'\xef\xaa\x55\xaa'
        # 4 Bytes 0x00
        header += b'\x00\x00\x00\x00'
        # 4 Bytes Typ (0x01) - In den Logs war dies 00000001
        header += b'\x00\x00\x00\x01'
        # 67 Bytes Padding (Nullen), damit JSON bei Byte 79 startet
        header += b'\x00' * 67
        return header

    def send_command(self, cmd_dict):
        """Sendet JSON verpackt im Binär-Header per UDP."""
        try:
            # 1. Socket erstellen (UDP!)
            # UDP braucht kein .connect(), wir senden direkt
            if not self.sock:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.sock.settimeout(5)

            # 2. Payload bauen
            json_payload = json.dumps(cmd_dict, separators=(',', ':')).encode('utf-8')
            header = self._get_header()
            full_packet = header + json_payload

            logging.info(f"Sending UDP Packet ({len(full_packet)} bytes) to {self.ip}:{self.port}")
            # logging.debug(f"Payload: {full_packet.hex()}")

            # 3. Senden
            self.sock.sendto(full_packet, (self.ip, self.port))

            # 4. Auf Antwort warten
            try:
                data, addr = self.sock.recvfrom(4096)
                logging.info(f"Received UDP response from {addr}: {len(data)} bytes")
                
                # Wir müssen den Header in der Antwort vermutlich ignorieren
                # Suche nach dem Start des JSON '{'
                try:
                    json_start = data.index(b'{')
                    json_data = data[json_start:]
                    parsed = json.loads(json_data.decode('utf-8'))
                    logging.info(f"Parsed Response: {parsed}")
                    return parsed
                except ValueError:
                    logging.warning("Response contained no JSON part.")
                    return None
                    
            except socket.timeout:
                logging.warning("No response received (Timeout).")
                return None

        except Exception as e:
            logging.error(f"Error sending command: {e}")
            return None

    def login(self):
        """Führt den Handshake aus."""
        # Zeitstempel generieren
        current_time = int(time.time())
        
        # Der Login-Payload exakt aus Ihren Logs (cmdId: 0)
        login_payload = {
            "cmdId": 0,
            "usrName": "admin",
            "password": "admin",
            "needVideo": 0,
            "needAudio": 0,
            "utcTime": current_time,
            "supportHeartBeat": True
        }
        
        logging.info("Attempting UDP Login...")
        # Mehrfache Versuche, da UDP unzuverlässig sein kann (Paketverlust)
        for i in range(3):
            response = self.send_command(login_payload)
            if response and response.get("result") == 0:
                logging.info("Login Successful!")
                return True
            time.sleep(1)
            
        logging.error("Login Failed after retries.")
        return False

    def get_device_info(self):
        payload = {"cmdId": 512, "token": 0} 
        return self.send_command(payload)

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None
