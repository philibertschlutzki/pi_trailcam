import socket
import time
import logging
import struct
import threading
import config

# Logging konfigurieren
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CameraClient:
    """
    Client für Kameras mit dem Artemis-Protokoll (Magic 0xD1).
    Header-Struktur (4 Bytes):
      Byte 0: 0xD1 (Magic)
      Byte 1: Packet Type (0x00=Cmd, 0x01=Data/Ack)
      Byte 2-3: Sequence Number (Big Endian)
    """

    def __init__(self):
        self.ip = config.CAM_IP
        self.port = 40611  # Port aus deinen Dumps (40611 ist korrekt)
        self.sock = None
        self.seq_num = 1
        self.running = False
        self.keep_alive_thread = None

    def connect(self):
        """Initialisiert den UDP Socket."""
        logger.info(f"Initialisiere UDP Socket zu {self.ip}:{self.port}...")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(3.0)
            self.seq_num = 1
            return True
        except Exception as e:
            logger.error(f"Fehler beim Erstellen des Sockets: {e}")
            self.sock = None
            return False

    def close(self):
        """Schließt die Verbindung."""
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        logger.info("Socket geschlossen.")

    def _get_header(self, pkt_type):
        """
        Erstellt den 4-Byte Header.
        Struct Format: >BBH (Big Endian: U8, U8, U16)
        """
        magic = 0xD1
        return struct.pack('>BBH', magic, pkt_type, self.seq_num)

    def send_packet(self, payload, pkt_type=0x00, wait_for_response=True):
        """Sendet ein Paket mit dem korrekten Header."""
        if not self.sock:
            logger.error("Kein Socket verbunden.")
            return None

        try:
            header = self._get_header(pkt_type)
            packet = header + payload
            
            # Log nur für Command-Pakete, um Spam bei Video zu vermeiden
            if pkt_type == 0x00:
                logger.debug(f"Sende CMD (Seq {self.seq_num}): {packet.hex()}")

            self.sock.sendto(packet, (self.ip, self.port))
            self.seq_num += 1

            if not wait_for_response:
                return True

            try:
                data, _ = self.sock.recvfrom(2048)
                # Validierung: Beginnt es mit 0xD1?
                if len(data) >= 4 and data[0] == 0xD1:
                    return data
                else:
                    logger.warning(f"Unbekannte Antwort: {data.hex()}")
                    return data
            except socket.timeout:
                logger.warning(f"Timeout beim Warten auf Antwort (Seq {self.seq_num-1})")
                return None

        except Exception as e:
            logger.error(f"Fehler beim Senden: {e}")
            return None

    def login(self):
        """
        Führt den Artemis-Handshake durch.
        KORREKTUR: Sendet 'ARTEMIS' + \x02 + Padding auf 53 Bytes.
        """
        logger.info("Sende Login-Handshake (ARTEMIS)...")
        
        # 1. Der String "ARTEMIS" + Null-Terminator
        magic_str = b'ARTEMIS\x00'
        
        # 2. Das kritische Byte 0x02 (aus dem Connect-Dump)
        # Dies fehlte im vorherigen Versuch und ist wahrscheinlich die Version.
        version_byte = b'\x02'
        
        # 3. Padding
        # Der Original-Dump hatte eine Länge von ca. 53 Bytes Payload.
        # Wir füllen den Rest mit Nullen auf, um sicherzugehen, dass die Kamera
        # das Paket nicht wegen Unterlänge verwirft.
        # 53 Bytes (Total) - 4 Bytes (Header) = 49 Bytes Payload
        # Wir haben bisher 8 (ARTEMIS\0) + 1 (0x02) = 9 Bytes.
        # Also fügen wir 40 Null-Bytes hinzu.
        padding = b'\x00' * 40
        
        payload = magic_str + version_byte + padding
        
        # Type 0x00 für Commands
        # Wir versuchen es 3 mal, da UDP unzuverlässig ist
        for attempt in range(3):
            logger.info(f"Login Versuch {attempt+1}...")
            response = self.send_packet(payload, pkt_type=0x00)
            
            if response:
                logger.info(f"Login Antwort erhalten: {response.hex()}")
                self.start_heartbeat()
                return True
            time.sleep(1)
        
        logger.error("Keine Antwort auf Login nach 3 Versuchen.")
        return False

    def start_heartbeat(self):
        """Sendet regelmäßig Pakete, damit die Kamera nicht einschläft."""
        self.running = True
        self.keep_alive_thread = threading.Thread(target=self._heartbeat_loop)
        self.keep_alive_thread.daemon = True
        self.keep_alive_thread.start()

    def _heartbeat_loop(self):
        """
        Simuliert die ACKs der App.
        Die App sendet oft Type 0x01 Pakete als Heartbeat/ACK.
        """
        logger.info("Starte Heartbeat-Loop...")
        while self.running:
            try:
                # Sende ein leeres Datenpaket oder einen Dummy-Payload
                # Type 0x01 (Data) wird oft als Keep-Alive akzeptiert
                dummy_payload = b'\x00\x00'
                self.send_packet(dummy_payload, pkt_type=0x01, wait_for_response=False)
                time.sleep(2) # Alle 2 Sekunden
            except Exception as e:
                logger.error(f"Heartbeat Fehler: {e}")
                break

    def start_stream(self):
        """
        Versuch, den Stream zu starten. 
        (Befehl geraten basierend auf ähnlichen Kameras, da spezifischer Dump fehlt)
        """
        logger.info("Versuche Stream-Start...")
        # Oft ist es ein Command (Type 0) mit Code 1 oder 2
        # Wir probieren einen generischen Start-Payload
        payload = b'\x01\x00\x00\x00' 
        self.send_packet(payload, pkt_type=0x00, wait_for_response=False)

    def get_device_info(self):
        logger.info("Get Device Info (Noch nicht implementiert für Artemis)")
        # Platzhalter
        pass

# --- Hauptprogramm zum Testen ---
if __name__ == "__main__":
    cam = CameraClient()
    if cam.connect():
        if cam.login():
            logger.info("Login erfolgreich! Warte auf Daten...")
            
            # Test: Versuche Stream zu starten
            cam.start_stream()
            
            # Lausche kurz auf eingehende Pakete (z.B. Video-Stream)
            try:
                for _ in range(10):
                    try:
                        data, addr = cam.sock.recvfrom(2048)
                        logger.info(f"RX Paket ({len(data)} bytes) Typ: {hex(data[1])} Seq: {data[2]:02x}{data[3]:02x}")
                    except socket.timeout:
                        pass
            except KeyboardInterrupt:
                pass
            
        cam.close()
