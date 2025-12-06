import socket
import time
import logging
import struct
import threading
import config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CameraClient:
    """
    Client für Kameras mit dem Artemis-Protokoll (Wrapped F1... / D1...).
    Outer Header (4 Bytes): [F1] [Type] [Len_H] [Len_L]
    Inner Header (4 Bytes): [D1] [Type] [Seq_H] [Seq_L]
    """

    def __init__(self):
        self.ip = config.CAM_IP
        self.port = 40611
        self.sock = None
        self.seq_num = 1
        self.running = False
        self.keep_alive_thread = None

    def connect(self):
        logger.info(f"Initialisiere UDP Socket zu {self.ip}:{self.port}...")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(5.0)
            self.seq_num = 1
            return True
        except Exception as e:
            logger.error(f"Fehler beim Erstellen des Sockets: {e}")
            return False

    def close(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        logger.info("Socket geschlossen.")

    def _get_inner_header(self, pkt_type):
        """Erstellt den inneren D1 Header."""
        magic = 0xD1
        return struct.pack('>BBH', magic, pkt_type, self.seq_num)

    def _get_outer_header(self, inner_packet, outer_type):
        """
        Erstellt den äußeren F1 Header.
        Länge ist die Länge des gesamten inneren Pakets (Header + Payload).
        """
        magic = 0xF1
        length = len(inner_packet)
        return struct.pack('>BBH', magic, outer_type, length)

    def send_packet(self, payload, inner_type=0x00, outer_type=0xD1, wait_for_response=True):
        if not self.sock:
            return None

        try:
            # 1. Inneres Paket bauen (D1...)
            inner_header = self._get_inner_header(inner_type)
            inner_packet = inner_header + payload

            # 2. Äußeres Paket bauen (F1...)
            outer_header = self._get_outer_header(inner_packet, outer_type)
            final_packet = outer_header + inner_packet

            logger.debug(f"TX (Seq {self.seq_num}): {final_packet.hex()}")
            self.sock.sendto(final_packet, (self.ip, self.port))
            self.seq_num += 1

            if not wait_for_response:
                return True

            try:
                data, _ = self.sock.recvfrom(2048)
                logger.debug(f"RX: {data.hex()}")
                return data
            except socket.timeout:
                logger.warning(f"Timeout (Seq {self.seq_num-1})")
                return None

        except Exception as e:
            logger.error(f"Send Error: {e}")
            return None

    def _build_login_payload(self, token_variant):
        """
        Erstellt Login-Payload nach verschiedenen Hypothesen.
        
        Smartphone-Dump (FUNKTIONIEREND):
          d100 0005 4152 5445 4d49 5300 0200 0000
          2b00 0000 2d00 0000 1900 0000 4933 6d62...
          = ARTEMIS\0 + 02 00 00 00 + 2b 00 00 00 + 2d 00 00 00 + 19 00 00 00 + Token
        
        Raspberry-Dump (FEHLGESCHLAGEN):
          d100 0001 4152 5445 4d49 5300 0200 0000
          0200 0100 1900 0000 4d7a 6c42...
          = ARTEMIS\0 + 02 00 00 00 + 02 00 01 00 + 19 00 00 00 + Token
        """
        
        # Konstante Teile
        artemis = b'ARTEMIS\x00'
        flags_1 = b'\x02\x00\x00\x00'  # Erste 4 Bytes nach ARTEMIS (immer gleich)
        token_len_field = b'\x19\x00\x00\x00'  # Längenfeld für Token (0x19 = 25)
        token_short = b'MzlB36X/IVo8ZzI5rG9j1w==\x00'  # 25 Zeichen + \0
        
        if token_variant == 'original':
            # ORIGINAL (aktueller, fehlgeschlagener Code)
            # Nach Flags_1: 02 00 01 00 (FALSCH?)
            mystery_bytes = b'\x02\x00\x01\x00'
            logger.info("[VARIANT: ORIGINAL] Nutze bytes: 02 00 01 00")
            return artemis + flags_1 + mystery_bytes + token_len_field + token_short
        
        elif token_variant == 'smartphone_dump':
            # SMARTPHONE-DUMP (aus tcpdump extrahiert)
            # Nach Flags_1: 2b 00 00 00 2d 00 00 00 (KORREKT?)
            mystery_bytes = b'\x2b\x00\x00\x00\x2d\x00\x00\x00'
            logger.info("[VARIANT: SMARTPHONE_DUMP] Nutze bytes: 2b 00 00 00 2d 00 00 00")
            return artemis + flags_1 + mystery_bytes + token_len_field + token_short
        
        elif token_variant == 'mystery_2b_only':
            # HYPOTHESE: Nur 2b ist relevant, 2d ist Token-Länge?
            # 02 00 00 00 + 2b 00 00 00 + 19 00 00 00 (ohne 2d)
            mystery_bytes = b'\x2b\x00\x00\x00'
            logger.info("[VARIANT: MYSTERY_2B_ONLY] Nutze bytes: 2b 00 00 00")
            return artemis + flags_1 + mystery_bytes + token_len_field + token_short
        
        elif token_variant == 'mystery_2d_only':
            # HYPOTHESE: Nur 2d ist relevant?
            mystery_bytes = b'\x2d\x00\x00\x00'
            logger.info("[VARIANT: MYSTERY_2D_ONLY] Nutze bytes: 2d 00 00 00")
            return artemis + flags_1 + mystery_bytes + token_len_field + token_short
        
        elif token_variant == 'no_mystery':
            # HYPOTHESE: Keine Mystery-Bytes, direkt Länge?
            logger.info("[VARIANT: NO_MYSTERY] Keine Mystery-Bytes, direkt Längenfeld")
            return artemis + flags_1 + token_len_field + token_short
        
        elif token_variant == 'sequence_variant':
            # HYPOTHESE: Mystery-Bytes sind Sequenznummern
            # Ändert sich bei jedem Versuch: 03, 04, 05, 06
            # Mapping zu Little-Endian oder Big-Endian?
            mystery_bytes = b'\x03\x00\x00\x00\x04\x00\x00\x00'  # Seq 3, 4
            logger.info("[VARIANT: SEQUENCE_VARIANT] Nutze bytes als Seq: 03 00 00 00 04 00 00 00")
            return artemis + flags_1 + mystery_bytes + token_len_field + token_short
        
        else:
            logger.error(f"Unbekante Variante: {token_variant}")
            return None

    def login(self):
        logger.info("\n" + "="*70)
        logger.info("STARTE SYSTEMATISCHEN LOGIN-TEST")
        logger.info("="*70)
        
        # Test-Varianten in Reihenfolge
        variants = [
            'smartphone_dump',     # WAHRSCHEINLICHSTE: Bytes aus funktionierendem Dump
            'original',            # FALLBACK: Aktueller, fehlgeschlagener Code
            'mystery_2b_only',     # Alternative 1
            'mystery_2d_only',     # Alternative 2
            'no_mystery',          # Alternative 3
            'sequence_variant',    # Alternative 4 (Hypothese: Sequenznummern)
        ]
        
        for variant_idx, variant in enumerate(variants, 1):
            logger.info(f"\n--- Test {variant_idx}/{len(variants)}: {variant.upper()} ---")
            
            payload = self._build_login_payload(variant)
            if payload is None:
                continue
            
            logger.info(f"Payload ({len(payload)} Bytes): {payload.hex()}")
            
            # Versuche 3x mit dieser Variante
            for attempt in range(3):
                logger.info(f"  Versuch {attempt+1}/3...")
                response = self.send_packet(payload, inner_type=0x00, outer_type=0xD0)
                
                if response:
                    logger.info(f"\n🎉 LOGIN ERFOLGREICH mit Variante '{variant}'!")
                    logger.info(f"Antwort ({len(response)} Bytes): {response.hex()}")
                    logger.info("="*70)
                    self.start_heartbeat()
                    return True
                
                time.sleep(0.5)  # Kürzere Pause zwischen Versuchen
            
            logger.warning(f"  ✗ Variante '{variant}' erfolglos. Nächste...")
        
        logger.error("\n" + "="*70)
        logger.error("❌ ALLE VARIANTEN FEHLGESCHLAGEN")
        logger.error("="*70)
        logger.error("Nächste Schritte:")
        logger.error("1. BLE-Dump analysieren für echten Auth-Token")
        logger.error("2. TCP-Dump des Smartphones genauer untersuchen")
        logger.error("3. Neue Hypothesen entwickeln")
        return False

    def start_heartbeat(self):
        self.running = True
        self.keep_alive_thread = threading.Thread(target=self._heartbeat_loop)
        self.keep_alive_thread.daemon = True
        self.keep_alive_thread.start()

    def _heartbeat_loop(self):
        logger.info("Starte Heartbeat Loop (Alle 2s)...")
        while self.running:
            try:
                self.send_packet(b'\x00\x00', inner_type=0x01, outer_type=0xD1, wait_for_response=False)
                time.sleep(2)
            except Exception:
                break
