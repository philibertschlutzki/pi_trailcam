#!/usr/bin/env python3
"""
BLE Token Extractor für KJK230 Kamera
Extrahiert den Auth-Token direkt nach dem BLE-Wake

Usage:
    sudo python3 extract_ble_token.py
"""

import re
import base64
import logging
import subprocess
import sys
import time
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class BLETokenExtractor:
    """Extrahiert Tokens aus hcidump Output"""
    
    def __init__(self, camera_mac="C6:1E:0D:E0:32:E8"):
        self.camera_mac = camera_mac
        self.tokens_found = []
        self.hex_patterns = []
    
    def start_capture(self, duration=30):
        """Startet hcidump Capture für spezifische Dauer"""
        logger.info(f"🔍 Starte BLE-Capture für {duration} Sekunden...")
        logger.info(f"📱 Ziel-Gerät: {self.camera_mac}")
        logger.info(f"💡 Stelle sicher, dass die Kamera aufwacht!\n")
        
        try:
            # Starte hcidump
            cmd = ["hcidump", "-i", "hci0", "-X", "-v"]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Sammle Output
            output_lines = []
            start_time = time.time()
            
            while time.time() - start_time < duration:
                try:
                    line = process.stdout.readline()
                    if line:
                        output_lines.append(line)
                        # Echtzeit-Analyse
                        self._analyze_line(line)
                except:
                    pass
            
            # Beende Prozess
            process.terminate()
            
            # Finale Analyse
            self._analyze_output('\n'.join(output_lines))
            
        except FileNotFoundError:
            logger.error("❌ hcidump nicht gefunden!")
            logger.error("   Installiere: sudo apt-get install bluez-tools")
            sys.exit(1)
        except Exception as e:
            logger.error(f"❌ Fehler beim Capture: {e}")
            sys.exit(1)
    
    def _analyze_line(self, line):
        """Analysiert eine einzelne Zeile des Dumps"""
        # Suche nach Base64-Mustern
        matches = re.findall(r'[A-Za-z0-9+/]{30,60}={0,2}', line)
        for match in matches:
            if self._is_valid_token(match):
                if match not in self.tokens_found:
                    logger.info(f"🎯 TOKEN GEFUNDEN: {match}")
                    self.tokens_found.append(match)
                    self._decode_token(match)
    
    def _analyze_output(self, output):
        """Analysiert gesamten Output"""
        logger.info("\n" + "="*70)
        logger.info("📊 ANALYSE DES BLE-DUMPS")
        logger.info("="*70)
        
        # Suche nach langen Hex-Strings (Token in Hex)
        # Base64 Token in Hex:
        # I3mbwVIx... = 4933 6d62 7756 4978...
        hex_pattern = r'\b[0-9a-f]{4}\s+[0-9a-f]{4}\s+[0-9a-f]{4}\s+[0-9a-f]{4}\s+[0-9a-f]{4}'
        matches = re.findall(hex_pattern, output, re.IGNORECASE)
        
        # Filtere nach Länge (Token sollte min. 40 Hex-Chars sein)
        if matches:
            logger.info(f"\n🔍 Hex-Patterns gefunden:")
            for i, match in enumerate(matches[:5], 1):  # Top 5
                logger.info(f"  {i}. {match}")
        
        # Suche nach bekannten Token-Signaturen
        if "I3mb" in output or "4933 6d62" in output:
            logger.info("\n✅ Bekannter Token I3mbwVIx... gefunden!")
            self._extract_token_hex(output, "4933 6d62")
    
    def _extract_token_hex(self, data, hex_start):
        """Extrahiert Token direkt aus Hex"""
        # Finde die Position
        pos = data.find(hex_start)
        if pos >= 0:
            # Extrahiere die nächsten 60 Hex-Bytes (ca. 45 Base64 chars)
            hex_section = data[pos:pos+300]
            logger.info(f"\n🔐 Hex-Sektion: {hex_section[:100]}")
    
    def _is_valid_token(self, s):
        """Prüft ob String ein gültiger Token sein könnte"""
        # Muss Base64-Format sein
        if not re.match(r'^[A-Za-z0-9+/]{30,60}={0,2}$', s):
            return False
        
        # Versuche zu dekodieren
        try:
            decoded = base64.b64decode(s)
            # Token sollte mindestens 20 Bytes sein
            return len(decoded) >= 20
        except:
            return False
    
    def _decode_token(self, token):
        """Dekodiert und zeigt Token-Details"""
        try:
            decoded = base64.b64decode(token)
            hex_repr = decoded.hex()
            logger.info(f"   Base64: {token}")
            logger.info(f"   Dekodiert (hex): {hex_repr}")
            logger.info(f"   Länge: {len(token)} chars / {len(decoded)} bytes")
        except Exception as e:
            logger.warning(f"   Dekodier-Fehler: {e}")
    
    def print_summary(self):
        """Zeigt Zusammenfassung"""
        logger.info("\n" + "="*70)
        logger.info("📋 ZUSAMMENFASSUNG")
        logger.info("="*70)
        
        if self.tokens_found:
            logger.info(f"\n✅ {len(self.tokens_found)} Token gefunden:\n")
            for i, token in enumerate(self.tokens_found, 1):
                logger.info(f"  {i}. {token}")
            
            # Speichere in Datei
            token_file = Path("extracted_tokens.txt")
            with open(token_file, "w") as f:
                for token in self.tokens_found:
                    f.write(f"{token}\n")
            logger.info(f"\n💾 Tokens gespeichert in: {token_file}")
        else:
            logger.warning("\n❌ Keine Tokens gefunden!")
            logger.info("\n💡 Troubleshooting:")
            logger.info("   • Ist die Kamera eingeschaltet?")
            logger.info("   • BLE sichtbar? Versuche: sudo hcitool lescan")
            logger.info("   • Ist die MAC-Adresse korrekt?")
            logger.info("   • Versuche: sudo hcidump -i hci0 -X -v (manual)")

def main():
    print("="*70)
    print("🔐 BLE TOKEN EXTRACTOR FOR KJK230 CAMERA")
    print("="*70)
    
    # Prüfe ob Root
    if sys.geteuid() != 0:
        logger.error("❌ Dieses Script muss mit sudo ausgeführt werden!")
        logger.error("   Versuche: sudo python3 extract_ble_token.py")
        sys.exit(1)
    
    # Prüfe Dependencies
    try:
        subprocess.run(["hcidump", "-h"], capture_output=True, check=False)
    except FileNotFoundError:
        logger.error("❌ hcidump nicht gefunden!")
        logger.error("   Installiere: sudo apt-get install bluez-tools")
        sys.exit(1)
    
    # Starte Extraction
    extractor = BLETokenExtractor(camera_mac="C6:1E:0D:E0:32:E8")
    
    logger.info("\n📋 ANLEITUNG:")
    logger.info("  1. Warte auf 'Token GEFUNDEN' Nachricht (ca. 30 Sekunden)")
    logger.info("  2. ODER: In anderem Terminal: python3 main.py")
    logger.info("  3. Kamera wird aufgeweckt → Token sollte angezeigt werden\n")
    
    # Starte Capture (30 Sekunden)
    try:
        extractor.start_capture(duration=30)
    except KeyboardInterrupt:
        logger.info("\n⏸️  Capture unterbrochen")
    
    # Zeige Zusammenfassung
    extractor.print_summary()
    
    logger.info("\n" + "="*70)
    logger.info("✅ Token Extraction abgeschlossen")
    logger.info("="*70)

if __name__ == "__main__":
    main()
