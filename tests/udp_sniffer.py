#!/usr/bin/env python3
"""
UDP Sniffer für pi_trailcam Projekt mit automatischer WLAN-Verbindung
Zeichnet UDP-Verkehr zwischen Smartphone und Kamera auf
"""

import socket
import struct
import logging
import sys
import os
from datetime import datetime
import argparse
import subprocess
import time

# Importiere config aus parent directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import config

# Logging konfigurieren
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(f'udp_capture_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    ]
)
logger = logging.getLogger("UDPSniffer")


class WiFiConnector:
    """Verwaltet die WLAN-Verbindung zur Kamera"""
    
    def __init__(self):
        self.ssid_prefix = config.WIFI_SSID_PREFIX
        self.password = config.WIFI_PASSWORD
        self.connected_ssid = None
    
    def _run_command(self, command_list, log_errors=True):
        """Führt Shell-Befehle sicher aus"""
        try:
            result = subprocess.run(
                command_list,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            if log_errors:
                cmd_str = " ".join(command_list)
                logger.error(f"Befehl fehlgeschlagen: {cmd_str}\nFehler: {e.stderr}")
            return None
    
    def scan_for_camera_wifi(self, timeout=60):
        """
        Scannt nach Kamera-WLAN
        
        Args:
            timeout: Maximale Suchzeit in Sekunden
            
        Returns:
            str: SSID der Kamera oder None
        """
        logger.info(f"Suche nach WLAN mit Präfix '{self.ssid_prefix}'...")
        start_time = time.time()
        
        while (time.time() - start_time) < timeout:
            # Rescan
            self._run_command(["nmcli", "dev", "wifi", "rescan"])
            time.sleep(2)
            
            # Liste verfügbare Netzwerke
            output = self._run_command(["nmcli", "-t", "-f", "SSID", "dev", "wifi", "list"])
            if output:
                ssids = output.split('\n')
                for ssid in ssids:
                    ssid = ssid.strip()
                    if ssid.startswith(self.ssid_prefix):
                        logger.info(f"Kamera-WLAN gefunden: {ssid}")
                        return ssid
            
            logger.debug("Kamera-SSID noch nicht gefunden...")
            time.sleep(3)
        
        logger.error("Timeout: Kamera-WLAN nicht gefunden.")
        return None
    
    def connect(self, timeout=60):
        """
        Verbindet sich mit dem Kamera-WLAN
        
        Args:
            timeout: Maximale Zeit für Suche und Verbindung
            
        Returns:
            bool: True bei erfolgreicher Verbindung
        """
        # Suche SSID
        found_ssid = self.scan_for_camera_wifi(timeout)
        if not found_ssid:
            return False
        
        # Cleanup alte Profile
        logger.info(f"Entferne alte Profile für {found_ssid}...")
        self._run_command(["nmcli", "connection", "delete", found_ssid], log_errors=False)
        time.sleep(1)
        
        # Verbinde
        logger.info(f"Verbinde mit {found_ssid}...")
        cmd = ["nmcli", "dev", "wifi", "connect", found_ssid, "password", self.password]
        
        if self._run_command(cmd):
            logger.info(f"Erfolgreich verbunden mit {found_ssid}")
            self.connected_ssid = found_ssid
            # Warte auf DHCP
            time.sleep(5)
            return True
        else:
            logger.error(f"Verbindung zu {found_ssid} fehlgeschlagen")
            return False
    
    def get_connection_info(self):
        """Zeigt Verbindungsinformationen"""
        output = self._run_command(["nmcli", "dev", "status"])
        if output:
            logger.info(f"Netzwerk Status:\n{output}")
        
        # IP-Adresse ermitteln
        output = self._run_command(["ip", "addr", "show", "wlan0"])
        if output:
            logger.info(f"WLAN0 Interface Info:\n{output}")


class UDPSniffer:
    def __init__(self, interface='wlan0', camera_ip=None, output_file=None):
        """
        Initialisiert den UDP Sniffer
        
        Args:
            interface: Netzwerk-Interface (z.B. 'eth0', 'wlan0')
            camera_ip: IP der Kamera (optional, für Filterung)
            output_file: Datei für rohe Paket-Dumps
        """
        self.interface = interface
        self.camera_ip = camera_ip
        self.output_file = output_file
        self.packet_count = 0
        
        # Raw Socket erstellen (erfordert root)
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
            self.sock.bind((interface, 0))
            logger.info(f"UDP Sniffer gestartet auf Interface: {interface}")
            if camera_ip:
                logger.info(f"Filtere Pakete für Kamera IP: {camera_ip}")
        except PermissionError:
            logger.error("Root-Rechte erforderlich! Führe mit 'sudo' aus.")
            sys.exit(1)
        except OSError as e:
            logger.error(f"Fehler beim Erstellen des Sockets: {e}")
            sys.exit(1)

    def parse_ethernet_header(self, packet):
        """Parse Ethernet Header"""
        eth_header = packet[:14]
        eth = struct.unpack('!6s6sH', eth_header)
        eth_protocol = socket.ntohs(eth[2])
        return eth_protocol

    def parse_ip_header(self, packet):
        """Parse IP Header"""
        ip_header = packet[14:34]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        
        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        
        protocol = iph[6]
        src_addr = socket.inet_ntoa(iph[8])
        dst_addr = socket.inet_ntoa(iph[9])
        
        return protocol, src_addr, dst_addr, iph_length

    def parse_udp_header(self, packet, iph_length):
        """Parse UDP Header"""
        udp_header = packet[14 + iph_length:14 + iph_length + 8]
        udph = struct.unpack('!HHHH', udp_header)
        
        src_port = udph[0]
        dst_port = udph[1]
        length = udph[2]
        checksum = udph[3]
        
        return src_port, dst_port, length

    def extract_udp_data(self, packet, iph_length):
        """Extrahiere UDP Payload"""
        header_size = 14 + iph_length + 8
        data = packet[header_size:]
        return data

    def log_packet(self, src_ip, src_port, dst_ip, dst_port, data):
        """Logge Paket-Informationen"""
        self.packet_count += 1
        
        logger.info("="*80)
        logger.info(f"Paket #{self.packet_count}")
        logger.info(f"Quelle:      {src_ip}:{src_port}")
        logger.info(f"Ziel:        {dst_ip}:{dst_port}")
        logger.info(f"Größe:       {len(data)} Bytes")
        
        # Hexdump der ersten 64 Bytes
        hex_preview = data[:64].hex()
        logger.info(f"Daten (hex): {' '.join([hex_preview[i:i+2] for i in range(0, len(hex_preview), 2)])}")
        
        # ASCII-Darstellung
        ascii_data = ''.join([chr(b) if 32 <= b < 127 else '.' for b in data[:64]])
        logger.info(f"Daten (asc): {ascii_data}")
        
        # Speichere vollständige Daten in Datei
        if self.output_file:
            with open(self.output_file, 'ab') as f:
                timestamp = datetime.now().isoformat()
                entry = f"\n{'='*80}\n"
                entry += f"Timestamp: {timestamp}\n"
                entry += f"Paket #{self.packet_count}\n"
                entry += f"Von: {src_ip}:{src_port} -> An: {dst_ip}:{dst_port}\n"
                entry += f"Größe: {len(data)} Bytes\n"
                entry += f"Hex: {data.hex()}\n"
                entry += f"ASCII: {ascii_data}\n"
                f.write(entry.encode())

    def start_sniffing(self):
        """Starte das Sniffing"""
        logger.info("Starte UDP Packet Capture... (CTRL+C zum Beenden)")
        
        try:
            while True:
                packet = self.sock.recvfrom(65565)[0]
                
                # Parse Ethernet Header
                eth_protocol = self.parse_ethernet_header(packet)
                
                # Prüfe ob IPv4 (0x0800)
                if eth_protocol == 8:
                    # Parse IP Header
                    protocol, src_ip, dst_ip, iph_length = self.parse_ip_header(packet)
                    
                    # Prüfe ob UDP (Protocol 17)
                    if protocol == 17:
                        # Filter nach Kamera-IP falls angegeben
                        if self.camera_ip:
                            if src_ip != self.camera_ip and dst_ip != self.camera_ip:
                                continue
                        
                        # Parse UDP Header
                        src_port, dst_port, length = self.parse_udp_header(packet, iph_length)
                        
                        # Extrahiere Daten
                        data = self.extract_udp_data(packet, iph_length)
                        
                        # Logge Paket
                        self.log_packet(src_ip, src_port, dst_ip, dst_port, data)
                        
        except KeyboardInterrupt:
            logger.info(f"\nSniffing beendet. {self.packet_count} Pakete aufgezeichnet.")
            self.sock.close()


def main():
    parser = argparse.ArgumentParser(description='UDP Sniffer für pi_trailcam mit Auto-WLAN-Verbindung')
    parser.add_argument('-i', '--interface', default='wlan0', 
                        help='Netzwerk-Interface (default: wlan0)')
    parser.add_argument('-c', '--camera-ip', default=config.CAM_IP,
                        help=f'IP-Adresse der Kamera für Filterung (default: {config.CAM_IP})')
    parser.add_argument('-o', '--output', default='udp_packets.dump',
                        help='Output-Datei für rohe Paket-Dumps (default: udp_packets.dump)')
    parser.add_argument('--no-connect', action='store_true',
                        help='Überspringe automatische WLAN-Verbindung')
    parser.add_argument('--wifi-timeout', type=int, default=60,
                        help='Timeout für WLAN-Verbindung in Sekunden (default: 60)')
    
    args = parser.parse_args()
    
    # Check root
    if os.geteuid() != 0:
        logger.error("Dieses Script benötigt Root-Rechte. Bitte mit 'sudo' ausführen.")
        sys.exit(1)
    
    # Schritt 1: WLAN-Verbindung herstellen (falls gewünscht)
    if not args.no_connect:
        logger.info("="*80)
        logger.info("SCHRITT 1: WLAN-VERBINDUNG")
        logger.info("="*80)
        
        wifi = WiFiConnector()
        if not wifi.connect(timeout=args.wifi_timeout):
            logger.error("Konnte keine Verbindung zum Kamera-WLAN herstellen.")
            sys.exit(1)
        
        # Zeige Verbindungsinfo
        wifi.get_connection_info()
        logger.info("WLAN-Verbindung erfolgreich!")
    else:
        logger.info("WLAN-Verbindung übersprungen (--no-connect)")
    
    # Schritt 2: Starte Sniffer
    logger.info("="*80)
    logger.info("SCHRITT 2: UDP SNIFFING")
    logger.info("="*80)
    
    sniffer = UDPSniffer(
        interface=args.interface,
        camera_ip=args.camera_ip,
        output_file=args.output
    )
    
    sniffer.start_sniffing()


if __name__ == "__main__":
    main()
