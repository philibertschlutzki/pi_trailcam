#!/usr/bin/env python3
"""
UDP Sniffer für pi_trailcam Projekt
Zeichnet UDP-Verkehr zwischen Smartphone und Kamera auf
"""

import socket
import struct
import logging
import sys
from datetime import datetime
import argparse

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


class UDPSniffer:
    def __init__(self, interface='eth0', camera_ip=None, output_file=None):
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
    parser = argparse.ArgumentParser(description='UDP Sniffer für pi_trailcam Projekt')
    parser.add_argument('-i', '--interface', default='wlan0', 
                        help='Netzwerk-Interface (default: wlan0)')
    parser.add_argument('-c', '--camera-ip', 
                        help='IP-Adresse der Kamera für Filterung')
    parser.add_argument('-o', '--output', 
                        help='Output-Datei für rohe Paket-Dumps')
    
    args = parser.parse_args()
    
    sniffer = UDPSniffer(
        interface=args.interface,
        camera_ip=args.camera_ip,
        output_file=args.output
    )
    
    sniffer.start_sniffing()


if __name__ == "__main__":
    main()
