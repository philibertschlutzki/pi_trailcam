#!/usr/bin/env python3
"""
UDP Sniffer für pi_trailcam Projekt mit automatischer WLAN-Verbindung
Zeichnet UDP-Verkehr zwischen Smartphone und Kamera auf

MIT ARP SPOOFING (MAN-IN-THE-MIDDLE) MODUS:
Leitet Traffic zwischen Smartphone und Kamera über den Raspberry Pi um,
um ALLE Pakete mitzuschneiden.

WARNUNG: ARP Spoofing nur in eigenen Netzwerken verwenden!
Das Kamera-WLAN gehört zur Kamera und ist daher kein fremdes Netzwerk.
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
import threading
import signal

try:
    from scapy.all import ARP, Ether, send, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

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


class ARPSpoofer:
    """
    ARP Spoofing für Man-in-the-Middle Packet Capture
    Leitet Traffic zwischen Target (Smartphone) und Gateway (Kamera) über diesen Host um
    
    Verwendet Scapy für echtes ARP Spoofing!
    """
    
    def __init__(self, target_ip, gateway_ip, interface='wlan0'):
        if not SCAPY_AVAILABLE:
            raise ImportError(
                "Scapy ist nicht installiert!\n"
                "Installiere es mit: sudo apt-get install python3-scapy\n"
                "Oder: sudo pip3 install scapy"
            )
        
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.running = False
        self.thread = None
        self.target_mac = None
        self.gateway_mac = None
        self.own_mac = None
        
    def _get_mac(self, ip):
        """Ermittle MAC-Adresse für IP via ARP mit Scapy"""
        try:
            logger.debug(f"Sende ARP Request an {ip}...")
            # Sende ARP Request mit scapy
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), 
                timeout=3, 
                verbose=False,
                iface=self.interface,
                retry=2
            )
            
            if ans:
                mac = ans[0][1].hwsrc
                logger.debug(f"MAC für {ip}: {mac}")
                return mac
            else:
                logger.debug(f"Keine Antwort von {ip}")
                
        except Exception as e:
            logger.error(f"Fehler beim Ermitteln der MAC-Adresse für {ip}: {e}")
        
        return None
    
    def _get_own_mac(self):
        """Ermittle eigene MAC-Adresse des Interface"""
        try:
            result = subprocess.run(
                ['cat', f'/sys/class/net/{self.interface}/address'],
                capture_output=True,
                text=True,
                check=True
            )
            mac = result.stdout.strip()
            logger.debug(f"Eigene MAC ({self.interface}): {mac}")
            return mac
        except Exception as e:
            logger.error(f"Fehler beim Ermitteln der eigenen MAC: {e}")
            return None
    
    def _enable_ip_forwarding(self):
        """Aktiviert IP Forwarding im Kernel"""
        try:
            subprocess.run(
                ['sysctl', '-w', 'net.ipv4.ip_forward=1'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True
            )
            logger.info("✓ IP Forwarding aktiviert")
        except Exception as e:
            logger.error(f"Fehler beim Aktivieren von IP Forwarding: {e}")
    
    def _disable_ip_forwarding(self):
        """Deaktiviert IP Forwarding im Kernel"""
        try:
            subprocess.run(
                ['sysctl', '-w', 'net.ipv4.ip_forward=0'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True
            )
            logger.info("✓ IP Forwarding deaktiviert")
        except Exception as e:
            logger.error(f"Fehler beim Deaktivieren von IP Forwarding: {e}")
    
    def _spoof_loop(self):
        """Hauptloop für ARP Spoofing - Sendet echte ARP-Pakete"""
        logger.info("ARP Spoofing Loop gestartet...")
        packet_count = 0
        
        while self.running:
            try:
                # KRITISCH: Sende gefälschte ARP Reply Pakete
                
                # 1. An Target (Smartphone): "Ich bin die Kamera"
                # op=2 = ARP Reply (is-at)
                # hwsrc = Unsere MAC (täuschen vor, Kamera zu sein)
                # psrc = Kamera IP (täuschen vor, Kamera zu sein)
                # hwdst = Smartphone MAC
                # pdst = Smartphone IP
                arp_to_target = ARP(
                    op=2,  # ARP Reply
                    hwsrc=self.own_mac,      # Unsere MAC
                    psrc=self.gateway_ip,    # Täusche Kamera-IP vor
                    hwdst=self.target_mac,   # Smartphone MAC
                    pdst=self.target_ip      # Smartphone IP
                )
                send(arp_to_target, verbose=False, iface=self.interface)
                
                # 2. An Gateway (Kamera): "Ich bin das Smartphone"
                arp_to_gateway = ARP(
                    op=2,  # ARP Reply
                    hwsrc=self.own_mac,      # Unsere MAC
                    psrc=self.target_ip,     # Täusche Smartphone-IP vor
                    hwdst=self.gateway_mac,  # Kamera MAC
                    pdst=self.gateway_ip     # Kamera IP
                )
                send(arp_to_gateway, verbose=False, iface=self.interface)
                
                packet_count += 2
                if packet_count % 10 == 0:  # Alle 5 Zyklen loggen
                    logger.debug(f"ARP Spoofing aktiv... ({packet_count} Pakete gesendet)")
                
                time.sleep(2)  # Alle 2 Sekunden spoofing packets senden
                
            except Exception as e:
                if self.running:
                    logger.error(f"Fehler im Spoof-Loop: {e}")
                time.sleep(1)
        
        logger.info(f"ARP Spoofing Loop beendet ({packet_count} Pakete gesendet)")
    
    def _restore_arp(self):
        """Stelle originale ARP-Einträge wieder her"""
        logger.info("Stelle originale ARP-Tabellen wieder her...")
        try:
            # Sende korrekte ARP-Pakete (mehrmals für Zuverlässigkeit)
            for i in range(3):
                # Restore Target's ARP table: Echte Kamera-MAC
                send(
                    ARP(
                        op=2,  # ARP Reply
                        hwsrc=self.gateway_mac,  # Echte Kamera MAC
                        psrc=self.gateway_ip,     # Kamera IP
                        hwdst=self.target_mac,    # Smartphone MAC
                        pdst=self.target_ip       # Smartphone IP
                    ),
                    verbose=False,
                    iface=self.interface
                )
                
                # Restore Gateway's ARP table: Echte Smartphone-MAC
                send(
                    ARP(
                        op=2,  # ARP Reply
                        hwsrc=self.target_mac,   # Echte Smartphone MAC
                        psrc=self.target_ip,     # Smartphone IP
                        hwdst=self.gateway_mac,  # Kamera MAC
                        pdst=self.gateway_ip     # Kamera IP
                    ),
                    verbose=False,
                    iface=self.interface
                )
                
                logger.debug(f"Restore-Zyklus {i+1}/3 gesendet")
                time.sleep(0.5)
            
            logger.info("✓ ARP-Tabellen wiederhergestellt")
                
        except Exception as e:
            logger.error(f"Fehler beim Wiederherstellen: {e}")
    
    def start(self):
        """Startet ARP Spoofing"""
        logger.warning("="*80)
        logger.warning("⚠️  WARNUNG: ARP SPOOFING AKTIVIERT (MAN-IN-THE-MIDDLE) ⚠️")
        logger.warning("Nur in eigenen Netzwerken verwenden!")
        logger.warning("Das Kamera-WLAN ist dein eigenes Netzwerk.")
        logger.warning("="*80)
        
        # Ermittle eigene MAC
        logger.info("Ermittle eigene MAC-Adresse...")
        self.own_mac = self._get_own_mac()
        if not self.own_mac:
            logger.error("❌ Konnte eigene MAC-Adresse nicht ermitteln!")
            return False
        logger.info(f"✓ Eigene MAC: {self.own_mac}")
        
        # Ermittle Target MAC
        logger.info(f"Ermittle MAC-Adresse für Target (Smartphone): {self.target_ip}...")
        self.target_mac = self._get_mac(self.target_ip)
        if not self.target_mac:
            logger.error(f"❌ Konnte MAC-Adresse für {self.target_ip} nicht ermitteln!")
            logger.error("   Stelle sicher, dass das Smartphone mit dem Netzwerk verbunden ist.")
            logger.error("   Prüfe mit: sudo python3 tests/udp_sniffer.py --scan")
            return False
        logger.info(f"✓ Target MAC: {self.target_mac}")
        
        # Ermittle Gateway MAC
        logger.info(f"Ermittle MAC-Adresse für Gateway (Kamera): {self.gateway_ip}...")
        self.gateway_mac = self._get_mac(self.gateway_ip)
        if not self.gateway_mac:
            logger.error(f"❌ Konnte MAC-Adresse für {self.gateway_ip} nicht ermitteln!")
            return False
        logger.info(f"✓ Gateway MAC: {self.gateway_mac}")
        
        # Aktiviere IP Forwarding
        logger.info("Aktiviere IP Forwarding...")
        self._enable_ip_forwarding()
        
        # Starte Spoofing Thread
        logger.info("Starte ARP Spoofing Thread...")
        self.running = True
        self.thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self.thread.start()
        
        logger.info("="*80)
        logger.info("✓ ARP Spoofing AKTIV - Traffic wird umgeleitet")
        logger.info(f"  Smartphone ({self.target_ip}) → glaubt wir sind Kamera ({self.gateway_ip})")
        logger.info(f"  Kamera ({self.gateway_ip}) → glaubt wir sind Smartphone ({self.target_ip})")
        logger.info("="*80)
        return True
    
    def stop(self):
        """Stoppt ARP Spoofing und stellt ARP-Tabellen wieder her"""
        logger.info("Stoppe ARP Spoofing...")
        self.running = False
        
        if self.thread:
            self.thread.join(timeout=3)
        
        # Stelle originale ARP-Einträge wieder her
        self._restore_arp()
        
        # Deaktiviere IP Forwarding
        self._disable_ip_forwarding()
        
        logger.info("✓ ARP Spoofing gestoppt")


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
    
    def get_own_ip(self, interface='wlan0'):
        """Ermittelt eigene IP-Adresse"""
        try:
            result = subprocess.run(
                ['ip', '-4', 'addr', 'show', interface],
                capture_output=True,
                text=True
            )
            
            for line in result.stdout.split('\n'):
                if 'inet ' in line:
                    ip = line.strip().split()[1].split('/')[0]
                    return ip
        except:
            pass
        return None
    
    def scan_network(self, interface='wlan0'):
        """Scannt Netzwerk nach aktiven Hosts (mit begrenzten parallelen Prozessen)"""
        logger.info("Scanne Netzwerk nach Geräten...")
        own_ip = self.get_own_ip(interface)
        if not own_ip:
            logger.error("Konnte eigene IP nicht ermitteln")
            return []
        
        # Ermittle Netzwerk-Präfix
        network_prefix = '.'.join(own_ip.split('.')[:-1])
        
        # Ping alle IPs im Netzwerk in BATCHES
        # Um Ressourcen-Überlastung zu vermeiden
        logger.info(f"Sende Pings an {network_prefix}.0/24...")
        
        BATCH_SIZE = 20  # Maximal 20 gleichzeitige Pings
        
        for batch_start in range(1, 255, BATCH_SIZE):
            batch_end = min(batch_start + BATCH_SIZE, 255)
            processes = []
            
            for i in range(batch_start, batch_end):
                ip = f"{network_prefix}.{i}"
                if ip != own_ip:  # Eigene IP überspringen
                    try:
                        proc = subprocess.Popen(
                            ['ping', '-c', '1', '-W', '1', ip],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL
                        )
                        processes.append(proc)
                    except Exception as e:
                        logger.debug(f"Fehler beim Starten von ping für {ip}: {e}")
            
            # Warte auf aktuellen Batch
            for proc in processes:
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
            
            # Progress
            progress = int((batch_end / 254) * 100)
            logger.info(f"  Scan Fortschritt: {progress}%")
        
        time.sleep(1)
        
        # Lese ARP-Tabelle
        devices = []
        try:
            result = subprocess.run(['arp', '-n'], capture_output=True, text=True)
            logger.info("Gefundene Geräte im Netzwerk:")
            for line in result.stdout.split('\n')[1:]:  # Erste Zeile überspringen (Header)
                parts = line.split()
                if len(parts) >= 3 and parts[2] != '<incomplete>':
                    ip = parts[0]
                    mac = parts[2]
                    if ip != own_ip:
                        devices.append({'ip': ip, 'mac': mac})
                        logger.info(f"  {ip:15s} - {mac}")
        except Exception as e:
            logger.error(f"Fehler beim Scannen: {e}")
        
        return devices


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


# Globale Variable für Cleanup
arp_spoofer = None

def cleanup_handler(signum, frame):
    """Signal Handler für sauberes Beenden"""
    global arp_spoofer
    logger.info("\nSIGINT empfangen, beende...")
    if arp_spoofer:
        arp_spoofer.stop()
    sys.exit(0)


def main():
    global arp_spoofer
    
    parser = argparse.ArgumentParser(
        description='UDP Sniffer für pi_trailcam mit Auto-WLAN-Verbindung und MITM-Modus',
        epilog='WARNUNG: ARP Spoofing (--mitm) nur in eigenen Netzwerken verwenden!'
    )
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
    parser.add_argument('--mitm', action='store_true',
                        help='Aktiviere ARP Spoofing (Man-in-the-Middle) Modus')
    parser.add_argument('-t', '--target-ip',
                        help='IP des Smartphones (für MITM-Modus). Wenn nicht angegeben, wird Netzwerk gescannt.')
    parser.add_argument('--scan', action='store_true',
                        help='Scanne Netzwerk nach Geräten und beende')
    
    args = parser.parse_args()
    
    # Check root
    if os.geteuid() != 0:
        logger.error("Dieses Script benötigt Root-Rechte. Bitte mit 'sudo' ausführen.")
        sys.exit(1)
    
    # Check scapy für MITM-Modus
    if args.mitm and not SCAPY_AVAILABLE:
        logger.error("MITM-Modus benötigt Scapy!")
        logger.error("Installiere mit: sudo apt-get install python3-scapy")
        logger.error("Oder: sudo pip3 install scapy")
        sys.exit(1)
    
    # Signal Handler registrieren
    signal.signal(signal.SIGINT, cleanup_handler)
    
    # Schritt 1: WLAN-Verbindung herstellen (falls gewünscht)
    wifi = None
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
        wifi = WiFiConnector()
    
    # Nur Scan durchführen?
    if args.scan:
        if wifi:
            wifi.scan_network(args.interface)
        sys.exit(0)
    
    # Schritt 2: ARP Spoofing (falls aktiviert)
    if args.mitm:
        logger.info("="*80)
        logger.info("SCHRITT 2: ARP SPOOFING (MITM)")
        logger.info("="*80)
        
        target_ip = args.target_ip
        
        # Wenn keine Target-IP angegeben, Netzwerk scannen
        if not target_ip:
            logger.info("Keine Target-IP angegeben. Scanne Netzwerk...")
            devices = wifi.scan_network(args.interface) if wifi else []
            
            if not devices:
                logger.error("Keine Geräte im Netzwerk gefunden!")
                logger.error("Bitte Target-IP manuell mit --target-ip angeben.")
                sys.exit(1)
            
            # Verwende erstes gefundenes Gerät (außer Kamera)
            for device in devices:
                if device['ip'] != args.camera_ip:
                    target_ip = device['ip']
                    logger.info(f"Verwende {target_ip} als Target")
                    break
            
            if not target_ip:
                logger.error("Konnte kein geeignetes Target finden!")
                sys.exit(1)
        
        # Starte ARP Spoofing
        try:
            arp_spoofer = ARPSpoofer(
                target_ip=target_ip,
                gateway_ip=args.camera_ip,
                interface=args.interface
            )
        except ImportError as e:
            logger.error(str(e))
            sys.exit(1)
        
        if not arp_spoofer.start():
            logger.error("ARP Spoofing konnte nicht gestartet werden!")
            sys.exit(1)
        
        logger.info(f"MITM aktiv: {target_ip} <-> {args.camera_ip}")
        time.sleep(2)  # Warte bis Spoofing etabliert ist
    
    # Schritt 3: Starte Sniffer
    logger.info("="*80)
    logger.info(f"SCHRITT {'3' if args.mitm else '2'}: UDP SNIFFING")
    logger.info("="*80)
    
    try:
        sniffer = UDPSniffer(
            interface=args.interface,
            camera_ip=args.camera_ip,
            output_file=args.output
        )
        
        sniffer.start_sniffing()
    finally:
        # Cleanup bei Beendigung
        if arp_spoofer:
            arp_spoofer.stop()


if __name__ == "__main__":
    main()
