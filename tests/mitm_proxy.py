#!/usr/bin/env python3
"""
TrailCam MITM Proxy für Raspberry Pi
======================================
Zweck: UDP-Verbindungsaufbau zwischen Android App und KJK230 Kamera analysieren

Ablauf:
1. Erstellt Fake-AP "KJK_E0FF_pi" auf wlan0 (für Smartphone)
2. Verbindet sich mit echter Kamera "KJK_E0FF" auf wlan1
3. Leitet Traffic zwischen beiden weiter (NAT)
4. Captured alle Pakete für Issue #52 Analyse

Autor: Philibert Schlutzki
Datum: 2025-12-14
"""

import os
import sys
import time
import signal
import logging
import subprocess
import threading
from pathlib import Path
from datetime import datetime
from scapy.all import sniff, wrpcap, hexdump, UDP, IP

# ============================================================
# KONFIGURATION
# ============================================================

CONFIG = {
    # Netzwerk-Interfaces
    'management_if': 'eth0',          # Für SSH/Logs (bleibt unverändert)
    'ap_interface': 'wlan0',          # AP für Smartphone
    'client_interface': 'wlan1',       # Client zur Kamera
    
    # Access Point (für Smartphone)
    'ap_ssid': 'KJK_E0FF_pi',         # Leicht abweichend, aber erkennbar
    'ap_password': '85087127',         # Identisch zur Kamera
    'ap_channel': '6',
    'ap_ip': '192.168.43.1',           # Identische IP wie Kamera
    'ap_netmask': '255.255.255.0',
    'ap_dhcp_range': '192.168.43.50,192.168.43.150',
    
    # Kamera WiFi (echte Verbindung)
    'camera_ssid': 'KJK_E0FF',
    'camera_password': '85087127',
    'camera_ip': '192.168.43.1',       # Kamera-IP im eigenen Netz
    'camera_port': 40611,              # Hauptport für UDP
    
    # Capture-Einstellungen
    'capture_dir': '/tmp/mitm_captures',
    'capture_file_prefix': 'trailcam_mitm',
    'log_level': logging.INFO,
    
    # Analyse-Filter
    'analyze_udp': True,
    'analyze_tcp': True,
    'analyze_http': True,
}

# ============================================================
# LOGGING SETUP
# ============================================================

# Create capture directory if it doesn't exist (needed for logging)
Path(CONFIG['capture_dir']).mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=CONFIG['log_level'],
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"{CONFIG['capture_dir']}/mitm.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('TrailCamMITM')

# ============================================================
# UTILITY FUNKTIONEN
# ============================================================

def run_command(cmd, check=True, shell=True, capture_output=False):
    """Führt Shell-Befehl aus und loggt Ausgabe"""
    logger.debug(f"Executing: {cmd}")
    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            check=check,
            capture_output=capture_output,
            text=True
        )
        if capture_output:
            return result.stdout.strip()
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {cmd}\nError: {e}")
        if capture_output:
            return ""
        return False

def check_root():
    """Prüft Root-Rechte"""
    if os.geteuid() != 0:
        logger.error("This script must be run as root!")
        sys.exit(1)

def check_interfaces():
    """Prüft ob benötigte Interfaces existieren"""
    interfaces = os.listdir('/sys/class/net/')
    required = [CONFIG['ap_interface'], CONFIG['client_interface']]
    
    for iface in required:
        if iface not in interfaces:
            logger.error(f"Interface {iface} not found!")
            logger.info(f"Available interfaces: {', '.join(interfaces)}")
            sys.exit(1)
    
    logger.info("✓ All required interfaces found")

def install_dependencies():
    """Installiert benötigte Pakete"""
    packages = ['hostapd', 'dnsmasq', 'tcpdump', 'iptables']
    logger.info("Checking dependencies...")
    
    for pkg in packages:
        if not run_command(f"which {pkg}", check=False, capture_output=True):
            logger.info(f"Installing {pkg}...")
            run_command(f"apt-get install -y {pkg}")

# ============================================================
# ACCESS POINT SETUP
# ============================================================

class AccessPointManager:
    """Verwaltet den Access Point auf wlan0"""
    
    def __init__(self):
        self.hostapd_conf = '/tmp/mitm_hostapd.conf'
        self.dnsmasq_conf = '/tmp/mitm_dnsmasq.conf'
        self.hostapd_process = None
        self.dnsmasq_process = None
    
    def create_hostapd_config(self):
        """Erstellt hostapd Konfiguration"""
        config = f"""
interface={CONFIG['ap_interface']}
driver=nl80211
ssid={CONFIG['ap_ssid']}
hw_mode=g
channel={CONFIG['ap_channel']}
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase={CONFIG['ap_password']}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
"""
        Path(self.hostapd_conf).write_text(config)
        logger.info(f"✓ hostapd config created: {self.hostapd_conf}")
    
    def create_dnsmasq_config(self):
        """Erstellt dnsmasq Konfiguration (DHCP Server)"""
        config = f"""
interface={CONFIG['ap_interface']}
dhcp-range={CONFIG['ap_dhcp_range']},255.255.255.0,24h
dhcp-option=3,{CONFIG['ap_ip']}
dhcp-option=6,8.8.8.8,8.8.4.4
server=8.8.8.8
log-queries
log-dhcp
bind-interfaces
"""
        Path(self.dnsmasq_conf).write_text(config)
        logger.info(f"✓ dnsmasq config created: {self.dnsmasq_conf}")
    
    def setup_interface(self):
        """Konfiguriert wlan0 Interface"""
        logger.info("Setting up AP interface...")
        
        # Interface runterfahren
        run_command(f"ip link set {CONFIG['ap_interface']} down")
        
        # IP zuweisen
        run_command(f"ip addr flush dev {CONFIG['ap_interface']}")
        run_command(f"ip addr add {CONFIG['ap_ip']}/24 dev {CONFIG['ap_interface']}")
        
        # Interface hochfahren
        run_command(f"ip link set {CONFIG['ap_interface']} up")
        
        logger.info(f"✓ Interface {CONFIG['ap_interface']} configured with IP {CONFIG['ap_ip']}")
    
    def start(self):
        """Startet Access Point"""
        logger.info("=" * 60)
        logger.info("STARTING ACCESS POINT")
        logger.info("=" * 60)
        
        # Bestehende Prozesse beenden
        run_command("killall hostapd", check=False)
        run_command("killall dnsmasq", check=False)
        time.sleep(1)
        
        # Configs erstellen
        self.create_hostapd_config()
        self.create_dnsmasq_config()
        
        # Interface setup
        self.setup_interface()
        
        # hostapd starten
        logger.info("Starting hostapd...")
        self.hostapd_process = subprocess.Popen(
            ['hostapd', self.hostapd_conf],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(3)
        
        if self.hostapd_process.poll() is not None:
            logger.error("hostapd failed to start!")
            sys.exit(1)
        
        logger.info("✓ hostapd running")
        
        # dnsmasq starten
        logger.info("Starting dnsmasq...")
        self.dnsmasq_process = subprocess.Popen(
            ['dnsmasq', '-C', self.dnsmasq_conf, '-d'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(2)
        
        if self.dnsmasq_process.poll() is not None:
            logger.error("dnsmasq failed to start!")
            sys.exit(1)
        
        logger.info("✓ dnsmasq running")
        logger.info(f"✓ Access Point '{CONFIG['ap_ssid']}' is ready!")
        logger.info(f"  → Clients will get IPs from {CONFIG['ap_dhcp_range']}")
    
    def stop(self):
        """Stoppt Access Point"""
        logger.info("Stopping Access Point...")
        
        if self.hostapd_process:
            self.hostapd_process.terminate()
            self.hostapd_process.wait()
        
        if self.dnsmasq_process:
            self.dnsmasq_process.terminate()
            self.dnsmasq_process.wait()
        
        run_command("killall hostapd", check=False)
        run_command("killall dnsmasq", check=False)
        
        logger.info("✓ Access Point stopped")

# ============================================================
# KAMERA VERBINDUNG
# ============================================================

class CameraConnectionManager:
    """Verwaltet die Verbindung zur echten Kamera auf wlan1"""
    
    def __init__(self):
        self.connected = False
        self.camera_network_ip = None
    
    def connect(self):
        """Verbindet mit Kamera WiFi"""
        logger.info("=" * 60)
        logger.info("CONNECTING TO CAMERA WIFI")
        logger.info("=" * 60)
        
        # Interface hochfahren
        run_command(f"ip link set {CONFIG['client_interface']} up")
        time.sleep(1)
        
        # Bestehende Verbindungen trennen
        logger.info("Disconnecting existing connections...")
        run_command(f"wpa_cli -i {CONFIG['client_interface']} disconnect", check=False)
        time.sleep(1)
        
        # Nach Kamera-WiFi suchen
        logger.info(f"Scanning for '{CONFIG['camera_ssid']}'...")
        scan_output = run_command(
            f"iwlist {CONFIG['client_interface']} scan | grep -i '{CONFIG['camera_ssid']}'",
            check=False,
            capture_output=True
        )
        
        if not scan_output:
            logger.warning(f"Camera WiFi '{CONFIG['camera_ssid']}' not found in scan!")
            logger.info("Continuing anyway (might appear after AP starts)...")
        else:
            logger.info(f"✓ Found '{CONFIG['camera_ssid']}'")
        
        # WPA Supplicant Config erstellen
        wpa_conf = f"""
network={{
    ssid="{CONFIG['camera_ssid']}"
    psk="{CONFIG['camera_password']}"
    key_mgmt=WPA-PSK
    priority=10
}}
"""
        wpa_conf_file = '/tmp/mitm_wpa_supplicant.conf'
        Path(wpa_conf_file).write_text(wpa_conf)
        
        # wpa_supplicant starten
        logger.info("Starting wpa_supplicant...")
        run_command(f"killall wpa_supplicant", check=False)
        time.sleep(1)
        
        run_command(
            f"wpa_supplicant -B -i {CONFIG['client_interface']} -c {wpa_conf_file}",
            check=True
        )
        
        # Warten auf Verbindung
        logger.info("Waiting for connection...")
        for i in range(30):
            time.sleep(1)
            status = run_command(
                f"wpa_cli -i {CONFIG['client_interface']} status | grep wpa_state=COMPLETED",
                check=False,
                capture_output=True
            )
            if status:
                logger.info(f"✓ Connected to '{CONFIG['camera_ssid']}' after {i+1}s")
                self.connected = True
                break
        
        if not self.connected:
            logger.error("Failed to connect to camera WiFi!")
            return False
        
        # DHCP IP holen
        logger.info("Requesting IP via DHCP...")
        run_command(f"dhclient -v {CONFIG['client_interface']}")
        time.sleep(2)
        
        # IP auslesen
        self.camera_network_ip = run_command(
            f"ip addr show {CONFIG['client_interface']} | grep 'inet ' | awk '{{print $2}}' | cut -d/ -f1",
            capture_output=True
        )
        
        if self.camera_network_ip:
            logger.info(f"✓ Got IP on camera network: {self.camera_network_ip}")
        else:
            logger.error("Failed to get IP on camera network!")
            return False
        
        # Ping zur Kamera
        logger.info(f"Testing connection to camera {CONFIG['camera_ip']}...")
        if run_command(f"ping -c 3 -I {CONFIG['client_interface']} {CONFIG['camera_ip']}", check=False):
            logger.info("✓ Camera is reachable!")
        else:
            logger.warning("Camera not reachable via ping (might still work)")
        
        return True
    
    def disconnect(self):
        """Trennt Verbindung zur Kamera"""
        logger.info("Disconnecting from camera WiFi...")
        run_command(f"wpa_cli -i {CONFIG['client_interface']} disconnect", check=False)
        run_command(f"killall wpa_supplicant", check=False)
        run_command(f"ip link set {CONFIG['client_interface']} down")
        logger.info("✓ Disconnected from camera")

# ============================================================
# NAT / ROUTING
# ============================================================

class NetworkForwarder:
    """Konfiguriert NAT und Routing zwischen wlan0 und wlan1"""
    
    def __init__(self):
        self.rules_applied = False
    
    def enable_ip_forwarding(self):
        """Aktiviert IP Forwarding im Kernel"""
        logger.info("Enabling IP forwarding...")
        run_command("sysctl -w net.ipv4.ip_forward=1")
        logger.info("✓ IP forwarding enabled")
    
    def setup_nat(self):
        """Konfiguriert NAT (Network Address Translation)"""
        logger.info("Setting up NAT rules...")
        
        # Alte Regeln löschen
        run_command("iptables -t nat -F", check=False)
        run_command("iptables -F", check=False)
        
        # NAT für Traffic von wlan0 (Smartphone) zu wlan1 (Kamera)
        run_command(
            f"iptables -t nat -A POSTROUTING -o {CONFIG['client_interface']} -j MASQUERADE"
        )
        
        # Forwarding Rules
        run_command(
            f"iptables -A FORWARD -i {CONFIG['ap_interface']} -o {CONFIG['client_interface']} -j ACCEPT"
        )
        run_command(
            f"iptables -A FORWARD -i {CONFIG['client_interface']} -o {CONFIG['ap_interface']} -m state --state RELATED,ESTABLISHED -j ACCEPT"
        )
        
        self.rules_applied = True
        logger.info("✓ NAT configured")
        logger.info(f"  → Traffic from {CONFIG['ap_interface']} will be forwarded to {CONFIG['client_interface']}")
    
    def cleanup(self):
        """Entfernt NAT Rules"""
        if not self.rules_applied:
            return
        
        logger.info("Cleaning up NAT rules...")
        run_command("iptables -t nat -F", check=False)
        run_command("iptables -F", check=False)
        run_command("sysctl -w net.ipv4.ip_forward=0", check=False)
        logger.info("✓ NAT rules removed")

# ============================================================
# TRAFFIC CAPTURE
# ============================================================

class TrafficCapturer:
    """Captured und analysiert den gesamten Traffic"""
    
    def __init__(self):
        self.capture_file = None
        self.packets = []
        self.running = False
        self.capture_thread = None
        self.tcpdump_process = None
    
    def start(self):
        """Startet Traffic Capture"""
        logger.info("=" * 60)
        logger.info("STARTING TRAFFIC CAPTURE")
        logger.info("=" * 60)
        
        # Capture File erstellen
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.capture_file = f"{CONFIG['capture_dir']}/{CONFIG['capture_file_prefix']}_{timestamp}.pcap"
        
        logger.info(f"Capture file: {self.capture_file}")
        
        # tcpdump starten (captured auf beiden Interfaces)
        tcpdump_filter = f"host {CONFIG['camera_ip']} or net 192.168.43.0/24"
        
        cmd = [
            'tcpdump',
            '-i', 'any',  # Alle Interfaces
            '-w', self.capture_file,
            '-U',  # Unbuffered
            '-v',
            tcpdump_filter
        ]
        
        logger.info(f"Starting tcpdump: {' '.join(cmd)}")
        self.tcpdump_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        time.sleep(2)
        
        if self.tcpdump_process.poll() is not None:
            logger.error("tcpdump failed to start!")
            return False
        
        logger.info("✓ tcpdump running")
        
        # Scapy Capture Thread starten (für Live-Analyse)
        self.running = True
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()
        
        logger.info("✓ Live packet analysis started")
        logger.info("=" * 60)
        return True
    
    def _capture_loop(self):
        """Scapy Capture Loop (läuft in separatem Thread)"""
        def packet_handler(pkt):
            if not self.running:
                return
            
            self.packets.append(pkt)
            
            # Analyse für UDP-Pakete (PPPP Protokoll)
            if pkt.haslayer(UDP):
                self._analyze_udp_packet(pkt)
        
        # Capture auf beiden Interfaces
        sniff(
            iface=[CONFIG['ap_interface'], CONFIG['client_interface']],
            prn=packet_handler,
            store=False,
            stop_filter=lambda _: not self.running
        )
    
    def _analyze_udp_packet(self, pkt):
        """Analysiert UDP-Pakete auf PPPP/Artemis Protokoll"""
        if not pkt.haslayer(UDP):
            return
        
        udp_layer = pkt[UDP]
        
        # Prüfe auf relevante Ports
        relevant_ports = [40611, 32100, 32108, 5085]
        if udp_layer.sport not in relevant_ports and udp_layer.dport not in relevant_ports:
            return
        
        # Extrahiere Payload
        payload = bytes(udp_layer.payload)
        if len(payload) < 4:
            return
        
        # Prüfe auf PPPP Magic Byte (0xF1)
        if payload[0] == 0xF1:
            self._log_pppp_packet(pkt, payload)
    
    def _log_pppp_packet(self, pkt, payload):
        """Loggt PPPP Paket Details"""
        ip_layer = pkt[IP]
        udp_layer = pkt[UDP]
        
        # PPPP Header analysieren
        magic = payload[0]
        pkt_type = payload[1]
        length = int.from_bytes(payload[2:4], 'big')
        
        direction = "→" if ip_layer.dst == CONFIG['camera_ip'] else "←"
        
        type_names = {
            0xE1: "INIT",
            0xD0: "LOGIN",
            0xD1: "DATA",
            0xD3: "CTRL",
            0xD4: "MEDIA"
        }
        type_name = type_names.get(pkt_type, f"UNKNOWN({hex(pkt_type)})")
        
        logger.info(
            f"[PPPP {direction}] {ip_layer.src}:{udp_layer.sport} → "
            f"{ip_layer.dst}:{udp_layer.dport} | "
            f"Type: {type_name} | Len: {length} | "
            f"Payload: {payload[:min(32, len(payload))].hex()}"
        )
        
        # Bei Login-Paketen: Token extrahieren
        if pkt_type == 0xD0 and len(payload) > 20:
            if b'ARTEMIS' in payload:
                logger.info(f"  → LOGIN packet detected! Full payload length: {len(payload)}")
                # Token könnte hier dekodiert werden
    
    def stop(self):
        """Stoppt Traffic Capture"""
        logger.info("Stopping traffic capture...")
        
        self.running = False
        
        if self.tcpdump_process:
            self.tcpdump_process.terminate()
            self.tcpdump_process.wait()
        
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        
        logger.info(f"✓ Capture stopped. Total packets: {len(self.packets)}")
        logger.info(f"✓ PCAP saved to: {self.capture_file}")
        
        # Statistiken
        self._print_statistics()
    
    def _print_statistics(self):
        """Gibt Capture-Statistiken aus"""
        logger.info("=" * 60)
        logger.info("CAPTURE STATISTICS")
        logger.info("=" * 60)
        
        udp_count = sum(1 for pkt in self.packets if pkt.haslayer(UDP))
        pppp_count = sum(1 for pkt in self.packets if pkt.haslayer(UDP) and len(bytes(pkt[UDP].payload)) > 0 and bytes(pkt[UDP].payload)[0] == 0xF1)
        
        logger.info(f"Total packets captured: {len(self.packets)}")
        logger.info(f"UDP packets: {udp_count}")
        logger.info(f"PPPP packets: {pppp_count}")
        logger.info(f"Capture file: {self.capture_file}")
        logger.info("=" * 60)

# ============================================================
# MAIN MITM ORCHESTRATOR
# ============================================================

class TrailCamMITM:
    """Haupt-Klasse die alles koordiniert"""
    
    def __init__(self):
        self.ap_manager = AccessPointManager()
        self.camera_manager = CameraConnectionManager()
        self.forwarder = NetworkForwarder()
        self.capturer = TrafficCapturer()
        self.running = False
    
    def setup(self):
        """Initialisiert alle Komponenten"""
        logger.info("=" * 60)
        logger.info("TrailCam MITM Proxy - Setup Phase")
        logger.info("=" * 60)
        
        # Checks
        check_root()
        check_interfaces()
        install_dependencies()
        
        # Capture Directory erstellen
        Path(CONFIG['capture_dir']).mkdir(parents=True, exist_ok=True)
        
        logger.info("✓ Setup complete")
    
    def start(self):
        """Startet MITM Proxy"""
        logger.info("=" * 60)
        logger.info("Starting MITM Proxy...")
        logger.info("=" * 60)
        
        try:
            # 1. Access Point starten
            self.ap_manager.start()
            time.sleep(5)
            
            # 2. Mit Kamera verbinden (auf wlan1)
            if not self.camera_manager.connect():
                logger.error("Failed to connect to camera!")
                return False
            
            time.sleep(3)
            
            # 3. NAT/Forwarding aktivieren
            self.forwarder.enable_ip_forwarding()
            self.forwarder.setup_nat()
            
            # 4. Traffic Capture starten
            if not self.capturer.start():
                logger.error("Failed to start traffic capture!")
                return False
            
            self.running = True
            
            logger.info("=" * 60)
            logger.info("✓ MITM PROXY IS RUNNING")
            logger.info("=" * 60)
            logger.info(f"Smartphone AP: {CONFIG['ap_ssid']} (Password: {CONFIG['ap_password']})")
            logger.info(f"Camera Network: {CONFIG['camera_ssid']} (via {CONFIG['client_interface']})")
            logger.info(f"Traffic is being captured to: {self.capturer.capture_file}")
            logger.info("=" * 60)
            logger.info("Waiting for smartphone to connect...")
            logger.info("Press Ctrl+C to stop")
            logger.info("=" * 60)
            
            return True
            
        except Exception as e:
            logger.error(f"Error during startup: {e}")
            return False
    
    def wait_for_activity(self):
        """Wartet auf Traffic und zeigt Status"""
        try:
            last_count = 0
            while self.running:
                time.sleep(10)
                
                current_count = len(self.capturer.packets)
                if current_count > last_count:
                    logger.info(f"[STATUS] Packets captured: {current_count} (+{current_count - last_count})")
                    last_count = current_count
                
        except KeyboardInterrupt:
            logger.info("\n[INTERRUPT] Received Ctrl+C, stopping...")
            self.running = False
    
    def stop(self):
        """Stoppt MITM Proxy"""
        logger.info("=" * 60)
        logger.info("Stopping MITM Proxy...")
        logger.info("=" * 60)
        
        self.running = False
        
        # In umgekehrter Reihenfolge aufräumen
        self.capturer.stop()
        self.forwarder.cleanup()
        self.camera_manager.disconnect()
        self.ap_manager.stop()
        
        logger.info("=" * 60)
        logger.info("✓ MITM Proxy stopped")
        logger.info("=" * 60)
        logger.info(f"Capture file: {self.capturer.capture_file}")
        logger.info("Analyze with:")
        logger.info(f"  tcpdump -r {self.capturer.capture_file} -X")
        logger.info(f"  wireshark {self.capturer.capture_file}")
        logger.info("=" * 60)

# ============================================================
# MAIN
# ============================================================

def main():
    """Entry Point"""
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║         TrailCam MITM Proxy for Raspberry Pi             ║
    ║              UDP Connection Analysis Tool                 ║
    ║                                                           ║
    ║  Purpose: Analyze UDP connection between Android App     ║
    ║           and KJK230 Camera (Issue #52)                  ║
    ║                                                           ║
    ║  Author: Philibert Schlutzki                             ║
    ║  Date: 2025-12-14                                        ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    mitm = TrailCamMITM()
    
    # Signal Handler für sauberes Beenden
    def signal_handler(sig, frame):
        logger.info("\nReceived signal, shutting down...")
        mitm.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Setup
        mitm.setup()
        
        # Start
        if mitm.start():
            # Warten auf Activity
            mitm.wait_for_activity()
        else:
            logger.error("Failed to start MITM proxy")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
    finally:
        mitm.stop()

if __name__ == '__main__':
    main()
