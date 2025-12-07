# Artemis PPPP Protocol Wrapper - Implementierungsplan

## 🎯 Executive Summary

**Problem:** Die Kamera nutzt **PPPP (P2P Push Proxy Protocol)** von Tutk/CS2 Network als Transport-Layer. Das Artemis-Protokoll läuft **innerhalb** von PPPP-Paketen, nicht direkt über UDP.

**Lösung:** Wrapping aller Artemis-Pakete in PPPP-Header gemäß TCPDump-Analyse.

---

## 📊 Protokoll-Stack

```
┌─────────────────────────────────────────┐
│  Application Layer (Python Client)     │
├─────────────────────────────────────────┤
│  Artemis Protocol (Discovery/Login)    │  ← Bestehende Implementation
│  - 0xF1 0xE0 (Discovery)                │
│  - 0xF1 0xD0 (Login)                    │
├─────────────────────────────────────────┤
│  PPPP Session Layer                     │  ← **NEU: Zu implementieren**
│  - Header Wrapping                      │
│  - Dual Sequence Numbers                │
│  - Session Type Mapping                 │
├─────────────────────────────────────────┤
│  UDP/IP (Port 40611)                    │
└─────────────────────────────────────────┘
```

---

## 🔬 PPPP Paket-Struktur (aus TCPDump-Analyse)

### **Vollständiges Paket-Format**

```
┌──────────────────────────────────────────────────────────┐
│  PPPP Outer Header (4 bytes)                             │
├──────────────────────────────────────────────────────────┤
│  Byte 0:    0xF1         = PPPP Magic                    │
│  Byte 1:    0xD1/0xD3    = PPPP Command Type             │
│  Bytes 2-3: Length       = Payload length (Big Endian)   │
└──────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────┐
│  PPPP Inner Header (4 bytes)                             │
├──────────────────────────────────────────────────────────┤
│  Byte 4:    0xD1/0xD3    = Session Type                  │
│  Byte 5:    Subcommand   = 0x00 (Discovery), 0x03 (Login)│
│  Bytes 6-7: PPPP Seq     = Sequence Number (Big Endian)  │
└──────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────┐
│  Artemis Payload (Variable)                              │
├──────────────────────────────────────────────────────────┤
│  Artemis-specific data (token, commands, etc.)           │
└──────────────────────────────────────────────────────────┘
```

### **Beispiele aus TCPDump**

#### **Discovery Paket**
```hex
f1 d1 00 06    ← PPPP Outer Header (Magic: 0xF1, Type: 0xD1, Length: 6)
d1 00 00 01    ← PPPP Inner Header (Type: 0xD1, Sub: 0x00, Seq: 1)
00 1b          ← Artemis Payload (Discovery Seq: 0x001B)

Total: 10 bytes
```

#### **Login Paket**
```hex
f1 d1 00 26    ← PPPP Outer Header (Length: 0x26 = 38 bytes)
d1 03 00 11    ← PPPP Inner Header (Sub: 0x03 = Login, Seq: 0x0011)
[38 bytes Artemis Login Payload]
  - "ARTEMIS\x00"
  - Version (0x02000000)
  - Mystery bytes (0x2b000000 0x2d000000)
  - Token length + token

Total: 46 bytes (4 + 4 + 38)
```

---

## 🔑 Wichtige Erkenntnisse

### **1. Dual Sequence Numbers**

**Es gibt ZWEI unabhängige Sequenznummern:**

| Sequenz | Offset | Typ | Zweck |
|---------|--------|-----|-------|
| **PPPP Seq** | Bytes 6-7 | Big Endian 16-bit | PPPP-Layer Packet Tracking |
| **Artemis Seq** | Variiert | Big Endian 16-bit | Artemis-Protokoll Session |

**Beide müssen separat hochgezählt werden!**

```python
self.pppp_seq = 1       # PPPP Layer
self.artemis_seq = 0x001B  # Artemis Layer (aus BLE)
```

### **2. PPPP Session Types**

| Outer Type | Inner Type | Subcommand | Verwendung |
|------------|------------|------------|------------|
| 0xD1 | 0xD1 | 0x00 | Discovery Request |
| 0xD1 | 0xD1 | 0x01 | Discovery Response |
| 0xD1 | 0xD1 | 0x03 | Login Request |
| 0xD1 | 0xD1 | 0x04 | Login Response |
| 0xD3 | 0xD3 | 0x01 | Heartbeat/Control |
| 0xD4 | 0xD4 | 0x11 | Data Transfer (Video/Files) |

### **3. Dynamic Length Calculation**

PPPP Length = `len(Inner Header) + len(Artemis Payload)` = `4 + payload_len`

```python
pppp_length = 4 + len(artemis_payload)  # Inner header + payload
```

---

## 🛠️ Implementation Plan

### **Phase 1: PPPP Wrapper Class** ✅

**Datei:** `modules/pppp_wrapper.py`

**Funktionen:**
- `wrap_pppp(artemis_payload, session_type, subcommand)` → bytes
- `unwrap_pppp(packet)` → dict mit `{pppp_seq, artemis_payload}`
- `increment_pppp_seq()` → void

**Test:** `tests/test_pppp_wrapper.py`

### **Phase 2: CameraClient Integration** 🔄

**Modifikationen in `modules/camera_client.py`:**

1. **Import PPPP Wrapper**
   ```python
   from modules.pppp_wrapper import PPPPWrapper
   ```

2. **Initialisierung**
   ```python
   def __init__(self, ...):
       self.pppp = PPPPWrapper(logger=self.logger)
       self.seq_num = 1  # Artemis Seq
   ```

3. **Discovery mit PPPP**
   ```python
   def discovery_phase(self):
       # Alter Code:
       # discovery_packet = b'\xF1\xE0\x00\x00'
       
       # Neuer Code:
       artemis_payload = struct.pack('>H', self.seq_num)
       discovery_packet = self.pppp.wrap_discovery(artemis_payload)
       self.seq_num += 1
   ```

4. **Login mit PPPP**
   ```python
   def login(self, variant='BLE_DYNAMIC'):
       artemis_payload = self._build_login_payload(variant)
       login_packet = self.pppp.wrap_login(artemis_payload)
       response = self.send_raw_packet(login_packet)
   ```

5. **Response Parsing**
   ```python
   def _parse_response(self, raw_data):
       parsed = self.pppp.unwrap_pppp(raw_data)
       pppp_type = parsed['inner_type']
       pppp_sub = parsed['subcommand']
       artemis_data = parsed['payload']
       return artemis_data
   ```

### **Phase 3: BLE Integration** ✅ (bereits implementiert)

**Die Mystery Bytes sind aus BLE gelöst:**

```python
# In ble_token_listener.py:
return {
    "token": token_str,
    "sequence": sequence  # Diese 4 Bytes!
}

# In camera_client.py:
self.sequence_bytes = ble_result['sequence']
```

**Verwendung im Login:**
```python
if variant == 'BLE_DYNAMIC' and self.sequence_bytes:
    mystery_bytes = self.sequence_bytes + self.sequence_bytes  # 8 bytes total
else:
    mystery_bytes = MYSTERY_VARIANTS[variant]
```

### **Phase 4: Testing & Validation** 🧪

**Testszenarien:**

1. **Unit Tests**
   - PPPP Wrapper korrekt
   - Sequence Number Handling
   - Length Calculation

2. **Integration Tests**
   - Discovery → Response
   - Login → Success
   - Heartbeat → Keepalive

3. **TCPDump Validation**
   - Gesendete Pakete = TCPDump Pattern
   - Responses werden korrekt geparst

---

## 📝 Code-Beispiele

### **PPPP Wrapper Class**

```python
import struct
import logging

class PPPPWrapper:
    """Wrapper for PPPP protocol layer."""
    
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.pppp_seq = 1
    
    def wrap_pppp(self, payload: bytes, outer_type: int, inner_type: int, subcommand: int) -> bytes:
        """
        Wrap Artemis payload in PPPP headers.
        
        Args:
            payload: Artemis protocol payload
            outer_type: PPPP outer command type (0xD1, 0xD3, etc.)
            inner_type: PPPP inner session type
            subcommand: Subcommand byte (0x00, 0x03, etc.)
        
        Returns:
            Complete PPPP packet ready to send
        """
        # Inner Header (4 bytes)
        inner_header = struct.pack('>BBH', inner_type, subcommand, self.pppp_seq)
        
        # Outer Header (4 bytes)
        pppp_payload = inner_header + payload
        outer_header = struct.pack('>BBH', 0xF1, outer_type, len(pppp_payload))
        
        packet = outer_header + pppp_payload
        
        self.logger.debug(
            f"[PPPP] Wrapped: Outer=0xD{outer_type:X}, Inner=0xD{inner_type:X}, "
            f"Sub=0x{subcommand:02X}, Seq={self.pppp_seq}, Len={len(payload)}"
        )
        
        self.pppp_seq += 1
        return packet
    
    def wrap_discovery(self, artemis_seq: int) -> bytes:
        """Wrap discovery packet."""
        payload = struct.pack('>H', artemis_seq)
        return self.wrap_pppp(payload, outer_type=0xD1, inner_type=0xD1, subcommand=0x00)
    
    def wrap_login(self, artemis_payload: bytes) -> bytes:
        """Wrap login packet."""
        return self.wrap_pppp(artemis_payload, outer_type=0xD1, inner_type=0xD1, subcommand=0x03)
    
    def wrap_heartbeat(self, artemis_seq: int) -> bytes:
        """Wrap heartbeat packet."""
        payload = struct.pack('>HH', artemis_seq, 0x0000)
        return self.wrap_pppp(payload, outer_type=0xD3, inner_type=0xD3, subcommand=0x01)
    
    def unwrap_pppp(self, packet: bytes) -> dict:
        """
        Unwrap PPPP packet to extract Artemis payload.
        
        Returns:
            {
                'outer_magic': 0xF1,
                'outer_type': 0xD1,
                'length': 38,
                'inner_type': 0xD1,
                'subcommand': 0x04,
                'pppp_seq': 17,
                'payload': b'...',  # Artemis data
            }
        """
        if len(packet) < 8:
            raise ValueError(f"Packet too short: {len(packet)} bytes")
        
        # Parse Outer Header
        outer_magic, outer_type, length = struct.unpack('>BBH', packet[0:4])
        
        # Parse Inner Header
        inner_type, subcommand, pppp_seq = struct.unpack('>BBH', packet[4:8])
        
        # Extract Artemis Payload
        artemis_payload = packet[8:]
        
        self.logger.debug(
            f"[PPPP] Unwrapped: Outer=0x{outer_type:02X}, Inner=0x{inner_type:02X}, "
            f"Sub=0x{subcommand:02X}, Seq={pppp_seq}, Payload={len(artemis_payload)} bytes"
        )
        
        return {
            'outer_magic': outer_magic,
            'outer_type': outer_type,
            'length': length,
            'inner_type': inner_type,
            'subcommand': subcommand,
            'pppp_seq': pppp_seq,
            'payload': artemis_payload,
        }
```

### **Integration in CameraClient**

```python
class CameraClient:
    def __init__(self, camera_ip=None, logger=None):
        # ... existing code ...
        self.pppp = PPPPWrapper(logger=self.logger)
        self.artemis_seq = 0x001B  # Start value from BLE
    
    def discovery_phase(self) -> bool:
        """Send PPPP-wrapped discovery."""
        self._set_state(CameraState.DISCOVERING, "starting discovery")
        
        # Build PPPP-wrapped discovery packet
        packet = self.pppp.wrap_discovery(self.artemis_seq)
        self.artemis_seq += 1
        
        self.logger.info(f"[DISCOVERY] Sending PPPP Discovery: {packet.hex()}")
        
        try:
            self.sock.sendto(packet, (self.ip, self.port))
            data, addr = self.sock.recvfrom(2048)
            
            # Parse PPPP response
            response = self.pppp.unwrap_pppp(data)
            
            if response['subcommand'] == 0x01:  # Discovery ACK
                self.logger.info(f"[DISCOVERY] ✓ ACK received")
                self._set_state(CameraState.DISCOVERED, f"on port {self.active_port}")
                return True
            else:
                self.logger.warning(f"[DISCOVERY] Unexpected subcommand: 0x{response['subcommand']:02X}")
                return False
                
        except socket.timeout:
            self.logger.warning("[DISCOVERY] Timeout")
            return False
    
    def login(self, variant: str = 'BLE_DYNAMIC') -> bool:
        """Send PPPP-wrapped login."""
        if not self.session_token:
            self.logger.error("[LOGIN] No session token")
            return False
        
        # Build Artemis login payload
        artemis_payload = self._build_login_payload(variant)
        
        # Wrap in PPPP
        packet = self.pppp.wrap_login(artemis_payload)
        
        self.logger.info(f"[LOGIN] Sending PPPP Login ({len(packet)} bytes)")
        
        try:
            self.sock.sendto(packet, (self.ip, self.port))
            data, addr = self.sock.recvfrom(2048)
            
            # Parse PPPP response
            response = self.pppp.unwrap_pppp(data)
            
            if response['subcommand'] == 0x04:  # Login ACK
                self.logger.info("[LOGIN] ✓ SUCCESS")
                self._set_state(CameraState.AUTHENTICATED, f"variant {variant}")
                self.start_heartbeat()
                return True
            else:
                self.logger.error(f"[LOGIN] Failed. Subcommand: 0x{response['subcommand']:02X}")
                return False
                
        except socket.timeout:
            self.logger.error("[LOGIN] Timeout")
            return False
```

---

## ✅ Checkliste

### **Phase 1: PPPP Wrapper** 🔄

- [ ] Erstelle `modules/pppp_wrapper.py`
- [ ] Implementiere `wrap_pppp()`
- [ ] Implementiere `unwrap_pppp()`
- [ ] Implementiere `wrap_discovery()`
- [ ] Implementiere `wrap_login()`
- [ ] Implementiere `wrap_heartbeat()`
- [ ] Unit Tests für alle Funktionen

### **Phase 2: CameraClient Integration** 🔄

- [ ] Import PPPPWrapper in `camera_client.py`
- [ ] Initialisiere `self.pppp` in `__init__()`
- [ ] Update `discovery_phase()` mit PPPP wrapping
- [ ] Update `login()` mit PPPP wrapping
- [ ] Update Response Parsing
- [ ] Update Heartbeat mit PPPP wrapping
- [ ] Test Discovery + Login Flow

### **Phase 3: Validation** 🧪

- [ ] TCPDump Capture während Test
- [ ] Vergleiche gesendete Pakete mit Original TCPDump
- [ ] Verify Sequence Numbers korrekt
- [ ] Verify Response Parsing
- [ ] Test mit echter Kamera

### **Phase 4: Documentation** 📝

- [ ] Update README.md
- [ ] Docstrings für neue Funktionen
- [ ] Beispiel-Code für Nutzer
- [ ] Troubleshooting Guide

---

## 🐛 Bekannte Probleme & Lösungen

### **Problem 1: Mystery Bytes im Login**

**Status:** ✅ GELÖST

**Lösung:** Die 8 Mystery Bytes kommen aus BLE:
```python
sequence_bytes = ble_result['sequence']  # 4 bytes from BLE
mystery_bytes = sequence_bytes + sequence_bytes  # Duplicate to 8 bytes
```

### **Problem 2: Dual Sequence Numbers**

**Status:** ✅ GELÖST

**Lösung:** Separate Tracking:
```python
self.pppp_seq = 1       # PPPP Layer (managed by PPPPWrapper)
self.artemis_seq = 0x001B  # Artemis Layer (from BLE or manual)
```

### **Problem 3: Response Timeout**

**Status:** 🔄 IN PROGRESS

**Mögliche Ursachen:**
- PPPP Header fehlt → Kamera ignoriert Paket
- Falsche Sequence Number → Kamera rejected
- Port-Binding Problem → Antwort geht an falschen Port

**Debug:**
```bash
# TCPDump auf Server
sudo tcpdump -i any -s0 -X "udp port 40611" -w debug.pcap

# Wireshark Filter
udp.port == 40611 && udp.length > 4
```

---

## 🚀 Nächste Schritte

1. **Implementiere `pppp_wrapper.py`** (siehe Code-Beispiel oben)
2. **Teste Unit Tests** mit bekannten TCPDump-Paketen
3. **Integriere in `camera_client.py`**
4. **Führe `test_pppp_artemis.py` aus** (siehe nächste Datei)
5. **Capture mit TCPDump** und vergleiche Output
6. **Iteriere** basierend auf Kamera-Response

---

## 📚 Referenzen

- **TCPDump Log:** `tcpdump_1800_connect.log`
- **libArLink.so Strings:** `arlink_strings.txt`
- **PPPP SDK Dokumentation:** Tutk/CS2 Network (proprietär)
- **Bestehender Code:**
  - `modules/camera_client.py`
  - `modules/ble_token_listener.py`
  - `tests/test_camera_client.py`

---

## 📞 Support

Bei Fragen oder Problemen:
1. Check TCPDump logs
2. Verify PPPP Header mit Hex-Dump
3. Test mit `test_pppp_artemis.py`
4. Open GitHub Issue mit:
   - TCPDump Output
   - Python Log Output
   - Erwartetes vs. Aktuelles Verhalten
