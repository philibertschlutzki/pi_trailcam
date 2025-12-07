# PPPP Protocol Testing Guide

## 📚 Overview

Dieses Verzeichnis enthält Tests und Dokumentation für die PPPP (P2P Push Proxy Protocol) Integration in das TrailCam-Projekt.

**PPPP** ist ein proprietäres Protokoll von Tutk/CS2 Network, das als Transport-Layer für das Artemis-Kamera-Protokoll dient.

---

## 📁 Dateien

### **Dokumentation**
- [`Artemis_PPPP_wrapper.md`](Artemis_PPPP_wrapper.md) - Vollständiger Implementierungsplan

### **Tests**
- [`test_pppp_artemis.py`](test_pppp_artemis.py) - Umfassende Test-Suite
- [`test_camera_client.py`](test_camera_client.py) - Legacy Unit Tests (wird aktualisiert)

### **Implementation**
- [`../modules/pppp_wrapper.py`](../modules/pppp_wrapper.py) - PPPP Wrapper-Klasse
- [`../modules/camera_client.py`](../modules/camera_client.py) - Kamera-Client (nutzt PPPP)

---

## 🚀 Quick Start

### **1. Unit Tests (kein Kamera-Hardware nötig)**

```bash
# Nur PPPP Wrapper Tests
python tests/test_pppp_artemis.py --unit-only
```

**Erwartete Ausgabe:**
```
======================================================================
  UNIT TESTS
======================================================================

[TEST] PPPP Discovery Packet Wrapping
👍 [✓ PASS] PPPP Discovery Wrapper
    Packet: f1d10006d10000010001b (10 bytes)

[TEST] PPPP Login Packet Wrapping
👍 [✓ PASS] PPPP Login Wrapper
    Packet: 46 bytes, Token: MzlB36X/IVo8ZzI5rG9j...

[TEST] PPPP Packet Unwrapping
👍 [✓ PASS] PPPP Packet Unwrapping
    Parsed: Seq=1, Artemis=0x001B

🎯 OVERALL: 3/3 tests passed
🎉 ALL TESTS PASSED! PPPP Wrapper is working correctly.
```

---

### **2. Integration Tests (benötigt Kamera)**

#### **Voraussetzungen:**
1. Kamera eingeschaltet und WiFi aktiv
2. Raspberry Pi mit Kamera-WiFi verbunden
3. BLE Token extrahiert (optional, Fallback vorhanden)

#### **BLE Token extrahieren:**

```bash
# Mit Hauptprogramm
python main.py --ble-only

# Token wird in ble_token_cache.txt gespeichert
```

#### **Tests ausführen:**

```bash
# Alle Tests mit Standard-Kamera-IP (aus config.py)
python tests/test_pppp_artemis.py

# Mit custom Kamera-IP
python tests/test_pppp_artemis.py --camera 192.168.43.1

# Verbose Logging
python tests/test_pppp_artemis.py --verbose
```

**Erwartete Ausgabe:**
```
======================================================================
  PPPP + ARTEMIS PROTOCOL TEST SUITE
======================================================================

======================================================================
  UNIT TESTS
======================================================================
👍 [✓ PASS] PPPP Discovery Wrapper
👍 [✓ PASS] PPPP Login Wrapper
👍 [✓ PASS] PPPP Packet Unwrapping

======================================================================
  INTEGRATION TESTS
======================================================================

[TEST] Discovery Integration Test
[>] Sending discovery: f1d10006d10000010001b
[<] Response from ('192.168.43.1', 40611): f1d10006d10100020020
👍 [✓ PASS] Discovery Integration
    Got ACK from ('192.168.43.1', 40611)

======================================================================
  FULL INTEGRATION TEST
======================================================================

[STEP 1] Initialize CameraClient with PPPP wrapper
[STEP 2] Check for BLE token
[BLE] Loaded cached token: MzlB36X/IVo8ZzI5rG9j...
[BLE] Sequence: 2b000000
[STEP 3] Discovery phase
[STEP 3] ✓ Discovery successful
[STEP 4] Login phase
[STEP 4] ✓ Login successful
[STEP 5] Send heartbeat
[STEP 5] ✓ Heartbeat thread running
[STEP 6] Cleanup
👍 [✓ PASS] Full Integration Test
    Complete flow: BLE → Discovery → Login → Heartbeat

======================================================================
  TEST SUMMARY
======================================================================
Unit Tests: 3/3 passed
Integration Tests: 2/2 passed

🎯 OVERALL: 5/5 tests passed
🎉 ALL TESTS PASSED! PPPP Wrapper is working correctly.
```

---

### **3. Mit TCPDump Debugging**

Für detailliertes Protokoll-Debugging:

```bash
# Terminal 1: Start TCPDump
sudo tcpdump -i any -s0 -X "udp port 40611" -w pppp_test.pcap

# Terminal 2: Run Tests
python tests/test_pppp_artemis.py --verbose

# Terminal 1: Stop TCPDump (Ctrl+C)
# Dann analysieren:
wireshark pppp_test.pcap
```

**Wireshark Filter:**
```
udp.port == 40611 && udp.length > 4
```

---

## 🔍 Troubleshooting

### **Problem: Discovery Timeout**

**Symptom:**
```
[✗ FAIL] Discovery Integration
    Timeout waiting for response
```

**Lösungen:**
1. **Kamera-IP prüfen:**
   ```bash
   ping 192.168.43.1
   ```

2. **Port 40611 offen?**
   ```bash
   nmap -sU -p 40611 192.168.43.1
   ```

3. **WiFi-Verbindung:**
   ```bash
   iwconfig
   # Sollte zeigen: ESSID:"KJK_..."
   ```

4. **TCPDump prüfen:**
   - Werden Pakete gesendet?
   - Kommt eine Response zurück?

---

### **Problem: Login Failed**

**Symptom:**
```
[✗ FAIL] Full Integration - Login
    Login failed
```

**Lösungen:**

1. **BLE Token aktuell?**
   ```bash
   # Token ist nur ~5-10 Minuten gültig
   # Neu extrahieren:
   python main.py --ble-only
   ```

2. **Mystery Bytes korrekt?**
   ```bash
   # In test output prüfen:
   [BLE] Sequence: 2b000000
   # Sollte 4 bytes sein, nicht leer
   ```

3. **PPPP Wrapper korrekt?**
   ```bash
   # Unit Tests laufen lassen:
   python tests/test_pppp_artemis.py --unit-only
   # Alle sollten PASS sein
   ```

4. **TCPDump analysieren:**
   - Vergleiche gesendetes Login-Paket mit `tcpdump_1800_connect.log`
   - Header sollten identisch sein

---

### **Problem: PPPP Wrapper Unit Tests Failed**

**Symptom:**
```
[✗ FAIL] PPPP Discovery Wrapper
    Wrong outer magic: 0xF0
```

**Lösung:**

Das deutet auf einen Bug in `pppp_wrapper.py` hin.

1. **Check Implementation:**
   ```python
   # In modules/pppp_wrapper.py
   PPPP_MAGIC = 0xF1  # Sollte 0xF1 sein!
   ```

2. **Verify Struct Pack:**
   ```python
   # Big Endian?
   struct.pack('>BBH', 0xF1, 0xD1, 6)
   # Sollte: b'\xf1\xd1\x00\x06'
   ```

3. **Test manuell:**
   ```python
   from modules.pppp_wrapper import PPPPWrapper
   pppp = PPPPWrapper()
   packet = pppp.wrap_discovery(0x001B)
   print(packet.hex())  # Sollte: f1d10006d10000010001b
   ```

---

## 📊 Test Coverage

### **Unit Tests (PPPP Wrapper)**

| Test | Was wird getestet | Status |
|------|-------------------|--------|
| `test_pppp_wrapper_discovery` | Discovery Paket-Struktur | ✅ |
| `test_pppp_wrapper_login` | Login Paket-Struktur | ✅ |
| `test_pppp_unwrap` | Response Parsing | ✅ |

### **Integration Tests (Mit Kamera)**

| Test | Was wird getestet | Benötigt |
|------|-------------------|----------|
| `test_discovery_integration` | Discovery Request/Response | Kamera WiFi |
| `test_full_integration` | BLE + Discovery + Login + Heartbeat | Kamera WiFi + BLE |

---

## 📦 Erwartete Pakete (Referenz)

### **Discovery Request**
```hex
f1 d1 00 06  ← PPPP Outer: Magic=0xF1, Type=0xD1, Len=6
d1 00 00 01  ← PPPP Inner: Type=0xD1, Sub=0x00, Seq=1
00 1b        ← Artemis: Seq=0x001B

Total: 10 bytes
```

### **Discovery Response**
```hex
f1 d1 00 06  ← PPPP Outer
d1 01 00 02  ← PPPP Inner: Sub=0x01 (ACK), Seq=2
00 20        ← Artemis: Response data

Total: 10 bytes
```

### **Login Request**
```hex
f1 d1 00 26  ← PPPP Outer: Len=38 (0x26)
d1 03 00 11  ← PPPP Inner: Sub=0x03 (Login), Seq=17
[38 bytes Artemis Login]
  41 52 54 45 4d 49 53 00  ← "ARTEMIS\x00"
  02 00 00 00              ← Version 2.0
  2b 00 00 00 2b 00 00 00  ← Mystery bytes (from BLE)
  16 00 00 00              ← Token length = 22
  4d 7a 6c 42 ... 00       ← Token + null terminator

Total: 46 bytes (4 + 4 + 38)
```

### **Login Response**
```hex
f1 d1 [LEN]  ← PPPP Outer
d1 04 [SEQ]  ← PPPP Inner: Sub=0x04 (Login ACK)
[Response data]
```

---

## 📝 Best Practices

### **Beim Schreiben von Tests**

1. **Immer Unit Tests zuerst:**
   ```bash
   python tests/test_pppp_artemis.py --unit-only
   ```
   Nur wenn diese PASS sind, Integration Tests.

2. **TCPDump bei Integration Tests:**
   - Hilft bei Debugging
   - Zeigt exakt was gesendet/empfangen wird

3. **BLE Token Cache nutzen:**
   ```bash
   # Token einmal holen
   python main.py --ble-only
   
   # Dann mehrfach testen ohne BLE
   python tests/test_pppp_artemis.py  # nutzt Cache
   python tests/test_pppp_artemis.py  # nutzt Cache
   ```

4. **Verbose Logging bei Problemen:**
   ```bash
   python tests/test_pppp_artemis.py --verbose 2>&1 | tee test_output.log
   ```

### **Beim Debuggen**

1. **Hex-Dumps vergleichen:**
   ```python
   # Im Code:
   self.logger.debug(f"Sent: {packet.hex()}")
   self.logger.debug(f"Recv: {response.hex()}")
   ```

2. **PPPP Sequence Numbers tracken:**
   - Sollten kontinuierlich hochzählen
   - Reset bei neuer Session

3. **Byte Order prüfen:**
   ```python
   # Big Endian (PPPP):
   struct.pack('>H', 0x001B)  # = b'\x00\x1b'
   
   # Little Endian (Artemis Version):
   struct.pack('<I', 0x02000000)  # = b'\x00\x00\x00\x02'
   ```

---

## 🔗 Referenzen

- **Implementierungsplan:** [Artemis_PPPP_wrapper.md](Artemis_PPPP_wrapper.md)
- **PPPP Wrapper Code:** [`../modules/pppp_wrapper.py`](../modules/pppp_wrapper.py)
- **TCPDump Log:** `tcpdump_1800_connect.log` (im Projekt-Root)
- **libArLink.so Strings:** `arlink_strings.txt` (im Projekt-Root)

---

## ❓ Support

Bei Problemen:

1. **Check Logs:** `--verbose` Flag nutzen
2. **TCPDump:** Pakete mit Original vergleichen
3. **Unit Tests:** `--unit-only` zuerst prüfen
4. **GitHub Issue:** Mit Logs + TCPDump Output

---

## ✅ Success Criteria

**Unit Tests:**
```
🎯 OVERALL: 3/3 tests passed
```

**Integration Tests:**
```
🎯 OVERALL: 5/5 tests passed
🎉 ALL TESTS PASSED!
```

**Produktiv-Nutzung:**
- Discovery erfolgreich
- Login erfolgreich
- Heartbeat läuft
- Kamera antwortet auf Commands

---

**Happy Testing! 🚀**
