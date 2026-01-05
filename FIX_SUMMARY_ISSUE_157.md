# Fix Summary: Issue #157 - Login Timeout

**Issue**: #157  
**Datum**: 2026-01-05  
**Version**: v4.16  
**Status**: ✅ Implementiert (Hardware-Test ausstehend)

---

## Problem

Das Login schlägt mit folgendem Fehler fehl:
```
❌ Login Timeout (no token received, 0 MsgType=3 packets buffered)
```

Die Kamera sendet keine Login-Response (MsgType=3) mit dem erforderlichen Token.

---

## Root Cause Analysis

Detaillierte Analyse der MITM-Captures (ble_udp_1.log) zeigt, dass die funktionierende App:

1. Den **Login-Request dreimal** sendet (Zeilen 378, 402, 417)
2. Alle drei mit **identischer RUDP Seq=0** und **AppSeq=1**
3. Die Kamera erst **nach dem dritten Request** antwortet (Zeile 463)

Dies ist **kein** Retry-Mechanismus bei Fehlern, sondern **erwartetes Protokollverhalten**.

### MITM-Sequenz (funktionierende App):

| Zeile | Paket | RUDP Seq | ARTEMIS | Beschreibung |
|-------|-------|----------|---------|--------------|
| 378 | TX | 0 | MsgType=2, AppSeq=1 | **Login Request #1** |
| 393 | TX | 3 | - | **Magic1 Handshake** |
| 396 | RX | 0 | - | ACK von Kamera |
| 402 | TX | 0 | MsgType=2, AppSeq=1 | **Login Request #2** ← FEHLT in v4.15! |
| 417 | TX | 0 | MsgType=2, AppSeq=1 | **Login Request #3** ← FEHLT in v4.15! |
| 463 | RX | 1 | **MsgType=3, AppSeq=1** | **Login Response** ✅ |

### Fehlerhafte Sequenz (v4.15):

```
Login#1 (Seq=0) → Magic1 (Seq=3) → [WARTEN] → TIMEOUT ❌
```

### Korrekte Sequenz (v4.16):

```
Login#1 (Seq=0) → Magic1 (Seq=3) → Login#2 (Seq=0) → Login#3 (Seq=0) → Response ✅
```

---

## Implementierte Lösung

### Änderungen in `get_thumbnail_perp.py` (v4.16)

**Zeilen 1151-1184**: Login-Handshake erweitert um zwei Retransmissions

```python
# Step 1: Login#1
login_pkt, _ = self.build_packet(0xD0, login_body, force_seq=0)
self.send_raw(login_pkt, desc=f"Login#1(cmdId=0,AppSeq={login_app_seq})")

# Step 1b: Magic1 Handshake
magic1_pkt, _ = self.build_packet(0xD1, MAGIC_BODY_1, force_seq=3)
self.send_raw(magic1_pkt, desc="Magic1")
time.sleep(MAGIC1_PROCESSING_DELAY)

# Step 1c: Pump immediate responses (ACKs)
self.pump(timeout=0.1, accept_predicate=lambda _: False, filter_evt=False)

# Step 1d: Login#2 (RETRANSMIT - same Seq=0, same body!)
login_pkt2, _ = self.build_packet(0xD0, login_body, force_seq=0)
self.send_raw(login_pkt2, desc=f"Login#2(cmdId=0,AppSeq={login_app_seq})")

# Step 1e: Login#3 (RETRANSMIT - same Seq=0, same body!)
login_pkt3, _ = self.build_packet(0xD0, login_body, force_seq=0)
self.send_raw(login_pkt3, desc=f"Login#3(cmdId=0,AppSeq={login_app_seq})")

# Step 2: NOW wait for response (camera should respond after triple transmission)
logger.info(">>> Login Handshake Step 2: Wait for Login Response...")
```

### Kritische Details:

1. **Gleiche RUDP-Seq**: Alle drei Login-Requests verwenden `force_seq=0`
   - Dies ist eine echte Retransmission im RUDP-Sinne
   
2. **Gleiches AppSeq**: Alle drei haben `AppSeq=1`
   - Gleiche logische Anfrage auf Application-Layer
   
3. **Identischer Payload**: Alle drei verwenden `login_body`
   - Wichtig: Gleicher verschlüsselter JSON (gleicher `utcTime`!)
   
4. **Kurze Pausen**: 0.1s zwischen Login#1 und Login#2/3
   - Basierend auf MITM-Timing-Analyse

---

## Erwartetes Verhalten

Nach diesem Fix sollte das Debug-Log wie folgt aussehen:

```
>>> Login Handshake Step 1: Send Login Request (cmdId=0, AppSeq=1)
🔐 Login JSON: {"cmdId":0,"usrName":"admin",...}
🔧 build_artemis_frame: MsgType=2, AppSeq=1, BodyLen=173
📊 Login packet: RUDP seq=0, ARTEMIS MsgType=2, AppSeq=1
📤 RUDP DATA Seq=0 BodyLen=197 ... Login#1(cmdId=0,AppSeq=1)

>>> Login Handshake Step 1b: Send Magic1 packet
📤 RUDP ACK Seq=3 BodyLen=10 ... Magic1

>>> Login Handshake Step 1c: Retransmit Login #2
📤 RUDP DATA Seq=0 BodyLen=197 ... Login#2(cmdId=0,AppSeq=1)

>>> Login Handshake Step 1d: Retransmit Login #3
📤 RUDP DATA Seq=0 BodyLen=197 ... Login#3(cmdId=0,AppSeq=1)

>>> Login Handshake Step 2: Wait for Login Response (MsgType=3, AppSeq=1)
📥 RUDP DATA Seq=1 ... | ARTEMIS MsgType=3 AppSeq=1        ← ERWARTET!
✅ Login Response detected: MsgType=3, AppSeq=1
✅ Login Response received (MsgType=3)

>>> Extracting token from Login Response (AppSeq=1)...
✅ TOKEN OK (login, strict) app_seq=1 token_len=XXX        ← ERFOLG!
```

---

## Historischer Kontext

### Evolution der Fixes:

| Version | Problem | Fix | Status |
|---------|---------|-----|--------|
| v4.13 | FRAG-Pakete nicht ge-ACKt | ACK-Logik für FRAG hinzugefügt | ✅ Behoben |
| v4.14 | Falsche RUDP-Seq für Login | `force_seq=0` für Login implementiert | ✅ Behoben |
| v4.15 | Magic1-Paket fehlt | `force_seq=3` für Magic1 hinzugefügt | ✅ Behoben |
| **v4.16** | **Login-Retransmissions fehlen** | **Login#2 und Login#3 hinzugefügt** | ✅ **IMPLEMENTIERT** |

### Debug-Log-Evolution:

1. **debug05012026_1.log**: FRAG-ACK-Problem
   - `FRAG ohne ARTEMIS-Signatur; skip reassembly/ack`
   
2. **debug05012026_2.log**: Login mit falscher Seq
   - `RUDP DATA Seq=1` (statt Seq=0)
   
3. **debug05012026_3.log**: Login-Seq korrigiert, aber Magic1 fehlt
   - `RUDP DATA Seq=0` ✅ aber keine Magic1
   
4. **debug05012026_4.log**: Login-Seq und Magic1 OK, aber keine Retransmissions
   - `RUDP DATA Seq=0` ✅
   - `RUDP ACK Seq=3` (Magic1) ✅
   - **ABER**: Nur ein Login-Request → Keine Response ❌

---

## Validierung

### Code-Qualität:
- ✅ Python-Syntax-Check bestanden
- ✅ CodeQL Security Scan: 0 Alerts
- ✅ Vorhandene Tests (test_ack_format_and_mitm_login.py) bestanden

### Hardware-Test:
- ⏳ Ausstehend (erfordert physische Kamera)
- Erwartung: Login-Success mit Token-Extraktion

---

## Referenzen

- **Issue**: [#157](https://github.com/philibertschlutzki/pi_trailcam/issues/157)
- **Detaillierte Analyse**: `ANALYSE_KONSOLIDIERT_LOGIN.md`
- **Hypothesen-Dokument**: `HYPOTHESEN_LOGIN_FEHLER.md`
- **Protokoll-Spezifikation**: `Protocol_analysis.md`
- **MITM-Capture**: `tests/MITM_Captures/ble_udp_1.log` (Zeilen 378-475)
- **Implementierung**: `get_thumbnail_perp.py` (v4.16)

---

## Nächste Schritte

1. ✅ Code implementiert
2. ✅ Dokumentation erstellt
3. ✅ Security-Scan durchgeführt
4. ⏳ Hardware-Test (durch Benutzer)
5. ⏳ Feedback und ggf. Nachbesserung

---

## Technische Notizen

### Warum sendet die App den Login dreimal?

**Theorie 1: Kamera-Firmware-Initialisierung**
- Die Kamera benötigt möglicherweise Zeit, um den Empfangszustand zu initialisieren
- Die ersten Requests dienen als "Wake-Up" oder Zustandsvorbereitung

**Theorie 2: Protokoll-Design für UDP-Robustheit**
- UDP ist unzuverlässig (keine garantierte Zustellung)
- Dreifache Übertragung erhöht Erfolgswahrscheinlichkeit drastisch
- Wurde wahrscheinlich in die Firmware "hart kodiert"

**Theorie 3: Timing/Synchronisation**
- Die Kamera könnte auf eine bestimmte Sequenz von Paketen warten
- Die Kombination Login→Magic1→Login→Login könnte ein "Signature Pattern" sein

**Fazit**: Unabhängig vom "Warum" - es ist **dokumentiertes Verhalten** der funktionierenden App und muss repliziert werden.

### Best Practices für zukünftige Protokoll-Reverse-Engineering:

1. **MITM-Captures sind Gold**: Zeigen exaktes Verhalten der funktionierenden App
2. **Timing beachten**: Nicht nur was gesendet wird, sondern auch wann und wie oft
3. **Retransmissions analysieren**: Scheinbare "Duplikate" können essentiell sein
4. **Sequenznummern prüfen**: Gleiche Seq = Retransmission, nicht neues Paket
5. **Nicht annehmen**: Was "logisch" erscheint, muss nicht stimmen (z.B. "ein Login reicht")

---

**Ende des Fix-Summaries**
