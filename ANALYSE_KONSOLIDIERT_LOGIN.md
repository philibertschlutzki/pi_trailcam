# Konsolidierte Analyse: Login-Fehler und Lösungsansatz

**Datum**: 2026-01-05  
**Issue**: #157  
**Problem**: Login Timeout - Kamera sendet keine Login-Response (MsgType=3)

---

## Zusammenfassung

Das Login schlägt fehl, weil die Kamera die Login-Response nicht sendet. Die Analyse der MITM-Captures zeigt, dass die funktionierende App **den Login-Request dreimal sendet**, bevor die Kamera antwortet. Die aktuelle Implementierung sendet den Request nur einmal.

---

## Chronologie der Analyse

### Version debug05012026_1.log (18:47 Uhr)
**Problem**: FRAG-Pakete wurden nicht ge-ACKt
- Zeilen 13-50: "FRAG ohne ARTEMIS-Signatur (vermutlich LBCS/Discovery); skip reassembly/ack"
- **Fix**: ACK-Logik für FRAG-Pakete hinzugefügt

### Version debug05012026_2.log (19:15 Uhr)
**Problem**: Falsche RUDP-Sequenznummer für Login
- Zeile 24: Login mit Seq=1 gesendet (statt Seq=0)
- Zeile 26: Magic1 mit Seq=1 gesendet (statt Seq=3)
- **Fix**: `force_seq=0` für Login und `force_seq=3` für Magic1 implementiert

### Version debug05012026_3.log (19:44 Uhr)
**Problem**: Login mit Seq=1, kein Magic1-Paket
- Zeile 28: Login mit Seq=1 (FALSCH!)
- Magic1 fehlt komplett
- **Status**: Fixes noch nicht vollständig angewendet

### Version debug05012026_4.log (20:18 Uhr) - AKTUELL
**Problem**: Korrekte Sequenznummern, aber keine Response
- Zeile 27: Login mit Seq=0 ✅
- Zeile 29: Magic1 mit Seq=3 ✅
- **ABER**: Keine Login-Response von der Kamera!

---

## Detaillierte MITM-Analyse (ble_udp_1.log)

### Erfolgreicher Login-Ablauf der funktionierenden App:

| Zeile | Zeit | Richtung | RUDP Typ | RUDP Seq | ARTEMIS | Beschreibung |
|-------|------|----------|----------|----------|---------|--------------|
| 378 | - | TX | 0xD0 (DATA) | 0 | MsgType=2, AppSeq=1 | **Login Request #1** |
| 393 | - | TX | 0xD1 (ACK/CTRL) | 3 | - | **Magic1 Handshake** |
| 396 | - | RX | 0xD0 (DATA) | 0 | - | ACK-Payload "ACK" |
| 399 | - | TX | 0xD1 (ACK) | 1 | - | ACK für Seq=0 |
| 402 | - | TX | 0xD0 (DATA) | 0 | MsgType=2, AppSeq=1 | **Login Request #2** (Wiederholung!) |
| 417 | - | TX | 0xD0 (DATA) | 0 | MsgType=2, AppSeq=1 | **Login Request #3** (Wiederholung!) |
| 463 | - | RX | 0xD0 (DATA) | 1 | **MsgType=3, AppSeq=1** | **Login Response** ✅ |

### Kritische Erkenntnisse:

1. **Dreifache Übertragung**: Die App sendet den Login-Request **drei Mal**
   - Zeile 378: Erster Versuch
   - Zeile 402: Zweiter Versuch (nach ACK-Empfang)
   - Zeile 417: Dritter Versuch
   
2. **Gleiche Sequenznummer**: Alle drei Login-Requests haben **RUDP Seq=0**
   - Dies ist korrekt - es ist eine Retransmission, kein neues Paket

3. **Gleiches AppSeq**: Alle drei Requests haben **AppSeq=1**
   - Die Application-Layer-Sequenz bleibt gleich (gleiche logische Anfrage)

4. **Timing**: Die Wiederholungen erfolgen unmittelbar nach dem ersten Versuch
   - Keine langen Wartezeiten zwischen den Versuchen

5. **Response-Trigger**: Die Kamera antwortet erst **nach dem dritten Request**
   - Zeile 463: Login Response kommt nach dem dritten Versuch

---

## Hypothesen

### ✅ Hypothese 1: RUDP Seq=0 erforderlich (BESTÄTIGT & IMPLEMENTIERT)

**Beobachtung**: Login muss mit RUDP Seq=0 gesendet werden.

**Status**: ✅ Implementiert in v4.15
- `force_seq=0` für Login-Request
- Zeile 27 (debug05012026_4.log) zeigt korrekten Seq=0

### ✅ Hypothese 2: Magic1 Handshake erforderlich (BESTÄTIGT & IMPLEMENTIERT)

**Beobachtung**: Nach Login muss Magic1-Paket (Seq=3, 6 Nullbytes) gesendet werden.

**Status**: ✅ Implementiert in v4.15
- Magic1 mit `force_seq=3` und `MAGIC_BODY_1` (6 Nullbytes)
- Zeile 29 (debug05012026_4.log) zeigt korrekten Magic1

### 🆕 Hypothese 3: Login-Retransmission erforderlich (NEU!)

**Beobachtung**: Die funktionierende App sendet den Login-Request **dreimal**.

**Begründung**:
1. **Protokoll-Robustheit**: Das UDP-basierte RUDP-Protokoll ist nicht 100% zuverlässig
2. **Kamera-Firmware-Verhalten**: Die Kamera scheint den Login-Request manchmal zu "übersehen"
3. **Bewährte Praxis**: Die offizielle App verwendet diese Retransmission-Strategie

**Theorie**:
- Die Kamera hat möglicherweise ein Timing-Problem oder einen internen Zustand
- Sie "hört" erst beim zweiten oder dritten Versuch richtig zu
- Die dreifache Übertragung ist ein **kritischer Teil des Protokolls**, nicht nur eine Fehlerbehandlung

**Status**: ❌ NICHT IMPLEMENTIERT (Ursache des aktuellen Fehlers!)

---

## Vergleich: Funktionierende App vs. Aktuelle Implementierung

### Funktionierende App (MITM):
```
1. Login (Seq=0, AppSeq=1)
2. Magic1 (Seq=3)
3. [Empfange ACK]
4. Login (Seq=0, AppSeq=1)  ← WIEDERHOLUNG!
5. Login (Seq=0, AppSeq=1)  ← WIEDERHOLUNG!
6. [Empfange Login-Response MsgType=3]
```

### Aktuelle Implementierung (debug05012026_4.log):
```
1. Login (Seq=0, AppSeq=1)  ✅
2. Magic1 (Seq=3)           ✅
3. [Warten auf Response...]
4. [TIMEOUT - keine Response] ❌
```

**Fehlende Schritte**: Login-Wiederholungen (Zeilen 4-5)

---

## Lösungsansatz

### Implementierung: Triple Login Transmission

```python
# Step 1: Send login request #1
login_pkt, login_rudp_seq = self.build_packet(0xD0, login_body, force_seq=0)
self.send_raw(login_pkt, desc=f"Login#1(cmdId=0,AppSeq={login_app_seq})")

# Step 1b: Send Magic1 handshake
magic1_pkt, _ = self.build_packet(0xD1, MAGIC_BODY_1, force_seq=3)
self.send_raw(magic1_pkt, desc="Magic1")

# Brief pause to allow camera to process
time.sleep(0.1)

# Step 1c: ACK any immediate response
self.pump(timeout=0.5, accept_predicate=lambda _: False, filter_evt=False)

# Step 1d: Retransmit login (matching MITM behavior - line 402)
# CRITICAL: Use same Seq=0 and AppSeq (it's a retransmission, not a new request)
login_pkt2, _ = self.build_packet(0xD0, login_body, force_seq=0)
self.send_raw(login_pkt2, desc=f"Login#2(cmdId=0,AppSeq={login_app_seq})")

# Step 1e: Second retransmit (matching MITM behavior - line 417)
login_pkt3, _ = self.build_packet(0xD0, login_body, force_seq=0)
self.send_raw(login_pkt3, desc=f"Login#3(cmdId=0,AppSeq={login_app_seq})")

# Step 2: Now wait for login response
# (nach den drei Übertragungen sollte die Kamera antworten)
```

### Wichtige Details:

1. **Gleiche RUDP-Seq**: Alle drei Login-Requests müssen `Seq=0` haben
   - Es ist eine Retransmission, kein neues Paket
   
2. **Gleiches AppSeq**: Alle drei haben `AppSeq=1`
   - Gleiche logische Anfrage
   
3. **Identischer Payload**: Alle drei müssen denselben verschlüsselten Login-JSON enthalten
   - Wichtig: `utcTime` muss gleich bleiben!
   
4. **Timing**: Kurze Pausen zwischen den Übertragungen
   - Ca. 0.1-0.5 Sekunden basierend auf MITM-Timing

---

## Erwartetes Verhalten nach Fix

Nach Implementierung der Login-Retransmissions sollte der Debug-Log wie folgt aussehen:

```
>>> Login Handshake Step 1: Send Login Request (cmdId=0, AppSeq=1)
📤 RUDP DATA Seq=0 ... Login#1(cmdId=0,AppSeq=1)

>>> Login Handshake Step 1b: Send Magic1 packet
📤 RUDP ACK Seq=3 ... Magic1

>>> Login Handshake Step 1c: Retransmit Login #2
📤 RUDP DATA Seq=0 ... Login#2(cmdId=0,AppSeq=1)

>>> Login Handshake Step 1d: Retransmit Login #3
📤 RUDP DATA Seq=0 ... Login#3(cmdId=0,AppSeq=1)

>>> Login Handshake Step 2: Wait for Login Response (MsgType=3, AppSeq=1)
📥 RUDP DATA Seq=1 | ARTEMIS MsgType=3 AppSeq=1   ← ERWARTET!
✅ Login Response received (MsgType=3)

>>> Extracting token from Login Response (AppSeq=1)...
✅ TOKEN OK (login, strict) app_seq=1 token_len=XXX
```

---

## Weitere Hypothesen (geprüft und verworfen)

### ❌ Hypothese 4: ACK-Verhalten
**Status**: Widerlegt
- ACKs werden in v4.15 korrekt gesendet
- Debug-Logs zeigen korrekte ACK-Sequenzen

### ❌ Hypothese 5: Verschlüsselung/Encoding
**Status**: Widerlegt
- Login-JSON wird korrekt verschlüsselt (AES-ECB mit PHASE2_KEY)
- Base64-Encoding ist korrekt

### ❌ Hypothese 6: Timing
**Status**: Teilweise relevant
- Timing ist wichtig für Stabilität
- Aber nicht die Hauptursache des Fehlers
- Die Retransmissions sind wichtiger als präzises Timing

---

## Referenzen

- **Issue**: #157
- **Protokoll-Spezifikation**: `Protocol_analysis.md`
- **MITM-Captures**: 
  - `tests/MITM_Captures/ble_udp_1.log` (Zeilen 378-475)
  - `tests/MITM_Captures/ble_udp_2.log`
- **Debug-Logs**:
  - `tests/debug04012026.txt` (erste Version)
  - `tests/debug05012026.log` (ACK-Fix)
  - `tests/debug05012026_1.log` (FRAG-ACK-Fix)
  - `tests/debug05012026_2.log` (Seq-Fix teilweise)
  - `tests/debug05012026_3.log` (Seq-Fix fehlt)
  - `tests/debug05012026_4.log` (Seq-Fix OK, aber keine Response)
- **Frühere Hypothesen**: `HYPOTHESEN_LOGIN_FEHLER.md`
- **Implementierung**: `get_thumbnail_perp.py` (v4.15)

---

## Nächste Schritte

1. ✅ Analyse abgeschlossen
2. ⏳ Implementierung der Login-Retransmissions
3. ⏳ Test mit echter Hardware
4. ⏳ Validierung der Token-Extraktion
5. ⏳ Security-Scan
