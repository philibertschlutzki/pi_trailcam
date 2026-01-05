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

### Version debug05012026_4.log (20:18 Uhr)
**Problem**: Korrekte Sequenznummern, aber keine Response
- Zeile 27: Login mit Seq=0 ✅
- Zeile 29: Magic1 mit Seq=3 ✅
- **ABER**: Keine Login-Response von der Kamera!

### Version debug05012026_5.log (20:58 Uhr) - AKTUELL
**Problem**: Unerwarteter Heartbeat zwischen Magic1 und Login-Retransmissions
- Zeile 27: Login #1 mit Seq=0, AppSeq=1 ✅
- Zeile 29: Magic1 mit Seq=3 ✅
- **Zeile 33: Heartbeat mit Seq=4, AppSeq=2** ❌ SOLLTE NICHT DA SEIN!
- Zeile 34-37: Login #2 und #3 Retransmissions ✅
- **ABER**: Keine Login-Response von der Kamera!

**Root Cause**: Der Heartbeat mit AppSeq=2 zwischen Magic1 und den Login-Retransmissions verwirrt die Kamera. Die Kamera erwartet nach Login AppSeq=1 entweder:
  - Die Login-Response (MsgType=3, AppSeq=1), ODER
  - Eine Retransmission des Login-Requests (MsgType=2, AppSeq=1)
  
Aber NICHT ein Heartbeat mit AppSeq=2! Das bricht die erwartete Sequenz.

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

### ✅ Hypothese 3: Login-Retransmission erforderlich (IMPLEMENTIERT, aber mit Bug)

**Beobachtung**: Die funktionierende App sendet den Login-Request **dreimal**.

**Begründung**:
1. **Protokoll-Robustheit**: Das UDP-basierte RUDP-Protokoll ist nicht 100% zuverlässig
2. **Kamera-Firmware-Verhalten**: Die Kamera scheint den Login-Request manchmal zu "übersehen"
3. **Bewährte Praxis**: Die offizielle App verwendet diese Retransmission-Strategie

**Theorie**:
- Die Kamera hat möglicherweise ein Timing-Problem oder einen internen Zustand
- Sie "hört" erst beim zweiten oder dritten Versuch richtig zu
- Die dreifache Übertragung ist ein **kritischer Teil des Protokolls**, nicht nur eine Fehlerbehandlung

**Status**: ✅ IMPLEMENTIERT in v4.16 (Zeilen 1151, 1176, 1182 in get_thumbnail_perp.py)

### 🆕 Hypothese 4: Heartbeat stört Login-Sequenz (NEU! - HAUPTPROBLEM)

**Beobachtung**: debug05012026_5.log Zeile 33 zeigt einen Heartbeat (AppSeq=2) zwischen Magic1 und Login-Retransmissions.

**MITM-Analyse (ble_udp_1.log)**:
```
Zeile 378: TX Login #1 (RUDP Seq=0, ARTEMIS MsgType=2, AppSeq=1)
Zeile 393: TX Magic1 (RUDP Seq=3, ACK/CTRL)
Zeile 396: RX ACK
Zeile 399: TX ACK für empfangenen ACK
Zeile 402: TX Login #2 (RUDP Seq=0, ARTEMIS MsgType=2, AppSeq=1) ← DIREKT nach ACK!
Zeile 417: TX Login #3 (RUDP Seq=0, ARTEMIS MsgType=2, AppSeq=1)
Zeile 435: RX Login Response (MsgType=3, AppSeq=1)
```

**Aktuelles Verhalten (debug05012026_5.log)**:
```
Zeile 27: TX Login #1 (Seq=0, AppSeq=1)
Zeile 29: TX Magic1 (Seq=3)
Zeile 33: TX Heartbeat (Seq=4, AppSeq=2) ← SOLLTE NICHT DA SEIN!
Zeile 34: TX Login #2 (Seq=0, AppSeq=1)
Zeile 37: TX Login #3 (Seq=0, AppSeq=1)
Zeile 49: TIMEOUT - keine Response
```

**Problem**: 
Die Kamera erwartet nach dem Login-Request (AppSeq=1) als nächstes ARTEMIS-Paket:
- ENTWEDER: Login-Response (MsgType=3, AppSeq=1)
- ODER: Login-Retransmission (MsgType=2, AppSeq=1)

Der Heartbeat mit AppSeq=2 **bricht diese erwartete Sequenz**. Die Kamera-Firmware scheint einen Zustandsautomaten zu haben, der:
1. Nach Login-Request (AppSeq=1) in einem "Warte auf Login-Verarbeitung" Zustand ist
2. Nur Login-Retransmissions mit AppSeq=1 akzeptiert (um Robustheit zu garantieren)
3. Durch den Heartbeat (AppSeq=2) verwirrt wird und die nachfolgenden Login-Retransmissions ignoriert

**Root Cause**: 
Der Aufruf `self.pump(timeout=0.1, ...)` in Zeile 1167 von get_thumbnail_perp.py triggert `send_heartbeat()` (pump Zeile 911-912), weil `self.global_seq > 1` (es ist 3 nach Magic1).

**Status**: ❌ KRITISCHER BUG - Dies ist die wahrscheinliche Hauptursache des Login-Timeouts!

---

## Vergleich: Funktionierende App vs. Aktuelle Implementierung

### Funktionierende App (MITM):
```
1. Login (Seq=0, AppSeq=1)
2. Magic1 (Seq=3)
3. [Empfange ACK]
4. [Sende ACK für empfangenen ACK]
5. Login (Seq=0, AppSeq=1)  ← WIEDERHOLUNG!
6. Login (Seq=0, AppSeq=1)  ← WIEDERHOLUNG!
7. [Empfange Login-Response MsgType=3, AppSeq=1] ✅
```

### Aktuelle Implementierung (debug05012026_5.log):
```
1. Login (Seq=0, AppSeq=1)  ✅
2. Magic1 (Seq=3)           ✅
3. Heartbeat (Seq=4, AppSeq=2) ❌ FEHLER!
4. Login (Seq=0, AppSeq=1)  ✅ (aber zu spät/ignoriert)
5. Login (Seq=0, AppSeq=1)  ✅ (aber zu spät/ignoriert)
6. [TIMEOUT - keine Response] ❌
```

**Kritischer Unterschied**: Der Heartbeat mit AppSeq=2 in Schritt 3 stört die Login-Sequenz!

**Fehlende Schritte**: 
- Kein Heartbeat zwischen Magic1 und Login-Retransmissions
- Die Login-Retransmissions müssen DIREKT nach dem ACK-Austausch erfolgen

---

## Lösungsansatz

### FIX: Heartbeat zwischen Magic1 und Login-Retransmissions unterdrücken

**Problem**: Der `pump()` Aufruf in Zeile 1167 triggert `send_heartbeat()`, weil `self.global_seq > 1`.

**Lösung Option A - Heartbeat-Bedingung erweitern**:
```python
# In pump() Funktion, Zeile 911-912:
# Verhindere Heartbeat während kritischer Login-Phase
if self.active_port and self.global_seq > 1 and not self._in_login_handshake:
    self.send_heartbeat()
```

**Lösung Option B - pump() mit no_heartbeat Parameter** (EMPFOHLEN):
```python
def pump(self, timeout, accept_cmd=None, accept_predicate=None, filter_evt=True, no_heartbeat=False):
    while time.time() - start < timeout:
        if self.active_port and self.global_seq > 1 and not no_heartbeat:
            self.send_heartbeat()
        # ... rest of pump logic
```

Dann in run():
```python
# Step 1c: ACK/pump any immediate responses from camera
# CRITICAL: no_heartbeat=True to avoid interfering with login sequence
self.pump(timeout=0.1, accept_predicate=lambda _: False, filter_evt=False, no_heartbeat=True)
```

**Erwartetes Verhalten nach Fix**:
```
1. Login #1 (Seq=0, AppSeq=1)
2. Magic1 (Seq=3)
3. [Pump 0.1s ohne Heartbeat] ← FIX!
4. Login #2 (Seq=0, AppSeq=1)
5. Login #3 (Seq=0, AppSeq=1)
6. [Warte auf Login Response]
7. Login Response empfangen (MsgType=3, AppSeq=1) ← ERWARTET!
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

### ❌ Hypothese 5: ACK-Verhalten
**Status**: Widerlegt
- ACKs werden in v4.15 korrekt gesendet
- Debug-Logs zeigen korrekte ACK-Sequenzen

### ❌ Hypothese 6: Verschlüsselung/Encoding
**Status**: Widerlegt
- Login-JSON wird korrekt verschlüsselt (AES-ECB mit PHASE2_KEY)
- Base64-Encoding ist korrekt

### ❌ Hypothese 7: Timing
**Status**: Teilweise relevant
- Timing ist wichtig für Stabilität
- Aber nicht die Hauptursache des Fehlers
- Die Retransmissions sind wichtiger als präzises Timing

### ❌ Hypothese 8: RUDP-Sequenznummern
**Status**: Widerlegt (bereits gefixt)
- v4.15+ verwendet korrekt force_seq=0 für Login
- v4.15+ verwendet korrekt force_seq=3 für Magic1
- RUDP-Sequenzen sind korrekt implementiert

---

## 🎯 FINALER ROOT CAUSE (Issue #159)

### Identifiziertes Problem

**Symptom**: Login Timeout - keine Token-Response von der Kamera (0 MsgType=3 Pakete gepuffert)

**Root Cause**: Ein unerwarteter Heartbeat (AppSeq=2) wird zwischen Magic1 und den Login-Retransmissions gesendet.

**Technische Details**:
1. Nach dem Login-Request (AppSeq=1) erwartet die Kamera-Firmware:
   - Entweder eine Login-Response zu senden (MsgType=3, AppSeq=1)
   - Oder weitere Login-Requests mit AppSeq=1 zu empfangen (Retransmissions)

2. Der Heartbeat mit AppSeq=2 bricht diese Erwartung:
   - Die Kamera befindet sich in einem Login-Verarbeitungszustand
   - AppSeq=2 signalisiert "neue Operation", aber die Kamera ist noch nicht bereit
   - Die nachfolgenden Login-Retransmissions werden ignoriert

3. Der Heartbeat wird ausgelöst durch:
   - `self.pump(timeout=0.1, ...)` in Zeile 1167
   - pump() ruft `send_heartbeat()` wenn `self.global_seq > 1` (Zeilen 911-912)
   - Nach Magic1 ist global_seq=3, daher wird Heartbeat gesendet

### Beweis aus MITM-Capture

**Funktionierende App (ble_udp_1.log)**:
- Zeile 378: Login AppSeq=1
- Zeile 393: Magic1
- Zeile 402: Login AppSeq=1 (Retransmission) ← Kein Heartbeat dazwischen!
- Zeile 417: Login AppSeq=1 (Retransmission)
- Zeile 435: Login Response empfangen ✅

**Fehlerhafte Implementierung (debug05012026_5.log)**:
- Zeile 27: Login AppSeq=1
- Zeile 29: Magic1
- Zeile 33: **Heartbeat AppSeq=2** ← FEHLER!
- Zeile 34: Login AppSeq=1 (ignoriert)
- Zeile 37: Login AppSeq=1 (ignoriert)
- Zeile 49: Timeout ❌

### Fix-Strategie

**Minimal Change**: Heartbeat während Login-Handshake unterdrücken

Option 1: `no_heartbeat` Parameter für `pump()` (EMPFOHLEN)
Option 2: Login-Flag `_in_login_handshake` einführen
Option 3: pump() nur dort aufrufen, wo Heartbeat sicher ist

**Erwartete Verbesserung**: 
Nach dem Fix sollte die Login-Response erfolgreich empfangen werden, da die AppSeq-Sequenz nicht mehr unterbrochen wird.

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
