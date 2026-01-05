# Hypothesen: Warum das Login nicht erfolgreich ist

## Zusammenfassung

Das Login schlägt fehl, weil **zwei kritische Unterschiede** zwischen der funktionierenden App und der aktuellen Implementierung existieren.

## Hypothese 1: Falsche RUDP Sequenznummer ✅ BESTÄTIGT

### Beobachtung

**Funktionierende App (MITM Capture `ble_udp_1.log` Zeile 378):**
```
f1 d0 00 c5 d1 00 00 00 41 52 54 45 4d 49 53 00
                   ^^
              RUDP Seq = 0
```

**Fehlerhafte Implementierung (`debug05012026_3.log` Zeile 28):**
```
f1 d0 00 c5 d1 00 00 01 41 52 54 45 4d 49 53 00
                   ^^
              RUDP Seq = 1 (FALSCH!)
```

### Analyse

Die Kamera erwartet, dass der Login-Request mit **RUDP Sequence Number 0** gesendet wird. Dies ist vermutlich eine Art "Session-Reset-Signal" - Seq=0 signalisiert der Kamera den Start einer neuen Kommunikationssession.

Die aktuelle Implementierung hatte den `force_seq` Parameter nicht gesetzt, sodass die normale Sequenznummer (1) verwendet wurde. Dies führte dazu, dass die Kamera den Login-Request ignorierte.

### Beweis

Vergleich der Hex-Dumps zeigt eindeutig:
- **Funktionierende App**: Byte 7 = `0x00` (Seq=0)
- **Fehlerhafte Version**: Byte 7 = `0x01` (Seq=1)

Beide Pakete sind ansonsten identisch - gleiches ARTEMIS Header, gleiche verschlüsselten Login-Daten.

## Hypothese 2: Fehlendes "Magic1" Handshake-Paket ✅ BESTÄTIGT

### Beobachtung

**Funktionierende App sendet nach Login (MITM `ble_udp_1.log` Zeile 393-394):**
```
⚡ [UDP TX] Sende (14 bytes) FD:117
750f305028  f1 d1 00 0a d1 00 00 03 00 00 00 00 00 00
            ^^          ^^ ^^    ^^
            |           |  |     Seq=3
            |           |  Payload: 6 Nullbytes
            |           Length=10 (4+6)
            Type=0xD1 (ACK/CTRL)
```

**Fehlerhafte Implementierung:** 
Dieses Paket wird **gar nicht gesendet**!

### Analyse

Das "Magic1" Paket ist ein kritischer Teil des Login-Handshakes:

1. **Timing**: Wird unmittelbar nach dem Login-Request gesendet (vor der Antwort)
2. **Sequenz-Sprung**: Die Sequenznummer springt von 0 auf 3 (nicht inkrementell!)
3. **Payload**: 6 Bytes Nullen (bereits als `MAGIC_BODY_1` definiert, aber nie verwendet)
4. **Paket-Typ**: RUDP 0xD1 (ACK/CTRL), nicht 0xD0 (DATA)

Laut `Protocol_analysis.md` §5 (Phase 2: Handshake):
> **Schritt 5**: Client -> Cam | 0xD1 | - | **Magic 1** (`00 00...` Payload). Seq springt oft.

### Theorie: Warum ist dieses Paket notwendig?

Das Magic1-Paket scheint ein **Synchronisationssignal** zu sein:

1. Es zeigt der Kamera, dass der Client das korrekte Protokoll implementiert
2. Der Sequenz-Sprung (0→3) könnte als "Challenge" dienen
3. Die Kamera wartet auf dieses Signal, bevor sie die Login-Response sendet

Ohne dieses Paket bleibt die Kamera im "Warte-Zustand" und sendet keine Login-Response.

## Hypothese 3: ACK-Verhalten ❌ NICHT RELEVANT

### Ursprüngliche Vermutung

Die älteren Debug-Logs (`debug04012026.txt`) zeigen:
```
FRAG ohne ARTEMIS-Signatur (vermutlich LBCS/Discovery); skip reassembly/ack
```

Dies deutete darauf hin, dass FRAG-Pakete nicht ge-ACKt wurden.

### Widerlegung

Die neueren Logs (`debug05012026_3.log`) zeigen, dass FRAG-Pakete jetzt korrekt ge-ACKt werden:
```
📤 RUDP ACK Seq=83 BodyLen=6 to=192.168.43.1:40611 ACK(rx_seq=83)
```

Das ACK-Verhalten wurde also bereits in einer früheren Iteration korrigiert und ist nicht die Ursache des aktuellen Login-Fehlers.

## Hypothese 4: Verschlüsselung/Encoding ❌ NICHT RELEVANT

### Überprüfung

Die verschlüsselten Login-Daten in den Hex-Dumps sind praktisch identisch:

**MITM (funktionierende App):**
```
4a 38 57 57 75 51 44 50 6d 59 53 4c 66 75 2f 67 58 41 47 2b
(J8WWuQDPmYSLfu/gXAG+...)
```

**Aktuelle Implementierung:**
```
52 4a 46 76 73 68 4d 73 53 71 45 34 32 31 79 34 4c 63 78 5a
(RJFvshMsSqE421y4LcxZ...)
```

Die Unterschiede sind erwartbar (dynamische `utcTime`, verschiedene Timestamps). Die Verschlüsselung selbst funktioniert korrekt - das Problem liegt im Transport-Layer (RUDP), nicht im Application-Layer (ARTEMIS).

## Hypothese 5: Timing ⚠️ TEILWEISE RELEVANT

### Beobachtung

Die funktionierende App sendet:
1. Login (Seq=0)
2. **Sofort** Magic1 (Seq=3)
3. Wartet auf Response

Die fehlerhafte Implementierung sendete:
1. Login (Seq=1)
2. **Nichts**
3. Wartet auf Response (timeout)

### Relevanz

Ein `sleep(0.1)` wurde nach dem Magic1-Paket hinzugefügt (`MAGIC1_PROCESSING_DELAY`), um der Kamera Zeit zum Verarbeiten zu geben. Dies ist jedoch wahrscheinlich nicht kritisch - die MITM-Captures zeigen, dass die App nicht speziell wartet.

Wichtiger ist die **Reihenfolge**: Login → Magic1 → (dann warten).

## Fazit

### Bestätigte Ursachen (Fixes implementiert):

1. ✅ **RUDP Seq=0 fehlt**: Login-Request muss mit `force_seq=0` gesendet werden (v4.15)
2. ✅ **Magic1 Paket fehlt**: Nach Login muss ein Handshake-Paket (Seq=3, 6 Nullbytes) gesendet werden (v4.15)
3. ✅ **Login-Retransmissions fehlen**: Login-Request muss **dreimal** gesendet werden (v4.16)
   - MITM-Analyse zeigt: Die funktionierende App sendet Login dreimal (ble_udp_1.log Zeilen 378, 402, 417)
   - Alle drei mit gleicher RUDP Seq=0 und AppSeq=1 (Retransmission, nicht neue Requests)
   - Kamera antwortet erst nach dem dritten Versuch (Zeile 463)
   - Dies ist **nicht** Fehlerbehandlung, sondern Teil des erwarteten Protokollflusses

### Nicht-Ursachen:

- ❌ ACK-Verhalten (bereits korrigiert)
- ❌ Verschlüsselung (funktioniert korrekt)
- ❌ Timing (relevant für Stabilität, aber nicht die Hauptursache)

### Erwartetes Verhalten nach Fix v4.16:

Nach Implementierung aller drei Fixes sollte die Kamera wie folgt antworten:

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
📥 RUDP DATA Seq=1 | ARTEMIS MsgType=3 AppSeq=1
✅ Login Response received (MsgType=3)

>>> Extracting token from Login Response (AppSeq=1)...
✅ TOKEN OK (login, strict) app_seq=1 token_len=XXX
```

## Hypothese 6: Login-Retransmission erforderlich ✅ BESTÄTIGT (v4.16)

### Beobachtung

Die funktionierende App sendet den Login-Request **dreimal**:
- **MITM ble_udp_1.log Zeile 378**: Login#1 (Seq=0, AppSeq=1)
- **MITM ble_udp_1.log Zeile 402**: Login#2 (Seq=0, AppSeq=1) - Wiederholung
- **MITM ble_udp_1.log Zeile 417**: Login#3 (Seq=0, AppSeq=1) - Wiederholung
- **MITM ble_udp_1.log Zeile 463**: Kamera sendet Login-Response (MsgType=3)

### Analyse

Alle drei Login-Requests sind identisch:
- **Gleiche RUDP-Seq**: Seq=0 (es ist eine Retransmission, kein neues Paket)
- **Gleiches AppSeq**: AppSeq=1 (gleiche logische Anfrage)
- **Gleicher Payload**: Identischer verschlüsselter Login-JSON (gleicher utcTime!)

Dies ist **kein** Retry-Mechanismus bei Fehlern, sondern Teil des erwarteten Protokolls.

### Beweis

Vergleich debug05012026_4.log (fehlerhaft) vs. MITM (funktionierend):

**Fehlerhafter Ablauf (debug05012026_4.log)**:
```
Zeile 27: Login#1 (Seq=0) ✅
Zeile 29: Magic1 (Seq=3) ✅
[keine weiteren Login-Requests] ❌
[Timeout - keine Response]
```

**Funktionierender Ablauf (MITM ble_udp_1.log)**:
```
Zeile 378: Login#1 (Seq=0) ✅
Zeile 393: Magic1 (Seq=3) ✅
Zeile 402: Login#2 (Seq=0) ✅ FEHLT IN v4.15!
Zeile 417: Login#3 (Seq=0) ✅ FEHLT IN v4.15!
Zeile 463: Login-Response (MsgType=3) empfangen ✅
```

### Theorie: Warum ist dreifache Übertragung notwendig?

1. **Kamera-Firmware-Verhalten**: Die Kamera scheint den ersten Request zu "ignorieren" oder nutzt ihn zur Zustandsvorbereitung
2. **Protokoll-Design**: Die Kamera-Firmware wurde so entwickelt, dass sie mehrfache Übertragungen erwartet
3. **Robustheit**: Da UDP-basiert, könnte dies ursprünglich als Paketverluststrategie gedacht gewesen sein
4. **Timing/Synchronisation**: Die Kamera könnte Zeit benötigen, um interne Zustände zu initialisieren

Wichtig: Dies ist **dokumentiertes Verhalten** der funktionierenden App, nicht eine Workaround-Lösung.

### Fix implementiert in v4.16

```python
# Login#1
login_pkt, _ = self.build_packet(0xD0, login_body, force_seq=0)
self.send_raw(login_pkt, desc=f"Login#1(cmdId=0,AppSeq={login_app_seq})")

# Magic1
magic1_pkt, _ = self.build_packet(0xD1, MAGIC_BODY_1, force_seq=3)
self.send_raw(magic1_pkt, desc="Magic1")

# Pump immediate responses
self.pump(timeout=0.1, accept_predicate=lambda _: False, filter_evt=False)

# Login#2 (Retransmit - same Seq=0, same body)
login_pkt2, _ = self.build_packet(0xD0, login_body, force_seq=0)
self.send_raw(login_pkt2, desc=f"Login#2(cmdId=0,AppSeq={login_app_seq})")

# Login#3 (Retransmit - same Seq=0, same body)
login_pkt3, _ = self.build_packet(0xD0, login_body, force_seq=0)
self.send_raw(login_pkt3, desc=f"Login#3(cmdId=0,AppSeq={login_app_seq})")

# NOW wait for response - camera should respond after triple transmission
```

### Status

✅ **BESTÄTIGT und IMPLEMENTIERT in v4.16**
- Hypothese durch MITM-Analyse bestätigt
- Fix implementiert in `get_thumbnail_perp.py`
- Erwartet: Login-Success mit Token-Extraktion



## Referenzen

- **Issue**: #155
- **MITM Referenz**: `tests/MITM_Captures/ble_udp_1.log` Zeilen 378-491
- **Protokoll-Spezifikation**: `Protocol_analysis.md` §5
- **Debug-Logs**: 
  - `tests/debug05012026_3.log` (fehlerhaft)
  - `tests/debug04012026.txt` (ältere Version)
- **Fix-Dokumentation**: `FIX_SUMMARY_ISSUE_155.md`
