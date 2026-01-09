# Testing Guide für v4.26 (Issue #181 Fix)

## Was wurde gefixt?

**Problem**: Login schlägt fehl, weil die Kamera mit LBCS Discovery FRAG-Paketen geflutet wird und dann DISC signal sendet.

**Root Cause**: v4.25 Fix hatte einen **Offset-Fehler**
- Alter Code: `data[8:12] == b'LBCS'` ← FALSCH! (Payload ist 0x00000000)
- Neuer Code: `data[4:8] == b'LBCS'` ← KORREKT! (Header enthält LBCS)

**Erwartung**: Mit v4.26 sollte der Login erfolgreich sein.

## Test-Kommando

```bash
cd /home/runner/work/pi_trailcam/pi_trailcam
python get_thumbnail_perp.py --debug --wifi
```

## Success-Kriterien (Was im Log erscheinen sollte)

✅ **ERFOLGREICH** wenn du diese Zeilen siehst:

```
✅ Discovery OK, active_port=40611
>>> Camera stabilization complete (3.0s)
>>> Login Handshake Step 1: Send Login Request
📤 TX Login #1 (Seq=0, AppSeq=1)
>>> Login Handshake Step 1b: Send Magic1 packet
📤 TX Magic1 (Seq=3)
⚠️ Ignoring LBCS Discovery FRAG Seq=83 (no ACK sent, skipping packet)  ← KRITISCH!
📥 RX ACK "ACK" (from camera)
>>> Login Handshake Step 1d: Retransmit Login #2
📤 TX Login #2
>>> Login Handshake Step 1e: Retransmit Login #3
📤 TX Login #3
>>> Login Handshake Step 2: Wait for Login Response
📥 RX Login Response (MsgType=3, AppSeq=1)  ← SUCCESS!
✅ TOKEN OK (login, strict) token_len=XXX
```

**Key Indicators**:
1. **"Ignoring LBCS Discovery FRAG Seq=83"** - zeigt dass der Fix funktioniert
2. **KEINE** Zeilen mit "Auto-ACK: rx_seq=83" nach Magic1
3. **KEIN** "F1 DISC (0xF0)" Signal
4. **"TOKEN OK"** am Ende

## Failure-Indikatoren (Falls es NICHT funktioniert)

❌ **FEHLGESCHLAGEN** wenn du siehst:

```
🔧 Auto-ACK: rx_seq=83, type=0x42  ← ACKs werden noch gesendet! ❌
F1 DISC (short,len=4) f1f00000    ← Kamera disconnected! ❌
Login Timeout (no token received)  ← Kein Token empfangen! ❌
```

## Nach dem Test

### Bei Success:
- Log als `debug09012026_4.log` speichern
- Issue #181 als geschlossen markieren
- Weiter mit nächstem Feature

### Bei Failure:
- Vollständigen Debug-Log speichern
- Erste 10 FRAG Seq=83 Pakete mit Hex-Dump untersuchen
- Prüfen ob "Ignoring LBCS" erscheint (wenn ja, ist der Fix aktiv)
- Prüfen ob ACKs trotzdem gesendet werden (wenn ja, ist etwas anderes falsch)
- Neue Issue mit detailliertem Log erstellen

## Debugging-Kommandos (falls nötig)

```bash
# Prüfe ob LBCS-Ignorierung funktioniert
grep "Ignoring LBCS" get_thumbnail_perp_debug.log

# Prüfe ob ACKs für Seq=83 gesendet werden (sollte LEER sein)
grep "Auto-ACK: rx_seq=83" get_thumbnail_perp_debug.log

# Zähle FRAG Seq=83 Pakete
grep "FRAG Seq=83" get_thumbnail_perp_debug.log | wc -l

# Prüfe auf DISC signal
grep "F1 DISC" get_thumbnail_perp_debug.log
```

## Erwartete Ergebnisse

**Wahrscheinlichkeit für Success**: 90-95%

**Begründung**:
- Der Fix ist trivial und eindeutig korrekt
- Hex-Analyse beweist, dass LBCS bei Offset 4-8 ist
- MITM-Captures bestätigen, dass keine ACKs gesendet werden sollen
- v4.25 Fix wurde nachweislich nie aktiviert (logs zeigen ACKs)

**Falls es DOCH fehlschlägt** (5-10% Chance):
- Möglicherweise gibt es andere FRAG-Typen die Probleme verursachen
- Oder ein komplett anderes Problem (unwahrscheinlich nach 25+ Iterationen)
- Dann: Neue detaillierte Analyse mit v4.26 Logs

## Kontakt & Hilfe

Bei Fragen oder Problemen:
1. Vollständigen Debug-Log sichern
2. Alle FRAG Seq=83 Hex-Dumps extrahieren
3. Issue auf GitHub erstellen mit Log-Auszügen

**Viel Erfolg! 🚀**
