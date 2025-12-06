# 🚀 QUICK START: Artemis Protocol Hypothesis Test

## TL;DR - 30 Sekunden Setup

```bash
cd ~/pi_trailcam && git pull origin main
```

```bash
# Terminal 1: tcpdump starten
sudo tcpdump -i wlan0 udp port 40611 -X -v
```

```bash
# Terminal 2: Test starten
sudo ./venv/bin/python3 main.py
```

**→ Beobachte die Logs!** Eine von 6 Varianten sollte funktionieren.

---

## 📊 Was wird getestet?

| # | Variante | Mystery Bytes | Status |
|---|----------|---------------|--------|
| 1 | **SMARTPHONE_DUMP** ⭐ | `2b 00 00 00 2d 00 00 00` | **HÖCHSTE WAHRSCHEINLICHKEIT** |
| 2 | ORIGINAL | `02 00 01 00` | Fallback (aktueller Code) |
| 3 | MYSTERY_2B_ONLY | `2b 00 00 00` | Alternative |
| 4 | MYSTERY_2D_ONLY | `2d 00 00 00` | Alternative |
| 5 | NO_MYSTERY | (keine) | Alternative |
| 6 | SEQUENCE_VARIANT | `03 00 00 00 04 00 00 00` | Sequenznummern-Hypothese |

---

## ✅ Erfolgs-Szenarios

### **Szenario A: Login gelingt sofort**
```
🎉 LOGIN ERFOLGREICH mit Variante 'smartphone_dump'!
Antwort: f1d0...
```
**→ PROBLEM GELÖST!**  
Die Byte-Struktur war die Ursache.

---

### **Szenario B: Andere Variante funktioniert**
```
🎉 LOGIN ERFOLGREICH mit Variante 'mystery_2b_only'!
```
**→ Neue Hypothese bestätigt!**  
Die Struktur unterscheidet sich subtil.

---

### **Szenario C: Alle Varianten fehlgeschlagen**
```
❌ ALLE VARIANTEN FEHLGESCHLAGEN
```
**→ Problem liegt NICHT in Mystery-Bytes!**  
Nächster Schritt:
```bash
# BLE-Dump analysieren für echten Token
sudo hcidump -X -i hci0
```

---

## 🔧 Logs Anzeigen

```bash
# Python-Ausgabe
tail -50 ~/.pi_trailcam/main.log

# oder Live-Monitoring
sudo ./venv/bin/python3 main.py | grep -E '(VARIANT|ERFOLG|FEHLGE|Timeout)'
```

---

## 🎓 Bytemap als Referenz

```
SMARTPHONE (funktioniert):
f1d0 0045 d100 0005 ARTEMIS\0 02000000 2b000000 2d000000 19000000 [Token]

RASPBERRY (aktuell fehlgeschlagen):
f1d0 0031 d100 0001 ARTEMIS\0 02000000 02000100 19000000 [Token]
                                         ^^^^^^^^ HIER IST DER FEHLER!
```

---

## 🎯 Nächste Schritte nach Test

### Falls erfolgreich:
```bash
# 1. Variante notieren
echo "ERFOLGREICHE VARIANTE: smartphone_dump" > DEBUG_RESULT.txt

# 2. Normale Workflow testen
python3 main.py

# 3. Überprüfen: WiFi, Login, Heartbeat, Bilder
```

### Falls fehlgeschlagen:
```bash
# 1. BLE-Dump starten
sudo hcidump -X -i hci0 > ble_debug.log &

# 2. Kamera aufwecken & Login versuchen
python3 main.py

# 3. Nach Token-String suchen
grep -E "[A-Za-z0-9+/]{30,}" ble_debug.log
```

---

## 📞 Support / Debugging

**Problem: Alle Timeouts**
- Kamera WiFi sichtbar? `iwconfig`
- Mit Kamera verbunden? `iwconfig wlan0`
- Port offen? `sudo netstat -uln | grep 40611`

**Problem: Connection Refused**
- Kamera IP korrekt? `ping 192.168.43.1`
- BLE Wake funktioniert? Logs checken

**Problem: Eine Variante funktioniert, aber nicht dauerhaft?**
- Heartbeat läuft? Prüfe `_heartbeat_loop`
- Timing-Probleme? Erhöhe `socket.settimeout()`

---

## 📈 Metriken

```
Ver suche pro Variante: 3x (à 0.5s Abstand)
Varianten insgesamt: 6
Max. Test-Dauer: ~10 Sekunden
```

---

## ✨ Key Insight

> **Die Bytes `2b 00 00 00 2d 00 00 00` sind DER Unterschied zwischen funktionierend (Smartphone) und fehlgeschlagen (Raspberry).**

Deine aktuellen Bytes `02 00 01 00` sind FALSCH.  
Wenn SMARTPHONE_DUMP funktioniert → Problem GELÖST! ✅

---

**Lass mich wissen welche Variante erfolgreich ist! 🚀**
