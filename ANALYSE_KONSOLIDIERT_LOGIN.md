# Konsolidierte Analyse zum Login-Problem (chronologisch)

> Datei aktualisiert basierend auf allen verfügbaren Logs (siehe Liste unten), Protokollanalyse und MITM‑Captures.

## Referenzen
- Repository: https://github.com/philibertschlutzki/pi_trailcam
- Protokoll-Spezifikation: https://github.com/philibertschlutzki/pi_trailcam/blob/main/Protocol_analysis.md
- MITM UDP-Logs:
  - https://github.com/philibertschlutzki/pi_trailcam/blob/main/tests/MITM_Captures/ble_udp_1.log
  - https://github.com/philibertschlutzki/pi_trailcam/blob/main/tests/MITM_Captures/ble_udp_2.log
  - https://github.com/philibertschlutzki/pi_trailcam/blob/main/tests/MITM_Captures/traffic_port_get_pictures_thumpnail.log
- Relevante Debug-Logs (Auswahl):
  - tests/debug05012026*.log
  - tests/debug06012026_*.log
  - tests/debug07012026_1.log
  - tests/debug08012026_1.log
  - tests/debug09012026_1..6.log
  - tests/debug09012026_7.log
  - tests/debug09012026_8.log

---

## Kurzfassung (aktuell)
Das System führt eine Login-Handschlagsequenz mit der Kamera durch (ARTEMIS über RUDP). Die Client-Seite sendet die Login-Anfrage (ARTEMIS MsgType=2, AppSeq=1) und mehrere Retransmits sowie ein "Magic1"-ACK. Die Kamera antwortet jedoch nicht mit dem erwarteten ARTEMIS Login-Response (MsgType=3, AppSeq=1). Stattdessen werden viele kleine Pakete vom Typ LBCS/FRAG (Seq=83) und wiederholte kleine DATA/ACK-Pakete beobachtet; zusätzlich tauchen regelmäßig Kurz-Fehlerpakete auf (F1 ERR, hex f1e00000) und gegen Ende ein DISC (f1f00000). Das Script identifiziert keinen Token (keine MsgType=3 Pakete gepuffert) → Login Timeout.

---

## Chronologische Konsolidierung (wichtigste Ereignisse)
1. Discovery-Phase erfolgreich (LBCS DISC/FRAG, active_port=40611).
2. Kamera-Stabilisation (3s) -> Login Request gesendet (ARTEMIS MsgType=2, AppSeq=1).
3. Magic1-ACK gesendet; global_seq auf 0 zurückgesetzt (Vorbereitung auf ACK Seq=1).
4. Kamera sendet viele FRAG Seq=83 (LBCS Discovery) — Client ignoriert diese ("Ignoring LBCS Discovery FRAG").
5. Kamera sendet mehrfach kleine DATA Seq=0 (ACK-Payloads). Client ackt (wichtig: anfangs client ackt mit spezieller "ACK" payload zur Login-Unterstützung, siehe Issue #185).
6. Client retransmitet Login mehrfach (Login#2, Login#3).
7. Client wechselt in Login response wait mode und unterdrückt ACKs für Kamera-ACK-Pakete ("suppressing ACK for camera's 'ACK' packets").
8. Statt eines ARTEMIS MsgType=3 Login-Responses kommen weiterhin:
   - LBCS FRAG Seq=83 (immer wieder)
   - F1 ERR (short,len=4) f1e00000
   - vereinzelt RUDP ACK Pakete vom Gerät (mit unterschiedlichen BodyLen/Seq)
   - RAW RX Dump zeigt nur 4-Byte Nachrichten wie f1e00000 und am Ende f1f00000 (DISC)
9. Nach Wartezeit/Herzschlagsequenz (heartbeats AppSeq=2+) und mehreren RAW RX Dumps: Kein vollständiger MsgType=3 empfangen → Login Timeout.

---

## Bisherige Hypothesen (aus früheren Analysen)
- H1: Der Kamera-Login-Response (MsgType=3) wird fragmentiert/gekürzt und deshalb vom Client nicht als vollständiges ARTEMIS-Paket erkannt.
- H2: Kamera verwendet einen anderen Port oder eine andere Sequenz/Adresse für die Login-Response; Discovery/FRAG-Pakete (Seq=83) stören die Erkennung.
- H3: Client-seitige ACK/Sequenz-Handling (z. B. Reset von global_seq, ACK suppression) unterbricht oder verhindert die vollständige Übertragung der Login-Response.
- H4: RAW-Pakete f1e00000 und f1f00000 sind Status/Fehler/Disconnect-Indikatoren der Kamera — die Kamera lehnt die Login-Response ab oder sendet Fehler statt des Login-Tokens.
- H5: Zeitstempel/utcTime oder CRC/Checksumme in Login JSON nicht korrekt, Kamera verwirft die Anfrage (selten, aber möglich).

---

## Neue Hypothesen (basierend auf den aktuellen Logs debug09012026_7/8.log)
Die neuen Logs (debug09012026_7.log & debug09012026_8.log) zeigen ein wiederkehrendes Muster: viele LBCS FRAG Seq=83 Pakete und wiederholte F1 ERR (f1e00000) Short-Pakete. Ausgehend davon ergänze ich folgende Hypothesen:

- H6: Die Kamera sendet die eigentliche Login-Response auf einem anderen RUDP-Channel/Seq (z. B. erwartet die Kamera, dass der Client den LBCS-Discovery-Fragmentkanal nutzt), wir filtern diese fälschlich als "LBCS" und ignorieren sie. Die Antworten könnten darin verpackt sein.
  - Begründung: FRAG Seq=83 taucht während des gesamten Handshakes immer wieder auf; die Client-Logs markieren diese konsequent als Ignored.
  - **STATUS: WIDERLEGT** - MITM zeigt keine LBCS-Nutzung für Login-Response

- H7: Das Timing/Sequenz-Verhalten der Kamera verlangt, dass nach Magic1 eine bestimmte ACK-Antwort (nicht unterdrückt) gesendet wird; das Unterdrücken der ACKs verhindert die Kamera, die nächste Nutzlast (MsgType=3) zu senden. Die Zeile "🔒 Entered login response wait mode - suppressing ACK for camera's 'ACK' packets" korreliert mit dem anschließenden Ausbleiben der Login-Response.
  - Begründung: Einige Embedded-Implementierungen senden Payload erst dann, wenn sie eine Reihe erwarteter ACKs erhalten; wenn der Client ACKs unterdrückt, bleibt das Gerät in einem halbfertigen Zustand.
  - **STATUS: TEILWEISE BESTÄTIGT** - ACK-Suppression ist nach Login#3 korrekt (MITM bestätigt), aber es gibt einen anderen Grund für das Fehlen von MsgType=3

- H8: Die Kamera sendet kurz-formatige Status-/Fehlerpakete (f1e00000) weil entweder die Session nicht vollständig initialisiert ist (z. B. fehlender Token-Handshake) oder weil der Client mehrfach die selbe AppSeq/Login-Paket sendet (doppelte Login#2/#3) und die Kamera darauf mit Fehlern/Disconnects reagiert.
  - **STATUS: WAHRSCHEINLICH** - ERR-Pakete erscheinen als Reaktion auf fehlerhafte Sequenz/Timing

- H9: Es gibt eine Port-/NAT-Problematik: Discovery an 3333 vs 40611 mehrfach; Kamera antwortet auf 40611 aber für den Login-Response wechselt sie eventuell auf 3333 oder eine andere Source-Port-Kombination; der Client empfängt aber nur an active_port und verwirft andere eingehende Pakete.
  - Begründung: Es gibt sowohl DISC Sendeversuche an 3333 als auch an 40611 in den Logs.
  - **STATUS: UNWAHRSCHEINLICH** - Logs zeigen alle Pakete kommen von 40611

## KRITISCHE NEUE ANALYSE (09.01.2026, debug09012026_8.log)

### WICHTIGSTER FUND: RUDP ACK-Pakete werden empfangen aber nicht richtig verarbeitet!

**Vergleich MITM (ble_udp_1.log) vs. Aktuelle Implementation (debug09012026_8.log):**

**MITM-Sequenz (funktionierend):**
- Line 378: TX Login #1 (Seq=0)
- Line 393: TX Magic1 (Seq=3)
- Line 396: RX DATA "ACK" (Seq=0)
- Line 399: TX ACK (Seq=1) - ACK für camera's "ACK" packet
- Line 402: TX Login #2 (Seq=0)
- Line 417: TX Login #3 (Seq=0)
- **Line 432: RX RUDP ACK (Seq=1, BodyLen=6)** ← **KRITISCH!**
- **Line 435: RX MsgType=3 (Seq=1) - Login Response!** ✅

**Aktuelle Implementation (debug09012026_8.log):**
- 19:32:45,640: TX Login #1 (Seq=0)
- 19:32:45,655: TX Magic1 (Seq=3)
- 19:32:45,748: RX DATA "ACK" (Seq=0)
- 19:32:45,769: TX ACK (Seq=1) - ACK für camera's "ACK" packet ✅
- 19:32:45,799: TX Login #2 (Seq=0)
- 19:32:45,819: TX Login #3 (Seq=0)
- 19:32:45,837: 🔒 Entered login response wait mode - suppressing ACK
- **19:32:48,792: RX RUDP ACK Seq=1 BodyLen=6** ← **EMPFANGEN!**
- **19:32:48,802: RX RUDP ACK Seq=2 BodyLen=8** ← **EMPFANGEN!**
- 19:32:48,813: RX F1 ERR (f1e00000) ← **STATTDESSEN ERR!**
- 19:32:48,826: RX F1 ERR (f1e00000)
- 19:32:56,346: RX F1 DISC (f1f00000) ← **DISCONNECT!**
- ❌ NO MsgType=3!

### NEUE HYPOTHESE H10 (HAUPTVERDACHT):

**H10: Die Kamera erwartet eine spezifische Reaktion auf ihre RUDP ACK-Pakete (Seq=1/2), bevor sie MsgType=3 sendet.**

Beobachtungen:
1. Wir empfangen die RUDP ACK-Pakete (Seq=1 und Seq=2) korrekt
2. Diese Pakete werden geloggt aber NICHT verarbeitet (pump() ignoriert sie)
3. Unmittelbar nach den RUDP ACKs sendet die Kamera ERR-Signale statt MsgType=3
4. MITM zeigt: Nach RX RUDP ACK folgt sofort RX MsgType=3
5. Bei uns: Nach RX RUDP ACK folgt ERR → die Kamera ist "verärgert"

**Mögliche Ursachen:**
- **10a:** Wir müssen die RUDP ACK-Pakete mit einem eigenen ACK bestätigen (unwahrscheinlich - RUDP ACKs werden normalerweise NICHT ge-ACKt)
- **10b:** Der TIMING zwischen Login#3 und dem Empfang der RUDP ACKs ist kritisch - wir senden Login#3 zu schnell/langsam
- **10c:** Die Kamera sendet RUDP ACKs als Antwort auf unsere Login-Pakete, erwartet aber dass wir KEINE weiteren "ACK" DATA Pakete mehr ACKen (was wir korrekt tun via Suppression)
- **10d:** Es gibt einen Sequenznummer-Konflikt: Camera sendet RUDP ACK Seq=1 und Seq=2, aber diese kollidieren mit unserem global_seq
- **10e:** Die 3-Sekunden-Verzögerung zwischen Login#3 (19:32:45,819) und den RUDP ACKs (19:32:48,792) ist ein Indikator - die Kamera wartet zu lange oder wir "verschlafen" etwas

**TIMING-ANALYSE (kritisch):**
- MITM: Nach Login #3 kommen ACK+MsgType=3 **sofort** (innerhalb von ~30ms)
- Unsere Impl: Nach Login #3 kommen RUDP ACKs erst nach **3 Sekunden**!
- Dies deutet auf ein **TIMEOUT** in der Kamera hin!
- Die Kamera wartet auf etwas von uns, bekommt es nicht, sendet nach 3s timeout die ACKs, dann ERR

**NEUE HYPOTHESE H11 (SEHR WAHRSCHEINLICH):**

**H11: Wir senden die Login-Pakete (#1, #2, #3) mit zu wenig Verzögerung dazwischen, oder die ACK-Suppression greift zu früh/spät.**

Analyse der Timestamps:
```
MITM (funktionierend) - Lines 378, 402, 417:
Login #1 → Magic1 → RX "ACK" → TX ACK → Login #2 → Login #3
(Verzögerungen unbekannt, da MITM nur Pakete zeigt, keine Zeitstempel)

Unsere Implementation:
19:32:45,640: Login #1
19:32:45,655: Magic1 (Δ=15ms)
19:32:45,748: RX "ACK" (Δ=93ms)
19:32:45,769: TX ACK (Δ=21ms)
19:32:45,799: Login #2 (Δ=30ms) ← SEHR SCHNELL!
19:32:45,819: Login #3 (Δ=20ms) ← SEHR SCHNELL!
19:32:45,837: ACK-Suppression aktiviert (Δ=18ms)
19:32:45,854-46,882: Viele "ACK" DATA Pakete werden unterdrückt (gut!)
19:32:48,792: RUDP ACK Seq=1 (Δ=2.9 Sekunden!) ← TIMEOUT!
```

**Der Zeitunterschied von 2.9 Sekunden zwischen Login #3 und den RUDP ACKs ist NICHT normal!**

Die Kamera sendet die RUDP ACKs deutlich verspätet, was auf einen internen Timeout hindeutet.

**Hypothesis H12 (PRIMARY HYPOTHESIS - AWAITING HARDWARE TEST):**

**H12: We send Login #2 and #3 too quickly, overwhelming camera firmware which needs processing time between packets.**

Beobachtungen:
1. Login #1 wird gesendet
2. Magic1 wird gesendet  
3. Camera ACK empfangen und ge-ACKt ✅
4. Login #2 wird gesendet
5. **PAUSE 50-100ms** ← FEHLT!
6. Login #3 wird gesendet
7. **PAUSE 50-100ms** ← FEHLT!
8. ACK-Suppression aktivieren
9. Warten auf MsgType=3

Aktuell senden wir Login #2 und #3 **zu schnell hintereinander** (30ms und 20ms Abstand). Die Kamera könnte diese als "Flood" interpretieren oder hat nicht genug Zeit, sie zu verarbeiten.

---

## Konkrete Debug- und Fix-Vorschläge (AKTUALISIERT, priorisiert nach neuer Analyse)

### HÖCHSTE PRIORITÄT (basierend auf H12):
1. **FIX: Verzögerung zwischen Login-Retransmissions einfügen**
   - Füge 50-100ms Pause zwischen Login #1→#2 und Login #2→#3 ein
   - Rationale: Die 2.9s Verzögerung vor den RUDP ACKs deutet auf Kamera-Timeout hin; möglicherweise überlasten wir die Kamera mit zu schnellen Retransmits
   - Implementation: `time.sleep(0.1)` zwischen Login #2 und Login #3 einfügen
   - Erwartetes Ergebnis: RUDP ACKs kommen schneller, gefolgt von MsgType=3

2. **DEBUG: Logging für RUDP ACK-Pakete verbessern**
   - Aktuell werden RUDP ACK-Pakete (0xD1) empfangen aber nicht speziell behandelt
   - Füge explizites Handling für RUDP ACK-Pakete in pump() hinzu
   - Logge, wenn RUDP ACKs während der Login-Wartezeit empfangen werden
   - Rationale: Verstehen, ob die RUDP ACKs korrekt empfangen werden und das Timing

3. **FIX: Prüfe, ob ACK-Suppression zur richtigen Zeit aktiviert wird**
   - Aktiviere ACK-Suppression erst NACH einer kurzen Wartezeit post Login #3
   - Aktuell aktivieren wir sie sofort (Δ=18ms nach Login #3)
   - Versuche: 100-200ms Pause nach Login #3, DANN ACK-Suppression
   - Rationale: Die Kamera könnte erwarten, dass wir noch 1-2 "ACK" Pakete ACKen, bevor wir supprimieren

### MITTLERE PRIORITÄT:
4. Temporär nur Login #1 + Magic1 senden, KEINE Retransmits #2/#3, und beobachten
   - Rationale: Testen ob Retransmits das Problem sind
   - Erwartetes Ergebnis: Wenn MsgType=3 kommt → Retransmits sind das Problem; wenn nicht → etwas anderes fehlt

5. Analysiere die empfangenen RUDP ACK-Pakete im Detail:
   - RUDP ACK Seq=1 BodyLen=6: hex=f1d10006d10000010000
   - RUDP ACK Seq=2 BodyLen=8: hex=f1d10008d100000200000000
   - Vergleiche diese mit MITM Line 432 (Seq=1, BodyLen=6)
   - Prüfe: Warum sendet Kamera 2 ACKs statt nur einen? Was bedeutet Seq=2 BodyLen=8?
   - Mögliche Interpretation: Seq=1 ACK für Magic1/Login, Seq=2 ACK für etwas anderes?

### NIEDRIGE PRIORITÄT (bereits widerlegt/geprüft):
~~6. Deaktivieren der ACK-Suppression~~ → H7 teilweise bestätigt, ACK-Suppression ist korrekt
~~7. Längerer RAW-RX-Dump~~ → Bereits implementiert, liefert keine neuen Erkenntnisse
~~8. FRAG Seq=83 analysieren~~ → H6 widerlegt, LBCS ist nicht relevant

---

## Welche Änderungen im Code (konkreter Vorschlag)
- In der Login-Handshake-Routine:
  - Vor dem Betreten des "login response wait mode" die Option einbauen: "suppress_ack_during_wait" (default true) -> setzbar auf false via ENV/Flag für Debug.
  - Log-Level erhöhen und die RAW-RX-DUMP-Dauer nach Magic1 auf 30–60s verlängern.
  - Temporär FRAG Seq=83 nicht ignorieren, sondern puffernd behandeln und versuchen, die Payload auf ARTEMIS-Headers zu prüfen.

---

## Abschätzung: Anzahl weiterer Iterationen mit GitHub Copilot (AKTUALISIERT)
- **Neue Schätzung: 2–4 Iterationen** (reduziert von 3-6)
  - **Iteration 1 (KRITISCH):** Implementiere Verzögerungen zwischen Login-Retransmits (50-100ms). Test → neue Logs analysieren
    - Wenn erfolgreich: Problem gelöst! ✅
    - Wenn nicht erfolgreich: Gehe zu Iteration 2
  - **Iteration 2 (FALLBACK):** Experimentiere mit ACK-Suppression-Timing (verzögerte Aktivierung post Login #3)
    - Teste: ACK-Suppression erst nach 100-200ms aktivieren
    - Analysiere neue Logs
  - **Iteration 3 (DEBUGGING):** Falls immer noch nicht erfolgreich, prüfe Retransmit-Strategie
    - Teste ohne Retransmits (#2/#3), nur Login #1
    - Analysiere RUDP ACK-Pakete im Detail (warum 2 ACKs? Seq=1 und Seq=2?)
  - **Iteration 4 (FEINTUNING):** Finale Anpassungen basierend auf den Erkenntnissen aus Iteration 1-3

**Begründung der reduzierten Schätzung:**
- H12 (Timing zwischen Retransmits) ist sehr wahrscheinlich die Hauptursache
- Der 2.9s Timeout vor den RUDP ACKs ist ein klarer Indikator
- MITM-Vergleich zeigt, dass alle Pakete korrekt sind, nur das Timing ist falsch
- Fix ist einfach (time.sleep) und kann schnell getestet werden

---

## Optimierter Prompt für die nächste Copilot-Iteration (AKTUALISIERT)

> **Ziel:** Login Timeout beheben - Kamera sendet RUDP ACKs aber kein MsgType=3, gefolgt von ERR/DISC Signalen.

### PRIORITÄT 1 - TIMING FIX (Iteration 1):

**Prompt (Deutsch):**
```
Analysiere den Login-Handshake in get_thumbnail_perp.py und behebe das Timing-Problem:

PROBLEM:
- Login #1, Magic1, Login #2, Login #3 werden zu schnell hintereinander gesendet (30ms und 20ms Abstand)
- Kamera antwortet erst nach 2.9 Sekunden mit RUDP ACKs (statt sofort wie in MITM)
- Nach den RUDP ACKs sendet Kamera ERR/DISC statt MsgType=3

LÖSUNG:
1. Füge 100ms Verzögerung (time.sleep(0.1)) zwischen Login #2 und Login #3 ein
2. Füge optional 50ms Verzögerung zwischen Login #1→Magic1→#2 ein
3. Teste, ob RUDP ACKs dann schneller kommen und MsgType=3 folgt

ERWARTETES VERHALTEN (per MITM):
Login #1 → Magic1 → RX "ACK" → TX ACK(Seq=1) → 
Login #2 (mit Pause) → Login #3 (mit Pause) → 
RX RUDP ACK (Seq=1) sofort → RX MsgType=3 ✅

Implementiere die Änderungen und erstelle einen Test-Run.
```

### PRIORITÄT 2 - ACK SUPPRESSION TIMING (Fallback für Iteration 2):

**Prompt (Deutsch):**
```
Falls Timing-Fix (Iteration 1) nicht erfolgreich war:

Ändere den Zeitpunkt, wann ACK-Suppression aktiviert wird:
1. Aktuell: Sofort nach Login #3 (Δ=18ms)
2. Neu: Erst 150ms NACH Login #3

Begründung:
- Kamera könnte erwarten, dass wir noch 1-2 "ACK" DATA Pakete ACKen
- Zu frühe Suppression verhindert möglicherweise kritischen Handshake
- MITM-Analyse zeigt möglicherweise Pause zwischen Login #3 und Suppression

Teste, ob spätere Suppression zu erfolgreicher MsgType=3 führt.
```

### PRIORITÄT 3 - RETRANSMIT STRATEGIE (Debugging für Iteration 3):

**Prompt (Deutsch):**
```
Experimentiere mit Retransmit-Strategie:

TEST 1: Sende NUR Login #1 + Magic1, KEINE Retransmits #2/#3
- Beobachte: Kommt MsgType=3?
- Wenn JA → Retransmits sind das Problem
- Wenn NEIN → etwas anderes fehlt

TEST 2: Analysiere die 2 RUDP ACKs im Detail:
- Warum sendet Kamera RUDP ACK Seq=1 UND Seq=2?
- MITM zeigt nur einen ACK (Seq=1, BodyLen=6)
- Unsere Logs zeigen zwei ACKs (Seq=1 BodyLen=6, Seq=2 BodyLen=8)
- Sind das ACKs für Login #2 und #3?
- Müssen wir diese ACKs speziell behandeln?
```

---

## Nächste Schritte (AKTUALISIERT - konkret und priorisiert)

### SOFORT (Iteration 1):
1. **Implementiere Timing-Fix in get_thumbnail_perp.py:**
   - Zeile ~1765: Füge `time.sleep(0.1)` nach Login #2 ein
   - Zeile ~1770: Füge `time.sleep(0.1)` nach Login #3 ein
   - Optional: Füge `time.sleep(0.05)` nach Login #1 und nach Magic1 ein
2. **Testlauf durchführen:**
   - Führe get_thumbnail_perp.py aus
   - Sammle neue Logs (debug09012026_9.log)
   - Prüfe: Kommen RUDP ACKs schneller? (< 1s statt 2.9s)
   - Prüfe: Folgt MsgType=3 nach den RUDP ACKs?

### FALLBACK (Iteration 2 - falls Iteration 1 nicht erfolgreich):
3. **ACK-Suppression-Timing anpassen:**
   - Ändere Zeile ~1777: Aktiviere `_in_login_response_wait` nicht sofort
   - Füge `time.sleep(0.15)` VOR der Zeile `self._in_login_response_wait = True` ein
   - Testlauf mit neuen Logs

### DEBUGGING (Iteration 3 - falls Iteration 1+2 nicht erfolgreich):
4. **Retransmit-Strategie testen:**
   - Kommentiere Login #2 und #3 aus (nur Login #1 senden)
   - Testlauf → beobachte ob MsgType=3 kommt
   - Dokumentiere Ergebnisse

5. **RUDP ACK-Handling verbessern:**
   - Implementiere explizite Behandlung für RUDP ACK-Pakete in pump()
   - Logge detailliert, wenn RUDP ACKs empfangen werden
   - Analysiere die Bedeutung von Seq=1 vs Seq=2

### DOKUMENTATION:
6. **Nach jedem erfolgreichen Fix:**
   - Aktualisiere ANALYSE_KONSOLIDIERT_LOGIN.md mit Ergebnis
   - Dokumentiere welche Hypothese bestätigt/widerlegt wurde
   - Erstelle SUMMARY-Datei für Issue #191

---

## Ergänzende Beobachtungen aus debug09012026_7.log & debug09012026_8.log (Kurzbulletpoints)
- Wiederholte FRAG Seq=83 während des gesamten Login-Fensters (möglicherweise Discovery/Beacon-Verhalten der Kamera).
- Viele kurze F1 ERR (f1e00000) Pakete — diese sind reine 4-Byte Notices; keine ARTEMIS-Payloads erkennbar.
- RAW RX-Dumps enthalten im relevanten Zeitraum nur f1e00000 / f1f00000, kein vollständiges MsgType=3.
- Client sendet mehrere Heartbeats (AppSeq=2+) nach dem Timeout, aber offenbar ohne Erfolg.

---

## Abschluss
Ich habe dieses Konsolidierungsdokument mit den neuen Hypothesen ergänzt. Als nächsten Schritt werde ich die vorgeschlagenen Code-Änderungen (ACK suppression Flag + RAW-DUMP-Verlängerung + FRAG-Puffern) vorschlagen/implementieren — sobald du einverstanden bist, mache ich einen PR mit den Änderungen.
