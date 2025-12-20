# Analyse der Kommunikation: `main_correct.py` vs. `frida_udp_traffic.log`

## Ergebnis
Die Kommunikation in `main_correct.py` funktioniert **nicht** genau gleich wie im Log `frida_udp_traffic.log`. Es gibt signifikante Unterschiede im Ablauf, den verwendeten Paket-Typen und der Behandlung von Antworten.

## Gefundene Diskrepanzen

### 1. Phase 1: LBCS Discovery (Session ID)
*   **Im Log:** Das Antwortpaket (`0xF1 0x43`) enthält nach der Sequenz `CCCJJ` (Ende bei Index 20) noch 3 Null-Bytes. Eine variable ID (Session ID) scheint erst ab Index 24 (`0x18`) zu beginnen.
*   **Im Code:** Der Code extrahiert `resp[20:24]`. Dies entspricht den Bytes `4A 00 00 00` (Teil von "JJ" und Padding). Dies ist vermutlich statisch und keine korrekte Session ID.
*   **Abweichung:** Der Code verwendet wahrscheinlich den falschen Offset für die Session ID.

### 2. Phase 2: Encrypted Pre-Login (`0xF9`)
*   **Im Log:** Der Client sendet verschlüsselte Daten (`0xF1 0xF9`). Daraufhin empfängt er `ACK` Pakete (`0xF1 0xD0 ... ACK`) und `LBCS` Broadcasts (`0xF1 0x42`).
*   **Im Code:** Der Code sendet 84 Null-Bytes (Dummy) "blind" dreimal hintereinander und ignoriert jegliche Antworten oder ACKs.
*   **Abweichung:** Fehlendes Handling von ACKs und fehlende echte Verschlüsselung (wobei letzteres bekannt ist, aber das Verhalten "Blind Senden" weicht ab).

### 3. Fehlender PPPP-Paket-Typ `0xD1`
*   **Im Log:** Es ist eine massive Nutzung von Paketen mit dem Outer Header `0xF1 0xD1` zu sehen (z.B. `f1 d1 00 0e ...`). Diese werden oft direkt nach `0xD0` Paketen gesendet, vermutlich als Transport-Layer ACK oder Keepalive.
*   **Im Code:** Dieser Paket-Typ (`0xD1` als Outer Header Type) existiert nicht. Der Code sendet nur `0xD0` (Data), `0x41` (Discovery) und `0xF9` (Pre-Login).
*   **Abweichung:** Der Transport-Layer ist unvollständig implementiert.

### 4. Phase 4: Session-Ablauf nach Login
*   **Im Log:** Nach dem Login (`Type 1`) sendet der Client aktiv weitere Befehle:
    *   Befehle mit Artemis Payload Type `2`, `3`, `4`, etc.
    *   Dazwischen werden `0xD1` Pakete ausgetauscht.
*   **Im Code:** Nach dem erfolgreichen Login geht der Code in eine Endlosschleife (`phase4_heartbeat_loop`), die **nur empfängt** ("listen for now"). Es werden keine weiteren Befehle gesendet.
*   **Abweichung:** Der eigentliche Funktionsumfang (Status abfragen, Konfiguration) fehlt im Code komplett.

---

## Nötige Schritte zur Angleichung

Um das Verhalten von `main_correct.py` an das Log anzupassen, sind folgende Schritte in einer Markdown-Datei oder als Code-Changes nötig:

1.  **Session ID Logik korrigieren:**
    *   Ändern des Offsets beim Auslesen der Session ID in `phase1_lbcs_discovery` von `[20:24]` auf `[24:28]` (oder basierend auf dynamischer Analyse des `CCCJJ` Endes).

2.  **PPPP `0xD1` Support implementieren:**
    *   Hinzufügen einer Methode in `PPPPSession`, um Pakete mit Typ `0xF1 0xD1` zu senden.
    *   Analysieren des Logs, wann genau diese gesendet werden (z.B. als Bestätigung auf empfangene Pakete).

3.  **Reaktives Senden implementieren:**
    *   Statt "Blind Senden" in Phase 2 sollte auf das `ACK` gewartet werden.

4.  **Befehlskette nachbilden:**
    *   In `Phase 4` muss eine Sequenz von Befehlen implementiert werden, die dem Log entspricht (z.B. `GetState` Command senden), anstatt nur passiv zu warten.

5.  **Payload-Struktur verfeinern:**
    *   Sicherstellen, dass die Artemis-Payloads (Inner Header Sequenznummern) korrekt hochgezählt werden, wie im Log beobachtet.
