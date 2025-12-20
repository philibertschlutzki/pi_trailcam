# Antworten auf Fragen aus Issue #112

Hier sind die Antworten auf die "Kritischen offenen Fragen" basierend auf der aktuellen Codebasis (`main_correct.py`), den Analysedateien (`ANALYSE_UND_SCHRITTE.md`, `STEPS_TO_REPLICATE_TRAFFIC.md`) und dem vorhandenen Wissen.

## 🔴 Kritische offene Fragen

### 1. Verschlüsselung und Kryptographie
*   **Frage:** Welcher Algorithmus? Woher kommt der Key? Wie wird Phase 2 generiert?
*   **Antwort:** Der genaue Verschlüsselungsalgorithmus (vermutlich AES) und der Schlüsselaustausch sind noch **nicht** per Reverse-Engineering geklärt.
    *   **Aktuelle Lösung:** Wir verwenden eine **Replay-Attack-Strategie**. Die Phase 2 Payload (`PHASE2_ENCRYPTED_PAYLOAD` in `main_correct.py`) ist ein hardcodiertes Byte-Array (`0x0c 0xcb...`), das aus einem erfolgreichen Traffic-Log (`frida_udp_traffic.log`) extrahiert wurde.
    *   Es findet aktuell keine dynamische Verschlüsselung statt.

### 2. Session-Token-Generierung aus BLE
*   **Frage:** Wie generiert? Timestamp/Nonce? Gültigkeit?
*   **Antwort:** Das Token wird als Base64-String über eine BLE-Notification (`0000ffe1...`) empfangen.
    *   **Struktur:** Die interne Struktur ist unbekannt (Opaque Blob).
    *   **Gültigkeit:** Es scheint für die Dauer der Session gültig zu sein.
    *   **Implementierung:** `main_correct.py` akzeptiert ein Token via Kommandozeile (`--token`) oder holt es dynamisch über BLE. Für Tests wird oft ein bekanntes Token aus den Logs (`TEST_BLE_TOKEN`) wiederverwendet.

### 3. ACK/NAK-Protokolllogik
*   **Frage:** Wann ACKs? Retransmission? Flow Control?
*   **Antwort:** Das Protokoll nutzt `0xF1 D1` Pakete (Outer Header) für Flow Control und Bestätigungen.
    *   **Logik:** Der Inner Header dieser Pakete enthält Sequenznummern, die bestätigt werden (Payload).
    *   **Code:** Die Klasse `PPPPSession` implementiert `parse_ack_packet`, welches diese Pakete auswertet und bestätigte Sequenznummern aus der `pending_acks`-Liste im `SequenceManager` entfernt.
    *   **Retransmission:** In Phase 2 wartet der Code explizit auf ein ACK (`0xF1 D0 ... ACK`). Fehlt dieses, wird das Paket erneut gesendet (Retry-Loop).

### 4. Payload-Padding und Alignment-Regeln
*   **Frage:** 4-Byte-Alignment? Null-Padding?
*   **Antwort:** Ja, Payloads müssen auf 4-Byte-Grenzen ausgerichtet sein.
    *   **Implementierung:** In `send_artemis_command` wird dies explizit durchgeführt:
        ```python
        if len(artemis_header) % 4 != 0:
            padding = b'\x00' * (4 - (len(artemis_header) % 4))
            artemis_header += padding
        ```
    *   Es wird **Null-Padding** (`\x00`) verwendet.

### 5. Bildübertragungsprotokoll
*   **Frage:** Reassembly? Checksums? Ende-Signal?
*   **Antwort:** Dies ist im aktuellen Python-Code **noch nicht implementiert**.
    *   Es existiert keine Logik für Fragmentierung oder Reassembly in `main_correct.py`.
    *   Dies bleibt eine offene Aufgabe, die eine tiefere Analyse von `udp_traffic_3.log` erfordert.

## 🟡 Wichtige zu klärende Details

### 6. Session-ID und Device-ID Handling
*   **Frage:** Persistente Session ID? Device ID Aufbau?
*   **Antwort:**
    *   **Session ID:** Diese ist dynamisch und wird aus der **Discovery Response (Type `0x43`)** extrahiert.
    *   **Korrektur:** Frühere Versionen lasen am falschen Offset (`[20:24]`). Der aktuelle Stand (laut `ANALYSE_UND_SCHRITTE.md` Empfehlung und Code) ist Offset **`[24:28]`**.
    *   **Device ID:** Der String "LBCS..." scheint statisch oder fest mit der Hardware verdrahtet zu sein.

### 7. Command-Type-Mapping vollständig
*   **Frage:** Was machen Cmd 2-6? Weitere Commands?
*   **Antwort:** Die Befehle 2 bis 6 gehören zur **Initialisierungs-Sequenz** (Handshake) nach dem Login.
    *   **Mapping:** Ihre genaue Funktion ("Check Status", "GetConfig") ist nicht dokumentiert, aber ihre **Reihenfolge ist strikt** und im Code (`phase4_initialization_sequence`) durch Replay von Base64-Payloads abgebildet.
    *   Weitere Befehle (Video, Einstellungen) sind im Code nicht vorhanden.

### 8. Error-Code-Semantik
*   **Frage:** Error Codes?
*   **Antwort:** Bekannt ist lediglich `{"result": 0}` für Erfolg.
    *   Der Code prüft aktuell primär auf das Vorhandensein von Antworten (Timeouts) oder ACKs, wertet aber keine spezifischen Error-Codes im JSON-Payload aus (außer im Log-Output).

### 9. WiFi-Modus und Netzwerk-Topologie
*   **Frage:** Station Mode vs. AP Mode?
*   **Antwort:** Die Kamera arbeitet im **AP-Modus** (Access Point).
    *   **IP:** Standardmäßig `192.168.43.1`.
    *   **Verbindung:** Der Raspberry Pi verbindet sich als Client mit diesem Netzwerk (`WiFiWorker` nutzt `nmcli`).
    *   Station Mode ist unbestätigt.

### 10. BLE-Wakeup-Details
*   **Frage:** Magic Bytes? Timing?
*   **Antwort:**
    *   **Magic Bytes:** `0x13, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00` (hardcodiert in `main_correct.py`).
    *   **Timing:** Nach dem Senden der Bytes wartet der Code (`main_correct.py`) **5 Sekunden**, bevor er versucht, sich mit dem WLAN zu verbinden, um der Kamera Zeit zum Booten des WiFi-Stacks zu geben.
