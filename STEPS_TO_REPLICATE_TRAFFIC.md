# Schritte zur Replikation des Netzwerkverkehrs (Frida Log vs. Code)

Die Analyse des Frida-Traffic-Logs (`frida_udp_traffic.log`) und des aktuellen Codes (`main_correct.py`) zeigt signifikante Unterschiede. Um die Kommunikation **genau gleich** zu gestalten, müssen folgende Schritte im Code implementiert werden.

## 1. Phase 2: Korrekter Payload (Verschlüsselung)
Der aktuelle Code sendet `84` Null-Bytes (`\x00`). Das Log zeigt jedoch einen spezifischen, verschlüsselten Payload.

*   **Diskrepanz:**
    *   Code: `encrypted_payload = b'\x00' * 84`
    *   Log: `0c cb 9a 2b 5f ...` (84 Bytes)
*   **Lösung:**
    *   Ersetzen Sie den Dummy-Payload durch die exakten Bytes aus dem Log (sofern diese statisch sind) oder implementieren Sie die entsprechende Verschlüsselung (AES/DES), falls bekannt. Für eine exakte Replikation des Logs sollten zunächst die aufgezeichneten Bytes (`76a40e1468`...) verwendet werden.

## 2. Implementierung von `0xF1 0xD1` Kontroll-Paketen
Das Log ist durchzogen von Paketen des Typs `0xF1 0xD1` (Outer Header), die der Code aktuell nicht sendet. Diese scheinen als "Keep-Alive", "Flow Control" oder "ACK" zu dienen.

*   **Diskrepanz:**
    *   Code: Sendet nur `0xF1 0xD0` (Commands).
    *   Log: Sendet regelmäßig `0xF1 0xD1`.
    *   Beispiel Log: `f1 d1 00 0e d1 00 00 05 ...`
*   **Lösung:**
    *   Implementieren Sie eine Methode `send_control_packet(seq, payload)`, die `0xF1 0xD1` Pakete erstellt.
    *   Analysieren Sie die Sequenznummern (`d1 00 00 05` -> Seq 5?). Es scheint, dass diese Pakete parallel zu den Befehlen gesendet werden.
    *   Fügen Sie diese Aufrufe an den entsprechenden Stellen (nach Login, zwischen Befehlen) ein.

## 3. Exakte Befehlsabfolge (Phase 4)
Der Code springt nach dem Login in einen simplen Heartbeat-Loop. Das Log zeigt jedoch eine spezifische Initialisierungs-Sequenz.

*   **Diskrepanz:**
    *   Code: `Login` -> `Loop (Cmd 10 / Dummy)`
    *   Log: `Login` -> `Cmd 2` (Check Status?) -> `Cmd 0x10001` (GetState?) -> `Cmd 3` -> ...
*   **Lösung:**
    *   Ersetzen Sie `phase4_heartbeat_loop` durch eine `phase4_initialization_sequence`.
    *   Senden Sie die folgenden Befehle nacheinander (mit Wartezeit auf Antwort):
        1.  **Cmd 2:** Payload `y+DD...` (Base64).
        2.  **Cmd 0x10001 (oder Ver 2 Cmd 1):** Payload `MzlB...` (Base64).
        3.  **Cmd 4:** Payload `I3mb...` (Base64).
        4.  **Cmd 5:** Payload `y+DD...` (Wiederholung Cmd 2?).
        5.  **Cmd 6:** Payload `36Rw...` (Base64).
        6.  **Cmd 7:** Payload `90RH...` (Base64).

## 4. Verwendung der exakten Base64-Payloads
Der Code nutzt aktuell `b'{}'` oder den Login-Token. Für eine exakte Replikation müssen die Payloads aus dem Log übernommen werden.

*   **Beispiel Cmd 2 (aus Log):**
    *   Header: `ARTEMIS\x00` + `02 00 00 00` (Ver) + `02 00 00 00` (Cmd)
    *   Payload Len: `2d 00 00 00` (45 Bytes)
    *   Data: `79 2b 44 44 62 71 4d 4e 4e 6e 56 35 ...` (ASCII: `y+DDbqMNNnV5...`)
*   **Lösung:**
    *   Extrahieren Sie alle Base64-Strings aus dem Log und hinterlegen Sie diese als Konstanten im Code (z.B. `CMD_2_PAYLOAD = "y+DD..."`).
    *   Nutzen Sie diese Konstanten in `send_artemis_command`.

## 5. Sequenz-Nummern Synchronisation
Im Log variieren die inneren Sequenznummern (z.B. Login Seq 0, dann Control Packet Seq 5).

*   **Analyse:**
    *   Es muss geprüft werden, ob `0xD0` (Commands) und `0xD1` (Control) denselben Zähler nutzen oder getrennte.
    *   Passen Sie den `SequenceManager` an, um die im Log beobachteten Sprünge oder Zählweisen nachzubilden (ggf. manuelles Setzen der Seq für Testzwecke).

## Zusammenfassung der Aufgaben
1.  `phase2_pre_login`: Payload auf die Log-Bytes ändern.
2.  `PPPPSession`: Methode `send_control_d1` hinzufügen.
3.  `phase4`: Die statische Befehlskette (Cmd 2, 0x10001, 4, 5, 6, 7...) implementieren.
4.  Konstanten für die Base64-Payloads anlegen.
