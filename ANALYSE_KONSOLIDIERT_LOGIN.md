# Konsolidierte Analyse zum Login-Problem (chronologisch)

> Datei aktualisiert basierend auf allen verfügbaren Logs (siehe Liste unten), Protokollanalyse und MITM‑Captures.
> **Status 16.01.2026**: Kritischer Fehler im Discovery-Exit identifiziert (Issue #195).

## Referenzen
- Repository: https://github.com/philibertschlutzki/pi_trailcam
- Protokoll-Spezifikation: https://github.com/philibertschlutzki/pi_trailcam/blob/main/Protocol_analysis.md
- MITM UDP-Logs:
  - tests/MITM_Captures/ble_udp_1.log (Referenz für erfolgreichen Login)
- Relevante Debug-Logs:
  - tests/debug09012026_8.log (Issue #191)
  - tests/debug16012026_1.log (Aktuell: Issue #195)

---

## Kurzfassung (aktuell)
Der Login scheitert, weil die Kamera **statt einer Login-Response (MsgType=3)** Fehlersignale (**0xE0 ERROR** und **0xF0 DISC**) sendet.
Die Analyse von `debug16012026_1.log` zeigt, dass die Kamera während der gesamten Login-Sequenz weiterhin **Discovery-Pakete (LBCS FRAG Seq=83)** sendet.
Dies deutet darauf hin, dass die Kamera den Discovery-Modus nicht verlassen hat. Im Vergleich dazu stoppen diese Pakete im erfolgreichen MITM-Capture *vor* dem Login.
Das gleichzeitige Senden von Login-Requests, während die Kamera noch im Discovery-Modus sendet, führt zum Abbruch durch die Kamera.

---

## Chronologische Konsolidierung (wichtigste Ereignisse & Fixes)

1.  **Issue #185 (ACK Logic):** Client hat DATA-Pakete mit "ACK"-Payload nicht bestätigt.
    *   *Fix:* Alle DATA-Pakete werden bestätigt.
2.  **Issue #187 (Seq Num):** Client hat falsche Sequenznummern nach Magic1 gesendet.
    *   *Fix:* Reset `global_seq` nach Magic1, Nutzung von `next_seq()` für ACKs.
3.  **Issue #189/191 (ACK Suppression):** Client hat ACKs zu lange unterdrückt oder in Endlosschleife gesendet.
    *   *Fix:* Zeitlich begrenzte ACK-Suppression (200ms/5 Pakete) nach Login#3.
4.  **Issue #195 (Aktuell - Discovery Exit):** Trotz korrekter ACKs sendet die Kamera ERROR.
    *   *Befund:* Massive Flutung mit LBCS FRAG Seq=83 Paketen *während* des Logins.
    *   *Ursache:* Client beendet Discovery-Phase zu früh, ohne "Auslaufen" (Draining) der Pakete abzuwarten. Kamera bleibt im Discovery-State.

---

## Detaillierte Analyse: Issue #195 (debug16012026_1.log)

### Vergleich: MITM (OK) vs. Debug Log (FAIL)

**MITM (ble_udp_1.log):**
*   Zeile 375: Letztes `RUDP FRAG Seq=83` (Discovery).
*   Zeile 378: `TX Login#1`.
*   **Resultat:** Keine weiteren FRAG-Pakete während des Logins. Kamera antwortet mit `MsgType=3`.

**Debug Log (debug16012026_1.log):**
*   17:02:51,762: Discovery OK.
*   17:02:54,798: Start Login#1 (nach 3s Pause).
*   17:02:54,898: `📥 RUDP FRAG Seq=83` (Discovery) - **IGNORED**.
*   ... (Dutzende weitere FRAG Seq=83 Pakete während des Handshakes) ...
*   17:02:56,315: `📥 F1 ERR (short,len=4) f1e00000` (Fehler).
*   17:03:03,657: `📥 F1 DISC (short,len=4) f1f00000` (Disconnect).
*   **Resultat:** Login Timeout.

### Hypothesen

#### **H17: Discovery Exit Problem (Bestätigt)**
*   **Beobachtung:** Die Kamera sendet ununterbrochen Discovery-Antworten (FRAG Seq=83), auch nachdem der Client die Discovery für beendet erklärt hat.
*   **Problem:** Der Client kehrt sofort nach dem ersten Antwortpaket aus `discovery()` zurück und geht in einen `sleep`. Die Kamera sendet weiter. Wenn der Client nach dem Sleep wieder liest (`pump`), ist der Puffer voll mit alten FRAG-Paketen oder die Kamera ist immer noch im Sendemodus.
*   **Konsequenz:** Die Login-Pakete kollidieren logisch mit dem Discovery-State der Kamera -> Kamera sendet ERROR/DISC.
*   **Lösung:** Implementierung einer "Drain"-Phase in `discovery()`. Nach der ersten Antwort muss der Client noch kurz (0.5 - 1.0s) weiterhören und alle ankommenden LBCS-Pakete verwerfen ("draining"), bis Ruhe einkehrt.

#### H18: utcTime Abweichung (Unwahrscheinlich)
*   Zeitstempel im Log (`1768579374`) entspricht korrekt `2026-01-16 17:02:54`.

#### H19: JSON Encoding (Unwahrscheinlich)
*   Bisher keine Hinweise auf Encoding-Fehler, da wir gar keine Antwort (außer ERR) bekommen.

---

## Plan: Behebung von Issue #195

### Ziel
Implementierung einer **Discovery Drain Phase**, um sicherzustellen, dass die Kamera den Discovery-Modus verlassen hat, bevor der Login beginnt.

### Code-Änderungen (`get_thumbnail_perp.py`)
In der Methode `discovery()`:
1.  Nach Erkennung des aktiven Ports (`✅ Discovery OK`): **Nicht sofort returnen.**
2.  Schleife starten (z.B. für 1.0 Sekunden):
    *   `recvfrom` aufrufen.
    *   Prüfen, ob es sich um LBCS FRAG Pakete handelt (`data[4:8] == b'LBCS'`).
    *   Diese Pakete zählen und loggen ("🗑️ Draining...").
    *   Wenn Timeout (keine Pakete mehr), Schleife früher beenden.
3.  Erst danach `return True`.

### Erwartetes Ergebnis
*   Discovery wird durchgeführt.
*   Client "frisst" alle nachfolgenden Discovery-Pakete der Kamera.
*   Kamera stellt das Senden von FRAG Seq=83 ein.
*   Nachfolgender 3s-Sleep (`CAMERA_STABILIZATION_DELAY`) verläuft ruhig.
*   Login-Handshake startet ohne störende FRAG-Pakete.
*   Kamera antwortet mit `MsgType=3` (Login Token).

---

## Schätzung & Prompt

**Verbleibende Iterationen:** 1-2
(Iteration 1: Fix Discovery Drain. Iteration 2: Falls noch Detailprobleme, Feintuning.)

**Optimierter Prompt:**
```text
Implementiere die "Discovery Drain"-Logik in der discovery()-Methode von get_thumbnail_perp.py.
Ziel: Verhindere das "FRAG Seq=83 Flooding" während des Logins (Issue #195).
Details:
1. Füge in discovery() nach dem erfolgreichen Empfang ("Discovery OK") eine Loop ein.
2. Die Loop soll für max. 1.0 Sekunden laufen (time.time()).
3. Rufe sock.recvfrom() auf und konsumiere alle Pakete.
4. Logge verworfene LBCS-Pakete als DEBUG ("Draining...").
5. Beende die Loop vorzeitig bei socket.timeout (Silence).
6. Returniere erst danach True.
```
