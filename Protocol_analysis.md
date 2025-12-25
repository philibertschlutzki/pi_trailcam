Hier ist die **technisch vollständige und präzise Protokollspezifikation** für die KJK/Artemis Wildkamera-Kommunikation.

Dieses Dokument basiert auf der forensischen Analyse der `ble_udp_1.log`, `app_debug.log` und `App_Log` Dateien. Es dient als "Single Source of Truth" für die Implementierung eines Clients.

---

# Protokoll-Spezifikation: KJK/Artemis Wildkamera Interface v1.0

## 1. Architektur-Übersicht

Die Kommunikation erfolgt über ein proprietäres Stack-Modell auf UDP-Basis:

1. **Physisch/Link:** Wi-Fi (Credentials via BLE).
2. **Transport:** **RUDP** (Reliable UDP) – Ein Custom-Layer für Sequenzierung, Fragmentierung und ACKs.
3. **Applikation:** **Artemis** – Ein verschlüsseltes Command-Response-Protokoll mit JSON-Payloads.

---

## 2. Phase 0: Bluetooth LE (Wake-Up & Credentials)

Bevor eine Wi-Fi-Verbindung möglich ist, muss das WLAN-Modul der Kamera via BLE aktiviert werden.

* **Service UUID:** `00001800-...` (Generic Access) / Custom Service
* **Write Characteristic:** `00000002-0000-1000-8000-00805f9b34fb`
* **Notify Characteristic:** `00000003-0000-1000-8000-00805f9b34fb`

**Ablauf:**

1. **Wake-Up Command:** Client schreibt `0x13 0x57 0x01 0x00 0x00 0x00 0x00 0x00` auf Characteristic `...0002`.
2. **Credentials Empfang:** Kamera sendet via Notify auf `...0003` JSON-Fragmente.
* Zusammengesetztes JSON: `{"ret":0, "ssid":"KJK_XXXX", "bssid":"...", "pwd":"..."}`.



---

## 3. Transport Layer: RUDP (Reliable UDP)

Jedes UDP-Paket besitzt einen 8-Byte Header. Die Kommunikation ist **Big-Endian** für den RUDP-Header.

### 3.1 RUDP Header Struktur (8 Bytes)

| Offset | Feld | Länge | Beschreibung |
| --- | --- | --- | --- |
| 0x00 | **Magic** | 1 Byte | Immer `0xF1` |
| 0x01 | **Type** | 1 Byte | Paket-Typ (siehe 3.2) |
| 0x02 | **Length** | 2 Bytes | Länge der **Payload + 4** (Header-Suffix-Overhead) |
| 0x04 | **Const** | 1 Byte | Immer `0xD1` |
| 0x05 | **Pad** | 2 Bytes | `0x00 0x00` |
| 0x07 | **Seq** | 1 Byte | Sequenznummer (0-255, rollierend) |

### 3.2 Paket-Typen (Byte 0x01)

| Typ | Name | Beschreibung |
| --- | --- | --- |
| `0xD0` | **DATA** | Reguläres Datenpaket (enthält Artemis-Payload). Erfordert ACK. |
| `0xD1` | **ACK/CTRL** | Bestätigung oder Kontrollpaket (Magic 1/2). |
| `0x42` | **FRAG** | Datenfragment (Teil einer größeren Artemis-Nachricht). Erfordert ACK. |
| `0xF9` | **PRE_LOGIN** | Initialisierung der Verschlüsselung (Nonce Exchange). |
| `0x41` | **DISC_RESP** | Antwort auf Discovery Broadcast. |
| `0x43` | **KEEPALIVE** | Low-Level Keepalive (oft ohne Payload). |

### 3.3 Acknowledge (ACK) Format (Kritisch!)

Ein ACK muss exakt **10 Bytes** lang sein (8 Byte Header + 2 Byte Payload).
Falsche Länge führt zu Retransmissions (Endlos-Schleifen).

* **Header:** `F1 D1 00 06 D1 00 00 [RX_SEQ]`
* **Payload:** `00 [RX_SEQ]`

**Regel:** Jedes eingehende Paket vom Typ `0xD0` oder `0x42` muss mit einem ACK bestätigt werden, das die empfangene Sequenznummer (`RX_SEQ`) im Header (Byte 7) und in der Payload (Byte 1) trägt.

---

## 4. Application Layer: Artemis

Die Artemis-Payload befindet sich im Datenbereich des RUDP-Pakets.
Alle Integer-Werte im Artemis-Header sind **Little-Endian**.

### 4.1 Artemis Header (20 Bytes)

| Offset | Feld | Länge | Wert / Beschreibung |
| --- | --- | --- | --- |
| 0x00 | **Magic** | 8 Bytes | `"ARTEMIS\0"` (`41 52 54 45 4d 49 53 00`) |
| 0x08 | **CmdID** | 4 Bytes | Command ID (z.B. `2`=Hello, `0`=Login) |
| 0x0C | **AppSeq** | 4 Bytes | App-Level Sequenzzähler (inkrementierend) |
| 0x10 | **Len** | 4 Bytes | Länge der nachfolgenden Daten (Base64-String) |

### 4.2 Payload & Verschlüsselung

Die Daten nach dem Artemis-Header sind **immer** ein Base64-String, der `\x00`-terminiert ist.

1. **Format:** `Header` + `Base64_String` + `0x00`.
2. **Inhalt:** Der Base64-String dekodiert zu einem AES-verschlüsselten Block.
3. **AES Parameter:**
* **Key:** `a01bc23ed45fF56A` (16 Bytes, statisch für Phase 2).
* **Mode:** AES-128-ECB.
* **Padding:** PKCS7.


4. **Klartext:** Ein JSON-Objekt.

---

## 5. Verbindungsablauf (State Machine)

### Phase 1: Discovery & Pre-Login

1. **Discovery (UDP Broadcast):**
* Client sendet `LBCS`-Payload an Port 40611.
* Kamera antwortet mit `F1 41...` (Discovery Response).


2. **Pre-Login (Encryption Init):**
* Client sendet RUDP Typ `0xF9`. Payload: Statischer Header + verschlüsselte Nonce/Time.
* Kamera antwortet (meist RUDP Typ `0x42` oder `0xD0`).



### Phase 2: Handshake (Der "Golden Path")

Hier scheiterten frühere Implementierungen. Der Ablauf muss exakt sein.

| Schritt | Richtung | RUDP Typ | Artemis Cmd | Inhalt / Aktion |
| --- | --- | --- | --- | --- |
| 1 | Client -> Cam | `0xD0` | `2` (Hello) | "Hello"-JSON (verschlüsselt). |
| 2 | Cam -> Client | `0xD1` | - | **ACK** für Hello. |
| 3 | Cam -> Client | `0xD0` | **`3`** (Result) | **Kritisch:** Antwort auf Hello ist Cmd 3! Script muss dies akzeptieren. |
| 4 | Client -> Cam | `0xD1` | - | **ACK** für Cmd 3. |
| 5 | Client -> Cam | `0xD1` | - | **Magic 1** (`00 00...` Payload). Seq springt oft. |
| 6 | Client -> Cam | `0xD1` | - | **Magic 2** (`00 00` Payload). |

*Hinweis:* Nach Schritt 6 setzt die App den RUDP-Sequenzzähler oft zurück oder synchronisiert ihn neu.

### Phase 3: Stabilisierung & Login

1. **Stabilisierung (Heartbeats):**
* Client sendet `Cmd 2` (Heartbeat, Payload `MzlB...`) alle **3 Sekunden**.
* Client **wartet zwingend** auf das ACK der Kamera für jeden Heartbeat, um Sequenz-Synchronität zu beweisen.


2. **Login:**
* Client sendet `Cmd 0` (Login Request) mit User/Pass und `utcTime`.
* **Wichtig:** Client wartet auf **`Cmd 3`** (Login Response).
* **Token:** Aus dem JSON der Response (`{"token": 12345...}`) wird der Session-Token extrahiert.



### Phase 4: Datentransfer (Operation)

Für alle weiteren Befehle (z.B. Dateiliste `Cmd 768`, Thumbnails `Cmd 772`) gilt:

* Der Token muss im JSON enthalten sein: `{"cmdId": 768, "token": "..."}`.
* **Große Daten (Fragmentierung):**
* Kamera sendet Pakete vom Typ `0x42` (FRAG).
* Jedes Fragment muss ge-ACKt werden.
* Das letzte Paket ist Typ `0xD0` (mit Artemis-Header) und schließt den Transfer ab.
* Die Payload aller Fragmente + des letzten Pakets wird konkateniert -> ergibt Artemis Header + Base64 Daten.



---

## 6. Konstanten Referenz

**Ports:**

* UDP 40611 (Command/Control)
* UDP 3333 (Data/Stream - optional)

**Schlüssel:**

* AES Key: `b"a01bc23ed45fF56A"`

**Magic Payloads:**

* **Discovery (LBCS):** `f14100144c42435300000000000000004343434a4a000000`
* **Heartbeat Body:** `415254454d49530002000000...` (Artemis Header Cmd 2 + Base64 `MzlB...`)

**Timing:**

* Heartbeat-Intervall: **3.0 Sekunden**.
* Socket Timeout: **0.5 - 1.0 Sekunden** (aggressives Polling nötig).

---

## 7. Fehlerbehandlung & Filterung

Um Stabilität zu gewährleisten, muss der Client "Noise" filtern:

1. **Ignore Cmd 9:** Die Kamera sendet unaufgefordert `Cmd 9` (Notifications). Diese dürfen nicht als Antwort auf einen Request (wie Login) interpretiert werden.
2. **Retry:** Wenn nach 1s kein ACK kommt -> Retransmit.
3. **Buffer:** Empfangspuffer auf OS-Ebene (SO_RCVBUF) auf mind. 2MB setzen, da Bursts von Fragmenten kommen.
