# Protocol Analysis: Artemis PPPP Wrapper

## 1. Overview
This document details the reverse engineering of the TrailCam Go Android application (`com.xlink.trailcamgo`) and its communication protocol. The camera uses a proprietary protocol (referred to as "Artemis") wrapped inside the PPPP (P2P Push Proxy Protocol) transport layer.

**Analysis Source:**
- APK: `com.xlink.trailcamgo` (Version 2.x)
- Libraries: `libArLink.so` (Native P2P logic)
- Classes: `com.xlink.arlink.ArLinkApi`, `Artemis*` commands
- Packet Captures: `tcpdump` logs from device interactions

## 2. Protocol Stack Structure

The communication is layered as follows:

1.  **Transport Layer**: UDP (Ports 40611, 59130, etc.)
2.  **Session Layer**: PPPP (P2P Push Proxy Protocol) - Magic `0xF1`
3.  **Application Layer**: Artemis Protocol (Payload inside PPPP)

```
[UDP Header]
    [PPPP Outer Header (4 Bytes)]
        [PPPP Inner Header (4 Bytes)]
            [Artemis Payload (Variable)]
```

## 3. PPPP Headers

Analysis of `libArLink.so` and packet dumps reveals the PPPP header structure.

### 3.1 Outer Header (4 Bytes)
| Offset | Field | Value | Description |
|---|---|---|---|
| 0 | Magic | `0xF1` | Protocol Identifier |
| 1 | Type | `0xD1`, `0xD0`, `0xE1` | Packet Type (Standard, Login, Init) |
| 2-3 | Length | `uint16_t` (BE) | Length of Inner Header + Payload |

**Observed Packet Types:**
- `0xD1`: Standard Session Data (Discovery, Command)
- `0xD0`: Login Handshake (Specific to Artemis)
- `0xE1`: Initialization / Wake-up
- `0xD3`: Control / Heartbeat
- `0xD4`: Large Data Transfer (Video/Images)

### 3.2 Inner Header (4 Bytes)
| Offset | Field | Value | Description |
|---|---|---|---|
| 0 | Session Type | `0xD1`, `0xE1` | Usually matches Outer Type, but not always |
| 1 | Subcommand | `uint8_t` | Command ID (0x00=Disc, 0x03=Login) |
| 2-3 | Sequence | `uint16_t` (BE) | PPPP Session Sequence Number |

**Sequence Number Rules:**
- Starts at 1.
- Increments by 1 for every packet sent.
- Maintained per session. Resetting it mid-session causes packet rejection.

## 4. Connection Flow

The connection process involves three distinct phases identified in the APK logic (`ArLinkApi.logIn`) and verified via `tcpdump`.

### Phase 1: Initialization (Wake-up)
Before standard discovery, the app sends "Initialization" packets to wake up the camera's UDP stack.
*   **Packet:** `F1 E1 00 04 E1 00 00 01`
*   **Outer Type:** `0xE1`
*   **Inner Type:** `0xE1`
*   **Subcommand:** `0x00`
*   **Payload:** None

### Phase 2: Discovery
The app broadcasts (or unicasts to known IP) a discovery packet containing the current **Artemis Sequence Number**.
*   **Packet:** `F1 D1 00 06 D1 00 00 02 [00 1B]`
*   **Outer Type:** `0xD1`
*   **Subcommand:** `0x00` (Discovery Request)
*   **Payload:** 2 Bytes (Artemis Sequence, e.g., `0x001B` derived from BLE)

**Response:**
*   **Subcommand:** `0x01` (Discovery ACK)
*   **Payload:** Device capabilities/ID.

### Phase 3: Login (Authentication)
The app authenticates using a Session Token obtained via Bluetooth LE (BLE).
*   **Packet:** `F1 D0 00 45 D1 03 00 03 [Artemis Login Payload]`
*   **Outer Type:** `0xD0` (Critical Finding: Login uses `0xD0`, not `0xD1`)
*   **Subcommand:** `0x03` (Login Request)
*   **Payload:** Artemis Login Structure (see below)

**Artemis Login Payload Structure:**
1.  **Magic:** `ARTEMIS\x00` (8 bytes)
2.  **Version:** `0x02000000` (4 bytes, Little Endian)
3.  **Sequence/Mystery:** 4-8 bytes (Derived from BLE sequence)
4.  **Token Length:** 4 bytes (Little Endian)
5.  **Token:** Session Token String (ASCII)

## 5. Reverse Engineering Evidence

### 5.1 Native Library (`libArLink.so`)
Strings extracted from the shared object verify the PPPP library usage:
*   `PPCS_Initialize`
*   `PPCS_Connect`
*   `PPCS_Write`
*   `PPCS_Read`
*   `ArLink_Initialize`

### 5.2 Java Bytecode (`classes.dex`)
The `com.xlink.trailcamgo` package contains the JNI wrapper `ArLinkApi` which exposes these native functions to the Android app. The method `logIn` orchestrates the `PPCS_Connect` calls.

### 5.3 TCPDump Verification
Traffic analysis confirms the `F1 D0` header for login packets, which differs from the standard `F1 D1` used for discovery.
*   *Log Entry:* `f1d0 0045 d100 0005 ... 4152 5445 4d49 53` ("ARTEMIS")
*   This proves the need for the `wrap_login` modification implemented in `modules/pppp_wrapper.py`.

## 6. Implementation Notes

The Python implementation (`modules/pppp_wrapper.py`) has been updated to reflect these findings:
1.  **`wrap_init()`**: Added to support Phase 1.
2.  **`wrap_login()`**: Modified to use `Outer Type 0xD0`.
3.  **Sequence Handling**: Separate counters for PPPP (transport) and Artemis (application) layers are strictly enforced.

## 7. Encryption / Security
The PPPP layer itself does not appear to use heavy encryption for the handshake, relying instead on the session token exchanged via BLE. The "Mystery Bytes" (Sequence) act as a nonce to prevent replay attacks.
