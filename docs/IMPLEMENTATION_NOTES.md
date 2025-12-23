# Implementation Notes: Current Architecture

This document describes the **actual current implementation** in `main.py` as of December 2025.

## Overview

The `main.py` script is a **single-file, synchronous UDP client** that orchestrates camera control through three main worker classes:

- `BLEWorker` - Handles Bluetooth Low Energy wakeup
- `WiFiWorker` - Manages WiFi connectivity via nmcli
- `Session` - Core UDP protocol handler for LBCS/Artemis communication

## Architecture

### Single-Threaded, Event-Driven Design

```
┌─────────────────────┐
│  main() with args   │
├─────────────────────┤
│  --ble flag?        │ YES → BLEWorker.wake_camera()
│  --wifi flag?       │ YES → WiFiWorker.connect()
│                     │
│  Session().run()    │ ALWAYS → Main protocol handler
└─────────────────────┘
```

**Key principle:** Sequential execution, not parallel threads. Each phase completes before the next begins.

### Class Responsibilities

#### BLEWorker

```python
class BLEWorker:
    @staticmethod
    async def wake_camera(mac: str) -> bool:
        # 1. Scan for BLE device with timeout of 45 seconds
        # 2. Connect to device
        # 3. Write 8-byte payload to characteristic UUID 00000002-0000-1000-8000-00805f9b34fb
        # 4. Return success/failure
```

**Payload:** `0x13 0x57 0x01 0x00 0x00 0x00 0x00 0x00`

**Effect:** Triggers camera's WiFi radio activation (takes ~15 seconds after write)

**Exception handling:** Catches `bleak` client errors and returns False on any failure

#### WiFiWorker

```python
class WiFiWorker:
    @staticmethod
    def connect(ssid: str, password: str) -> bool:
        # 1. Check if already connected with `iwgetid -r`
        # 2. Delete old nmcli profile: `sudo nmcli c delete <ssid>`
        # 3. Force WiFi rescan: `sudo nmcli d wifi rescan`
        # 4. Connect: `sudo nmcli d wifi connect <ssid> password <pass> ifname wlan0`
        # 5. Return success/failure
```

**Critical detail:** Deletes the profile **before** connecting to avoid "key-mgmt" errors from stale configs.

**Error handling:** Parses stderr for detailed error messages and returns False if connection fails.

#### Session (Core Protocol Handler)

```python
class Session:
    def setup_network(self) -> bool
        # Get local IP by connecting dummy socket to TARGET_IP
        # Bind UDP socket to FIXED_LOCAL_PORT (35281) or OS-assigned fallback
        # Return True if socket ready

    def discover(self) -> bool
        # Loop 5 times with 1-second timeouts
        # For each loop: send LBCS_PAYLOAD to both TARGET_PORTS on broadcast + unicast
        # Listen for response with header byte 0xF1 and type 0x42 or 0xD0
        # Store active_port when match found
        # Return True on discovery success

    def login(self) -> bool
        # Create JSON: {"utcTime": <unix timestamp>, "nonce": <8 random bytes hex>}
        # Encrypt with AES-128-ECB using key "a01bc23ed45fF56A"
        # Prepend 28-byte PHASE2_STATIC_HEADER
        # Wrap with 0xF1 0xF9 header + length field
        # Send to TARGET_IP:active_port
        # Wait briefly for response
        # Return True (assume success if socket ready)

    def run(self) -> None
        # Execute setup_network() → discover() → login()
        # On success: Send ARTEMIS_HELLO packet
        # Enter infinite event loop:
        #   - Receive packets (timeout: 1 second)
        #   - Filter by size (ignore 40, 157, 11-with-ACK, 4-ping-responses)
        #   - Log others
        #   - Send HEARTBEAT_PAYLOAD every 2 seconds
        #   - Track errors (exit on 5+ consecutive socket errors)
```

## Data Structures

### Configuration Constants (Top of main.py)

```python
TARGET_IP = "192.168.43.1"
TARGET_PORTS = [40611, 3333]
FIXED_LOCAL_PORT = 35281

DEFAULT_SSID = "KJK_E0FF"
DEFAULT_PASS = "85087127"
BLE_MAC = "C6:1E:0D:E0:32:E8"

PHASE2_KEY = b"a01bc23ed45fF56A"
PHASE2_STATIC_HEADER = bytes.fromhex("0ccb9a2b5f951eb669dfaa375a6bbe3e76202e13c9d1aa3631be74e5")

LBCS_PAYLOAD = bytes.fromhex("f14100144c42435300000000000000004343434a4a000000")
ARTEMIS_HELLO = bytes.fromhex("f1d000c5d1000000415254454d495300...")
HEARTBEAT_PAYLOAD = bytes.fromhex("f1d1000ed100000500000000000000000000")
```

### Session State Variables

```python
class Session:
    self.sock: Optional[socket.socket]     # UDP socket
    self.local_ip: Optional[str]           # IP to bind to
    self.active_port: Optional[int]        # Port camera responded on
    self.running: bool = True              # Event loop control
```

## Network Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ Raspberry Pi                    │ Camera (192.168.43.1)        │
├─────────────────────────────────────────────────────────────────┤
│                                 │                              │
│ BLE Write (if --ble flag)        │                              │
│ ─────────────────────────────→  │ Activate WiFi (15s later)    │
│                                 │                              │
│ nmcli connect (if --wifi flag)   │                              │
│ ─────────────────────────────→  │ Hotspot now active           │
│                                 │                              │
│ LBCS Payload → Port 40611        │                              │
│ ─────────────────────────────→  │                              │
│                                 │ ← F1 42 or F1 D0 (Response)  │
│                                 │                              │
│ Pre-Login (0xF9)                │                              │
│ Encrypted JSON → Port 40611      │                              │
│ ─────────────────────────────→  │                              │
│                                 │ ← F1 ?? (ACK or status)      │
│                                 │                              │
│ ARTEMIS Hello (0xD0)             │                              │
│ Session token → Port 40611       │                              │
│ ─────────────────────────────→  │ Session established          │
│                                 │                              │
│ Heartbeat every 2 seconds        │                              │
│ ─────────────────────────────→  │ Maintain connection          │
│                                 │                              │
│ Listen for events (filtered)     │                              │
│ ←─────────────────────────────   │ Send status/event packets    │
│                                 │                              │
```

## Packet Structure

### Generic Artemis Packet Format

```
Byte 0:     0xF1 (Magic)
Byte 1:     Type (0x41=LBCS, 0xD0=Artemis, 0xF9=Login, 0xD1=Heartbeat, etc.)
Bytes 2-3:  Length (big-endian, uint16, includes everything after this field)
Bytes 4+:   Payload (variable, may be encrypted)
```

### LBCS Discovery Payload

```hex
f1 41                           # Magic + Type (LBCS Discovery)
00 14                           # Length: 20 bytes
4c 42 43 53 00 00 00 00        # "LBCS" + padding
00 00 00 00 43 43 43 4a 4a 00 # More padding/identifier
00 00                           # End
```

### Pre-Login (0xF9) Packet Structure

```
0xF1 0xF9                       # Magic + Type
[2-byte length]                 # Length field
[28-byte static header]         # From PHASE2_STATIC_HEADER
[AES-encrypted JSON]            # Plaintext: {"utcTime": <int>, "nonce": "<hex>"}
```

**Encryption key:** `a01bc23ed45fF56A` (ASCII, not binary)

**Plaintext example:**
```json
{"utcTime":1703432143,"nonce":"a1b2c3d4e5f6a7b8"}
```

### ARTEMIS Hello (0xD0) Packet

```
0xF1 0xD0                       # Magic + Type
00 C5                           # Length: 197 bytes
[D1 00 00 00 41 52 54 45 4D 49 53 00 ...]  # Hardcoded session payload
[... 160+ bytes of encoded session token ...]
```

### Heartbeat (0xD1)

```
0xF1 0xD1                       # Magic + Type
00 0E                           # Length: 14 bytes
[D1 00 00 05 00 00 00 00 00 00 00 00]  # Heartbeat structure
```

**Sent every 2 seconds to maintain session.**

## Packet Filtering Logic

To reduce log spam, received packets are filtered by size:

```python
if d_len in [40, 157]:                      # Standard status packets
    pass  # Ignored
elif d_len == 11 and d_hex.endswith("41434b"):  # ACK packets
    pass  # Ignored
elif d_len == 4 and d_hex == "f1e00000":   # Ping responses
    pass  # Ignored
else:
    logger.info(...)  # Log everything else
```

**Rationale:** Status packets (40/157 bytes) are sent frequently and don't indicate events. ACK and ping responses are protocol noise. Everything else (events, commands) is worth logging.

## Dependencies Analysis

### bleak (0.20.1)
- **Used by:** `BLEWorker.wake_camera()`
- **Purpose:** Bluetooth Low Energy scanning and client connection
- **Critical classes:** `BleakScanner`, `BleakClient`
- **Async/await:** Yes, main.py runs with `asyncio.run()`

### pycryptodome (≥3.19.0)
- **Used by:** `Session.login()`
- **Purpose:** AES-128-ECB encryption of login credentials
- **Critical classes:** `AES`, `Crypto.Util.Padding.pad()`

### netifaces (≥0.11.0)
- **Used by:** None directly in current code!
- **Imported but not used:** `import netifaces` is present but no `netifaces.` calls in main.py
- **Likely vestigial:** Kept from earlier development (may have been for interface enumeration)

### scapy (≥2.5.0)
- **Used by:** None!
- **Status:** Listed in requirements.txt but not imported or used in main.py
- **Purpose:** Likely intended for raw packet analysis/generation (not needed for current implementation)

## Logging

**Format:**
```python
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger("CamClient")
```

**Log levels used:**
- `logger.info()` - Protocol flow, successful operations, packet reception
- `logger.warning()` - Non-fatal issues (e.g., "no login response, trying anyway")
- `logger.error()` - Fatal failures (network errors, BLE failures, WiFi connection failed)

## Exception Handling

### BLEWorker
- Catches generic `Exception` from `bleak` library
- Returns False on any error

### WiFiWorker
- Catches generic `Exception` from subprocess
- Logs stderr output for debugging

### Session.setup_network()
- Catches socket errors silently
- Logs "Netzwerk nicht bereit" if IP detection fails

### Session.discover()
- Catches `socket.timeout` (expected, part of retry logic)
- Catches `OSError` (network failures)
- Silently continues on errors

### Session.login()
- No exception handling (relies on timeout from `socket.recv()`)
- Returns True even if no response received

### Session.run()
- **Main loop exception handling:**
  - `socket.timeout` - Expected, loops continues
  - `OSError` on receive - Logs error, breaks loop if 5+ errors
  - `OSError` on send - Logs error, increments counter
  - `KeyboardInterrupt` - Logs "Abbruch durch User"
  - Generic code via `finally: socket.close()`

## Timing & Delays

- **BLE scan timeout:** 45 seconds
- **BLE client connection timeout:** 15 seconds
- **After BLE wakeup:** Script sleeps 15 seconds before WiFi connection
- **Discovery timeout per port:** 1 second per iteration, 5 iterations = 5 seconds per round
- **Discovery retry loop:** Multiple rounds until discovery succeeds
- **WiFi rescan delay:** 3 seconds (hardcoded `time.sleep(3)`)
- **Event loop socket timeout:** 1.0 second
- **Heartbeat interval:** 2.0 seconds
- **Main loop error tolerance:** Breaks after 5 consecutive socket errors

## Known Limitations & Future Work

1. **No command sending** - Session is established but no method to send custom commands beyond heartbeat
2. **No reconnection logic** - If connection drops, script exits (manual restart required)
3. **Hardcoded payloads** - ARTEMIS_HELLO and static headers are fixed; can't adapt to new firmware
4. **No parallel connection** - Despite some docs mentioning it, implementation is purely sequential
5. **Unused dependencies** - `netifaces` and `scapy` are imported but not used
6. **Minimal error recovery** - Most errors cause immediate exit or silent failure
7. **No configuration file** - All settings must be edited in source code

## Performance Characteristics

- **Typical startup time:** 15-30 seconds (dominated by BLE wakeup sleep)
- **Connection establishment:** 5-10 seconds (discovery + login)
- **Memory footprint:** Minimal (~20MB including Python runtime)
- **CPU usage:** Negligible when idling (socket timeout dominates)
- **Network bandwidth:** <1 KB/s during heartbeat phase

## Summary

The current implementation is a **straightforward, synchronous UDP client** with dedicated helpers for BLE and WiFi setup. It prioritizes simplicity and clarity over performance or advanced features. The protocol implementation directly maps to reverse-engineered payloads from the Android app, making it maintainable but rigid (hardcoded payloads limit adaptability to firmware updates).
