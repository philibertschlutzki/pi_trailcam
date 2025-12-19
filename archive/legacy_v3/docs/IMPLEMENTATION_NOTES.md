# Artemis Login Implementation Notes

## Overview
This implementation reproduces the Android App's login sequence for the TrailCam Go (KJK230).
The process consists of 4 distinct phases executed sequentially.

## Phases

### Phase 1: Initialization Wake-up
- **Packet**: `F1 E1 00 04 E1 00 00 01`
- **Purpose**: Wakes up the camera's UDP stack.
- **Timing**: Sent ONCE before discovery. 0.5s delay required after sending.

### Phase 2: Discovery
- **Request**: `F1 30 00 00` (LAN Search Broadcast)
- **Response**: `F1 41 00 14 ... [UID]`
- **Action**: Extracts Device UID (e.g., "LBCS-000000-CCCJJ") from the response payload.

### Phase 3: Artemis Login
- **Outer Header**: `F1 D0 [Len]`
- **Inner Header**: `D1 03 00 02` (Type D1, Subcommand 03, Sequence 2)
- **Payload**:
  - Magic: "ARTEMIS\0"
  - Version: `02 00 00 00` (LE)
  - Sequence: `01 00 00 00` (LE) (Derived from BLE or fallback)
  - Token Len: `05 00 00 00` (LE)
  - Token: "admin"
- **Response**: Checks for JSON payload containing `"errorCode": 0`.

### Phase 4: Heartbeat
- **Packet**: `F1 D1 [Len] D1 04 [Seq] {"cmdId": 525}`
- **Frequency**: Every 3.0 seconds.
- **Purpose**: Keeps the session alive.

## Usage

```python
from src.artemis_login import ArtemisLoginHandler
import asyncio

async def main():
    handler = ArtemisLoginHandler(target_ip="192.168.43.1")
    await handler.execute()

asyncio.run(main())
```

## Testing
Run unit tests with `pytest tests/test_artemis_login.py`.
