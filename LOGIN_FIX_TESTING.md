# Login Fix Testing Documentation

## Changes Summary

### 1. Critical AppSeq Bug Fix (H1)
**Problem**: Heartbeat construction inserted `heartbeat_cnt` byte into the middle of the AppSeq field, causing AppSeq to jump to 65537.

**Root Cause**:
```python
# OLD (BUGGY) CODE:
HEARTBEAT_BODY_START = bytes.fromhex("415254454d49530002000000")  # ARTEMIS\x00 + MsgType
body = bytearray(HEARTBEAT_BODY_START) + bytearray([self.heartbeat_cnt]) + bytearray(HEARTBEAT_PAYLOAD_END)
# This created: ARTEMIS\x00 + MsgType(4B) + [cnt](1B) + payload_end
# Where payload_end starts with 00 01 00 19...
# Result: AppSeq bytes = [cnt] 00 01 00 = 0x00010001 = 65537 when cnt=1
```

**Fix**:
```python
# NEW (CORRECT) CODE:
self.app_seq += 1
heartbeat_b64_payload = b"MzlB36X/IVo8ZzI5rG9j1w==\x00"
artemis_body = build_artemis_frame(ARTEMIS_MSG_REQUEST, self.app_seq, heartbeat_b64_payload)
pkt, _ = self.build_packet(0xD0, artemis_body)
```

**Validation**: Test `test_appseq_increment.py` confirms:
- AppSeq=1 → bytes: `01 00 00 00` ✅
- AppSeq=2 → bytes: `02 00 00 00` ✅
- AppSeq=3 → bytes: `03 00 00 00` ✅
- No 65537 jump occurs ✅

### 2. Login Handshake Refactor (H2)
**Problem**: Handshake sequence didn't match MITM capture; sent Magic1 prematurely.

**Old Flow**:
1. Send Login Request #1
2. Send Magic1 (0xD1 packet)
3. Wait for Magic1 echo
4. Resend Login Request #2
5. Wait briefly
6. Send heartbeats
7. Wait for token

**New Flow** (matching MITM):
1. Send Login Request (cmdId=0, AppSeq=1)
2. **Wait for Login Response (MsgType=3, AppSeq=1)**
3. ACK the response (automatic via pump())
4. Send stabilization heartbeats
5. Extract token from buffered response

**Key Changes**:
- Removed Magic1/Magic2 packets (not in MITM flow)
- Added explicit wait for login response with predicate
- Proper response detection before stabilization

### 3. AppSeq Management (H4)
**Added Features**:
- Input validation in `build_artemis_frame()`:
  - Warns if MsgType not in [2, 3]
  - Warns if AppSeq out of reasonable range (0-1000000)
- Debug logging shows:
  - MsgType, AppSeq, BodyLen
  - AppSeq bytes in little-endian hex
- Clear separation between `self.app_seq` (ARTEMIS) and `self.global_seq` (RUDP)

## Testing

### Unit Tests Created
1. **test_appseq_increment.py**:
   - Validates AppSeq encoding for values 1, 2, 3, 65537
   - Simulates login + heartbeat sequence
   - Confirms no 65537 bug
   - Status: ✅ PASSING

2. **test_decrypt_login_response.py**:
   - Tests multiple decryption strategies (ECB, CBC, prefix removal)
   - Validates token extraction logic
   - Status: ✅ PASSING

3. **test_mitm_login_response.py**:
   - Attempts to decrypt real MITM capture Base64 payload
   - Status: ⚠️ INCOMPLETE (need correct Base64 or key verification)

### Expected Behavior with Real Camera

#### Before Fix (debug05012026_2.log):
```
Login Request #1: AppSeq=1 ✓
Magic1 sent prematurely
Login Request #2: AppSeq=1 (resend)
Heartbeat cnt=1: AppSeq=65537 ❌ (BUG!)
Heartbeat cnt=2: AppSeq=65538 ❌
...
Result: No MsgType=3 response, no token
```

#### After Fix (expected):
```
Login Request: AppSeq=1 ✓
Wait for response...
Login Response received: MsgType=3, AppSeq=1 ✓
Stabilization Heartbeat 1: AppSeq=2 ✓
Stabilization Heartbeat 2: AppSeq=3 ✓
Token extracted from buffered response ✓
cmdId=768 request: AppSeq=4 ✓
```

### Manual Testing Checklist

When testing with real camera:

1. **Pre-test**:
   - [ ] Enable debug logging: `--debug`
   - [ ] Check initial state: `app_seq=0`, `global_seq=0`

2. **Login Phase**:
   - [ ] Verify Login Request uses AppSeq=1
   - [ ] Check for Login Response (MsgType=3, AppSeq=1)
   - [ ] Confirm Base64 payload in response
   - [ ] Verify ACK sent after response

3. **Heartbeat Phase**:
   - [ ] First heartbeat: AppSeq=2 (not 65537!)
   - [ ] Second heartbeat: AppSeq=3
   - [ ] Third heartbeat: AppSeq=4
   - [ ] Log should show proper hex: `02 00 00 00`, `03 00 00 00`, etc.

4. **Token Extraction**:
   - [ ] MsgType=3 packets buffered during handshake
   - [ ] Token extracted from cmdId=0 response
   - [ ] Token length > 0
   - [ ] No timeout errors

5. **Post-Login**:
   - [ ] cmdId=768 request uses next AppSeq (e.g., 4 or 5)
   - [ ] Response received and decrypted
   - [ ] No protocol errors

### Debug Log Markers to Look For

✅ **Success Indicators**:
```
🔧 build_artemis_frame: MsgType=2, AppSeq=1, BodyLen=...
   AppSeq bytes (LE): 01000000
📊 Heartbeat AppSeq=2, cnt=1
📊 Heartbeat AppSeq=3, cnt=2
✅ Login Response received (MsgType=3)
🔓 MsgType=3 Paket gepuffert (AppSeq=1, Buffer: 1 Pakete)
✅ TOKEN OK (login, strict) app_seq=1 token_len=...
```

❌ **Failure Indicators** (old behavior):
```
ARTEMIS MsgType=2 AppSeq=65537  ← BUG!
   AppSeq bytes (LE): 01000100   ← BUG!
❌ Login Timeout (kein Token empfangen, 0 MsgType=3 Pakete gepuffert)
```

## Files Changed

1. **get_thumbnail_perp.py**:
   - `build_artemis_frame()`: Added validation and debug logging
   - `send_heartbeat()`: Complete rewrite to use proper ARTEMIS frame
   - `run()`: Refactored login handshake sequence
   - Removed: Magic1/Magic2 premature sending
   - Added: Explicit login response wait with predicate

2. **tests/test_appseq_increment.py**: New test file
3. **tests/test_mitm_login_response.py**: New test file (WIP)

## Next Steps

1. **Test with Real Hardware**:
   - Run with `--debug --wifi` on Raspberry Pi
   - Capture new debug log
   - Compare with `tests/debug05012026_2.log`

2. **Verify MITM Base64 Payload**:
   - Confirm the captured Base64 `7sQ3+pH/...` is complete
   - Test decryption with all strategies
   - Document actual token structure

3. **Acceptance Criteria Verification**:
   - [x] AppSeq bug fixed (no 65537 jump)
   - [x] Handshake follows MITM sequence
   - [x] Debug logging added
   - [ ] Real camera returns MsgType=3 response ← **Needs hardware test**
   - [ ] Token extracted successfully ← **Needs hardware test**
   - [ ] cmdId=768 works ← **Needs hardware test**

## Code Review Notes

### Why the Bug Occurred
The original implementation tried to manually construct the ARTEMIS frame by concatenating byte arrays:
- `HEARTBEAT_BODY_START` contained partial header (up to MsgType)
- `heartbeat_cnt` was inserted as a single byte
- `HEARTBEAT_PAYLOAD_END` contained the rest

This broke the ARTEMIS header structure which requires:
- 8 bytes: Signature
- 4 bytes: MsgType (LE)
- 4 bytes: AppSeq (LE) ← **This got corrupted**
- 4 bytes: PayloadLen (LE)
- N bytes: Payload

### Why the Fix Works
The new implementation:
1. Uses the existing `build_artemis_frame()` helper
2. Passes `self.app_seq` as a proper integer
3. Lets struct.pack handle little-endian encoding
4. Maintains strict separation between ARTEMIS AppSeq and RUDP Seq

### Lessons Learned
- Don't manually construct binary protocols - use struct.pack
- Little-endian multi-byte fields are fragile when concatenating
- Always validate with test vectors (we used AppSeq=65537 as indicator)
- Protocol dumps (MITM) are invaluable for debugging
