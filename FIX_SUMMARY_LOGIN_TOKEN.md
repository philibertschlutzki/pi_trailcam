# Fix Summary: Login Response Token Reception

## Problem
The script `get_thumbnail_perp.py` v4.15 sent Login (cmdId=0) correctly but never received the ARTEMIS MsgType=3 Login-Response from the camera. The token remained empty, resulting in timeout. See `tests/debug05012026_1.log` for symptoms.

## Root Causes

### 1. FRAG ACK Handling (CRITICAL BUG - H2)
**Issue**: The script only ACK'd FRAG packets (type 0x42) if they contained the `ARTEMIS\0` signature. LBCS/Discovery FRAG packets (Seq=83) were being ignored.

**Spec Violation**: Per `Protocol_analysis.md` §3.3: "**Jedes eingehende Paket vom Typ 0xD0 oder 0x42 muss mit ACK bestätigt werden**" (Every incoming packet of type 0xD0 or 0x42 must be acknowledged).

**Impact**: The camera was flooding with LBCS/Discovery FRAG retransmissions because the client never ACK'd them. This likely caused the camera to enter a retry loop state where it wouldn't send the login response.

**Fix**: Changed line 904 from:
```python
if pkt_type == 0xD0 or (pkt_type == 0x42 and looks_artemis_frag):
```
to:
```python
if pkt_type == 0xD0 or pkt_type == 0x42:
```

This ensures ALL 0x42 packets are ACK'd, regardless of content.

### 2. Handshake Sequencing (CRITICAL BUG - H4)
**Issue**: The script was sending:
- Login Request (Seq=0)
- Magic1 (Seq=3, payload 6 bytes)
- Magic2 (Seq=1, payload 2 bytes)
- Wait for login response

**Actual Working Flow** (from MITM capture `ble_udp_2.log`):
1. Login Request #1 (Seq=0, MsgType=2, AppSeq=1)
2. Magic1 (Seq=1, type=0xD1, payload=`00 00`)
3. Wait for Magic1 echo from camera
4. **Login Request #2** (Re-send same request, Seq=0)
5. Camera sends Login Response (MsgType=3, AppSeq=1)
6. Client ACKs the login response

**Fix**: Rewrote the handshake flow (lines 1064-1112) to:
1. Send Login Request #1
2. Send Magic1 (0xD1, seq=1, payload=`00 00`)
3. Wait for Magic1 echo from camera
4. **Re-send Login Request #2** (critical step that was missing!)
5. Wait for Login Response

The second login request appears to be the trigger that causes the camera to send the actual response.

## Changes Made

### `get_thumbnail_perp.py`
1. **Line 899-918**: Fixed ACK logic to ACK all FRAG packets
2. **Line 1064-1112**: Rewrote login handshake flow to match MITM capture
3. **Line 917**: Changed log message from "skip reassembly/ack" to "ACK gesendet"

### New Test: `tests/test_ack_format_and_mitm_login.py`
Created comprehensive test validating:
- ACK packet format is exactly 10 bytes per spec
- ACK structure for various seq values (0, 1, 83, 255)
- Which packet types require ACK vs those that don't

## Verification
- [x] ACK format validated (test passes)
- [x] Packet type ACK requirements documented (test passes)
- [x] Handshake flow matches MITM capture
- [x] Existing tests still pass
- [ ] Actual camera test (requires hardware - cannot be simulated)

## Expected Outcome
After these fixes, the camera should:
1. Receive ACKs for all LBCS/Discovery FRAGs → Stop retransmitting
2. Receive the double login request in correct sequence → Send MsgType=3 response
3. MsgType=3 response gets buffered and token extracted
4. Script can proceed to cmdId=768 (file list) and beyond

## Notes
- The ARTEMIS encryption key from `Protocol_analysis.md` (`a01bc23ed45fF56A`) doesn't decrypt MITM captures, suggesting the captures may use session keys or the spec key is not accurate. However, the script has multiple fallback decryption strategies implemented.
- The ACK format implementation was already correct - it was the **logic** for when to send ACKs that was broken.
