# Fix Summary: Issue #155 - Login Timeout

## Problem Statement

The camera login was failing with the error:
```
❌ Login Timeout (no token received, 0 MsgType=3 packets buffered)
```

The camera was not responding to login requests, preventing any further communication.

## Root Cause Analysis

After analyzing the MITM traffic captures (`tests/MITM_Captures/ble_udp_1.log`) and comparing them with the failing debug logs (`tests/debug05012026_3.log`), two critical differences were identified:

### Issue 1: Incorrect RUDP Sequence Number

**Working sequence (MITM capture - ble_udp_1.log line 378):**
```
f1 d0 00 c5 d1 00 00 00 41 52 54 45 4d 49 53 00
                   ^^
              RUDP Seq = 0
```

**Failing sequence (debug05012026_3.log line 28):**
```
f1 d0 00 c5 d1 00 00 01 41 52 54 45 4d 49 53 00
                   ^^
              RUDP Seq = 1 (WRONG!)
```

The camera expects the login request to be sent with **RUDP sequence number 0**, but the implementation was using sequence number 1.

### Issue 2: Missing Magic1 Handshake Packet

After sending the login request, the working app immediately sends a "Magic1" packet (Protocol_analysis.md §5, Step 5). This is a critical handshake signal that the camera requires before it will respond with the login token.

**MITM capture (ble_udp_1.log line 393-394):**
```
⚡ [UDP TX] Sende (14 bytes) FD:117
750f305028  f1 d1 00 0a d1 00 00 03 00 00 00 00 00 00
```

This packet has:
- RUDP Type: 0xD1 (ACK/CTRL)
- RUDP Seq: 3 (sequence jump from 0 to 3)
- Payload: 6 bytes of zeros (MAGIC_BODY_1)

The current implementation was **not sending this packet at all**, causing the camera to ignore the login request.

## Solution Implemented

### Fix 1: Force RUDP Sequence to 0 for Login

**File:** `get_thumbnail_perp.py` line 1128

```python
# CRITICAL FIX: Use force_seq=0 for login request (per MITM capture)
login_pkt, login_rudp_seq = self.build_packet(0xD0, login_body, force_seq=0)
```

Changed from:
```python
login_pkt, login_rudp_seq = self.build_packet(0xD0, login_body)
```

### Fix 2: Send Magic1 Packet After Login

**File:** `get_thumbnail_perp.py` lines 1135-1143

```python
# Step 1b: Send Magic1 packet (per Protocol_analysis.md §5 and ble_udp_1.log line 393)
# This is a critical handshake packet that the camera expects after login
# The sequence number jumps to 3 as per the MITM capture
logger.info(">>> Login Handshake Step 1b: Send Magic1 packet")
magic1_pkt, _ = self.build_packet(0xD1, MAGIC_BODY_1, force_seq=3)
self.send_raw(magic1_pkt, desc="Magic1")

# Brief pause to allow camera to process
time.sleep(0.1)
```

The `MAGIC_BODY_1` constant was already defined in the code (in the CONSTANTS section) as `bytes.fromhex("000000000000")` but was never used.

## Expected Behavior After Fix

With these fixes, the login handshake should now match the MITM-captured sequence:

1. **Discovery** (RUDP 0x41 "LBCS" broadcast) ✅ Already working
2. **Pre-Login** (RUDP 0xF9 with encrypted nonce) ✅ Already working
3. **Login Request** (RUDP Seq=0, ARTEMIS MsgType=2, AppSeq=1) ✅ **FIXED**
4. **Magic1 Packet** (RUDP Seq=3, 6-byte zero payload) ✅ **FIXED**
5. **Login Response** (Camera sends MsgType=3, AppSeq=1 with token) ← Should now work
6. **ACK Login Response** ✅ Already working (automatic in pump())
7. **Stabilization** (Heartbeats) ✅ Already working
8. **Token Extraction** ✅ Already working

## Testing Recommendations

To verify the fix:

1. Run the script with `--debug` flag to capture detailed logs
2. Check for the log line: `>>> Login Handshake Step 1b: Send Magic1 packet`
3. Verify RUDP Seq=0 in the login packet hex dump
4. Verify RUDP Seq=3 in the Magic1 packet hex dump
5. Look for successful login response: `✅ Login Response received (MsgType=3)`
6. Confirm token extraction: `✅ TOKEN OK (login, strict) app_seq=1 token_len=...`

## References

- **Issue:** #155
- **MITM Captures:** `tests/MITM_Captures/ble_udp_1.log` lines 378-491
- **Protocol Specification:** `Protocol_analysis.md` §5 (Phase 2: Handshake)
- **Debug Logs:** `tests/debug05012026_3.log` (failing), compared with MITM captures
