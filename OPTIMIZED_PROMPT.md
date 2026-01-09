# Optimized GitHub Copilot Prompt for Trail Camera Login Fix

## Context

Python UDP client for KJK/Artemis trail camera. Implementing proprietary RUDP+ARTEMIS protocol based on MITM captures. Currently on v4.31 implementing timing fix for login timeout (Issue #191).

**Current Status**: v4.31 implemented timing delays between login retransmissions, awaiting hardware test.

---

## Quick Reference

**Repository**: https://github.com/philibertschlutzki/pi_trailcam  
**Main Script**: `get_thumbnail_perp.py` (v4.31)  
**Protocol Spec**: `Protocol_analysis.md`  
**Analysis Document**: `ANALYSE_KONSOLIDIERT_LOGIN.md`  
**Issue #191 Summary**: `FIX_SUMMARY_ISSUE_191.md`  

**MITM Capture** (working app): `tests/MITM_Captures/ble_udp_1.log`  
**Latest Debug Logs**: `tests/debug09012026_7.log` (v4.29), `tests/debug09012026_8.log` (v4.30)

---

## Issue #191: Login Timeout Due to Timing Problem

### Problem Statement

**Symptom**: Login timeout after 3 seconds, no token received, camera sends RUDP ACKs after 2.9s delay, then ERR/DISC signals  
**Root Cause**: Login retransmissions (#2, #3) sent too fast (30ms, 20ms intervals), camera timeout waiting for processing time  
**Fix (v4.31)**: Added 100ms delays between Login #1→#2 and #2→#3 to give camera processing time  

### Evidence

**MITM (working app)**: Lines 378→393→399→402→417→432→435
- Login #1 → Magic1 → ACK → Login #2 → Login #3 → RUDP ACK (immediate) → MsgType=3 ✅

**v4.30 (failed)**: Timestamps from debug09012026_8.log
- 19:32:45,640: Login #1
- 19:32:45,655: Magic1 (Δ=15ms)
- 19:32:45,769: TX ACK (Δ=114ms)
- 19:32:45,799: Login #2 (**Δ=30ms** ← TOO FAST!)
- 19:32:45,819: Login #3 (**Δ=20ms** ← TOO FAST!)
- 19:32:48,792: RX RUDP ACK (**Δ=2.9s** ← TIMEOUT!)
- 19:32:48,813: RX ERR (f1e00000) ❌

**Key Finding**: The 2.9 second delay before RUDP ACKs indicates camera timeout. Camera needs processing time between login packets.

### Changes in v4.31

1. Added `time.sleep(0.1)` before Login #2 transmission (line ~1765)
2. Added `time.sleep(0.1)` before Login #3 transmission (line ~1770)
3. Updated version docstring with detailed timing analysis

### Expected Test Output (v4.31)

```
TX Login #1 (Seq=0)
TX Magic1 (Seq=3)
RX DATA "ACK" (Seq=0)
TX ACK (Seq=1)
>>> Login Handshake Step 1d: Retransmit Login #2
[100ms delay]
TX Login #2 (Seq=0)
>>> Login Handshake Step 1e: Retransmit Login #3
[100ms delay]
TX Login #3 (Seq=0)
🔒 Entered login response wait mode
RX RUDP ACK Seq=1 (expected within <500ms, not 2.9s) ✅
RX MsgType=3 ✅ Login Response with token
✅ Login erfolgreich
```

---

## Common Debugging Scenarios

### If v4.31 Test Fails

**Check debug log for**:
1. Are the 100ms delays being applied? (Check timestamps between Login packets)
2. When do RUDP ACKs arrive? (<500ms is good, >2s indicates still timing out)
3. Any MsgType=3 packets buffered? (Check "X MsgType=3 packets buffered")
4. ERR (0xE0) or DISC (0xF0) signals present? (Should be NONE)

**If RUDP ACKs still arrive after >2 seconds**:
- If 1-2s delay: Partial improvement, increase delays to 200ms
- If >2.5s delay: No improvement, timing may not be root cause
- Try 200ms delays first before alternative approach
- Camera may have different processing requirements than expected

**If RUDP ACKs arrive quickly but MsgType=3 missing**:
- Timing fixed successfully! ✅ 
- Different issue preventing login response (not timing-related)
- Check for ERR signals before/after RUDP ACKs
- May need to respond to RUDP ACKs explicitly
- Investigate packet sequence after RUDP ACKs

**If MsgType=3 received but token extraction fails**:
- Login handshake successful! ✅
- Decryption issue, not timing issue
- Check AES key, IV, mode (ECB vs CBC)

### If v4.31 Succeeds (Iteration Complete!)

1. Close Issue #191
2. Document success in ANALYSE_KONSOLIDIERT_LOGIN.md
3. Test full workflow (file list, thumbnails, downloads)
4. Create release notes for v4.31
5. Celebrate! 🎉

---

## Prompt Templates

### For v4.32 (If v4.31 Timing Fix Insufficient)

```markdown
# TASK: Fix Login Failure v4.32 - Adjust Timing or Alternative Approach

## Context
Trail camera UDP client, v4.31 added 100ms delays but [SYMPTOM FROM DEBUG LOG].

## Previous Iteration Summary
v4.31 implemented 100ms delays between Login #1→#2 and #2→#3 to fix timing issue (Issue #191).
RUDP ACKs in v4.30 arrived after 2.9s timeout, indicating camera needs processing time.

## Current Problem
[COPY RELEVANT LINES FROM DEBUG LOG showing RUDP ACK timing]

Observed RUDP ACK timing: [X seconds after Login #3]
- If <500ms: Timing fix worked! ✅ Look for different issue
- If 1-2s: Partial improvement, may need longer delays
- If >2.5s: No improvement, timing may not be the issue

## Root Cause Analysis
Compare with MITM `tests/MITM_Captures/ble_udp_1.log` lines 378-435:
- [TIMING DIFFERENCE]
- [PACKET SEQUENCE DIFFERENCE]
- [NEW HYPOTHESIS]

## Proposed Fix Options
OPTION 1: Increase delays to 200ms
OPTION 2: Try alternative delay pattern (before Login #1, after camera ACK, etc.)
OPTION 3: Test without retransmits (#2/#3) to isolate issue
OPTION 4: Implement RUDP ACK response handling

## Files to Modify
- `get_thumbnail_perp.py`: Adjust sleep() values or sequence
- `FIX_SUMMARY_ISSUE_191.md`: Document test results

## Expected Result
RUDP ACKs arrive within <500ms, followed by MsgType=3 with token
```

### For Post-Login Issues

```markdown
# TASK: Fix [OPERATION] Failure - Issue #[NUMBER]

## Context
Trail camera client, login working (v4.30), but [OPERATION] fails.

## Problem
[SYMPTOM and LOG EVIDENCE]

## MITM Reference
Relevant MITM capture: `tests/MITM_Captures/[FILE].log` lines [X-Y]

## Proposed Fix
[CHANGES NEEDED]

## Files to Modify
- `get_thumbnail_perp.py`: [CHANGES]
```

---

## Key Principles for Future Fixes

1. **Always compare with MITM**: Every TX/RX must match MITM timing and sequence
2. **Minimal changes**: One bug fix per version, surgical edits only
3. **Preserve working fixes**: Don't break Issue #185, #187, #181 fixes
4. **Document thoroughly**: Update ANALYSE_KONSOLIDIERT_LOGIN.md with each iteration
5. **Test incrementally**: Run test immediately after each fix

---

## Critical Protocol Requirements (DO NOT BREAK)

✅ **LBCS Ignore** (Issue #179/181): Skip ACK for FRAG packets with `data[4:8] == b'LBCS'`  
✅ **First ACK** (Issue #185): Must ACK first "ACK" DATA packet after Magic1  
✅ **Seq Reset** (Issue #187): Reset `global_seq = 0` after Magic1 (Seq=3)  
✅ **ACK Seq** (Issue #187): Use `next_seq()` in ACK header, not `rx_seq`  
✅ **ACK Suppress** (Issue #189): Suppress ACK for "ACK" packets after Login #3  

---

## Version History Quick Ref

- **v4.23**: Added 1.0s camera stabilization (insufficient)
- **v4.24**: Increased to 3.0s stabilization
- **v4.25**: LBCS ignore (wrong offset) ❌
- **v4.26**: LBCS ignore (correct offset) ✅
- **v4.27**: Magic2 hypothesis (never tested, wrong)
- **v4.28**: ACK all "ACK" packets (creates loop) ❌
- **v4.29**: Seq reset + ACK next_seq() (ACK loop remains) ❌
- **v4.30**: ACK suppression after Login #3 (still timeout with 2.9s delay) ❌
- **v4.31**: **CURRENT** - 100ms timing delays between login retransmissions (awaiting test)

---

## Estimated Remaining Work

**If v4.31 succeeds**: 0-1 iterations (post-login operations testing)  
**If v4.31 partially works**: 1 iteration (adjust timing values)  
**If v4.31 fails completely**: 1-2 iterations (alternative hypothesis)  
**Confidence**: 80-85% (timing issue well-documented, fix targeted)  

**Total effort since Issue #157**: 16+ iterations  
**Progress**: Discovery ✅ | Stabilization ✅ | LBCS ✅ | Seq ✅ | ACK Logic ✅ | Timing → Testing  
**Estimated completion**: 1-2 days (assuming hardware access)  

---

## Contact & Resources

**Issues**: https://github.com/philibertschlutzki/pi_trailcam/issues  
**PR Branch**: `copilot/analyze-repository-and-logs-again`  
**Protocol Spec**: See `Protocol_analysis.md` for full RUDP/ARTEMIS spec  
**Analysis**: See `ANALYSE_KONSOLIDIERT_LOGIN.md` for all previous iterations  

---

## Appendix: Frequently Used Commands

**Test with debug**:
```bash
python get_thumbnail_perp.py --debug --wifi
```

**Test with BLE wakeup**:
```bash
python get_thumbnail_perp.py --debug --ble --wifi
```

**Check git status**:
```bash
git status
git log --oneline -10
```

**View recent debug logs**:
```bash
ls -lht tests/debug*.log | head -5
```

---

**Last Updated**: 2026-01-09 (v4.31 implementation)  
**Next Action**: Test v4.31 with real hardware, create debug log  
**If Successful**: Close Issue #191, document success, test file operations  
**If Failed**: Analyze RUDP ACK timing in new log, adjust delays or try alternative approach in v4.32  
