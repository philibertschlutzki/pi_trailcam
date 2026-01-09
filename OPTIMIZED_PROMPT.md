# Optimized GitHub Copilot Prompt for Trail Camera Login Fix

## Context

Python UDP client for KJK/Artemis trail camera. Implementing proprietary RUDP+ARTEMIS protocol based on MITM captures. Currently on v4.30 attempting to fix login timeout (Issue #189).

**Current Status**: v4.30 implemented ACK suppression after Login #3, awaiting hardware test.

---

## Quick Reference

**Repository**: https://github.com/philibertschlutzki/pi_trailcam  
**Main Script**: `get_thumbnail_perp.py` (v4.30)  
**Protocol Spec**: `Protocol_analysis.md`  
**Analysis Document**: `ANALYSE_KONSOLIDIERT_LOGIN.md`  
**Issue #189 Summary**: `ISSUE_189_SUMMARY.md`  

**MITM Capture** (working app): `tests/MITM_Captures/ble_udp_1.log`  
**Latest Debug Log** (v4.29 failed): `tests/debug09012026_7.log`  

---

## Issue #189: Login Timeout Due to ACK Loop

### Problem Statement

**Symptom**: Login timeout after 3 seconds, no token received, camera sends ERR/DISC signals  
**Root Cause**: Implementation ACKs camera's "ACK" packets continuously (74+ times), working app ACKs only once  
**Fix**: v4.30 adds `_in_login_response_wait` flag to suppress ACK after Login #3  

### Evidence

**MITM (working)**: Lines 399 (ACK first "ACK") → 402/417 (Login #2/#3) → 435 (Response) ✅  
**v4.29 (failed)**: Lines 28 (ACK) → 31/33 (Login #2/#3) → 37-336 (74+ ACK loop) → 435 (DISC) ❌  

### Changes in v4.30

1. Flag: `self._in_login_response_wait = False` in `__init__` (line ~607)
2. Logic: Check flag before ACKing "ACK" packets in `pump()` (lines ~1460-1486)
3. Set: After Login #3 in `run()` (line ~1780)
4. Clear: After login success/timeout (lines ~1827, 1845)

### Expected Test Output

```
TX Login #3 → 🔒 Entered login response wait mode
→ RX "ACK" → ⚠️ Suppressing ACK (max 1-2 suppression messages)
→ RX MsgType=3 ✅ Login Response received
→ ✅ TOKEN OK
```

---

## Common Debugging Scenarios

### If v4.30 Test Fails

**Check debug log for**:
1. Is "Entered login response wait mode" present? (Should appear after Login #3)
2. How many "Suppressing ACK" messages? (Should be 5-50, not 0)
3. Any MsgType=3 packets buffered? (Check "X MsgType=3 packets buffered")
4. ERR (0xE0) or DISC (0xF0) signals present? (Should be NONE)

**If "Entered login response wait mode" is missing**:
- Bug in run() method, flag not being set
- Check line ~1780 execution path

**If "Suppressing ACK" appears 0 times**:
- Camera not sending "ACK" packets (different behavior than expected)
- Consider alternative timing hypothesis

**If "Suppressing ACK" appears 74+ times but still timeout**:
- ACK suppression working, but camera expects different behavior
- May need to send something else instead of suppressing

**If MsgType=3 buffered but token extraction fails**:
- Decryption issue, not ACK issue
- Check AES key, IV, mode (ECB vs CBC)

### If v4.30 Succeeds (Iteration Complete)

1. Close Issue #189
2. Test full workflow (file list, thumbnails)
3. Document success in ANALYSE_KONSOLIDIERT_LOGIN.md
4. Create release notes for v4.30

---

## Prompt Templates

### For v4.31 (If v4.30 Fails)

```markdown
# TASK: Fix Login Failure v4.31 - Investigate [SPECIFIC ISSUE FROM DEBUG LOG]

## Context
Trail camera UDP client, v4.30 failed with [SYMPTOM]. See debug log `tests/debug[DATE].log`.

## Previous Iteration Summary
v4.30 implemented ACK suppression after Login #3 to fix endless ACK loop (Issue #189).
Flag `_in_login_response_wait` added to suppress ACK for camera's "ACK" packets.

## Current Problem
[COPY RELEVANT LINES FROM DEBUG LOG]

Debug log shows:
- [OBSERVATION 1 from log]
- [OBSERVATION 2 from log]
- [OBSERVATION 3 from log]

## Root Cause Analysis Needed
Compare debug log with MITM `tests/MITM_Captures/ble_udp_1.log` lines 393-435:
- [DIFFERENCE 1]
- [DIFFERENCE 2]
- [HYPOTHESIS]

## Proposed Fix
[MINIMAL CHANGE DESCRIPTION]

## Files to Modify
- `get_thumbnail_perp.py`: [SPECIFIC CHANGES]
- `ANALYSE_KONSOLIDIERT_LOGIN.md`: Add v4.31 analysis

## Expected Result
[DESCRIBE SUCCESS CRITERIA]

## Testing
Run: `python get_thumbnail_perp.py --debug --wifi`
Success criteria: [SPECIFIC LOG MESSAGES]
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
- **v4.30**: **CURRENT** - ACK suppression after Login #3 (awaiting test)

---

## Estimated Remaining Work

**If v4.30 succeeds**: 0-1 iterations (post-login operations testing)  
**If v4.30 fails**: 1-2 iterations (edge case or alternative hypothesis)  
**Confidence**: 75-80%  

**Total effort since Issue #157**: 15+ iterations  
**Progress**: Discovery ✅ | Stabilization ✅ | LBCS ✅ | Seq ✅ | ACK Logic → Testing  
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

**Last Updated**: 2026-01-09 (v4.30 implementation)  
**Next Action**: Test v4.30 with real hardware, create debug log  
**If Successful**: Close Issue #189, document success, test file operations  
**If Failed**: Analyze new debug log, create v4.31 with targeted fix  
