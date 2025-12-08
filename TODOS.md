# TODO List: LAN Optimization & Heartbeat Implementation

**Updated:** 2025-12-08  
**Status:** 95%+ Complete - Implementation Phase

---

## ⚠️ SOFORT (Next 24 Hours) - Verification Only

### 1. Code Verification

- [ ] **Verify pppp_wrapper.py has heartbeat support**
  ```bash
  grep -n "def wrap_heartbeat" modules/pppp_wrapper.py
  grep -n "0x05" modules/pppp_wrapper.py  # Heartbeat subcommand
  ```
  - **Expected:** Method exists, uses 0xD1 outer type, 0x05 subcommand
  - **If missing:** Implement wrap_heartbeat() method
  - **Priority:** Critical
  - **Owner:** @philibertschlutzki
  - **Est. Time:** 30 min

- [ ] **Verify config.py has correct constants**
  ```bash
  grep "ARTEMIS_KEEPALIVE_INTERVAL" config.py
  grep "DEFAULT_LAN_PORTS" config.py
  ```
  - **Expected:** `ARTEMIS_KEEPALIVE_INTERVAL = 3.0`, ports start with 40611
  - **If missing:** Add to config.py
  - **Priority:** High
  - **Owner:** @philibertschlutzki
  - **Est. Time:** 15 min

### 2. Functional Testing

- [ ] **Test module imports**
  ```bash
  python3 -c "from modules.commands import HeartbeatManager; print('OK')"
  python3 -c "from modules.commands import DeviceCommands; print('OK')"
  python3 -c "from modules.connection_manager import DEFAULT_LAN_PORTS; print('OK')"
  ```
  - **Expected:** All imports succeed
  - **Priority:** High
  - **Owner:** Any
  - **Est. Time:** 5 min

- [ ] **Verify command ID constants**
  ```bash
  python3 -c "
from modules.commands.command_ids import *
assert CMD_HEARTBEAT == 525
assert HEARTBEAT_INTERVAL_SEC == 3.0
print('Command IDs OK')
  "
  ```
  - **Expected:** All constants match
  - **Priority:** Medium
  - **Owner:** Any
  - **Est. Time:** 5 min

- [ ] **Verify port order**
  ```bash
  python3 -c "
from modules.connection_manager import DEFAULT_LAN_PORTS
assert DEFAULT_LAN_PORTS[0] == 40611, f'Expected 40611, got {DEFAULT_LAN_PORTS[0]}'
print(f'Port priority OK: {DEFAULT_LAN_PORTS}')
  "
  ```
  - **Expected:** 40611 is first port
  - **Priority:** High
  - **Owner:** Any
  - **Est. Time:** 5 min

---

## 📅 Diese Woche (Next 7 Days) - Integration & Testing

### 1. Code Integration

- [ ] **Integrate HeartbeatManager into CameraClient**
  - [ ] Add import: `from modules.commands.heartbeat import HeartbeatManager`
  - [ ] Add to `__init__`: `self.heartbeat_manager = HeartbeatManager(self)`
  - [ ] Start after login: `await self.heartbeat_manager.start()`
  - [ ] Stop on disconnect: `await self.heartbeat_manager.stop()`
  - **File:** `modules/camera_client.py`
  - **Priority:** Critical
  - **Owner:** @philibertschlutzki
  - **Est. Time:** 30 min

- [ ] **Implement error recovery (5-failure threshold)**
  - [ ] Modify `heartbeat.py` to count failures
  - [ ] Stop heartbeat after 5 consecutive failures
  - [ ] Log warning with failure count
  - [ ] Trigger reconnection in camera_client.py
  - **Priority:** High
  - **Owner:** @philibertschlutzki
  - **Est. Time:** 45 min

- [ ] **Integrate DeviceCommands into workflow**
  - [ ] Add import: `from modules.commands.device_commands import DeviceCommands`
  - [ ] Initialize: `self.commands = DeviceCommands(camera_client)`
  - [ ] Use for login: `await self.commands.login()`
  - [ ] Use for queries: `info = await self.commands.get_device_info()`
  - **File:** Integration point (TBD)
  - **Priority:** Medium
  - **Owner:** TBD
  - **Est. Time:** 1 hour

### 2. Unit Testing

- [ ] **Create tests/test_command_ids.py**
  ```python
  def test_command_ids():
      assert CMD_LOGIN == 0
      assert CMD_START_AV == 258
      assert CMD_STOP_AV == 259
      assert CMD_GET_DEV_INFO == 512
      assert CMD_HEARTBEAT == 525
      assert CMD_GET_MEDIA_LIST == 768
  
  def test_heartbeat_interval():
      assert HEARTBEAT_INTERVAL_SEC == 3.0
  
  def test_command_names():
      assert get_command_name(525) == "HEARTBEAT"
  ```
  - **Priority:** Medium
  - **Owner:** Any
  - **Est. Time:** 30 min

- [ ] **Create tests/test_heartbeat_basic.py**
  ```python
  async def test_heartbeat_starts():
      hb = HeartbeatManager(mock_client, interval_sec=3.0)
      assert not hb.is_running
      await hb.start()
      assert hb.is_running
      await hb.stop()
      assert not hb.is_running
  
  async def test_heartbeat_stops_after_failures():
      # Test 5-failure threshold
      hb = HeartbeatManager(failing_client, interval_sec=0.1)
      await hb.start()
      await asyncio.sleep(1.0)
      assert not hb.is_running  # Should stop after 5 failures
      assert hb._failed_count >= 5
  ```
  - **Priority:** High
  - **Owner:** @philibertschlutzki
  - **Est. Time:** 45 min

### 3. Integration Testing

- [ ] **Test LAN connection on actual device**
  - [ ] Set up network with camera in AP mode
  - [ ] Run connection manager
  - [ ] Measure time to first successful packet
  - [ ] Verify port 40611 is tried first (check logs)
  - [ ] Expected: <1 second total time
  - **Priority:** High
  - **Owner:** @philibertschlutzki
  - **Est. Time:** 1 hour

- [ ] **Test heartbeat on actual device**
  - [ ] Connect to camera
  - [ ] Start heartbeat manager
  - [ ] Measure 10 consecutive intervals
  - [ ] Calculate mean and standard deviation
  - [ ] Expected: 3.0 ± 0.05 seconds
  - **Priority:** High
  - **Owner:** @philibertschlutzki
  - **Est. Time:** 45 min

- [ ] **Test error recovery**
  - [ ] Start heartbeat
  - [ ] Simulate network failures (iptables, disconnect)
  - [ ] Verify heartbeat stops after 5 failures
  - [ ] Verify reconnection is triggered
  - [ ] Verify heartbeat resumes after reconnect
  - **Priority:** Medium
  - **Owner:** TBD
  - **Est. Time:** 1 hour

---

## 📚 Diese Iteration (2-3 Weeks) - Testing & Optimization

### 1. Unit Tests

- [ ] **Write comprehensive heartbeat tests**
  - [ ] Test interval accuracy (3.0s ± 0.01s)
  - [ ] Test 5-failure threshold
  - [ ] Test start/stop lifecycle
  - [ ] Test failure counter reset on success
  - [ ] Test properties (is_running, heartbeat_count, etc.)
  - **File:** `tests/test_heartbeat_comprehensive.py`
  - **Priority:** Medium
  - **Owner:** Any
  - **Est. Time:** 1.5 hours

- [ ] **Write port prioritization tests**
  ```python
  def test_port_order():
      # Verify 40611 is primary
      assert DEFAULT_LAN_PORTS[0] == 40611
      assert DEFAULT_LAN_PORTS[1] == 32100
      assert DEFAULT_LAN_PORTS[2] == 32108
  
  async def test_port_fallback(mock_device):
      # Test fallback to secondary ports
      # Block 40611, verify 32100 is tried
      pass
  ```
  - **File:** `tests/test_port_handling.py`
  - **Priority:** Medium
  - **Owner:** Any
  - **Est. Time:** 1 hour

### 2. Performance Tests

- [ ] **Memory leak check**
  - [ ] Run heartbeat for 1 hour
  - [ ] Monitor memory usage
  - [ ] Expected: <5% increase
  - **Script:** `tests/perf_memory_heartbeat.py`
  - **Priority:** Medium
  - **Owner:** TBD
  - **Est. Time:** 1+ hours runtime

- [ ] **CPU usage monitoring**
  - [ ] Measure CPU per heartbeat cycle
  - [ ] Expected: <1% CPU per heartbeat
  - [ ] No spikes during interval
  - **Script:** `tests/perf_cpu_heartbeat.py`
  - **Priority:** Low
  - **Owner:** TBD
  - **Est. Time:** 30 min

- [ ] **Network efficiency**
  - [ ] Measure actual bytes sent
  - [ ] Expected: 45 bytes per heartbeat
  - [ ] Bandwidth: ~15 bytes/second
  - **Script:** `tests/perf_network_heartbeat.py`
  - **Priority:** Low
  - **Owner:** TBD
  - **Est. Time:** 30 min

### 3. Documentation

- [ ] **Write implementation guide**
  - [ ] How to integrate heartbeat
  - [ ] Error handling patterns
  - [ ] Performance tuning tips
  - **File:** `docs/INTEGRATION_GUIDE.md`
  - **Priority:** Medium
  - **Owner:** Any
  - **Est. Time:** 1 hour

- [ ] **Update main README.md**
  - [ ] Reference new command modules
  - [ ] Link to HEARTBEAT_AND_COMMANDS.md
  - [ ] Include quick start example
  - **File:** `README.md`
  - **Priority:** Low
  - **Owner:** Any
  - **Est. Time:** 30 min

---

## ✅ Vor Production (Before Deployment) - Final Validation

### 1. Code Review

- [ ] **Review all new code**
  - [ ] Code style and conventions
  - [ ] Error handling completeness
  - [ ] Documentation accuracy
  - [ ] Test coverage
  - **Priority:** Critical
  - **Owner:** Senior developer
  - **Est. Time:** 2 hours

- [ ] **Security review**
  - [ ] No hardcoded credentials
  - [ ] Proper error messages (no info leakage)
  - [ ] Input validation
  - **Priority:** High
  - **Owner:** Security reviewer
  - **Est. Time:** 1 hour

### 2. System Integration Test

- [ ] **Full end-to-end test**
  - [ ] BLE handshake → WiFi → Connection → Login → Heartbeat → Commands
  - [ ] LAN mode: <1 second connection
  - [ ] Remote mode: Connection via relay
  - [ ] Both modes: Stable 30+ minute session
  - **Priority:** Critical
  - **Owner:** @philibertschlutzki
  - **Est. Time:** 2 hours

- [ ] **Error scenario testing**
  - [ ] Network failure during heartbeat
  - [ ] Device reboot during session
  - [ ] Heartbeat threshold breach
  - [ ] Port 40611 blocked, fallback to 32100
  - [ ] Each scenario: Verify recovery
  - **Priority:** High
  - **Owner:** TBD
  - **Est. Time:** 2+ hours

### 3. Performance Validation

- [ ] **Baseline measurement**
  - [ ] Connection time: Record actual vs expected
  - [ ] Heartbeat interval: Record jitter measurements
  - [ ] Device info response: Measure fragmentation
  - [ ] Document all findings
  - **Report:** `tests/BASELINE_REPORT.md`
  - **Priority:** High
  - **Owner:** TBD
  - **Est. Time:** 2 hours

---

## Time Estimation Summary

| Phase | Tasks | Est. Time | Owner |
|-------|-------|-----------|-------|
| **SOFORT** | Verification (4 items) | 1 hour | @philibertschlutzki |
| **Diese Woche** | Integration + Testing (6 items) | 8 hours | Mixed team |
| **Diese Iteration** | Unit + Performance + Docs (8 items) | 12 hours | Mixed team |
| **Vor Production** | Code Review + E2E + Validation (5 items) | 9 hours | Senior + team |
| **TOTAL** | All phases | ~30 hours | Full team |

**Estimated Timeline:** 2-3 weeks with parallel work

---

## Success Criteria

- [ ] All 4 SOFORT verification checks pass
- [ ] All unit tests pass
- [ ] Heartbeat interval measured: 3.0 ± 0.05s
- [ ] LAN connection time: <1 second (90%+ success)
- [ ] E2E test: Stable 30+ minute session
- [ ] Zero memory leaks in 1-hour test
- [ ] All documentation reviewed and approved
- [ ] Code review: No critical findings
- [ ] Performance baseline established

---

## Reference

- **Implementation Status:** `IMPLEMENTATION_STATUS.md`
- **Optimization Summary:** `OPTIMIZATION_SUMMARY.md`
- **Architecture:** `docs/ARCHITECTURE.md`
- **Commands:** `modules/commands/README.md`
- **Log Source:** `archive/2025-12-08log.txt`, `paste.txt`
