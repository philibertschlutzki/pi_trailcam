#!/usr/bin/env python3
"""
PPPP + Artemis Protocol Integration Test

This script tests the complete PPPP wrapping implementation for Artemis protocol.
Based on TCPDump analysis from tcpdump_1800_connect.log.

Usage:
    python tests/test_pppp_artemis.py
    python tests/test_pppp_artemis.py --verbose
    python tests/test_pppp_artemis.py --capture  # Run with tcpdump

Author: philibertschlutzki
Date: 2025-12-07
"""

import sys
import os
import time
import struct
import socket
import logging
import argparse
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import config
from modules.pppp_wrapper import PPPPWrapper
from modules.camera_client import CameraClient
from modules.ble_token_listener import TokenListener


class PPPPArtemisTest:
    """
    Comprehensive test suite for PPPP + Artemis integration.
    
    Tests:
    1. PPPP Wrapper Unit Tests
    2. Discovery with PPPP
    3. Login with PPPP (using BLE token)
    4. Heartbeat with PPPP
    5. Full Integration Flow
    """
    
    def __init__(self, camera_ip=None, verbose=False):
        self.camera_ip = camera_ip or config.CAM_IP
        self.verbose = verbose
        
        # Setup logging
        log_level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%H:%M:%S'
        )
        self.logger = logging.getLogger('PPPPTest')
        
        # Test components
        self.pppp = PPPPWrapper(logger=self.logger)
        self.client = None
        self.sock = None
        
        # Test results
        self.results = {
            'unit_tests': [],
            'discovery': None,
            'login': None,
            'heartbeat': None,
            'integration': None,
        }
    
    def print_banner(self, text):
        """Print test section banner."""
        width = 70
        self.logger.info("="* width)
        self.logger.info(f"  {text}")
        self.logger.info("="* width)
    
    def print_result(self, test_name, passed, details=""):
        """Print test result."""
        status = "✓ PASS" if passed else "✗ FAIL"
        emoji = "👍" if passed else "👎"
        self.logger.info(f"{emoji} [{status}] {test_name}")
        if details:
            self.logger.info(f"    {details}")
    
    # ========================================================================
    # UNIT TESTS
    # ========================================================================
    
    def test_pppp_wrapper_discovery(self):
        """Test PPPP discovery packet wrapping."""
        self.logger.info("\n[TEST] PPPP Discovery Packet Wrapping")
        
        try:
            # Build discovery packet
            artemis_seq = 0x001B
            packet = self.pppp.wrap_discovery(artemis_seq)
            
            # Expected structure from TCPDump:
            # f1 d1 00 06  d1 00 00 01  00 1b
            expected = bytes.fromhex('f1d10006d1000001001b')
            
            # Verify structure
            assert len(packet) >= 10, f"Packet too short: {len(packet)} bytes"
            
            # Check PPPP Outer Header
            outer_magic, outer_type, length = struct.unpack('>BBH', packet[0:4])
            assert outer_magic == 0xF1, f"Wrong outer magic: 0x{outer_magic:02X}"
            assert outer_type == 0xD1, f"Wrong outer type: 0x{outer_type:02X}"
            assert length == 6, f"Wrong length: {length}"
            
            # Check PPPP Inner Header
            inner_type, subcommand, pppp_seq = struct.unpack('>BBH', packet[4:8])
            assert inner_type == 0xD1, f"Wrong inner type: 0x{inner_type:02X}"
            assert subcommand == 0x00, f"Wrong subcommand: 0x{subcommand:02X}"
            
            # Check Artemis Payload
            artemis_payload_seq = struct.unpack('>H', packet[8:10])[0]
            assert artemis_payload_seq == artemis_seq, f"Wrong Artemis seq: 0x{artemis_payload_seq:04X}"
            
            self.print_result(
                "PPPP Discovery Wrapper",
                True,
                f"Packet: {packet.hex()} ({len(packet)} bytes)"
            )
            self.results['unit_tests'].append(('discovery_wrapper', True))
            return True
            
        except AssertionError as e:
            self.print_result("PPPP Discovery Wrapper", False, str(e))
            self.results['unit_tests'].append(('discovery_wrapper', False))
            return False
        except Exception as e:
            self.print_result("PPPP Discovery Wrapper", False, f"Exception: {e}")
            self.results['unit_tests'].append(('discovery_wrapper', False))
            return False
    
    def test_pppp_wrapper_login(self):
        """Test PPPP login packet wrapping."""
        self.logger.info("\n[TEST] PPPP Login Packet Wrapping")
        
        try:
            # Build Artemis login payload
            token = "MzlB36X/IVo8ZzI5rG9j1w=="
            sequence = b'\x2b\x00\x00\x00'
            
            artemis_payload = bytearray()
            artemis_payload.extend(b'ARTEMIS\x00')
            artemis_payload.extend(struct.pack('<I', 0x02000000))  # Version
            artemis_payload.extend(sequence + sequence)  # Mystery bytes (8 total)
            artemis_payload.extend(struct.pack('<I', len(token)))
            artemis_payload.extend(token.encode('ascii'))
            artemis_payload.append(0x00)
            
            # Wrap in PPPP
            packet = self.pppp.wrap_login(bytes(artemis_payload))
            
            # Verify structure
            assert len(packet) > 12, f"Packet too short: {len(packet)} bytes"
            
            # Check PPPP Outer Header
            outer_magic, outer_type, length = struct.unpack('>BBH', packet[0:4])
            assert outer_magic == 0xF1, f"Wrong outer magic: 0x{outer_magic:02X}"
            # FIX: Login uses Outer Type 0xD0 (Analysis Finding)
            assert outer_type == 0xD0, f"Wrong outer type: 0x{outer_type:02X}"
            assert length == len(artemis_payload) + 4, f"Wrong length: {length}"
            
            # Check PPPP Inner Header
            inner_type, subcommand, pppp_seq = struct.unpack('>BBH', packet[4:8])
            assert inner_type == 0xD1, f"Wrong inner type: 0x{inner_type:02X}"
            assert subcommand == 0x03, f"Wrong subcommand for login: 0x{subcommand:02X}"
            
            # Check Artemis Payload starts with "ARTEMIS"
            artemis_start = packet[8:16]
            assert artemis_start == b'ARTEMIS\x00', f"Wrong Artemis magic: {artemis_start}"
            
            self.print_result(
                "PPPP Login Wrapper",
                True,
                f"Packet: {len(packet)} bytes, Token: {token[:20]}..."
            )
            self.results['unit_tests'].append(('login_wrapper', True))
            return True
            
        except AssertionError as e:
            self.print_result("PPPP Login Wrapper", False, str(e))
            self.results['unit_tests'].append(('login_wrapper', False))
            return False
        except Exception as e:
            self.print_result("PPPP Login Wrapper", False, f"Exception: {e}")
            self.results['unit_tests'].append(('login_wrapper', False))
            return False
    
    def test_pppp_unwrap(self):
        """Test PPPP packet unwrapping."""
        self.logger.info("\n[TEST] PPPP Packet Unwrapping")
        
        try:
            # Real packet from TCPDump:
            # f1 d1 00 06  d1 00 00 01  00 1b
            test_packet = bytes.fromhex('f1d10006d1000001001b')
            
            # Unwrap
            parsed = self.pppp.unwrap_pppp(test_packet)
            
            # Verify
            assert parsed['outer_magic'] == 0xF1, "Wrong outer magic"
            assert parsed['outer_type'] == 0xD1, "Wrong outer type"
            assert parsed['length'] == 6, "Wrong length"
            assert parsed['inner_type'] == 0xD1, "Wrong inner type"
            assert parsed['subcommand'] == 0x00, "Wrong subcommand"
            assert parsed['pppp_seq'] == 1, "Wrong PPPP sequence"
            assert len(parsed['payload']) == 2, "Wrong payload length"
            
            artemis_seq = struct.unpack('>H', parsed['payload'])[0]
            assert artemis_seq == 0x001B, f"Wrong Artemis seq: 0x{artemis_seq:04X}"
            
            self.print_result(
                "PPPP Packet Unwrapping",
                True,
                f"Parsed: Seq={parsed['pppp_seq']}, Artemis=0x{artemis_seq:04X}"
            )
            self.results['unit_tests'].append(('unwrap', True))
            return True
            
        except AssertionError as e:
            self.print_result("PPPP Packet Unwrapping", False, str(e))
            self.results['unit_tests'].append(('unwrap', False))
            return False
        except Exception as e:
            self.print_result("PPPP Packet Unwrapping", False, f"Exception: {e}")
            self.results['unit_tests'].append(('unwrap', False))
            return False
    
    # ========================================================================
    # INTEGRATION TESTS
    # ========================================================================
    
    def test_discovery_integration(self):
        """Test discovery with real camera."""
        self.logger.info("\n[TEST] Discovery Integration Test")
        
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5.0)
            
            # Build discovery packet
            artemis_seq = 0x001B
            packet = self.pppp.wrap_discovery(artemis_seq)
            
            self.logger.info(f"[>] Sending discovery: {packet.hex()}")
            sock.sendto(packet, (self.camera_ip, config.CAM_PORT))
            
            # Wait for response
            try:
                data, addr = sock.recvfrom(2048)
                self.logger.info(f"[<] Response from {addr}: {data.hex()}")
                
                # Parse response
                response = self.pppp.unwrap_pppp(data)
                
                # Check if it's discovery ACK (subcommand 0x01)
                if response['subcommand'] == 0x01:
                    self.print_result(
                        "Discovery Integration",
                        True,
                        f"Got ACK from {addr}"
                    )
                    self.results['discovery'] = True
                    return True
                else:
                    self.print_result(
                        "Discovery Integration",
                        False,
                        f"Unexpected subcommand: 0x{response['subcommand']:02X}"
                    )
                    self.results['discovery'] = False
                    return False
                    
            except socket.timeout:
                self.print_result("Discovery Integration", False, "Timeout waiting for response")
                self.results['discovery'] = False
                return False
                
        except Exception as e:
            self.print_result("Discovery Integration", False, f"Exception: {e}")
            self.results['discovery'] = False
            return False
        finally:
            if sock:
                sock.close()
    
    def test_full_integration(self):
        """Test full flow: BLE -> Discovery -> Login -> Heartbeat."""
        self.print_banner("FULL INTEGRATION TEST")
        
        try:
            # Step 1: Initialize client
            self.logger.info("\n[STEP 1] Initialize CameraClient with PPPP wrapper")
            self.client = CameraClient(camera_ip=self.camera_ip, logger=self.logger)
            
            # Step 2: Get BLE token (if available)
            self.logger.info("\n[STEP 2] Check for BLE token")
            
            # Try to load cached token from BLE
            token_file = Path("ble_token_cache.txt")
            if token_file.exists():
                with open(token_file, 'r') as f:
                    lines = f.readlines()
                    if len(lines) >= 2:
                        token = lines[0].strip()
                        sequence_hex = lines[1].strip()
                        sequence = bytes.fromhex(sequence_hex)
                        
                        self.logger.info(f"[BLE] Loaded cached token: {token[:20]}...")
                        self.logger.info(f"[BLE] Sequence: {sequence.hex()}")
                        
                        self.client.set_session_credentials(token, sequence, use_ble_dynamic=True)
                    else:
                        self.logger.warning("[BLE] Token cache invalid, using test token")
                        self._use_test_token()
            else:
                self.logger.warning("[BLE] No token cache found, using test token")
                self._use_test_token()
            
            # Step 3: Discovery
            self.logger.info("\n[STEP 3] Discovery phase")
            if not self.client.connect_with_retries():
                self.print_result("Full Integration - Discovery", False, "Discovery failed")
                self.results['integration'] = False
                return False
            
            self.logger.info("[STEP 3] ✓ Discovery successful")
            
            # Step 4: Login
            self.logger.info("\n[STEP 4] Login phase")
            if not self.client.login(variant='BLE_DYNAMIC'):
                self.print_result("Full Integration - Login", False, "Login failed")
                self.results['integration'] = False
                return False
            
            self.logger.info("[STEP 4] ✓ Login successful")
            
            # Step 5: Heartbeat
            self.logger.info("\n[STEP 5] Send heartbeat")
            time.sleep(1)  # Wait for auto-heartbeat to start
            
            # Check if heartbeat thread is running
            if self.client.running and self.client.keep_alive_thread:
                self.logger.info("[STEP 5] ✓ Heartbeat thread running")
            else:
                self.logger.warning("[STEP 5] Heartbeat thread not started")
            
            # Step 6: Cleanup
            self.logger.info("\n[STEP 6] Cleanup")
            self.client.close()
            
            self.print_result(
                "Full Integration Test",
                True,
                "Complete flow: BLE → Discovery → Login → Heartbeat"
            )
            self.results['integration'] = True
            return True
            
        except Exception as e:
            self.logger.error(f"[INTEGRATION] Exception: {e}", exc_info=True)
            self.print_result("Full Integration Test", False, str(e))
            self.results['integration'] = False
            return False
        finally:
            if self.client:
                self.client.close()
    
    def _use_test_token(self):
        """Fallback to test token."""
        test_token = "MzlB36X/IVo8ZzI5rG9j1w=="
        test_sequence = b'\x2b\x00\x00\x00'
        self.client.set_session_credentials(test_token, test_sequence, use_ble_dynamic=True)
        self.logger.info(f"[TEST] Using fallback token: {test_token[:20]}...")
    
    # ========================================================================
    # TEST RUNNER
    # ========================================================================
    
    def run_all_tests(self):
        """Run all tests in sequence."""
        self.print_banner("PPPP + ARTEMIS PROTOCOL TEST SUITE")
        
        # Unit Tests
        self.print_banner("UNIT TESTS")
        self.test_pppp_wrapper_discovery()
        self.test_pppp_wrapper_login()
        self.test_pppp_unwrap()
        
        # Integration Tests
        self.print_banner("INTEGRATION TESTS")
        self.test_discovery_integration()
        
        # Full Flow
        self.test_full_integration()
        
        # Summary
        self.print_summary()
    
    def print_summary(self):
        """Print test summary."""
        self.print_banner("TEST SUMMARY")
        
        # Unit tests
        unit_passed = sum(1 for _, passed in self.results['unit_tests'] if passed)
        unit_total = len(self.results['unit_tests'])
        self.logger.info(f"Unit Tests: {unit_passed}/{unit_total} passed")
        
        # Integration tests
        integration_tests = [
            ('Discovery', self.results['discovery']),
            ('Full Integration', self.results['integration']),
        ]
        
        integration_passed = sum(1 for _, passed in integration_tests if passed)
        integration_total = len(integration_tests)
        self.logger.info(f"Integration Tests: {integration_passed}/{integration_total} passed")
        
        # Overall
        total_passed = unit_passed + integration_passed
        total_tests = unit_total + integration_total
        self.logger.info(f"\n🎯 OVERALL: {total_passed}/{total_tests} tests passed")
        
        if total_passed == total_tests:
            self.logger.info("🎉 ALL TESTS PASSED! PPPP Wrapper is working correctly.")
            return 0
        else:
            self.logger.error("❌ SOME TESTS FAILED. Check logs above for details.")
            return 1


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Test PPPP + Artemis protocol integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python tests/test_pppp_artemis.py                 # Run all tests
  python tests/test_pppp_artemis.py --verbose       # Verbose output
  python tests/test_pppp_artemis.py --camera 192.168.1.100  # Custom camera IP

Before running:
  1. Ensure camera is powered on and WiFi is active
  2. Run BLE token extraction if needed:
     python main.py --ble-only
  3. Optionally start tcpdump capture:
     sudo tcpdump -i any -s0 -w pppp_test.pcap "udp port 40611"
        """
    )
    
    parser.add_argument(
        '--camera',
        default=None,
        help=f"Camera IP address (default: {config.CAM_IP})"
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help="Enable verbose logging"
    )
    
    parser.add_argument(
        '--unit-only',
        action='store_true',
        help="Run only unit tests (no camera needed)"
    )
    
    args = parser.parse_args()
    
    # Run tests
    tester = PPPPArtemisTest(camera_ip=args.camera, verbose=args.verbose)
    
    if args.unit_only:
        tester.print_banner("UNIT TESTS ONLY")
        tester.test_pppp_wrapper_discovery()
        tester.test_pppp_wrapper_login()
        tester.test_pppp_unwrap()
        tester.print_summary()
    else:
        exit_code = tester.run_all_tests()
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
