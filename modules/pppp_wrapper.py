"""PPPP Protocol Wrapper for Artemis Camera.

This module implements the PPPP (P2P Push Proxy Protocol) wrapping layer
for the Artemis camera protocol. Based on analysis of libArLink.so and
TCPDump captures from the TrailCam Go app.

PPPP is a proprietary protocol by Tutk/CS2 Network used for P2P communication
with IoT cameras. The Artemis protocol runs as payload inside PPPP packets.

Protocol Phases (from PROTOCOL_ANALYSIS.md):
    1. Initialization (Wake-up): Uses Type 0xE1 to wake up the camera UDP stack.
    2. Discovery: Uses Type 0xD1 to verify device presence.
    3. Login: Uses Type 0xD0 (Outer) to authenticate.

Packet Structure:
    ┌────────────────────────────────────────┐
    │  PPPP Outer Header (4 bytes)          │
    ├────────────────────────────────────────┤
    │  Byte 0:    0xF1 (Magic)               │
    │  Byte 1:    Type (D1, D0, E1, etc.)    │
    │  Bytes 2-3: Length (Big Endian)        │
    └────────────────────────────────────────┘
    ┌────────────────────────────────────────┐
    │  PPPP Inner Header (4 bytes)           │
    ├────────────────────────────────────────┤
    │  Byte 4:    Session Type (D1, E1, etc.)│
    │  Byte 5:    Subcommand                 │
    │  Bytes 6-7: PPPP Sequence (Big Endian) │
    └────────────────────────────────────────┘
    ┌────────────────────────────────────────┐
    │  Artemis Payload (Variable)            │
    │  - Discovery, Login, Commands, etc.    │
    └────────────────────────────────────────┘

# Packet Types (from PROTOCOL_ANALYSIS.md Section 3.1):
# 0xD1: Standard Session Data (Discovery, Command)
# 0xD0: Login Handshake (Specific to Artemis)
# 0xE1: Initialization / Wake-up
# 0xD3: Control / Heartbeat
# 0xD4: Large Data Transfer (Video/Images)

Usage:
    >>> from modules.pppp_wrapper import PPPPWrapper
    >>> pppp = PPPPWrapper()
    >>> 
    >>> # Wrap init packet
    >>> init = pppp.wrap_init()
    >>>
    >>> # Wrap discovery packet
    >>> discovery = pppp.wrap_discovery(artemis_seq=0x001B)
    >>> print(discovery.hex())
    'f1d10006d10000010001b'
    >>> 
    >>> # Wrap login packet
    >>> artemis_login = build_artemis_login_payload(token, sequence)
    >>> login = pppp.wrap_login(artemis_login)
    >>> 
    >>> # Parse response
    >>> response_data = socket.recv(1024)
    >>> parsed = pppp.unwrap_pppp(response_data)
    >>> print(parsed['subcommand'])  # 0x01 = Discovery ACK, 0x04 = Login ACK

Author: philibertschlutzki
Date: 2025-12-07
Based on: TCPDump analysis and libArLink.so reverse engineering
"""

import struct
import logging
from typing import Dict, Optional


class PPPPWrapper:
    """Wrapper for PPPP protocol layer.
    
    This class handles wrapping and unwrapping of Artemis protocol packets
    in PPPP headers. It maintains the PPPP sequence number (transport layer)
    which is distinct from the Artemis sequence number (application layer).
    
    Attributes:
        pppp_seq (int): Current PPPP transport sequence number (increments with each packet)
        logger: Logger instance for debugging
    """
    
    # PPPP Constants
    PPPP_MAGIC = 0xF1
    
    # Outer Command Types
    OUTER_TYPE_STANDARD = 0xD1  # Standard commands
    OUTER_TYPE_LOGIN = 0xD0     # Login command (Analysis Finding)
    OUTER_TYPE_CONTROL = 0xD3   # Control messages
    OUTER_TYPE_DATA = 0xD4      # Data transfer
    OUTER_TYPE_INIT = 0xE1      # Initialization (Wakeup)
    
    # Inner Session Types (usually same as outer)
    INNER_TYPE_STANDARD = 0xD1
    INNER_TYPE_CONTROL = 0xD3
    INNER_TYPE_DATA = 0xD4
    INNER_TYPE_INIT = 0xE1
    
    # Subcommands
    SUBCOMMAND_DISCOVERY = 0x00
    SUBCOMMAND_DISCOVERY_ACK = 0x01
    SUBCOMMAND_LOGIN = 0x03
    SUBCOMMAND_LOGIN_ACK = 0x04
    SUBCOMMAND_HEARTBEAT = 0x01
    SUBCOMMAND_INIT = 0x00
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize PPPP wrapper.
        
        Args:
            logger: Optional logger instance. If None, creates default logger.
        """
        self.logger = logger or logging.getLogger(__name__)
        self.pppp_seq = 1
    
    def wrap_pppp(
        self,
        payload: bytes,
        outer_type: int,
        inner_type: int,
        subcommand: int
    ) -> bytes:
        """Wrap Artemis payload in PPPP headers.
        
        This is the core wrapping function. Use the convenience methods
        (wrap_discovery, wrap_login, etc.) for specific packet types.
        
        Args:
            payload: Artemis protocol payload
            outer_type: PPPP outer command type (0xD1, 0xD3, 0xD4)
            inner_type: PPPP inner session type (usually same as outer_type)
            subcommand: Subcommand byte (0x00=Discovery, 0x03=Login, etc.)
        
        Returns:
            Complete PPPP packet ready to send over UDP
        
        Example:
            >>> pppp = PPPPWrapper()
            >>> artemis_data = b'\x00\x1b'  # Artemis sequence
            >>> packet = pppp.wrap_pppp(
            ...     artemis_data,
            ...     outer_type=0xD1,
            ...     inner_type=0xD1,
            ...     subcommand=0x00
            ... )
            >>> print(packet.hex())
            'f1d10006d10000010001b'
        """
        # Build Inner Header (4 bytes)
        # Format: >BBH = Big Endian, Byte, Byte, Unsigned Short
        inner_header = struct.pack('>BBH', inner_type, subcommand, self.pppp_seq)
        
        # Build Outer Header (4 bytes)
        # Length = Inner Header (4) + Payload length
        pppp_payload = inner_header + payload
        outer_header = struct.pack(
            '>BBH',
            self.PPPP_MAGIC,
            outer_type,
            len(pppp_payload)
        )
        
        # Complete packet
        packet = outer_header + pppp_payload
        
        self.logger.debug(
            f"[PPPP WRAP] "
            f"Outer=0x{outer_type:02X}, "
            f"Inner=0x{inner_type:02X}, "
            f"Sub=0x{subcommand:02X}, "
            f"Seq={self.pppp_seq}, "
            f"PayloadLen={len(payload)}, "
            f"TotalLen={len(packet)}"
        )
        
        # Increment sequence for next packet
        self.pppp_seq += 1
        
        return packet
    
    def wrap_init(self) -> bytes:
        """Wrap initialization packet.

        Phase 1 of Connection: Initialization.
        Sends a special PPPP packet (Type 0xE1) to wake up the camera's UDP stack.
        Payload is empty.

        Structure:
        Outer: F1 E1 00 04
        Inner: E1 00 [Seq]
        Payload: None

        Returns:
            PPPP-wrapped init packet.
        """
        return self.wrap_pppp(
            b'',
            outer_type=self.OUTER_TYPE_INIT,
            inner_type=self.INNER_TYPE_INIT,
            subcommand=self.SUBCOMMAND_INIT
        )

    def wrap_discovery(self, artemis_seq: int) -> bytes:
        """Wrap discovery packet.
        
        Discovery packets are minimal - just the Artemis sequence number.
        
        Args:
            artemis_seq: Artemis protocol sequence number (usually 0x001B from BLE)
        
        Returns:
            PPPP-wrapped discovery packet (10 bytes total)
        
        Example:
            >>> pppp = PPPPWrapper()
            >>> packet = pppp.wrap_discovery(0x001B)
            >>> print(f"Discovery: {packet.hex()}")
            Discovery: f1d10006d10000010001b
        """
        # Artemis discovery payload is just 2 bytes: sequence number
        payload = struct.pack('>H', artemis_seq)
        
        return self.wrap_pppp(
            payload,
            outer_type=self.OUTER_TYPE_STANDARD,
            inner_type=self.INNER_TYPE_STANDARD,
            subcommand=self.SUBCOMMAND_DISCOVERY
        )
    
    def wrap_login(self, artemis_payload: bytes) -> bytes:
        """Wrap login packet.
        
        Phase 3 of Connection: Login.
        Login packets contain the full Artemis login structure.
        
        Analysis shows Login uses Outer Type 0xD0 (Artemis-specific handshake)
        instead of the standard 0xD1. This differs from generic PPPP implementations
        but is critical for the camera to accept the credentials.

        Structure:
        - Outer Type: 0xD0
        - Inner Type: 0xD1
        - Subcommand: 0x03 (Login)

        Args:
            artemis_payload: Complete Artemis login payload (built by caller)
        
        Returns:
            PPPP-wrapped login packet
        """
        # Note: Analysis shows Login usually uses Outer 0xD0, Inner 0xD1, Sub 0x03
        return self.wrap_pppp(
            artemis_payload,
            outer_type=self.OUTER_TYPE_LOGIN,  # 0xD0
            inner_type=self.INNER_TYPE_STANDARD, # 0xD1
            subcommand=self.SUBCOMMAND_LOGIN   # 0x03
        )
    
    def wrap_heartbeat(self, artemis_seq: int) -> bytes:
        """Wrap heartbeat/keepalive packet.
        
        Heartbeat packets keep the session alive. They contain minimal data.
        
        Args:
            artemis_seq: Current Artemis sequence number
        
        Returns:
            PPPP-wrapped heartbeat packet
        
        Example:
            >>> pppp = PPPPWrapper()
            >>> packet = pppp.wrap_heartbeat(0x0020)
        """
        # Heartbeat payload: Artemis seq (2 bytes) + padding (2 bytes)
        payload = struct.pack('>HH', artemis_seq, 0x0000)
        
        return self.wrap_pppp(
            payload,
            outer_type=self.OUTER_TYPE_CONTROL,
            inner_type=self.INNER_TYPE_CONTROL,
            subcommand=self.SUBCOMMAND_HEARTBEAT
        )
    
    def wrap_command(self, artemis_payload: bytes) -> bytes:
        """Wrap generic command packet.
        
        For custom commands not covered by the convenience methods.
        
        Args:
            artemis_payload: Complete Artemis command payload
        
        Returns:
            PPPP-wrapped command packet
        """
        return self.wrap_pppp(
            artemis_payload,
            outer_type=self.OUTER_TYPE_STANDARD,
            inner_type=self.INNER_TYPE_STANDARD,
            subcommand=0x00  # Generic command
        )
    
    def unwrap_pppp(self, packet: bytes) -> Dict:
        """Unwrap PPPP packet to extract Artemis payload.
        
        Parses both PPPP headers and returns structured data including
        the raw Artemis payload for further processing.
        
        Args:
            packet: Complete PPPP packet received from camera
        
        Returns:
            Dictionary containing:
                - outer_magic: Should be 0xF1
                - outer_type: PPPP command type
                - length: Payload length from header
                - inner_type: PPPP session type
                - subcommand: Subcommand byte (0x01=ACK, 0x04=Login ACK, etc.)
                - pppp_seq: PPPP sequence number from packet
                - payload: Raw Artemis data (bytes)
        
        Raises:
            ValueError: If packet is too short or malformed
        
        Example:
            >>> pppp = PPPPWrapper()
            >>> response = socket.recv(1024)
            >>> parsed = pppp.unwrap_pppp(response)
            >>> if parsed['subcommand'] == 0x01:
            ...     print("Got Discovery ACK")
            >>> artemis_data = parsed['payload']
        """
        if len(packet) < 8:
            raise ValueError(
                f"PPPP packet too short: {len(packet)} bytes (minimum 8)"
            )
        
        # Parse Outer Header (4 bytes)
        outer_magic, outer_type, length = struct.unpack('>BBH', packet[0:4])
        
        if outer_magic != self.PPPP_MAGIC:
            self.logger.warning(
                f"[PPPP UNWRAP] Unexpected magic: 0x{outer_magic:02X} "
                f"(expected 0x{self.PPPP_MAGIC:02X})"
            )
        
        # Parse Inner Header (4 bytes)
        inner_type, subcommand, pppp_seq = struct.unpack('>BBH', packet[4:8])
        
        # Extract Artemis Payload (everything after 8-byte PPPP headers)
        artemis_payload = packet[8:]
        
        self.logger.debug(
            f"[PPPP UNWRAP] "
            f"Outer=0x{outer_type:02X}, "
            f"Inner=0x{inner_type:02X}, "
            f"Sub=0x{subcommand:02X}, "
            f"Seq={pppp_seq}, "
            f"PayloadLen={len(artemis_payload)}"
        )
        
        return {
            'outer_magic': outer_magic,
            'outer_type': outer_type,
            'length': length,
            'inner_type': inner_type,
            'subcommand': subcommand,
            'pppp_seq': pppp_seq,
            'payload': artemis_payload,
        }
    
    def reset_sequence(self, seq: int = 1):
        """Reset PPPP sequence number.
        
        Useful for testing or when starting a new session.
        
        Args:
            seq: New sequence number (default: 1)
        """
        self.pppp_seq = seq
        self.logger.debug(f"[PPPP] Reset sequence to {seq}")
    
    def get_sequence(self) -> int:
        """Get current PPPP sequence number.
        
        Returns:
            Current sequence number (before next increment)
        """
        return self.pppp_seq
