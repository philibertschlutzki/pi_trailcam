#!/usr/bin/env python3
"""
Test-Script um Payload-Bytes aus tcpdump zu extrahieren und zu analysieren.
Vergleicht Smartphone-Dump mit Raspberry-Dump byte-für-byte.
"""

import struct
import base64

# === Smartphone Dump (funktionierend) ===
smartphone_hex = (
    "f1d0 0045 d100 0005 4152 5445 4d49 5300"
    "0200 0000 2b00 0000 2d00 0000 1900 0000"
    "4933 6d62 7756 4978 4a51 676e 5342 3947"
    "4a4b 4e6b 3542 7676 2f79 2b67 382b 4d58"
    "2f48 5643 4d6e 4371 7955 6f3d 00"
)

# === Raspberry Dump (fehlgeschlagen) ===
raspberry_hex = (
    "f1d0 0031 d100 0001 4152 5445 4d49 5300"
    "0200 0000 0200 0100 1900 0000 4d7a 6c42"
    "3336 582f 4956 6f38 5a7a 4935 7247 396a"
    "3177 3d3d 00"
)

def parse_hex(hex_str):
    """Konvertiert hex-String mit Spaces zu bytes."""
    return bytes.fromhex(hex_str.replace(" ", ""))

def analyze_payload(name, hex_data):
    """Analysiert eine Payload in detail."""
    data = parse_hex(hex_data)
    print(f"\n=== {name} ===")
    print(f"Gesamt-Länge: {len(data)} Bytes")
    print(f"Hex: {data.hex()}")
    
    # Outer Header (4 Bytes)
    outer_magic = data[0]
    outer_type = data[1]
    outer_len = struct.unpack('>H', data[2:4])[0]
    print(f"\nOuter Header:")
    print(f"  Magic: 0x{outer_magic:02x} (erwartung: 0xf1)")
    print(f"  Type: 0x{outer_type:02x} (0xd0 = Login)")
    print(f"  Inner-Länge: {outer_len} Bytes")
    
    # Inner Header (4 Bytes)
    inner_magic = data[4]
    inner_type = data[5]
    inner_seq = struct.unpack('>H', data[6:8])[0]
    print(f"\nInner Header:")
    print(f"  Magic: 0x{inner_magic:02x} (erwartung: 0xd1)")
    print(f"  Type: 0x{inner_type:02x}")
    print(f"  Sequence: {inner_seq}")
    
    # Payload (alles nach Byte 8)
    payload = data[8:]
    print(f"\nPayload ({len(payload)} Bytes):")
    print(f"  Hex: {payload.hex()}")
    
    # Struktur nach ARTEMIS\0
    if b'ARTEMIS' in payload:
        artemis_end = payload.index(b'ARTEMIS\x00') + 8
        print(f"\n  String 'ARTEMIS\\0' endet bei Byte {artemis_end}")
        
        after_artemis = payload[artemis_end:]
        print(f"  Nach ARTEMIS ({len(after_artemis)} Bytes):")
        print(f"    Hex: {after_artemis.hex()}")
        
        # Versuche zu dekodieren
        print(f"\n  Struktur-Analyse:")
        
        # Erste 4 Bytes
        if len(after_artemis) >= 4:
            field1 = struct.unpack('>I', after_artemis[0:4])[0]
            print(f"    [00-03]: {after_artemis[0:4].hex()} = 0x{field1:08x}")
        
        # Nächste 4 Bytes
        if len(after_artemis) >= 8:
            field2 = struct.unpack('>I', after_artemis[4:8])[0]
            print(f"    [04-07]: {after_artemis[4:8].hex()} = 0x{field2:08x} = {field2} (dezimal)")
        
        # Nächste 4 Bytes
        if len(after_artemis) >= 12:
            field3 = struct.unpack('>I', after_artemis[8:12])[0]
            print(f"    [08-11]: {after_artemis[8:12].hex()} = 0x{field3:08x} = {field3} (dezimal)")
        
        # Nächste 4 Bytes
        if len(after_artemis) >= 16:
            field4 = struct.unpack('>I', after_artemis[12:16])[0]
            print(f"    [12-15]: {after_artemis[12:16].hex()} = 0x{field4:08x} = {field4} (dezimal)")
        
        # Auth-Token
        if len(after_artemis) > 16:
            token_start = 16
            token_end = after_artemis.rfind(b'\x00')
            if token_end > token_start:
                token = after_artemis[token_start:token_end]
                print(f"\n  Auth-Token ({len(token)} Bytes):")
                print(f"    Hex: {token.hex()}")
                print(f"    ASCII: {token.decode('ascii', errors='ignore')}")
                try:
                    decoded = base64.b64decode(token)
                    print(f"    Dekodiert (base64): {decoded.hex()}")
                except:
                    print(f"    (nicht base64)")

def compare():
    """Vergleicht beide Dumps."""
    sp_data = parse_hex(smartphone_hex)
    rp_data = parse_hex(raspberry_hex)
    
    print("\n" + "="*60)
    print("VERGLEICH SMARTPHONE vs RASPBERRY")
    print("="*60)
    
    # Finde ARTEMIS
    sp_artemis_end = sp_data.index(b'ARTEMIS\x00') + 8
    rp_artemis_end = rp_data.index(b'ARTEMIS\x00') + 8
    
    sp_after = sp_data[sp_artemis_end:sp_artemis_end+16]
    rp_after = rp_data[rp_artemis_end:rp_artemis_end+16]
    
    print(f"\nBytes direkt nach ARTEMIS\\0:")
    print(f"  Smartphone: {sp_after.hex()}")
    print(f"  Raspberry:  {rp_after.hex()}")
    print(f"\n  UNTERSCHIEDE:")
    for i in range(min(len(sp_after), len(rp_after))):
        if sp_after[i] != rp_after[i]:
            print(f"    Byte {i}: 0x{sp_after[i]:02x} vs 0x{rp_after[i]:02x}")

if __name__ == "__main__":
    analyze_payload("SMARTPHONE (funktionierend)", smartphone_hex)
    analyze_payload("RASPBERRY (fehlgeschlagen)", raspberry_hex)
    compare()
    
    print("\n" + "="*60)
    print("HYPOTHESE: Bytes 2b 2d vs 02 01")
    print("="*60)
    print("""
Smartphone sendet nach ARTEMIS:
  02 00 00 00  (Flags/Version)
  2b 00 00 00  (0x2b = 43)
  2d 00 00 00  (0x2d = 45)
  19 00 00 00  (0x19 = 25 = Auth-Token-Länge)
  [45-Byte Base64 Token]

Raspberry sendet:
  02 00 00 00  (Flags/Version) ✓ Korrekt
  02 00 01 00  (0x0002) ✗ FALSCH
  19 00 00 00  (0x19 = 25) ✗ Sollte 2d sein?
  [25-Byte Base64 Token]

Vermutung: Die Bytes 2b und 2d sind WICHTIG und müssen vom
Smartphone-Dump kopiert werden!
    """)
