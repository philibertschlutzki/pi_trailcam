#!/usr/bin/env python3
"""Test decryption of the actual MITM login response.

This test uses the real Base64 payload from traffic_port_get_pictures_thumbnail.log:
MsgType=3, AppSeq=1, Base64: 7sQ3+pH/khrx+xvDdflBdzBAUkj6M98fdmvH...
"""

import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

PHASE2_KEY = b"a01bc23ed45fF56A"

# From MITM capture: traffic_port_get_pictures_thumbnail.log
# ⚡ [RX] Empfange UDP (157 bytes)
# 75116068c8  f1 d0 00 99 d1 00 00 01 41 52 54 45 4d 49 53 00  ........ARTEMIS.
# 75116068d8  03 00 00 00 01 00 00 00 81 00 00 00 37 73 51 33  ............7sQ3
# 75116068e8  2b 70 48 2f 6b 68 72 78 2b 78 76 44 64 66 6c 42  +pH/khrx+xvDdflB
# 75116068f8  64 7a 42 41 55 6b 6a 36 4d 39 38 66 64 6d 76 48  dzBAUkj6M98fdmvH
# 7511606908  53 6c 2b 31 71 32 32 4b 64 33 63 52 54 70 4d 35  Sl+1q22Kd3cRTpM5
# 7511606918  33 39 47 5a 63 42 30 6a 53 74 52 66 77 6a 4d 57  39GZcB0jStRfwjMW
# 7511606928  30 30 6f 52 31 35 31 42 61 4a 50 49 55 36 6d 4a  00oR151BaJPIU6mJ
# 7511606938  54 6e 53 31 57 73 64 64 64 38 75 2f 41 70 6f 58  TnS1Wsddd8u/ApoX
# 7511606948  59 31 7a 51 71 6a 67 3d 00 00 00 00 00 00 00 00  Y1zQqjg=........

MITM_LOGIN_RESPONSE_B64 = b"7sQ3+pH/khrx+xvDdflBdzBAUkj6M98fdmvHSl+1q22Kd3cRTpM539GZcB0jStRfwjMW00oR151BaJPIU6mJTnS1Wsddd8u/ApoXY1zQqjg="


def test_mitm_login_response_decryption():
    """Test that we can decrypt the real MITM login response and extract the token."""
    
    print("Testing MITM login response decryption...")
    print(f"Base64 payload length: {len(MITM_LOGIN_RESPONSE_B64)} chars")
    
    # Decode base64
    encrypted = base64.b64decode(MITM_LOGIN_RESPONSE_B64)
    print(f"Encrypted data length: {len(encrypted)} bytes (16-aligned: {len(encrypted) % 16 == 0})")
    print(f"Encrypted hex (first 32 bytes): {encrypted[:32].hex()}")
    
    result = None
    strategy = None
    
    # Try multiple decryption strategies (matching get_thumbnail_perp.py logic)
    
    # Strategy (a): AES-ECB
    try:
        print("\n[Strategy a] Trying AES-ECB...")
        cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
        decrypted = cipher.decrypt(encrypted)
        print(f"Decrypted hex (first 64 bytes): {decrypted[:64].hex()}")
        
        try:
            unpadded = unpad(decrypted, AES.block_size)
            result = json.loads(unpadded.decode("utf-8"))
            strategy = "ECB"
            print(f"✅ Standard ECB+unpad successful!")
        except Exception as e1:
            print(f"  Standard unpad failed: {e1}")
            # Try manual unpad
            s = decrypted.decode("utf-8", errors="ignore")
            end_idx = s.rfind("}")
            if end_idx != -1:
                json_str = s[: end_idx + 1]
                result = json.loads(json_str)
                strategy = "ECB-manual"
                print(f"✅ Manual ECB unpad successful!")
    except Exception as e:
        print(f"  ECB strategy failed: {e}")
    
    # Strategy (b): AES-CBC with IV = first 16 bytes
    if not result and len(encrypted) > 16 and len(encrypted[16:]) % 16 == 0:
        try:
            print("\n[Strategy b] Trying AES-CBC with IV...")
            iv = encrypted[:16]
            ciphertext = encrypted[16:]
            print(f"  IV: {iv.hex()}")
            print(f"  Ciphertext length: {len(ciphertext)}")
            
            cipher = AES.new(PHASE2_KEY, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(ciphertext)
            print(f"  Decrypted hex (first 64 bytes): {decrypted[:64].hex()}")
            
            try:
                unpadded = unpad(decrypted, AES.block_size)
                result = json.loads(unpadded.decode("utf-8"))
                strategy = "CBC"
                print(f"✅ CBC+unpad successful!")
            except Exception as e1:
                print(f"  Standard unpad failed: {e1}")
                # Try manual unpad
                s = decrypted.decode("utf-8", errors="ignore")
                end_idx = s.rfind("}")
                if end_idx != -1:
                    json_str = s[: end_idx + 1]
                    result = json.loads(json_str)
                    strategy = "CBC-manual"
                    print(f"✅ Manual CBC unpad successful!")
        except Exception as e:
            print(f"  CBC strategy failed: {e}")
    
    # Strategy (c): ECB with prefix removal
    if not result:
        for prefix_size in [3, 4, 8, 16]:
            if len(encrypted) > prefix_size and len(encrypted[prefix_size:]) % 16 == 0:
                try:
                    print(f"\n[Strategy c] Trying ECB with {prefix_size}-byte prefix removal...")
                    ciphertext = encrypted[prefix_size:]
                    cipher = AES.new(PHASE2_KEY, AES.MODE_ECB)
                    decrypted = cipher.decrypt(ciphertext)
                    print(f"  Decrypted hex (first 32 bytes): {decrypted[:32].hex()}")
                    
                    try:
                        unpadded = unpad(decrypted, AES.block_size)
                        result = json.loads(unpadded.decode("utf-8"))
                        strategy = f"ECB-prefix{prefix_size}"
                        print(f"✅ ECB-prefix{prefix_size}+unpad successful!")
                        break
                    except Exception:
                        s = decrypted.decode("utf-8", errors="ignore")
                        end_idx = s.rfind("}")
                        if end_idx != -1:
                            json_str = s[: end_idx + 1]
                            result = json.loads(json_str)
                            strategy = f"ECB-prefix{prefix_size}-manual"
                            print(f"✅ Manual ECB-prefix{prefix_size} unpad successful!")
                            break
                except Exception as e:
                    print(f"  ECB-prefix{prefix_size} failed: {e}")
    
    if not result:
        raise ValueError("All decryption strategies failed")
    
    print(f"\nDecrypted JSON:")
    print(json.dumps(result, indent=2))
    
    # Verify expected fields
    assert "cmdId" in result, "cmdId field missing"
    assert result["cmdId"] == 0, f"Expected cmdId=0, got {result['cmdId']}"
    
    # Check for token (might be in different field names)
    token_field = None
    for key in ["token", "sessionToken", "authToken", "accessToken"]:
        if key in result:
            token_field = key
            break
    
    if token_field:
        print(f"\n✅ Token found in field '{token_field}': {result[token_field][:20]}...")
        assert len(result[token_field]) > 0, "Token is empty"
    else:
        print(f"\n⚠️ No token field found. Available fields: {list(result.keys())}")
        print("Full JSON for inspection:")
        print(json.dumps(result, indent=2, ensure_ascii=False))
    
    return result


if __name__ == "__main__":
    try:
        result = test_mitm_login_response_decryption()
        print("\n🎉 MITM login response decryption test passed!")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
