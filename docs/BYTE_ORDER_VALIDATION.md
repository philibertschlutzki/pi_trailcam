# docs/BYTE_ORDER_VALIDATION.md

## Test-Ergebnisse vom 10.12.2025

### Byte-Order Test
- **Big-Endian:** ✅ Response nach ~10ms (Localhost Sim)
- **Little-Endian:** ❌ Timeout nach 2s
- **Fazit:** BYTE_ORDER = 'BE' (Big-Endian)

### Inner Header Test
- **Outer-only:** ❌ Timeout
- **Outer+Inner:** ✅ Response
- **Fazit:** Inner Header ist ERFORDERLICH

### CmdType Test
- **F1 30 (iLnk):** ❌ Timeout
- **F1 D1 (PPPP):** ✅ Response
- **Fazit:** CMD-Type = 0xD1 für Discovery

## Implementierungs-Folgerungen
1. Byte-Order bleibt Big-Endian ('>H')
2. Alle Pakete müssen Inner Header haben
3. Discovery nutzt CMD-Type 0xD1, nicht 0x30
4. Dokumentation von Palant.info ist für dieses Gerät nicht zutreffend
