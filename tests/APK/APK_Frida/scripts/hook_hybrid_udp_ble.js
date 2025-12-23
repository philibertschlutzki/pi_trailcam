/* ROBUST HYBRID SNIFFER (UDP + BLE)
   1. Native Hook für UDP (sendto/recvfrom) auf libc.so
   2. Java Hook für Bluetooth LE (Gatt)
*/

console.log("\n╔════════════════════════════════════════════════════╗");
console.log("║  HYBRID SNIFFER (UDP & BLUETOOTH LE)               ║");
console.log("╚════════════════════════════════════════════════════╝");

// =========================================================================
// TEIL 1: JAVA BLUETOOTH LE HOOKS
// =========================================================================

Java.perform(function() {
    try {
        var BluetoothGatt = Java.use("android.bluetooth.BluetoothGatt");
        var BluetoothGattCharacteristic = Java.use("android.bluetooth.BluetoothGattCharacteristic");

        // Helper: Java Byte-Array zu Hex-String
        function bytesToHex(bytes) {
            var hex = [];
            for (var i = 0; i < bytes.length; i++) {
                var b = bytes[i];
                if (b < 0) b += 256; // Signed Byte zu Unsigned
                var h = b.toString(16).toUpperCase();
                if (h.length === 1) h = "0" + h;
                hex.push(h);
            }
            return hex.join(" ");
        }

        // --- BLE TX (Senden: App -> Kamera) ---
        // Wir hooken writeCharacteristic, um zu sehen, was die App sendet
        BluetoothGatt.writeCharacteristic.overload('android.bluetooth.BluetoothGattCharacteristic').implementation = function(char) {
            var uuid = char.getUuid().toString();
            var val = char.getValue();
            
            console.log("\n🔵 [BLE TX] Write an UUID: " + uuid);
            console.log("    Data: " + bytesToHex(val));
            
            return this.writeCharacteristic(char);
        };
        
        // Neuere Android API (manchmal genutzt)
        try {
            BluetoothGatt.writeCharacteristic.overload('android.bluetooth.BluetoothGattCharacteristic', '[B', 'int').implementation = function(char, val, mode) {
                var uuid = char.getUuid().toString();
                console.log("\n🔵 [BLE TX] Write an UUID: " + uuid);
                console.log("    Data: " + bytesToHex(val));
                return this.writeCharacteristic(char, val, mode);
            };
        } catch(e) {}

        // --- BLE RX (Empfangen: Kamera -> App) ---
        // TRICK: Wir hooken setValue() in der Characteristic Klasse.
        // Das wird vom System aufgerufen, wenn eine Notification reinkommt,
        // um den lokalen Wert zu updaten.
        BluetoothGattCharacteristic.setValue.overload('[B').implementation = function(val) {
            var uuid = this.getUuid().toString();
            
            // Filter: Leere Updates ignorieren
            if (val.length > 0) {
                console.log("\n🔵 [BLE RX] Notification von UUID: " + uuid);
                console.log("    Data: " + bytesToHex(val));
            }
            return this.setValue(val);
        };

        console.log("[+] Java BLE Hooks installiert.");

    } catch (e) {
        console.log("[-] BLE Hooks fehlgeschlagen (App nutzt vielleicht kein Standard-BLE?): " + e);
    }
});

// =========================================================================
// TEIL 2: NATIVE UDP HOOKS (Dein Original-Code)
// =========================================================================

var sendtoPtr = null;
var recvfromPtr = null;

// Strategie 1: Modul-Instanz
try {
    var libc = Process.findModuleByName("libc.so");
    if (libc) {
        sendtoPtr = libc.findExportByName("sendto");
        recvfromPtr = libc.findExportByName("recvfrom");
    }
} catch (e) {}

// Strategie 2: DebugSymbol Fallback
if (!sendtoPtr) {
    try {
        sendtoPtr = DebugSymbol.getFunctionByName("sendto");
        recvfromPtr = DebugSymbol.getFunctionByName("recvfrom");
    } catch (e) {}
}

if (!sendtoPtr) {
    console.log("❌ KRITISCH: 'sendto' (UDP) nicht gefunden.");
} else {
    console.log("✅ 'sendto' (UDP) gefunden bei: " + sendtoPtr);
    startNativeHooks();
}

function hexLog(ptr, len) {
    try {
        console.log(hexdump(ptr, {
            offset: 0,
            length: len,
            header: false,
            ansi: false
        }));
    } catch(e) {}
}

function startNativeHooks() {
    // --- UDP SEND ---
    Interceptor.attach(sendtoPtr, {
        onEnter: function(args) {
            var fd = args[0].toInt32();
            var buf = args[1];
            var len = args[2].toInt32();

            // Filter: Magic Byte 0xF1 und Länge < 500 (Kein Video!)
            if (len > 5 && len < 500) {
                try {
                    var firstByte = buf.readU8();
                    if (firstByte === 0xF1) { 
                        console.log("\n⚡ [UDP TX] Sende (" + len + " bytes) FD:" + fd);
                        hexLog(buf, len);
                    }
                } catch (e) {}
            }
        }
    });

    // --- UDP RECV ---
    if (recvfromPtr) {
        Interceptor.attach(recvfromPtr, {
            onEnter: function(args) {
                this.buf = args[1];
            },
            onLeave: function(retval) {
                var len = retval.toInt32();
                if (len > 5 && len < 500) {
                    try {
                        var firstByte = this.buf.readU8();
                        if (firstByte === 0xF1) {
                            console.log("\n⚡ [UDP RX] Empfange (" + len + " bytes)");
                            hexLog(this.buf, len);
                        }
                    } catch (e) {}
                }
            }
        });
    }
    console.log("[*] Native UDP Hooks aktiv (Filter: 0xF1). Warte auf Traffic...");
}
