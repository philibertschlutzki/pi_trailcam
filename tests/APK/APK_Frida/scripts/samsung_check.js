/* SAMSUNG A40 MASTER HOOK
   - Kombiniert Java (Bluetooth) und Native (Netzwerk)
   - Filtert automatisch System-Rauschen
*/

function log(type, data, info) {
    console.log("\n╔" + "=".repeat(60) + "╗");
    console.log("║ " + type.padEnd(58) + " ║");
    console.log("╠" + "=".repeat(60) + "╣");
    if (info) console.log("║ " + info);
    console.log("╚" + "=".repeat(60) + "╝");
    try {
        console.log(hexdump(data, { offset: 0, length: data.length, header: false, ansi: true }));
    } catch (e) {}
}

Java.perform(function() {
    console.log("[*] Installiere Java Bluetooth Hooks (Samsung Mode)...");

    // 1. BLUETOOTH BEFEHLE (Java - sehr sauber)
    try {
        var BTChar = Java.use("android.bluetooth.BluetoothGattCharacteristic");
        
        // Senden (setValue wird aufgerufen, bevor writeCharacteristic passiert)
        BTChar.setValue.overload('[B').implementation = function(val) {
            log("BT SEND (Java)", this.getValue(), "UUID: " + this.getUuid().toString());
            return this.setValue(val);
        };

        // Empfangen (Wenn die App Daten liest)
        BTChar.getValue.implementation = function() {
            var val = this.getValue();
            if (val && val.length > 0) {
                log("BT RECV (Java)", val, "UUID: " + this.getUuid().toString());
            }
            return val;
        };
    } catch(e) {
        console.log("[-] Java Bluetooth Hook Fehler: " + e);
    }
});

// 2. NATIVE FILTER (Fallback & Netzwerk)
var writePtr = Module.findExportByName("libc.so", "write");
var sendtoPtr = Module.findExportByName("libc.so", "sendto");

if (writePtr) {
    Interceptor.attach(writePtr, {
        onEnter: function(args) {
            var len = args[2].toInt32();
            if (len > 10 && len < 1000) {
                var buf = args[1];
                // FILTER: Wir ignorieren das 8-Byte Rauschen und Android-Tracing ("B|...")
                try {
                    var head = buf.readUtf8String(Math.min(len, 5));
                    if (head.indexOf("|") === -1) { 
                        // Wir loggen write nur, wenn es KEIN Bluetooth ist (da wir BT schon über Java haben)
                        // Das hier fängt oft interne Kommunikation zur Kamera-Engine ab
                        // log("SYS WRITE", buf.readByteArray(len), "Len: " + len); 
                    }
                } catch(e) {}
            }
        }
    });
}

if (sendtoPtr) {
    Interceptor.attach(sendtoPtr, {
        onEnter: function(args) {
            var len = args[2].toInt32();
            if (len > 8) {
                log("UDP SEND (WLAN)", args[1].readByteArray(len), "Länge: " + len);
            }
        }
    });
}

console.log("[*] System bereit. Bitte Kamera verbinden!");
