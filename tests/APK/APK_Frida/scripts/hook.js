/* BULLETPROOF BLUETOOTH SNIFFER (Pure Java)
   Kein Native-Code -> Keine Abstürze.
   Fängt Scan, Verbindung und Daten ab.
*/

console.log("\n╔════════════════════════════════════════════════════╗");
console.log("║ BLUETOOTH SNIFFER AKTIV (SAFE MODE)                ║");
console.log("║ Warte auf 'Verbinden' am Handy...                  ║");
console.log("╚════════════════════════════════════════════════════╝");

Java.perform(function() {
    
    // Hilfsfunktion für Hex-Ausgabe
    function toHex(bytes) {
        if (!bytes) return "null";
        var res = [];
        for (var i = 0; i < bytes.length; i++) {
            res.push(('0' + (bytes[i] & 0xFF).toString(16)).slice(-2));
        }
        return res.join("").toUpperCase();
    }

    try {
        // 1. SCAN ERKENNUNG
        var LeScanner = Java.use("android.bluetooth.le.BluetoothLeScanner");
        var scanMethods = LeScanner.class.getDeclaredMethods();
        scanMethods.forEach(function(m) {
            if (m.getName() === "startScan") {
                m.setAccessible(true);
                LeScanner.startScan.overload('java.util.List', 'android.bluetooth.le.ScanSettings', 'android.bluetooth.le.ScanCallback').implementation = function(filters, settings, callback) {
                    console.log("\n[+] BLE SCAN GESTARTET (Suche nach Kamera...)");
                    return this.startScan(filters, settings, callback);
                };
            }
        });

        // 2. VERBINDUNG ERKENNUNG
        var BluetoothDevice = Java.use("android.bluetooth.BluetoothDevice");
        BluetoothDevice.connectGatt.overload('android.content.Context', 'boolean', 'android.bluetooth.BluetoothGattCallback').implementation = function(ctx, auto, cb) {
            console.log("\n[+] VERBINDUNGSVERSUCH zu: " + this.getName() + " [" + this.getAddress() + "]");
            return this.connectGatt(ctx, auto, cb);
        };

        // 3. DATEN ABFANGEN (SENDEN & EMPFANGEN)
        var BluetoothGattCharacteristic = Java.use("android.bluetooth.BluetoothGattCharacteristic");

        // App sendet an Kamera
        BluetoothGattCharacteristic.setValue.overload('[B').implementation = function(val) {
            var uuid = "UNKNOWN";
            try { uuid = this.getUuid().toString(); } catch(e) {}
            
            // Filter: Ignoriere Standard-Services (00002902 ist meist Notification Descriptor)
            if (uuid.indexOf("00002902") === -1) { 
                console.log("\n>>> BT SEND (App -> Cam) | UUID End: " + uuid.substring(4, 8));
                console.log("    HEX: " + toHex(val));
            }
            return this.setValue(val);
        };

        // Kamera antwortet
        BluetoothGattCharacteristic.getValue.implementation = function() {
            var val = this.getValue();
            if (val && val.length > 0) {
                var uuid = "UNKNOWN";
                try { uuid = this.getUuid().toString(); } catch(e) {}
                
                if (uuid.indexOf("00002902") === -1) {
                    console.log("\n<<< BT RECV (Cam -> App) | UUID End: " + uuid.substring(4, 8));
                    console.log("    HEX: " + toHex(val));
                }
            }
            return val;
        };

    } catch(e) {
        console.log("[!] Fehler: " + e.message);
    }
});
