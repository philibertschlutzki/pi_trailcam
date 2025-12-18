# TrailCam Go - Reverse Engineering Setup

Dieses Verzeichnis enthält die gepatchten APKs und Frida-Skripte, um die Bluetooth-Kommunikation der TrailCam Go App (v2.5) zu analysieren.

## Voraussetzungen
* Gerät mit Android 10/11 (Getestet auf Samsung A40, arm64)
* `adb` installiert
* `frida-tools` installiert (`pip install frida-tools`)

## Dateien
* `patched/`: Enthält die mit Frida-Gadget gepatchten und neu signierten APKs (v1+v2+v3 Scheme).
* `keystore/`: Der Schlüssel zum Signieren (`trailcam_sign.jks`). Passwort: `password` (oder was du gewählt hast).
* `scripts/hook.js`: Das finale Skript für Bluetooth (Java) und UDP (Native) Sniffing.

## Installation (Wichtig!)

Da es sich um eine Split-APK handelt und Samsung strenge Prüfungen hat, muss die Installation exakt so erfolgen:

1.  **Vorbereitung am Handy:**
    * Play Protect: **AUS**
    * Entwickleroptionen -> "Apps über USB überprüfen": **AUS** (Zwingend!)

2.  **Alte Version entfernen:**
    ```bash
    adb uninstall com.xlink.trailcamgo
    ```

3.  **Installation (Laptop):**
    Wir nutzen den "Push & Install"-Trick um USB-Verifizierung zu umgehen:

    ```bash
    # 1. Dateien aufs Handy schieben
    adb push patched/fixed-base.apk /data/local/tmp/base.apk
    adb push patched/fixed-config.apk /data/local/tmp/config.apk

    # 2. Session-Installation via Shell
    adb shell pm install-create -t -r --user 0 && \
    session_id=$(adb shell pm list sessions | grep com.xlink.trailcamgo | tail -1 | cut -d: -f2 | cut -d] -f1) && \
    echo "Installiere Session: $session_id" && \
    adb shell pm install-write $session_id base.apk /data/local/tmp/base.apk && \
    adb shell pm install-write $session_id config.apk /data/local/tmp/config.apk && \
    adb shell pm install-commit $session_id
    ```

## Anwendung starten (Sniffer)

Dieser Befehl startet die App automatisch und lädt das Frida-Skript:

```bash
adb shell monkey -p com.xlink.trailcamgo -c android.intent.category.LAUNCHER 1 && \
sleep 2 && \
frida -U -N com.xlink.trailcamgo -l scripts/hook.js
