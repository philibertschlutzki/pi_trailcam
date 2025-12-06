import time
import logging
from modules.camera_client import CameraClient

# Logging aktivieren
logging.basicConfig(level=logging.INFO)

def scan_for_file_list():
    client = CameraClient()
    
    # 1. Login
    if not client.login():
        print("Login fehlgeschlagen!")
        return

    print("Login erfolgreich. Teste Befehle für Dateiliste...")
    
    # Die wahrscheinlichsten Kandidaten testen
    candidates = [513, 514, 515, 531]
    
    for cmd_id in candidates:
        print(f"--- Teste cmdId: {cmd_id} ---")
        # Oft brauchen diese Befehle Parameter wie "page": 0 oder "count": 10
        # Wir testen erst leer, dann mit Parametern
        payloads = [
            {"cmdId": cmd_id},
            {"cmdId": cmd_id, "page": 0, "count": 20},
            {"cmdId": cmd_id, "path": "/DCIM"}
        ]
        
        for p in payloads:
            response = client.send_command(p)
            print(f"Sende: {p}")
            if response:
                print(f"Antwort: {response}")
                # Prüfen ob es wie eine Dateiliste aussieht (enthält 'list', 'data' oder Dateinamen)
                if "list" in str(response).lower() or "jpg" in str(response).lower():
                    print(f"TREFFER! cmdId {cmd_id} scheint die Dateiliste zu sein!")
            else:
                print("Keine Antwort.")
            time.sleep(0.5)

    client.close()

if __name__ == "__main__":
    scan_for_file_list()
