import time
import psutil
import hashlib
import threading
import asyncio
import aiohttp
import tkinter as tk
from tkinter import ttk
import queue
from concurrent.futures import ThreadPoolExecutor
import os
import shutil
import sys


def add_to_startup():
    # Pfad zum Autostart-Ordner des aktuellen Benutzers
    startup_dir = os.path.join(os.environ['APPDATA'], r'Microsoft\Windows\Start Menu\Programs\Startup')
    # Pfad zu Ihrem aktuellen Skript
    script_path = os.path.realpath(sys.argv[0])
    # Zielpfad im Autostart-Ordner
    dest_path = os.path.join(startup_dir, os.path.basename(script_path))

    # Überprüfen, ob das Skript bereits im Autostart-Ordner vorhanden ist
    if not os.path.exists(dest_path):
        try:
            shutil.copy(script_path, dest_path)
            print(f"Das Skript wurde dem Autostart hinzugefügt: {dest_path}")
        except Exception as e:
            print(f"Fehler beim Kopieren des Skripts in den Autostart-Ordner: {e}")
    else:
        print("Das Skript befindet sich bereits im Autostart-Ordner.")


# Funktion aufrufen
add_to_startup()

# Globaler API-Cache (TTL: 5 Minuten)
api_cache = {}  # {file_hash: (result, timestamp)}
CACHE_TTL = 300

# Starte einen eigenen asyncio-Loop in einem Hintergrundthread
async_loop = asyncio.new_event_loop()

def start_loop(loop):
    asyncio.set_event_loop(loop)
    loop.run_forever()

loop_thread = threading.Thread(target=start_loop, args=(async_loop,), daemon=True)
loop_thread.start()

async def create_session():
    return aiohttp.ClientSession()

session_future = asyncio.run_coroutine_threadsafe(create_session(), async_loop)
global_session = session_future.result()

# Asynchrone Funktion zur Abfrage der Malware-API
async def async_check_malware(file_hash):
    current_time = time.time()
    if file_hash in api_cache and current_time - api_cache[file_hash][1] < CACHE_TTL:
        return api_cache[file_hash][0]
    url = "https://mb-api.abuse.ch/api/v1/"
    payload = {"query": "get_info", "hash": file_hash}
    try:
        async with global_session.post(url, data=payload, timeout=3) as response:
            if response.status == 200:
                result = await response.json()
                api_cache[file_hash] = (result, current_time)
                return result
            else:
                print(f"API-Fehler, Statuscode: {response.status}")
                return None
    except Exception as e:
        print(f"Fehler beim API-Request: {e}")
        return None

# Funktion zur Berechnung des SHA256-Hashes einer Datei
def compute_file_hash(filepath):
    try:
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            sha256.update(f.read())
        return sha256.hexdigest()
    except Exception as e:
        print(f"Fehler beim Hashen von {filepath}: {e}")
        return None

hash_executor = ThreadPoolExecutor(max_workers=6)

def compute_file_hash_async(filepath):
    return hash_executor.submit(compute_file_hash, filepath)

# --- GUI-Bereich (alle Tkinter-Operationen im Main-Thread) ---

# Erstelle eine globale Tk-Instanz und eine Queue für GUI-Aufgaben
root = tk.Tk()
root.withdraw()  # Hauptfenster ausblenden
gui_queue = queue.Queue()

def process_gui_queue():
    try:
        while True:
            task = gui_queue.get_nowait()
            task()  # führe die übergebene Funktion aus
    except queue.Empty:
        pass
    root.after(100, process_gui_queue)

root.after(100, process_gui_queue)

def show_start_notification():
    notif = tk.Toplevel(root)
    notif.title("deldown Antivirus")
    notif.geometry("350x100")
    notif.configure(bg="#2b2b2b")
    notif.overrideredirect(True)
    notif.attributes("-topmost", True)

    # Positionierung unten rechts (10px Abstand)
    screen_width = notif.winfo_screenwidth()
    screen_height = notif.winfo_screenheight()
    x_position = screen_width - 360
    y_position = screen_height - 110
    notif.geometry(f"350x100+{x_position}+{y_position}")

    frame = tk.Frame(notif, bg="#2b2b2b", padx=10, pady=10)
    frame.pack(fill=tk.BOTH, expand=True)
    message = "deldown Antivirus läuft jetzt im Hintergrund. Sie sind geschützt."
    label = tk.Label(frame, text=message, fg="white", bg="#2b2b2b", font=("Arial", 10))
    label.pack()
    # Automatisches Schließen nach 5 Sekunden
    notif.after(5000, notif.destroy)

def show_alert_window_gui(file_path, result_queue):
    window = tk.Toplevel(root)
    window.title("deldown Antivirus")
    window.geometry("350x150")
    window.configure(bg="#2b2b2b")
    window.overrideredirect(True)
    window.attributes("-topmost", True)

    # Positionierung unten rechts (10px Abstand)
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x_position = screen_width - 360
    y_position = screen_height - 160
    window.geometry(f"350x150+{x_position}+{y_position}")

    frame = tk.Frame(window, bg="#2b2b2b", padx=15, pady=15)
    frame.pack(fill=tk.BOTH, expand=True)

    message_label = tk.Label(frame, text="Bedrohung erkannt!", fg="#ff5555", bg="#2b2b2b", font=("Arial", 12, "bold"))
    message_label.pack(anchor="w")

    file_label = tk.Label(frame, text=f"Schädliche Datei: {file_path}", fg="white", bg="#2b2b2b", font=("Arial", 10))
    file_label.pack(anchor="w", pady=(5, 10))

    button_frame = tk.Frame(frame, bg="#2b2b2b")
    button_frame.pack(fill=tk.X)

    style = ttk.Style()
    style.configure("TButton", font=("Arial", 10), padding=5)

    def on_delete():
        result_queue.put("delete")
        window.destroy()

    def on_ignore():
        result_queue.put("ignore")
        window.destroy()

    def on_details():
        result_queue.put("details")
        window.destroy()

    btn_delete = ttk.Button(button_frame, text="Datei löschen", command=on_delete, style="TButton")
    btn_delete.pack(side=tk.LEFT, expand=True, padx=5)
    btn_ignore = ttk.Button(button_frame, text="Ignorieren", command=on_ignore, style="TButton")
    btn_ignore.pack(side=tk.LEFT, expand=True, padx=5)
    btn_details = ttk.Button(button_frame, text="Details", command=on_details, style="TButton")
    btn_details.pack(side=tk.LEFT, expand=True, padx=5)

    # Warten, bis das Fenster geschlossen wird
    window.wait_window()

# --- Prozessüberwachung ---

seen_pids = set()

def process_new_process(proc_info):
    pid = proc_info.get('pid')
    name = proc_info.get('name')
    exe_path = proc_info.get('exe')
    if not exe_path:
        return
    print(f"Neuer Prozess: {name} (PID={pid})")

    # Asynchrone Hash-Berechnung
    future = compute_file_hash_async(exe_path)
    try:
        file_hash = future.result(timeout=3)
    except Exception as e:
        print(f"Fehler beim Hashen von {exe_path}: {e}")
        return
    if not file_hash:
        return
    print(f"Prozess {name} (PID={pid}): Hash = {file_hash}")

    # Asynchroner API-Check
    future_api = asyncio.run_coroutine_threadsafe(async_check_malware(file_hash), async_loop)
    try:
        result_api = future_api.result(timeout=3)
    except Exception as e:
        print(f"Fehler beim API-Check: {e}")
        return

    if result_api and result_api.get("query_status", "") != "hash_not_found":
        print(f"{exe_path} wurde als Bedrohung erkannt!")
        # Erhalte die Benutzerentscheidung über den GUI-Thread
        result_queue = queue.Queue()
        gui_queue.put(lambda: show_alert_window_gui(exe_path, result_queue))
        try:
            user_choice = result_queue.get(timeout=30)  # Warte bis zu 30 Sekunden
        except queue.Empty:
            user_choice = "ignore"
        if user_choice == "delete":
            try:
                proc = psutil.Process(pid)
                proc.terminate()  # Prozess freundlich beenden
                try:
                    proc.wait(timeout=2)
                except psutil.TimeoutExpired:
                    proc.kill()  # Notfall: sofort beenden
                print(f"{exe_path} wurde beendet.")
            except Exception as e:
                print(f"Fehler beim Beenden von {exe_path}: {e}")
        elif user_choice == "ignore":
            print(f"Bedrohung für {exe_path} ignoriert.")
        elif user_choice == "details":
            print(f"API-Details für {exe_path}: {result_api}")
    else:
        print(f"Prozess {name} (PID={pid}) ist sicher.")

def monitor_processes():
    global seen_pids
    while True:
        try:
            new_procs = [proc.info for proc in psutil.process_iter(['pid', 'name', 'exe'])
                         if proc.info['pid'] not in seen_pids]
            for proc in new_procs:
                seen_pids.add(proc['pid'])
            with ThreadPoolExecutor(max_workers=8) as executor:
                executor.map(process_new_process, new_procs)
            time.sleep(1)
        except Exception as e:
            print(f"Fehler in der Prozessüberwachung: {e}")

# --- Hauptprogramm ---

def main():
    show_start_notification()
    monitor_thread = threading.Thread(target=monitor_processes, daemon=True)
    monitor_thread.start()
    root.mainloop()

if __name__ == "__main__":
    main()
