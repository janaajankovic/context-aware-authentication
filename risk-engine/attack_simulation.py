import requests
import time
import csv
import random
from datetime import datetime

# --- KONFIGURACIJA METE ---
URL = "http://localhost:8080/api/auth/login"
USERNAME = "testuser"
CORRECT_PASSWORD = "master2026"
CSV_FILENAME = "rezultati_simulacije_master.csv"

# --- PODACI ZA SIMULACIJU ---
stolen_passwords = ["123456", "password", "admin", "test", "qwerty", CORRECT_PASSWORD]

# Lažne IP adrese koje asociraju na pretnje (poklapaju se sa našom crnom listom)
malicious_ips = ["104.21.34.4", "198.51.100.14", "8.8.8.8", "203.0.113.50"]
legit_ips = ["127.0.0.1", "localhost"]

legit_user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
malicious_user_agent = "python-requests/bot-script-v2.1"

def print_banner():
    print("======================================================")
    print("   RISK-BASED AUTHENTICATION - ATTACK SIMULATION      ")
    print("======================================================")
    print(f"[*] Target: {URL}")
    print(f"[*] User: {USERNAME}")
    print(f"[*] Izveštaj se čuva u: {CSV_FILENAME}")
    print("======================================================\n")

def send_request(req_id, is_legit=False):
    """Šalje jedan HTTP zahtev i vraća podatke za CSV."""
    
    # Priprema podataka zavisno od toga da li je zahtev legitiman ili napad
    if is_legit:
        ip = random.choice(legit_ips)
        pwd = CORRECT_PASSWORD
        ua = legit_user_agent
        req_type = "LEGITIMAN"
    else:
        ip = random.choice(malicious_ips)
        pwd = random.choice(stolen_passwords)
        ua = malicious_user_agent
        req_type = "NAPAD"

    headers = {
        "User-Agent": ua,
        "Content-Type": "application/json",
        "X-Forwarded-For": ip  # Simuliramo IP adresu iz koje zahtev dolazi
    }
    payload = {"username": USERNAME, "password": pwd}

    # Merenje latencije i slanje zahteva
    start_time = time.time()
    try:
        response = requests.post(URL, json=payload, headers=headers, timeout=5)
        latency = round((time.time() - start_time) * 1000)
        status = response.status_code
        
        # Interpretacija odgovora prema novoj Spring Boot arhitekturi
        if status == 200:
            outcome = "USPEH (Ulogovan - Nizak rizik)" if is_legit else "KRITIČNO (Sistem probijen!)"
        elif status == 202:
            outcome = "MFA ZAHTEVAN (Visok rizik)"
        elif status == 401:
            outcome = "ODBIJENO (Pogrešna lozinka)"
        elif status == 429:
            outcome = "BLOKIRANO (Redis Rate Limit)"
        else:
            outcome = f"NEPOZNATO ({status})"
            
    except Exception as e:
        latency = 0
        status = 000
        outcome = "GREŠKA U KONEKCIJI"

    # Prikaz u konzoli
    color_prefix = "[+]" if is_legit else "[-]"
    print(f"{color_prefix} #{req_id:03d} | Tip: {req_type: <9} | IP: {ip: <15} | Kod: {status} | Latencija: {latency}ms | Ishod: {outcome}")

    # Vraćamo red za CSV
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    return [req_id, timestamp, req_type, ip, pwd, status, outcome, latency]

def run_simulation():
    print_banner()
    
    with open(CSV_FILENAME, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        # Zaglavlje tabele
        writer.writerow(["ID_Zahteva", "Vreme", "Tip_Saobracaja", "Simulirana_IP", "Pokusana_Lozinka", "HTTP_Status", "Rezultat", "Latencija_ms"])

        # 1. Faza: Legitimni korisnici (Uspostavljanje normalnog stanja)
        print("--- [FAZA 1: Generisanje legitimnog saobraćaja] ---")
        for i in range(1, 6):
            csv_row = send_request(i, is_legit=True)
            writer.writerow(csv_row)
            time.sleep(0.5)

        # 2. Faza: Credential Stuffing (Hakerski napad)
        print("\n--- [FAZA 2: Distribuirani Credential Stuffing Napad] ---")
        for i in range(6, 106): # 100 hakerskih pokušaja
            csv_row = send_request(i, is_legit=False)
            writer.writerow(csv_row)
            time.sleep(0.1) # Brz rafalni napad

        # 3. Faza: Provera dostupnosti (Da li sistem i dalje radi za prave ljude)
        print("\n--- [FAZA 3: Post-napad legitimna provera] ---")
        for i in range(106, 111):
            csv_row = send_request(i, is_legit=True)
            writer.writerow(csv_row)
            time.sleep(0.5)

    print(f"\n[*] Simulacija je završena. Podaci su eksportovani u '{CSV_FILENAME}'.")

if __name__ == "__main__":
    run_simulation()