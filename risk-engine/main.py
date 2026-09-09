from fastapi import FastAPI
import psycopg2
from pydantic import BaseModel
from typing import List
import math
from datetime import datetime
import requests

app = FastAPI(title="Context-Aware Risk Engine")

class LoginContext(BaseModel):
    user_id: int
    ip_address: str
    user_agent: str
    login_time: str
    
class RiskResponse(BaseModel):
    risk_score: float
    reasons: List[str]
    requires_mfa: bool
    country: str
    city: str
    latitude: float
    longitude: float

DB_CONFIG = {
    "dbname": "risk_auth_db",
    "user": "admin",
    "password": "admin_password",
    "host": "localhost",
    "port": "5433"
}

KNOWN_THREAT_IPS = {
    "104.21.34.4": "Poznat VPN izlazni čvor",
    "198.51.100.14": "Tor Exit Node",
    "8.8.8.8": "Data Center (Bot mrežni opseg)",
    "203.0.113.50": "Prijavljena Spam/Malware aktivnost"
}

def check_ip_reputation(ip_address: str) -> str:
    return KNOWN_THREAT_IPS.get(ip_address, None)

def get_location_data_from_ip(ip_address: str):
    if ip_address in ["127.0.0.1", "localhost", "0:0:0:0:0:0:0:1"]:
        return {"country": "Serbia", "city": "Novi Sad", "lat": 45.2517, "lon": 19.8369} 
        
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=status,country,city,lat,lon", timeout=3)
        data = response.json()
        if data.get("status") == "success":
            return {
                "country": data.get("country"),
                "city": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon")
            }
    except Exception:
        pass
    return {"country": "Unknown", "city": "Unknown", "lat": None, "lon": None}

def get_last_successful_login(user_id: int):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("""
            SELECT login_timestamp, latitude, longitude 
            FROM device_contexts 
            WHERE user_id = %s AND is_successful = true
            ORDER BY login_timestamp DESC 
            LIMIT 1
        """, (user_id,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        
        if row:
            return {
                "timestamp": row[0],
                "lat": row[1],
                "lon": row[2]
            }
        return None
    except Exception as e:
        print(f"[DB ERROR] Greška pri povlačenju poslednje prijave: {e}")
        return None

def is_known_device_or_ip(user_id: int, current_ip: str) -> bool:
    if current_ip in ["127.0.0.1", "localhost", "0:0:0:0:0:0:0:1"]:
        return True

    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("SELECT username FROM app_users WHERE id = %s", (user_id,))
        user_row = cur.fetchone()
        
        if not user_row:
            return False
        
        username = user_row[0]
        cur.execute("""
            SELECT count(*) FROM login_history 
            WHERE username = %s AND ip_address = %s AND status LIKE 'SUCCESS%%'
        """, (username, current_ip))
        
        row = cur.fetchone()
        count = row[0] if row else 0
        cur.close()
        conn.close()
        return count > 0
    except Exception as e:
        print(f"[DB ERROR] Greška pri radu sa bazom: {e}")
        return True
    
def calculate_distance(lat1, lon1, lat2, lon2):
    R = 6371.0 
    lat1_rad = math.radians(lat1)
    lon1_rad = math.radians(lon1)
    lat2_rad = math.radians(lat2)
    lon2_rad = math.radians(lon2)
    dlon = lon2_rad - lon1_rad
    dlat = lat2_rad - lat1_rad
    a = math.sin(dlat / 2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c

@app.post("/api/analyze-risk", response_model=RiskResponse)
def analyze_risk(context: LoginContext):
    risk_score = 0.0
    reasons = []

    print("\n" + "="*80)
    print(f"[*] [RISK ENGINE] POČETAK EVALUACIJE KONTEKSTA ZA KORISNIKA ID: {context.user_id}")
    print(f"[*] Ulazni parametri -> IP: {context.ip_address} | Vrijeme: {context.login_time}")
    print(f"[*] User-Agent: {context.user_agent}")
    print("-"*80)

    # --- PRAVILO 1: Sumnjivi HTTP klijenti ---
    user_agent_lower = context.user_agent.lower()
    if "curl" in user_agent_lower or "postman" in user_agent_lower or "python-requests" in user_agent_lower:
        risk_score += 0.7
        reasons.append("Sumnjiv User-Agent (API alat/skripta)")
        print("[+] [Pravilo 1 - User-Agent]: AKTIVIRANO -> Detektovan API alat/skripta (+0.7)")
    else:
        print("[-] [Pravilo 1 - User-Agent]: NEAKTIVIRANO -> Klijent je standardni web pretraživač.")

    # --- PRAVILO 2: Sumnjivo vrijeme prijave ---
    try:
        hour = int(context.login_time.split(":")[0])
        if 2 <= hour <= 5:
            risk_score += 0.3
            reasons.append("Prijava u noćnim satima (02:00 - 05:00)")
            print(f"[+] [Pravilo 2 - Vrijeme prijave]: AKTIVIRANO -> Noćna aktivnost u {context.login_time} (+0.3)")
        else:
            print(f"[-] [Pravilo 2 - Vrijeme prijave]: NEAKTIVIRANO -> Vrijeme prijave ({context.login_time}) je uobičajeno.")
    except Exception:
        print("[-] [Pravilo 2 - Vrijeme prijave]: PRESKOČENO (greška u parsiranju vremena).")

    # --- PRAVILO 3: Geolokacija ---
    loc_data = get_location_data_from_ip(context.ip_address)
    country = loc_data["country"]
    current_lat = loc_data["lat"]
    current_lon = loc_data["lon"]

    print(f"[*] [Geolokacija API]: Utvrđena lokacija -> {loc_data.get('city', 'Unknown')}, {country} (Lat: {current_lat}, Lon: {current_lon})")

    if country not in ["Serbia", "Localhost", "Unknown"]:
        risk_score += 0.3
        reasons.append(f"Neočekivana država ({country})")
        print(f"[+] [Pravilo 3 - Geolokacija]: AKTIVIRANO -> Prijava iz neočekivane države [{country}] (+0.3)")
    else:
        print(f"[-] [Pravilo 3 - Geolokacija]: NEAKTIVIRANO -> Država [{country}] je u očekivanom opsegu.")

    # --- PRAVILO 4: Istorija (Nepoznata IP adresa) ---
    if not is_known_device_or_ip(context.user_id, context.ip_address):
        risk_score += 0.4
        reasons.append("Nepoznata IP adresa za ovog korisnika")
        print("[+] [Pravilo 4 - Istorija uređaja]: AKTIVIRANO -> Korisnik se nikad ranije nije prijavio sa ove IP (+0.4)")
    else:
        print("[-] [Pravilo 4 - Istorija uređaja]: NEAKTIVIRANO -> IP adresa je već poznata u bazi za ovog korisnika.")

    # --- PRAVILO 5: IP Reputacija ---
    threat_reason = check_ip_reputation(context.ip_address)
    if threat_reason:
        risk_score += 0.5
        reasons.append(f"IP na crnoj listi ({threat_reason})")
        print(f"[+] [Pravilo 5 - IP Reputacija]: AKTIVIRANO -> Adresa je na crnoj listi [{threat_reason}] (+0.5)")
    else:
        print("[-] [Pravilo 5 - IP Reputacija]: NEAKTIVIRANO -> IP adresa nije pronađena na Threat Intelligence crnim listama.")

    # --- PRAVILO 6: Impossible Travel ---
    last_login = get_last_successful_login(context.user_id)
    if last_login and last_login["lat"] and last_login["lon"]:
        prethodni_lat = last_login["lat"]
        prethodni_lon = last_login["lon"]
        prethodno_vreme = last_login["timestamp"]
        trenutno_vreme = datetime.now()
        
        vremenska_razlika_sekunde = abs((trenutno_vreme - prethodno_vreme).total_seconds())
        vremenska_razlika_sati = vremenska_razlika_sekunde / 3600.0
        
        if vremenska_razlika_sati > 0:
            distance = calculate_distance(prethodni_lat, prethodni_lon, current_lat, current_lon)
            speed = distance / vremenska_razlika_sati
            print(f"[*] [Impossible Travel Analiza]: Rastojanje od prethodne prijave: {round(distance, 2)} km | Proteklo vremena: {round(vremenska_razlika_sati, 3)}h | Izračunata brzina: {round(speed)} km/h")
            
            if speed > 1000:  
                risk_score += 0.8
                reasons.append(f"Impossible Travel ({round(speed)} km/h)")
                print(f"[+] [Pravilo 6 - Impossible Travel]: AKTIVIRANO -> Fizički nemoguća brzina kretanja (>1000 km/h) (+0.8)")
            else:
                print(f"[-] [Pravilo 6 - Impossible Travel]: NEAKTIVIRANO -> Brzina kretanja je fizički moguća.")
        else:
            print("[-] [Pravilo 6 - Impossible Travel]: PRESKOČENO (vremenska razlika je 0).")
    else:
        print("[-] [Pravilo 6 - Impossible Travel]: NEAKTIVIRANO -> Nema prethodnih uspješnih prijava sa koordinatama u bazi.")

    # Ograničavamo maksimalan rizik na 1.0 (100%)
    risk_score = min(risk_score, 1.0)
    requires_mfa = risk_score >= 0.6

    print("-"*80)
    print(f"[REZULTAT EVALUACIJE] KONAČNI SKOR RIZIKA: {round(risk_score, 2)}")
    print(f"[REZULTAT EVALUACIJE] AKTIVIRANI RAZLOZI: {reasons if reasons else ['Nema rizika']}")
    print(f"[POLICY ENGINE] Odluka -> Zahtijeva se MFA verifikacija: {requires_mfa}")
    print("="*80 + "\n")

    return {
        "risk_score": round(risk_score, 2),
        "reasons": reasons,
        "requires_mfa": requires_mfa,
        "country": country,
        "city": loc_data.get("city", "Unknown"),
        "latitude": current_lat,
        "longitude": current_lon
    }