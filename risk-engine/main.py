from fastapi import FastAPI
import psycopg2
from pydantic import BaseModel
from typing import List

app = FastAPI(title="Context-Aware Risk Engine")

# Definišemo kako izgleda JSON koji očekujemo od Spring Boot-a
class LoginContext(BaseModel):
    user_id: int
    ip_address: str
    user_agent: str
    login_time: str # Format: "HH:MM:SS"
    
class RiskResponse(BaseModel):
    risk_score: float
    reasons: List[str]
    requires_mfa: bool

# Konfiguracija za tvoju bazu
DB_CONFIG = {
    "dbname": "risk_auth_db",
    "user": "admin",
    "password": "admin_password",
    "host": "localhost",
    "port": "5433"
}

def get_country_from_ip(ip_address: str) -> str:
    """Proverava iz koje države dolazi IP adresa koristeći besplatan API."""
    # Lokalni IP (kada ti testiraš sa svog računara)
    if ip_address in ["127.0.0.1", "localhost", "0:0:0:0:0:0:0:1"]:
        return "Localhost"
        
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=status,country", timeout=3)
        data = response.json()
        if data.get("status") == "success":
            return data.get("country")
    except Exception:
        pass
    return "Unknown"

def is_known_device_or_ip(user_id: int, current_ip: str) -> bool:
    """Proverava u bazi da li se ovaj korisnik ikada ranije uspešno prijavio sa ove IP adrese."""
    if current_ip in ["127.0.0.1", "localhost", "0:0:0:0:0:0:0:1"]:
        return True # Lokalno testiranje uvek smatramo poznatim

    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        
        # Prvo nalazimo username preko user_id
        cur.execute("SELECT username FROM app_users WHERE id = %s", (user_id,))
        user_row = cur.fetchone()
        
        if not user_row:
            return False
        
        username = user_row[0]
        
        # Zatim brojimo uspešne prijave sa ovom IP adresom za tog korisnika
        cur.execute("""
            SELECT count(*) FROM login_history 
            WHERE username = %s AND ip_address = %s AND status LIKE 'SUCCESS%'
        """, (username, current_ip))
        
        count = cur.fetchone()[0]
        
        cur.close()
        conn.close()
        
        return count > 0
    except Exception as e:
        print(f"Greška pri radu sa bazom: {e}")
        return True # Ako baza trenutno nije dostupna, ne kažnjavamo korisnika visokim rizikom
    
@app.post("/api/analyze-risk", response_model=RiskResponse)
def analyze_risk(context: LoginContext):
    risk_score = 0.0
    reasons = []

    # Pravilo 1: Sumnjivi HTTP klijenti (Skripte i botovi)
    user_agent_lower = context.user_agent.lower()
    if "curl" in user_agent_lower or "postman" in user_agent_lower or "python-requests" in user_agent_lower:
        risk_score += 0.4
        reasons.append("Sumnjiv User-Agent (Pokušaj prijave preko API alata/skripte umesto pregledača)")

    # Pravilo 2: Sumnjivo vreme prijave (npr. noću između 02:00 i 05:00)
    try:
        hour = int(context.login_time.split(":")[0])
        if 2 <= hour <= 5:
            risk_score += 0.3
            reasons.append("Prijava van uobičajenog radnog vremena (Noćna aktivnost)")
    except Exception:
        pass # Ignorisanje greške u parsiranju vremena za sada

    # Pravilo 3: Geolokacija
    country = get_country_from_ip(context.ip_address)
    if country not in ["Serbia", "Localhost", "Unknown"]:
        risk_score += 0.3
        reasons.append(f"Prijava iz neočekivane države ({country})")

    # Pravilo 4: Istorija (Prethodno ponašanje iz baze)
    if not is_known_device_or_ip(context.user_id, context.ip_address):
        risk_score += 0.4
        reasons.append("Prijava sa potpuno nove IP adrese (Nepoznat uređaj/lokacija za ovog korisnika)")
        
    # Ograničavamo maksimalan rizik na 1.0 (100%)
    risk_score = min(risk_score, 1.0)

    # Policy Engine: Ako je rizik veći od 0.6, zahtevamo MFA
    requires_mfa = risk_score >= 0.6

    return {
        "risk_score": round(risk_score, 2),
        "reasons": reasons,
        "requires_mfa": requires_mfa
    }