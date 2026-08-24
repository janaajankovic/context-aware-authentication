from fastapi import FastAPI
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

    # Pravilo 3: Lokacija / IP (Ovo ćemo proširiti kasnije kada dodamo bazu prethodnih prijava)
    # risk_score += 0.5 ako je IP adresa iz rizične zemlje ili potpuno nova za korisnika

    # Ograničavamo maksimalan rizik na 1.0 (100%)
    risk_score = min(risk_score, 1.0)

    # Policy Engine: Ako je rizik veći od 0.6, zahtevamo MFA
    requires_mfa = risk_score >= 0.6

    return {
        "risk_score": round(risk_score, 2),
        "reasons": reasons,
        "requires_mfa": requires_mfa
    }