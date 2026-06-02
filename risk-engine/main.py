from fastapi import FastAPI

# Inicijalizacija aplikacije
app = FastAPI(
    title="Risk Engine API",
    description="Python backend za izračunavanje risk score-a (Master rad)"
)

# Endpoint za testiranje da li server radi
@app.get("/")
def health_check():
    return {"status": "success", "message": "Risk Engine radi uspešno!"}

# Ovde ćemo kasnije dodati endpoint za računanje rizika (npr. /calculate-risk)