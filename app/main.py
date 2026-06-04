from dotenv import load_dotenv
load_dotenv()  # loads .env from project root before anything else

from fastapi import FastAPI
from app.routers import scan, repo

app = FastAPI(title="VibeSec", version="1.0.0")

app.include_router(scan.router, prefix="/api/v1")
app.include_router(repo.router, prefix="/api/v1")

@app.get("/")
async def root():
    return {"status": "VibeSec running"}