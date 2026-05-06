from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI(
    title="Escudo Digital Pro",
    version="2.0"
)

@app.get("/")
async def home():
    return {
        "status": "online",
        "sistema": "Escudo Digital Pro"
    }

@app.get("/health")
async def health():
    return {
        "status": "ok"
    }

@app.get("/security")
async def security():
    return JSONResponse(
        status_code=403,
        content={"detail": "ACCESO DENEGADO POR SEGURIDAD"}
    )