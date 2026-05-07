from fastapi import FastAPI

app = FastAPI()

@app.get("/")
async def root():
    return {"mensaje": "Escudo Digital Pro activo"}

@app.get("/health")
async def health():
    return {"status": "ok"}