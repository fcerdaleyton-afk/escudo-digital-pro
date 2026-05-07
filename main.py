from fastapi import FastAPI
import uvicorn
import os

# Creamos la aplicación
app = FastAPI()

# Ruta principal para verificar que funciona
@app.get("/")
async def root():
    return {
        "mensaje": "Escudo Digital Pro activo",
        "estado": "Funcionando correctamente en Fly.io"
    }

# Ruta de salud para que Fly.io sepa que la app está viva
@app.get("/health")
async def health():
    return {"status": "ok"}

# Bloque de arranque obligatorio para producción
if __name__ == "__main__":
    # Fly.io asigna un puerto dinámico, lo leemos de aquí:
    port = int(os.environ.get("PORT", 8080))
    # '0.0.0.0' permite que el tráfico externo entre a la app
    uvicorn.run(app, host="0.0.0.0", port=port)
