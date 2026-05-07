from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.cors import CORSMiddleware

import re
import time
from datetime import datetime

app = FastAPI(
    title="Escudo Digital Pro v3",
    version="3.0"
)

# ==========================
# CONFIGURACIÓN SEGURA
# ==========================

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=[
        "escudo-digital-pro.onrender.com",
        "localhost",
        "127.0.0.1"
    ]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================
# MEMORIA TEMPORAL
# ==========================

ips_bloqueadas = {}
intentos = {}

# ==========================
# DETECTOR SIMPLE
# ==========================

def detectar_ataque(path, query, user_agent):

    patrones = [
        r"<script",
        r"union\s+select",
        r"\.\./",
        r"onerror=",
        r"drop\s+table"
    ]

    texto = f"{path} {query} {user_agent}".lower()

    for patron in patrones:
        if re.search(patron, texto):
            return True

    return False

# ==========================
# MIDDLEWARE SEGURIDAD
# ==========================

@app.middleware("http")
async def firewall(request: Request, call_next):

    inicio = time.time()

    ip = request.client.host
    path = request.url.path
    query = str(request.query_params)
    user_agent = request.headers.get("user-agent", "")

    # ======================
    # IP BLOQUEADA
    # ======================

    if ip in ips_bloqueadas:

        return JSONResponse(
            status_code=403,
            content={
                "error": "IP BLOQUEADA",
                "ip": ip,
                "timestamp": datetime.now().isoformat()
            }
        )

    # ======================
    # DETECCIÓN ATAQUE
    # ======================

    ataque = detectar_ataque(
        path,
        query,
        user_agent
    )

    if ataque:

        intentos[ip] = intentos.get(ip, 0) + 1

        if intentos[ip] >= 3:
            ips_bloqueadas[ip] = True

        return JSONResponse(
            status_code=403,
            content={
                "error": "ATAQUE DETECTADO",
                "ip": ip,
                "intentos": intentos[ip]
            }
        )

    # ======================
    # RESPUESTA NORMAL
    # ======================

    response = await call_next(request)

    # HEADERS SEGURIDAD
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"

    tiempo = time.time() - inicio

    print(
        f"[OK] {ip} | {path} | {tiempo:.3f}s"
    )

    return response

# ==========================
# RUTAS
# ==========================

@app.get("/")
async def home():

    return {
        "sistema": "Escudo Digital Pro",
        "version": "3.0",
        "status": "PROTECCIÓN ACTIVA"
    }

@app.get("/status")
async def status():

    return {
        "bloqueadas": len(ips_bloqueadas),
        "ips": list(ips_bloqueadas.keys())
    }

# ==========================
# HONEYPOTS
# ==========================

@app.get("/admin")
@app.get("/wp-admin")
@app.get("/phpmyadmin")
async def honeypot(request: Request):

    ip = request.client.host

    intentos[ip] = intentos.get(ip, 0) + 1

    if intentos[ip] >= 1:
        ips_bloqueadas[ip] = True

    return JSONResponse(
        status_code=404,
        content={
            "error": "Not Found"
        }
    )