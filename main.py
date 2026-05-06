from fastapi import FastAPI, Header, HTTPException, Request
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
import os

app = FastAPI(title="Escudo Digital Pro - Seguridad Máxima")

# VARIABLES SEGURAS DESDE RENDER
API_KEY = os.getenv("API_KEY")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

# MEMORIA TEMPORAL
ips_bloqueadas = {}
intentos = {}

# ==============================
# REGISTRO DE EVENTOS
# ==============================

def registrar_evento(ip, navegador, mensaje):
    with open("logs.txt", "a", encoding="utf-8") as f:
        f.write(
            f"{datetime.now()} | "
            f"IP: {ip} | "
            f"DISPOSITIVO: {navegador} | "
            f"EVENTO: {mensaje}\n"
        )

# ==============================
# ALERTAS CRÍTICAS
# ==============================

def enviar_alertas_criticas(ip, navegador):

    remitente = "f.cerdaleyton@gmail.com"

    mensaje = MIMEText(
        f"""
ALERTA CRÍTICA DEL ESCUDO DIGITAL

IP DETECTADA:
{ip}

DISPOSITIVO:
{navegador}

ESTADO:
BLOQUEADO AUTOMÁTICAMENTE

RECOMENDACIÓN:
Revisar actividad sospechosa inmediatamente.
"""
    )

    mensaje["Subject"] = "ESCUDO DIGITAL - ALERTA CRÍTICA"
    mensaje["From"] = remitente
    mensaje["To"] = remitente

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as servidor:
            servidor.login(remitente, EMAIL_PASSWORD)
            servidor.sendmail(
                remitente,
                remitente,
                mensaje.as_string()
            )

        print(f"[ALERTA] Correo enviado por amenaza desde {ip}")

    except Exception as e:
        print(f"[ERROR EMAIL] {e}")

# ==============================
# MOTOR DE SEGURIDAD
# ==============================

def verificar_seguridad(
    request: Request,
    x_api_key: str = Header(None)
):

    # DETECTAR IP REAL
    forwarded = request.headers.get("x-forwarded-for")

    if forwarded:
        ip = forwarded.split(",")[0].strip()
    else:
        ip = request.client.host

    navegador = request.headers.get("user-agent", "DESCONOCIDO")

    # ==========================
    # IP BLOQUEADA
    # ==========================

    if ip in ips_bloqueadas:

        registrar_evento(
            ip,
            navegador,
            "INTENTO POST-BLOQUEO"
        )

        raise HTTPException(
            status_code=403,
            detail="ACCESO DENEGADO POR SEGURIDAD"
        )

    # ==========================
    # API KEY INCORRECTA
    # ==========================

    if x_api_key != API_KEY:

        intentos[ip] = intentos.get(ip, 0) + 1

        registrar_evento(
            ip,
            navegador,
            f"FALLO AUTENTICACIÓN #{intentos[ip]}"
        )

        # BLOQUEO AUTOMÁTICO
        if intentos[ip] >= 3:

            ips_bloqueadas[ip] = True

            registrar_evento(
                ip,
                navegador,
                "IP BLOQUEADA AUTOMÁTICAMENTE"
            )

            enviar_alertas_criticas(ip, navegador)

        raise HTTPException(
            status_code=401,
            detail="CREDENCIALES INVÁLIDAS"
        )

    # RESET SI AUTENTICA
    intentos[ip] = 0

    registrar_evento(
        ip,
        navegador,
        "ACCESO EXITOSO"
    )

# ==============================
# RUTAS
# ==============================

@app.get("/")
def inicio(
    request: Request,
    x_api_key: str = Header(None)
):

    verificar_seguridad(request, x_api_key)

    return {
        "mensaje": "Escudo Digital Activo"
    }

# ==============================

@app.get("/status")
def ver_panel():

    return {
        "amenazas_bloqueadas": len(ips_bloqueadas),
        "ips_bloqueadas": list(ips_bloqueadas.keys()),
        "intentos": intentos
    }

# ==============================

@app.post("/desbloquear")
def desbloquear_ip(ip: str):

    if ip in ips_bloqueadas:

        del ips_bloqueadas[ip]
        intentos[ip] = 0

        return {
            "mensaje": f"IP {ip} desbloqueada"
        }

    return {
        "error": "IP no encontrada"
    }

# ==============================
# HONEYPOT
# ==============================

@app.get("/datos-privados-bancarios")
def honeypot(request: Request):

    forwarded = request.headers.get("x-forwarded-for")

    if forwarded:
        ip = forwarded.split(",")[0].strip()
    else:
        ip = request.client.host

    navegador = request.headers.get("user-agent", "DESCONOCIDO")

    ips_bloqueadas[ip] = True

    registrar_evento(
        ip,
        navegador,
        "ACTIVACIÓN HONEYPOT"
    )

    enviar_alertas_criticas(ip, navegador)

    return {
        "error": "Conexión perdida con el servidor"
    }