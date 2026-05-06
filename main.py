from fastapi import FastAPI, Header, HTTPException, Request
from datetime import datetime
import smtplib
from email.mime.text import MIMEText

app = FastAPI(title="Escudo Digital Pro - Seguridad Máxima")
API_KEY = "mi_clave_secreta_123" 

# Estructuras de control y memoria
ips_bloqueadas = {}
intentos = {}

# --- FUNCIONES DE PROTECCIÓN Y ALERTA ---

def registrar_evento(ip, navegador, mensaje):
    """Registra antecedentes técnicos en el archivo de logs [3, 4]"""
    with open("logs.txt", "a", encoding="utf-8") as f:
        f.write(f"{datetime.now()} | IP: {ip} | DISPOSITIVO: {navegador} | EVENTO: {mensaje}\n")

def enviar_alertas_criticas(ip, navegador):
    """Envía alertas inmediatas cuando se detecta un ataque [2]"""
    remitente = "f.cerdaleyton@gmail.com" # Debes configurar esto
    mensaje_mail = MIMEText(f"¡ALERTA CRÍTICA! Intento de vulneración detectado.\nIP: {ip}\nDispositivo: {navegador}\nEstado: BLOQUEADO DE RAÍZ.")
    mensaje_mail["Subject"] = "ESCUDO DIGITAL: Bloqueo de Seguridad Activado"
    
    # Aquí se integraría la alerta al teléfono (SMS) en el futuro
    print(f"ALERTA TELEFÓNICA: Intento de acceso sospechoso desde {ip}")

    try:
        # Esto requiere una 'Contraseña de Aplicación' de Google
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as servidor:
            servidor.login(remitente, "sxlpverdyxhbxwhq")
            servidor.sendmail(remitente, remitente, mensaje_mail.as_string())
    except:
        print("Aviso: Alerta de correo no enviada (falta configuración)")

def verificar_seguridad(request: Request, x_api_key: str = Header(None)):
    """Motor principal de rastreo y bloqueo [5, 6]"""
    ip = request.client.host
    navegador = request.headers.get("user-agent") # Rastreo de identidad del dispositivo

    # 1. Verificación de Bloqueo previo
    if ip in ips_bloqueadas:
        registrar_evento(ip, navegador, "INTENTO DE ACCESO POST-BLOQUEO (SIGILOSO)")
        raise HTTPException(
            status_code=403, 
            detail="ACCESO DENEGADO: El sistema ha bloqueado su conexión DESDE LA RAÍZ por actividad sospechosa. "
                   "Si es usted el propietario, CAMBIE SU PASSWORD DE INMEDIATO."
        )

    # 2. Verificación de Clave (API KEY)
    if x_api_key != API_KEY:
        intentos[ip] = intentos.get(ip, 0) + 1
        registrar_evento(ip, navegador, f"FALLO DE AUTENTICACIÓN #{intentos[ip]}")
        
        if intentos[ip] >= 3:
            ips_bloqueadas[ip] = True
            registrar_evento(ip, navegador, "!!! IP LOCALIZADA Y BLOQUEADA DE RAÍZ !!!")
            enviar_alertas_criticas(ip, navegador) # Dispara las alertas al teléfono/correo
        
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    # 3. Acceso Correcto
    intentos[ip] = 0
    registrar_evento(ip, navegador, "ACCESO EXITOSO")

# --- RUTAS DE ACCESO (ENDPOINTS) ---

@app.get("/")
def inicio(request: Request, x_api_key: str = Header(None)):
    verificar_seguridad(request, x_api_key)
    return {"mensaje": "Escudo Digital Activo y Protegiendo"}

@app.get("/status")
def ver_panel_control():
    """Muestra el estado de las amenazas detectadas [7]"""
    return {
        "amenazas_bloqueadas": len(ips_bloqueadas),
        "lista_negra": list(ips_bloqueadas.keys()),
        "intentos_por_ip": intentos
    }

@app.post("/desbloquear")
def desbloquear_ip(ip: str):
    """Permite al dueño desbloquear una IP manualmente [7]"""
    if ip in ips_bloqueadas:
        del ips_bloqueadas[ip]
        intentos[ip] = 0
        return {"mensaje": f"IP {ip} ha sido liberada"}
    return {"error": "IP no encontrada en la lista negra"}

# TRAMPA DE IDENTIDAD (Honeypot para detectar clonadores) [5]
@app.get("/datos-privados-bancarios")
def trampa_identidad(request: Request):
    ip = request.client.host
    navegador = request.headers.get("user-agent")
    ips_bloqueadas[ip] = True 
    registrar_evento(ip, navegador, "¡ALERTA! Intentaron acceder a la trampa de datos bancarios.")
    enviar_alertas_criticas(ip, navegador)
    return {"error": "Conexión perdida con el servidor de seguridad"}