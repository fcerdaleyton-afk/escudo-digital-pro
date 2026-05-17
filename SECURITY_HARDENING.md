Resumen de hardening aplicado a MARY V5

Objetivo: Elevar seguridad a nivel enterprise para despliegue público.

Cambios aplicados
- Nuevo módulo: `app/core/security.py` que contiene:
  - `SecurityHeadersMiddleware`: añade HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cross-Origin-* headers.
  - `RemoveServerHeaderMiddleware`: elimina cabeceras que revelan servidor (`Server`, `X-Powered-By`, etc.).
  - `RequestSizeLimitMiddleware`: limita tamaño máximo de payload (`MAX_BODY_SIZE` env).
  - `SimpleRateLimitMiddleware`: limitador en memoria por IP (`RATE_LIMIT` / `RATE_WINDOW`).
  - `verify_api_request` y `websocket_verify_token`: helpers para JWT / API Key.

- Registrado en `app/core/app_factory.py`:
  - Middlewares globales añadidos tempranamente en la cadena: remover headers, seguridad, tamaño, rate-limit.
  - Middleware HTTP que fuerza autenticación en rutas `/api/*` (excluye `/api/v1/auth`).
  - Handler genérico de excepciones para ocultar trazas internas (retorna 500 genérico).
  - Debug habilitado solo en `ENV=dev`.

- WebSocket (`app/api/conversational.py`): ahora valida token (`?token=` o header `Authorization: Bearer ...` o `X-API-Key`). Rechaza conexiones no autenticadas.

Recomendaciones y pasos siguientes
- Provisionar secretos en variables de entorno: `JWT_SECRET` (preferido) o `API_KEY`.
- Instalar dependencias para JWT si se usa: `PyJWT` (`pip install PyJWT`).
- Para rate-limiting en producción, reemplazar `SimpleRateLimitMiddleware` por un backend distribuido (Redis + SlowAPI / limits) para escalar.
- Revisar y ajustar `CORS_ORIGINS` en variables de entorno para permitir solo dominios de cliente válidos.

Pruebas locales rápidas
1. Establecer `API_KEY` temporal y crear la app:

```powershell
set API_KEY=testkey
py -3 -c "from app.core.app_factory import app_factory; app = app_factory.create_app(); print('APP_OK', type(app).__name__)"
```

2. Arrancar localmente (uvicorn)

```powershell
set API_KEY=testkey
python -m uvicorn app.asgi:app --host 127.0.0.1 --port 8081
```

3. Probar endpoints (añadiendo `X-API-Key: testkey` a las llamadas a `/api/*`):

```bash
curl http://127.0.0.1:8081/health/live
curl -X POST http://127.0.0.1:8081/api/v1/assistant/chat -H "X-API-Key: testkey" -H "Content-Type: application/json" -d '{"message":"hola"}'
```

Checklist pendiente / mejoras opcionales
- Integrar un limitador distribuido (Redis) y reemplazar limitador en memoria.
- Añadir pruebas E2E automatizadas (pytest) para websockets y límites.
- Aplicar CSP más restrictiva adaptada a los recursos del frontend.
- Habilitar TLS y revisar configuración de reverse proxy (headers `X-Forwarded-*`).

Estado actual
- Sistema funcional con hardening básico aplicado. No se rompieron endpoints principales; se añadió autenticación por defecto a rutas `/api/*`.
