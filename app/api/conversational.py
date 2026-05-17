from fastapi import APIRouter, Request
import os
from fastapi import WebSocket, WebSocketDisconnect
from app.core.security import websocket_verify_token, websocket_flood_protection
from app.core.rate_limit_config import limiter, GENERAL_LIMIT

router = APIRouter()

USE_OLLAMA = os.getenv('ENABLE_OLLAMA', 'false').lower() in ('1', 'true', 'yes')

try:
    from app.services.ollama_adapter import generate_with_ollama
except Exception:
    generate_with_ollama = None


@router.post('/chat')
@limiter.limit(GENERAL_LIMIT)
async def chat(request: Request):
    """Conversational endpoint. Uses Ollama when enabled and reachable, otherwise a safe local fallback."""
    body = await request.json()
    message = body.get('message', '') if isinstance(body, dict) else ''

    # Try Ollama if configured
    if USE_OLLAMA and generate_with_ollama:
        try:
            resp = await generate_with_ollama(message)
            if resp:
                return {'reply': resp, 'source': 'ollama'}
        except Exception:
            pass

    # Local safe rule-based responder
    text = message.lower() if isinstance(message, str) else ''
    if 'hola' in text or 'hello' in text:
        reply = 'Hola — MARY en modo asistente conversacional (modo local).'
    elif text.strip() == '':
        reply = 'Envía un mensaje en el campo "message" para conversar.'
    else:
        reply = f'Respuesta local (eco): {message}'

    return {'reply': reply, 'source': 'local-fallback'}


@router.websocket('/ws')
async def websocket_endpoint(websocket: WebSocket):
    """Simple WebSocket endpoint for real-time conversational text (echo / Ollama-backed)."""
    # Authenticate websocket (token via ?token= or Authorization header)
    token = websocket.query_params.get('token') or websocket.headers.get('authorization')
    if token and token.lower().startswith('bearer '):
        token = token.split(None, 1)[1]

    if not await websocket_verify_token(token):
        # reject connection
        await websocket.close(code=1008)
        return

    client_ip = websocket.headers.get('x-forwarded-for') or websocket.headers.get('X-Forwarded-For')
    if client_ip:
        client_ip = client_ip.split(',')[0].strip()
    else:
        client_ip = websocket.client.host if websocket.client else 'unknown'

    if not websocket_flood_protection.allow_message(client_ip):
        await websocket.close(code=1008)
        return

    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()

            if not websocket_flood_protection.allow_message(client_ip):
                await websocket.send_text('Rate limit exceeded for websocket messages.')
                await websocket.close(code=1008)
                return

            # Try Ollama first when configured
            if USE_OLLAMA and generate_with_ollama:
                try:
                    resp = await generate_with_ollama(data)
                    if resp:
                        await websocket.send_text(resp)
                        continue
                except Exception:
                    pass

            # Fallback echo
            await websocket.send_text(f'Local echo: {data}')

    except WebSocketDisconnect:
        return
