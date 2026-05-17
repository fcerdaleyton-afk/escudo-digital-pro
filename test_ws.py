import asyncio
try:
    import websockets
except Exception:
    import sys, subprocess
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'websockets'])
    import websockets

async def test():
    uri='ws://127.0.0.1:8081/api/v1/assistant/ws'
    try:
        async with websockets.connect(uri) as ws:
            await ws.send('Hello websocket after forced fallback')
            resp = await ws.recv()
            print('recv:', resp)
    except Exception as e:
        print('ws error', e)

asyncio.run(test())
