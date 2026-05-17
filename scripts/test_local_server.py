import httpx

urls = [
    ('HEALTH', 'http://127.0.0.1:8081/health/live', 'GET', None),
    ('CHAT', 'http://127.0.0.1:8081/api/v1/assistant/chat', 'POST', {'message': 'Hola desde MARY local'})
]

with httpx.Client(timeout=5) as client:
    for name, url, method, payload in urls:
        try:
            if method == 'GET':
                r = client.get(url)
            else:
                r = client.post(url, json=payload)
            print(name, r.status_code)
            print(r.text)
        except Exception as e:
            print(name, 'ERR', type(e).__name__, e)
