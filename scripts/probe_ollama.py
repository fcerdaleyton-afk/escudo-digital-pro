import httpx

urls = ['/', '/api/generate', '/api/models', '/models', '/api/list', '/models/list', '/api/v1/models', '/v1', '/api/status', '/status']
with httpx.Client(timeout=5) as c:
    for path in urls:
        url = 'http://127.0.0.1:11434' + path
        try:
            r = c.get(url)
            print(path, r.status_code, r.text[:400].replace('\n', ' '))
        except Exception as e:
            print(path, 'ERR', e)
