"""List FastAPI routes for the local app."""
import sys
from pprint import pprint

def list_routes():
    try:
        from app.asgi import app
    except Exception as e:
        print("Failed to import app.asgi:", e)
        sys.exit(2)

    routes = []
    for r in app.routes:
        try:
            methods = getattr(r, 'methods', None)
            path = getattr(r, 'path', getattr(r, 'pattern', str(r)))
            name = getattr(r, 'name', r.__class__.__name__)
            routes.append({'path': path, 'methods': list(methods) if methods else None, 'name': name})
        except Exception:
            routes.append({'route': str(r)})

    pprint(routes)

if __name__ == '__main__':
    list_routes()
