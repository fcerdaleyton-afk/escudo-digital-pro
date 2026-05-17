"""Statically extract FastAPI routes and included routers without importing the app."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def find_decorators():
    routes = []
    for p in ROOT.rglob('*.py'):
        try:
            text = p.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            continue

        # Find router decorators like @router.get('/path') or @router.post("/x")
        for m in re.finditer(r"@(?P<router>\w+)\.(get|post|put|delete|patch|options|head)\s*\(\s*([\"'])(?P<path>[^\"']+)([\"'])", text):
            routes.append({'file': str(p.relative_to(ROOT)), 'decorator': m.group(0), 'router': m.group('router'), 'path': m.group('path')})

        # Find include_router usages
        for m in re.finditer(r"include_router\s*\(\s*(?P<router>[^,\)]+)\s*(,|\))", text):
            routes.append({'file': str(p.relative_to(ROOT)), 'include_router': m.group(1).strip()})

    return routes

def main():
    routes = find_decorators()
    if not routes:
        print('No route decorators or include_router calls found (static scan).')
        return

    print('Discovered route patterns / include_router calls:')
    for r in routes:
        if 'path' in r:
            print(f"- {r['file']}: decorator {r['decorator']} -> {r['path']}")
        else:
            print(f"- {r['file']}: include_router({r['include_router']})")

if __name__ == '__main__':
    main()
