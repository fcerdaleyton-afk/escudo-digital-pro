import os

# Allow forcing the minimal fallback app for local development/testing
if os.getenv('FORCE_FALLBACK', '').lower() in ('1', 'true', 'yes'):
    e = 'force-fallback'
    app_factory = None
    from fastapi import FastAPI
    from app.api.conversational import router as conversational_router
    app = FastAPI(title="MARY V5 (forced-fallback)")
    app.include_router(conversational_router, prefix="/api/v1/assistant", tags=["Assistant"])
    @app.get('/health/live')
    async def live():
        return {'status': 'alive', 'note': 'forced-fallback', 'error': None}
else:
    try:
        from app.core.app_factory import app_factory
        # ASGI entrypoint used by uvicorn/gunicorn
        app = app_factory.create_app()
    except Exception as e:
        # Fallback minimal app to ensure local runnable state when optional deps are missing
        from fastapi import FastAPI
        from app.api.conversational import router as conversational_router

        app = FastAPI(title="MARY V5 (fallback)")
        app.include_router(conversational_router, prefix="/api/v1/assistant", tags=["Assistant"])

        @app.get('/health/live')
        async def live():
            return {'status': 'alive', 'note': 'fallback-app', 'error': str(e)}

if __name__ == "__main__":
    # Quick local debug run
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8081, log_level="info")
