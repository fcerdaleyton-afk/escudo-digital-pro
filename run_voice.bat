@echo off
REM Run MARY V5 Voice Assistant locally on Windows
REM Requires local Ollama instance running on http://127.0.0.1:11434
SETLOCAL

REM Prefer virtual environment activation if exists
IF EXIST "venv\Scripts\activate.bat" (
  call "venv\Scripts\activate.bat"
)

echo Starting MARY V5 Voice Assistant...
echo.
echo Requirements:
echo   - Ollama must be running on http://127.0.0.1:11434
echo   - Microphone must be accessible
echo.
echo Commands:
echo   - Say "salir" to exit
echo   - Say "adios" to quit
echo.

REM Check if Ollama is accessible
python -c "import httpx, asyncio; asyncio.run(httpx.AsyncClient(timeout=3).get('http://127.0.0.1:11434/api/tags'))" 2>nul
IF ERRORLEVEL 1 (
    echo WARNING: Could not detect Ollama on http://127.0.0.1:11434
    echo Please start Ollama first!
    echo.
    pause
    exit /b 1
)

python mary_voice.py

ENDLOCAL
pause
