@echo off
REM Run MARY V5 on Windows - Web Server or Voice Assistant
SETLOCAL

REM Prefer virtual environment activation if exists
IF EXIST "venv\Scripts\activate.bat" (
  call "venv\Scripts\activate.bat"
)

:menu
cls
echo.
echo ========================================================
echo        MARY V5 - Enterprise Security Platform
echo ========================================================
echo.
echo Choose mode:
echo   1 - Run Web Server (http://127.0.0.1:8081)
echo   2 - Run Voice Assistant (requires local Ollama)
echo   3 - Install Voice Dependencies
echo   Q - Quit
echo.
set /p choice="Enter choice: "

if /i "%choice%"=="1" goto webserver
if /i "%choice%"=="2" goto voice
if /i "%choice%"=="3" goto voicedeps
if /i "%choice%"=="Q" goto end
if /i "%choice%"=="q" goto end

echo Invalid choice
timeout /t 2 >nul
goto menu

:webserver
cls
echo.
echo Enabling Ollama integration...
SET ENABLE_OLLAMA=true
SET OLLAMA_URL=http://127.0.0.1:11434/api/generate
echo.
echo Starting MARY V5 Web Server on http://127.0.0.1:8081
echo Press Ctrl+C to stop
echo.
python -m uvicorn app.asgi:app --host 127.0.0.1 --port 8081 --reload
goto end

:voice
cls
echo.
echo Checking Ollama connectivity...
python -c "import httpx, asyncio; asyncio.run(httpx.AsyncClient(timeout=3).get('http://127.0.0.1:11434/api/tags'))" 2>nul
if ERRORLEVEL 1 (
    echo ERROR: Ollama not found on http://127.0.0.1:11434
    echo.
    echo Make sure Ollama is running first!
    echo.
    pause
    goto menu
)
echo OK - Ollama detected
echo.
echo Starting MARY V5 Voice Assistant...
echo Say "salir" or "adios" to exit
echo.
python mary_voice.py
goto menu

:voicedeps
cls
echo.
echo Installing voice assistant dependencies...
echo.
python -m pip install --upgrade pip setuptools wheel
python -m pip install pyttsx3==2.90 SpeechRecognition==3.10.0
echo.
echo Voice dependencies installed!
pause
goto menu

:end
echo.
ENDLOCAL
