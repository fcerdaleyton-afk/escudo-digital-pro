@echo off
REM Install voice assistant dependencies for MARY V5 on Windows
SETLOCAL

REM Prefer virtual environment activation if exists
IF EXIST "venv\Scripts\activate.bat" (
  call "venv\Scripts\activate.bat"
)

echo Installing voice assistant dependencies...
echo.

REM Install required packages
python -m pip install --upgrade pip setuptools wheel
python -m pip install pyttsx3==2.90 SpeechRecognition==3.10.0

echo.
echo Voice assistant dependencies installed successfully!
echo.
echo Next steps:
echo   1. Ensure Ollama is running locally (http://127.0.0.1:11434)
echo   2. Run: python mary_voice.py
echo.

ENDLOCAL
pause
