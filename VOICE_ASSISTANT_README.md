# MARY V5 Voice Assistant

Real-time conversational AI voice assistant for Windows 10+ with local Ollama integration.

## Features

✓ **Microphone Listening** - Real-time speech capture from default Windows microphone  
✓ **Spanish Speech-to-Text** - Native Windows (SAPI) + Google Cloud fallback  
✓ **Local Ollama Integration** - Connects to local LLM automatically  
✓ **Natural Female Spanish Voice** - pyttsx3 TTS with voice selection  
✓ **Conversation History** - Context-aware responses  
✓ **Lightweight** - ~50MB dependencies on Windows  
✓ **Automatic Setup** - Self-installing dependencies  

## Requirements

- Windows 10 or later
- Python 3.9+
- Local Ollama running (default: http://127.0.0.1:11434)
- Microphone access enabled
- ~200MB free disk space

## Quick Start

### 1. Install Voice Dependencies

```batch
install_voice.bat
```

Or manually:
```bash
pip install pyttsx3==2.90 SpeechRecognition==3.10.0
```

### 2. Start Ollama (in separate terminal)

```bash
ollama serve
```

Or if Ollama is installed as a Windows service, ensure it's running.

### 3. Run Voice Assistant

**Option A - Via Menu:**
```batch
run.bat
# Then select option 2
```

**Option B - Direct:**
```batch
run_voice.bat
```

Or manually:
```bash
python mary_voice.py
```

## Usage

1. Script will verify Ollama connection
2. Microphone will be calibrated (1-2 seconds)
3. Listen for "Hola, soy MARY"
4. Start speaking in Spanish
5. MARY will respond with audio output
6. Say "salir" or "adios" to exit

## Voice Commands

| Phrase | Action |
|--------|--------|
| "salir" | Exit voice assistant |
| "adios" | Exit voice assistant |
| "hasta luego" | Exit voice assistant |
| "terminar" | Exit voice assistant |

## Troubleshooting

### Microphone Issues

**"No se pudo acceder al micrófono"**
- Check Windows Sound Settings (Settings → Privacy & Security → Microphone)
- Ensure Python has microphone permission
- Test microphone with another application
- Run as Administrator if needed

### Audio Output Issues

**"Error al reproducir audio"**
- Check Windows Volume Mixer
- Ensure speakers are connected and not muted
- Restart audio service: `Restart-Service AudioSrv` (PowerShell as Admin)

### Ollama Connection

**"No se puede conectar a Ollama"**
- Start Ollama: `ollama serve`
- Verify Ollama is listening on http://127.0.0.1:11434
- Check Windows Firewall allows local connections
- Try: `curl http://127.0.0.1:11434/api/tags`

### Speech Recognition

**"No entendí, por favor repite"**
- Speak clearly in Spanish
- Reduce background noise
- Speak closer to microphone
- Check internet connection (Google SR fallback)

### No Spanish Female Voice Found

**"No se encontró voz española femenina"**
- System will use default voice
- Install Spanish language pack in Windows Settings
- Download additional voices from Settings → Accessibility → Speech

## Architecture

```
┌─────────────────────────────────────────┐
│  Windows Microphone                     │
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│  MARY Voice Assistant (mary_voice.py)   │
│  ├─ Speech Recognition (SAPI/Google)    │
│  ├─ Conversation Manager                │
│  └─ Text-to-Speech (pyttsx3)            │
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│  Local Ollama (LLM Inference)           │
│  ├─ Model Auto-detection                │
│  └─ Response Generation                 │
└──────────────────────────────────────────┘
```

## Performance

| Metric | Value |
|--------|-------|
| Startup Time | ~3-5 seconds |
| Microphone Calibration | ~2 seconds |
| Speech Recognition | 2-5 seconds (depends on speech length) |
| LLM Response | 5-30 seconds (depends on model) |
| Memory Usage | ~150-300 MB |

## Security Considerations

- Voice data is processed locally, not sent to cloud services (except Google fallback)
- Conversation history is kept in memory only (not persisted)
- Ollama connection uses HTTP (use HTTPS proxy for security)
- No authentication required for local Ollama (assume trusted network)

## Advanced Usage

### Change Ollama URL

Set environment variable before running:
```bash
set OLLAMA_URL=http://192.168.1.100:11434/api/generate
python mary_voice.py
```

### Use Specific Model

```bash
set OLLAMA_MODEL=llama3
python mary_voice.py
```

### Adjust Speech Rate

Edit `mary_voice.py` line ~157:
```python
engine.setProperty("rate", 150)  # 50-300 range
```

### Disable Auto-Dependency Install

Edit `mary_voice.py` line ~286:
```python
# ensure_dependencies()  # Comment this line
init_modules()
```

## Requirements.txt

Voice-specific dependencies are added to `requirements.txt`:
- `pyttsx3==2.90` - Text-to-Speech engine
- `SpeechRecognition==3.10.0` - Speech-to-Text library
- `PyAudio==0.2.13` - Audio I/O (optional, fallback supported)

Install all dependencies:
```bash
pip install -r requirements.txt
```

## Support

For issues, check:
1. Ollama installation: https://ollama.ai
2. Speech Recognition: https://github.com/Uberi/speech_recognition
3. pyttsx3 docs: https://github.com/nateshmbhat/pyttsx3

## License

Part of MARY V5 Enterprise Security Platform
