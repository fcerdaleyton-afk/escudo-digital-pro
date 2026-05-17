#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MARY V5 Local Real-Time Voice Assistant for Windows 10+.

Features:
- Microphone listening with speech-to-text (Spanish)
- Real-time Ollama integration for AI responses
- Natural female Spanish voice output
- Conversation history maintained for context
- Automatic dependency installation
- Windows 10+ optimized

Usage:
    python mary_voice.py

Requirements:
    - Windows 10+
    - Ollama running locally (default: http://127.0.0.1:11434)
    - Microphone access
"""

import argparse
import asyncio
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

# Windows audio modules - imported conditionally
pyttsx3 = None
speech_recognition = None
sr = None

OLLAMA_ROOT_URL = os.getenv('OLLAMA_URL', 'http://127.0.0.1:11434')
OLLAMA_GENERATE_PATH = '/api/generate'
OLLAMA_STATUS_PATHS = ['/', '/api/status']
OLLAMA_MAX_TOKENS = int(os.getenv('OLLAMA_MAX_TOKENS', '150'))
OLLAMA_STREAMING = os.getenv('OLLAMA_STREAMING', 'false').lower() == 'true'
OLLAMA_TEMPERATURE = float(os.getenv('OLLAMA_TEMPERATURE', '0.6'))
XAI_ENABLED = os.getenv('XAI_ENABLED', 'false').lower() == 'true'
XAI_API_KEY = os.getenv('XAI_API_KEY', '').strip()
XAI_MODEL = os.getenv('XAI_MODEL', 'grok-2')
XAI_ENDPOINT = 'https://api.x.ai/v1/chat/completions'
PREFER_CLOUD_AI = os.getenv('PREFER_CLOUD_AI', 'false').lower() == 'true'
CLOUD_AI_ENABLED = os.getenv('CLOUD_AI_ENABLED', 'false').lower() == 'true'  # TODO: CLOUD MIGRATION (legacy)
CLOUD_AI_ENDPOINT = os.getenv('CLOUD_AI_ENDPOINT', 'https://api.railway.app/v1/completions')  # TODO: CLOUD MIGRATION (legacy)
PREFERRED_OLLAMA_MODELS = [
     'llama3.2:3b',
    'llama3:latest',
    'llama3',
    'llama2',
    'gpt4o',
    'mistral',
]


def _parse_ollama_list(output: str) -> list[str]:
    models = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith('NAME') or line.startswith('---'):
            continue
        parts = re.split(r'\s+', line)
        if parts:
            models.append(parts[0])
    return models


def _trim_response(text: str, max_sentences: int = 3) -> str:
    """Trim response to reasonable length for voice output.
    
    Keeps responses concise and natural for conversational voice interaction.
    Splits on sentence boundaries, removes extra whitespace.
    """
    if not text or not isinstance(text, str):
        return ""
    
    text = text.strip()
    if not text:
        return ""
    
    # Split on sentence boundaries
    sentences = re.split(r'(?<=[.!?])\s+', text)
    
    # Keep first N sentences or until we hit ~200 chars
    result = []
    char_count = 0
    for sentence in sentences[:max_sentences]:
        if char_count + len(sentence) > 250:
            break
        result.append(sentence)
        char_count += len(sentence)
    
    trimmed = ' '.join(result).strip()
    # Ensure ends with punctuation if content exists
    if trimmed and trimmed[-1] not in '.!?':
        trimmed += '.'
    
    return trimmed


def _format_for_xai_api(prompt: str) -> list[dict]:
    """Convert Ollama prompt format to OpenAI chat/completions format for xAI API.
    
    xAI uses chat completions format with messages array, while Ollama uses
    simple text prompts. This converts our prompt into the required format.
    """
    # Extract system message and user message from combined prompt
    lines = prompt.split('\n')
    system_msg = lines[0] if lines else "Eres un asistente útil."
    
    # Collect all non-empty lines as user message
    user_lines = [line for line in lines[1:] if line.strip() and not line.startswith('MARY:')]
    user_msg = '\n'.join(user_lines).strip()
    
    if not user_msg:
        user_msg = "Hola"
    
    # Build OpenAI-format messages array
    messages = [
        {"role": "system", "content": system_msg},
        {"role": "user", "content": user_msg}
    ]
    
    return messages


async def _query_xai_cloud(prompt: str, max_tokens: int, temperature: float, api_key: str, model: str) -> Optional[str]:
    """Query xAI's Grok API (https://api.x.ai/v1/chat/completions).
    
    Returns response text or None if request fails. Caller handles fallback.
    This is a stateless helper that can be called without instance context.
    """
    if not api_key or not api_key.startswith('sk-'):
        return None
    
    try:
        import httpx
        
        messages = _format_for_xai_api(prompt)
        
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }
        
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(XAI_ENDPOINT, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
            
            # Extract message from OpenAI-format response
            if isinstance(data, dict) and 'choices' in data:
                choices = data.get('choices', [])
                if choices and isinstance(choices[0], dict):
                    message = choices[0].get('message', {})
                    if isinstance(message, dict):
                        content = message.get('content', '').strip()
                        if content:
                            return content
            
            return None
    except asyncio.TimeoutError:
        print("⏱ Timeout en xAI - intentando Ollama...")
        return None
    except Exception as e:
        print(f"⚠ Error en xAI API: {e}")
        return None


def _detect_local_ollama_models() -> list[str]:
    try:
        result = subprocess.run(
            ['ollama', 'list'],
            capture_output=True,
            text=True,
            timeout=8,
            check=True,
        )
        return _parse_ollama_list(result.stdout)
    except Exception:
        return []


def _select_best_ollama_model(models: list[str]) -> Optional[str]:
    if not models:
        return None

    env_model = os.getenv('OLLAMA_MODEL', '').strip()
    if env_model and env_model in models:
        return env_model

    for candidate in PREFERRED_OLLAMA_MODELS:
        for model in models:
            if model == candidate:
                return model

    for candidate in PREFERRED_OLLAMA_MODELS:
        for model in models:
            if model.startswith(candidate):
                return model

    return models[0]


def ensure_dependencies() -> None:
    """Install required packages if missing."""
    print("Verificando dependencias de audio...")
    
    packages_to_check = {
        "pyttsx3": "pyttsx3",
        "speech_recognition": "SpeechRecognition",
        "pyaudio": "PyAudio",
    }
    
    missing = []
    for module_name, pip_name in packages_to_check.items():
        try:
            __import__(module_name)
            print(f"  ✓ {module_name} instalado")
        except ImportError:
            missing.append((module_name, pip_name))
            print(f"  ✗ {module_name} falta")
    
    if missing:
        print("\nInstalando paquetes faltantes...")
        pip_names = [pip for _, pip in missing]
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--quiet"] + pip_names,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            print("  ✓ Dependencias instaladas correctamente\n")
        except subprocess.CalledProcessError as e:
            print(f"  ✗ Error al instalar dependencias: {e}")
            print("  Intenta instalar manualmente:")
            print(f"  pip install {' '.join(pip_names)}")
            raise


def init_modules() -> None:
    """Initialize audio and speech modules after dependencies are ready."""
    global pyttsx3, speech_recognition, sr
    
    try:
        import pyttsx3 as pyttsx3_module
        pyttsx3 = pyttsx3_module
    except ImportError as e:
        print(f"Error importing pyttsx3: {e}")
        raise
    
    try:
        import speech_recognition as sr_module
        speech_recognition = sr_module
        sr = sr_module
    except ImportError as e:
        print(f"Error importing speech_recognition: {e}")
        raise


class MaryVoiceAssistant:
    """Local voice assistant for MARY V5."""
    
    def __init__(self, ollama_root_url: str = OLLAMA_ROOT_URL, enable_streaming: bool = False):
        """Initialize the voice assistant.
        
        Args:
            ollama_root_url: Root URL to local Ollama service
            enable_streaming: Enable streaming responses (default: False for compatibility)
        """
        self.ollama_root_url = ollama_root_url.rstrip('/')
        self.ollama_generate_url = f"{self.ollama_root_url}{OLLAMA_GENERATE_PATH}"
        self.engine = self._init_tts_engine()
        self.recognizer = sr.Recognizer()
        self.conversation_history: List[str] = []
        self.max_history = 10
        self.stop_phrases = {
            "salir", "adios", "adiós", "hasta luego", "terminar", 
            "stop", "exit", "quit", "bye", "chao"
        }
        self.ollama_model = None
        self.enable_streaming = enable_streaming or OLLAMA_STREAMING
        self.max_tokens = OLLAMA_MAX_TOKENS
        self.temperature = OLLAMA_TEMPERATURE
        
        # xAI/Grok Cloud Integration
        self.xai_enabled = XAI_ENABLED and bool(XAI_API_KEY)
        self.xai_api_key = XAI_API_KEY
        self.xai_model = XAI_MODEL
        self.prefer_cloud = PREFER_CLOUD_AI
        
        # TODO: CLOUD MIGRATION - Future support for cloud AI routing
        self.cloud_ai_enabled = CLOUD_AI_ENABLED
        self.cloud_ai_endpoint = CLOUD_AI_ENDPOINT
        
        if self.xai_enabled:
            print(f"☁️ xAI Integration habilitado (modelo: {self.xai_model})")
        
        print("🎙️ Asistente de voz MARY inicializado\n")
    
    def _init_tts_engine(self):
        """Initialize text-to-speech engine with Spanish female voice."""
        engine = pyttsx3.init()
        
        # Configure speech rate and volume
        engine.setProperty("rate", 150)
        engine.setProperty("volume", 0.9)
        
        # Try to find Spanish female voice
        best_voice = self._find_spanish_female_voice(engine)
        if best_voice:
            engine.setProperty("voice", best_voice)
            print(f"✓ Voz seleccionada: {best_voice}")
        else:
            print("⚠ No se encontró voz española femenina, usando voz por defecto")
        
        return engine
    
    def _find_spanish_female_voice(self, engine) -> Optional[str]:
        """Find a Spanish female voice from available voices."""
        voices = engine.getProperty("voices") or []
        
        if not voices:
            return None
        
        spanish_female = None
        spanish_any = None
        
        for voice in voices:
            name = str(getattr(voice, "name", "")).lower()
            voice_id = str(getattr(voice, "id", "")).lower()
            
            # Check if Spanish
            is_spanish = any(
                keyword in name or keyword in voice_id
                for keyword in ["spanish", "españa", "castellano", "es_", "es-"]
            )
            
            # Check if female (heuristic)
            is_female = any(
                keyword in name
                for keyword in ["female", "mujer", "女", "woman", "sofia", "maria", 
                               "sara", "ines", "ana", "lucia", "violeta", "spanish female"]
            )
            
            if is_spanish:
                spanish_any = voice.id
                if is_female:
                    spanish_female = voice.id
                    break
        
        return spanish_female or spanish_any
    
    async def _verify_ollama(self) -> bool:
        """Verify Ollama is running and discover a model to use."""
        try:
            import httpx

            async with httpx.AsyncClient(timeout=8) as client:
                reachable = False
                for path in OLLAMA_STATUS_PATHS:
                    url = f"{self.ollama_root_url}{path}"
                    try:
                        response = await client.get(url)
                        if response.status_code == 200:
                            reachable = True
                            break
                    except Exception:
                        continue

                if not reachable:
                    print(f"✗ No se puede conectar a Ollama en {self.ollama_root_url}")
                    return False

            models = _detect_local_ollama_models()
            if not models:
                env_model = os.getenv('OLLAMA_MODEL', '').strip()
                if env_model:
                    models = [env_model]

            self.ollama_model = _select_best_ollama_model(models)
            if self.ollama_model:
                print(f"✓ Ollama detectado - Modelo: {self.ollama_model}\n")
                return True

            print("✗ Ollama está corriendo, pero no se detectaron modelos instalados.")
        except Exception as e:
            print(f"✗ No se puede conectar a Ollama: {e}")

        return False
    
    def speak(self, text: str) -> None:
        """Speak text using TTS engine."""
        if not text or not isinstance(text, str):
            return
        
        text = text.strip()
        if not text:
            return
        
        print(f"\n🔊 MARY: {text}\n")
        try:
            self.engine.say(text)
            self.engine.runAndWait()
        except Exception as e:
            print(f"Error al reproducir audio: {e}")
    
    def _build_prompt(self, user_message: str) -> str:
        """Build conversation prompt with history - optimized for low-latency responses.
        
        System prompt emphasizes brevity, warmth, and natural conversational tone.
        """
        system = (
            "Eres MARY, un asistente de voz amable y profesional. "
            "Responde siempre en español, de forma breve y cálida (máximo 2-3 frases). "
            "Sé conversacional, natural y empática. "
            "Si necesitas detalles técnicos, resúmelos en palabras simples."
        )
        
        lines = [system]
        
        # Add conversation history (last 5 exchanges for context without overwhelming)
        for i, msg in enumerate(self.conversation_history[-5:]):
            role = "Usuario" if i % 2 == 0 else "MARY"
            lines.append(f"{role}: {msg}")
        
        lines.append(f"Usuario: {user_message}")
        lines.append("MARY:")
        
        return "\n".join(lines)
    
    async def _query_ollama(self, prompt: str) -> str:
        """Query backend for conversational response with intelligent fallback.
        
        Priority flow:
        1. If xAI enabled: Try xAI Cloud first
        2. Fallback to Local Ollama
        3. If both fail: Return graceful message
        
        Includes low-latency optimizations: token limiting, trimming, timeout.
        """
        # Step 1: Try xAI Cloud if enabled and we have credentials
        if self.xai_enabled and not self.prefer_cloud:
            print("☁️ Intentando xAI Cloud...")
            response = await _query_xai_cloud(
                prompt,
                self.max_tokens,
                self.temperature,
                self.xai_api_key,
                self.xai_model
            )
            if response:
                print("✓ Respuesta de xAI")
                return _trim_response(response)
            # If cloud fails, fall through to Ollama
        
        # Step 2: Try Local Ollama (primary or fallback)
        if not self.ollama_model:
            # No Ollama available, try cloud as last resort
            if self.xai_enabled:
                print("☁️ Ollama no disponible, intentando xAI...")
                response = await _query_xai_cloud(
                    prompt,
                    self.max_tokens,
                    self.temperature,
                    self.xai_api_key,
                    self.xai_model
                )
                if response:
                    print("✓ Respuesta de xAI (fallback)")
                    return _trim_response(response)
            
            return "Lo siento, ningún backend de IA está disponible en este momento."
        
        # Step 3: Query Ollama
        try:
            import httpx

            payload = {
                "model": self.ollama_model,
                "prompt": prompt,
                "stream": self.enable_streaming,
                "temperature": self.temperature,
                "num_predict": self.max_tokens,
                "max_tokens": self.max_tokens,
            }
            
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.post(self.ollama_generate_url, json=payload)
                response.raise_for_status()
                data = response.json()

                if isinstance(data, dict):
                    for key in ('response', 'result', 'text', 'output'):
                        value = data.get(key)
                        if isinstance(value, str) and value.strip():
                            print("✓ Respuesta de Ollama")
                            return _trim_response(value.strip())

                    if 'choices' in data and isinstance(data['choices'], list) and data['choices']:
                        first = data['choices'][0]
                        if isinstance(first, dict):
                            for key in ('text', 'message', 'content'):
                                if isinstance(first.get(key), str) and first[key].strip():
                                    print("✓ Respuesta de Ollama")
                                    return _trim_response(first[key].strip())
                            if 'delta' in first and isinstance(first['delta'], dict):
                                delta_text = first['delta'].get('content')
                                if isinstance(delta_text, str) and delta_text.strip():
                                    print("✓ Respuesta de Ollama")
                                    return _trim_response(delta_text.strip())

                return response.text.strip() or "No recibí respuesta."
                
        except asyncio.TimeoutError:
            print("⏱ Timeout en Ollama")
            # Try xAI as last resort on timeout
            if self.xai_enabled:
                print("☁️ Intentando xAI como fallback...")
                response = await _query_xai_cloud(
                    prompt,
                    self.max_tokens,
                    self.temperature,
                    self.xai_api_key,
                    self.xai_model
                )
                if response:
                    print("✓ Respuesta de xAI (fallback por timeout)")
                    return _trim_response(response)
            
            return "Necesito un momento para pensar. ¿Puedes repetir la pregunta?"
        except Exception as e:
            print(f"✗ Error en Ollama: {e}")
            # Try xAI as last resort on error
            if self.xai_enabled:
                print("☁️ Intentando xAI como fallback...")
                response = await _query_xai_cloud(
                    prompt,
                    self.max_tokens,
                    self.temperature,
                    self.xai_api_key,
                    self.xai_model
                )
                if response:
                    print("✓ Respuesta de xAI (fallback por error)")
                    return _trim_response(response)
        
        return "Lo siento, no pude generar una respuesta en este momento."
    
    def _recognize_speech(self) -> Optional[str]:
        """Recognize Spanish speech from microphone."""
        try:
            with sr.Microphone() as source:
                print("🎤 Escuchando...")
                # Increase timeout for better recognition
                audio = self.recognizer.listen(
                    source, 
                    timeout=10, 
                    phrase_time_limit=15
                )
        except sr.WaitTimeoutError:
            print("⏱ Sin detección de voz, intentando de nuevo...")
            return None
        except Exception as e:
            print(f"Error de micrófono: {e}")
            return None
        
        print("⌛ Reconociendo...")
        
        # Try SAPI (Windows native) first for Spanish
        try:
            text = self.recognizer.recognize_sapi(audio, language="es-ES")
            return text.strip() if text else None
        except Exception:
            pass
        
        # Fallback to Google Speech Recognition
        try:
            text = self.recognizer.recognize_google(audio, language="es-ES")
            return text.strip() if text else None
        except sr.UnknownValueError:
            print("No entendí, por favor repite...")
            return None
        except Exception as e:
            print(f"Error de reconocimiento: {e}")
            return None
    
    async def run(self) -> None:
        """Main conversation loop."""
        print("=" * 60)
        print("🎙️  MARY V5 - Asistente de Voz Local")
        print("=" * 60)
        
        # Verify Ollama is available
        if not await self._verify_ollama():
            self.speak("No puedo conectar a Ollama. Verifica que esté ejecutándose.")
            return
        
        # Calibrate microphone
        try:
            with sr.Microphone() as source:
                print("\n📢 Calibrando micrófono (1 segundo)...")
                self.recognizer.adjust_for_ambient_noise(source, duration=1)
                print("✓ Micrófono calibrado\n")
        except Exception as e:
            print(f"Error al calibrar micrófono: {e}")
            self.speak("Error al acceder al micrófono.")
            return
        
        self.speak("Hola, soy MARY. Di salir para terminar.")
        
        # Main loop
        while True:
            try:
                # Get user input
                user_input = self._recognize_speech()
                if not user_input:
                    continue
                
                print(f"\n👤 Dijiste: {user_input}")
                
                # Check stop phrase
                if user_input.lower() in self.stop_phrases:
                    self.speak("Hasta luego. Que tengas un buen día.")
                    break
                
                # Add to history
                self.conversation_history.append(user_input)
                
                # Query Ollama
                prompt = self._build_prompt(user_input)
                response = await self._query_ollama(prompt)
                
                # Add response to history
                self.conversation_history.append(response)
                
                # Keep history manageable
                if len(self.conversation_history) > self.max_history:
                    self.conversation_history = self.conversation_history[-self.max_history:]
                
                # Speak response
                self.speak(response)
                
            except KeyboardInterrupt:
                print("\n\n⏹ Interrupción recibida")
                break
            except Exception as e:
                print(f"Error en bucle principal: {e}")
                self.speak("Ocurrió un error, intentando de nuevo...")
                time.sleep(1)
        
        print("\n✓ Asistente cerrado")


async def main():
    """Entry point."""
    parser = argparse.ArgumentParser(
        description="MARY V5 Voice Assistant with xAI/Grok Integration",
        epilog="""
Configuración de Backend:
  Ollama:  OLLAMA_URL=http://localhost:11434
  xAI:     XAI_API_KEY=sk-... XAI_ENABLED=true XAI_MODEL=grok-2
  
Ejemplos:
  python mary_voice.py                  # Usar solo Ollama (por defecto)
  XAI_API_KEY=sk-... python mary_voice.py --test-ollama  # Verificar backends
        """
    )
    parser.add_argument(
        "--test-ollama",
        action="store_true",
        help="Verificar la conexión con Ollama y generar una respuesta de prueba.",
    )
    parser.add_argument(
        "--ollama-url",
        default=OLLAMA_ROOT_URL,
        help="URL base de Ollama local (por defecto http://127.0.0.1:11434).",
    )
    parser.add_argument(
        "--streaming",
        action="store_true",
        help="Habilitar modo streaming para respuestas más rápidas (experimental).",
    )
    parser.add_argument(
        "--test-xai",
        action="store_true",
        help="Verificar la conexión con xAI API y generar una respuesta de prueba.",
    )
    args = parser.parse_args()

    try:
        ensure_dependencies()
        init_modules()

        assistant = MaryVoiceAssistant(
            ollama_root_url=args.ollama_url,
            enable_streaming=args.streaming
        )

        if args.test_xai:
            print("\n🔎 Test de xAI iniciado...")
            if not assistant.xai_enabled:
                print("✗ xAI no está configurado. Establece XAI_API_KEY y XAI_ENABLED=true")
                sys.exit(1)
            
            test_prompt = "Hola MARY, por favor responde con un mensaje corto de prueba."
            result = await _query_xai_cloud(
                test_prompt,
                assistant.max_tokens,
                assistant.temperature,
                assistant.xai_api_key,
                assistant.xai_model
            )
            if result:
                print(f"✓ xAI conectado (modelo: {assistant.xai_model})")
                print(f"Respuesta de prueba: {_trim_response(result)}\n")
            else:
                print("✗ No se pudo conectar a xAI. Verifica XAI_API_KEY.")
                sys.exit(1)
            return

        if args.test_ollama:
            print("\n🔎 Test de backends iniciado...")
            
            # Test xAI if enabled
            if assistant.xai_enabled:
                print("\n☁️ Probando xAI...")
                result = await _query_xai_cloud(
                    "Test",
                    assistant.max_tokens,
                    assistant.temperature,
                    assistant.xai_api_key,
                    assistant.xai_model
                )
                if result:
                    print("  ✓ xAI conectado")
                else:
                    print("  ⚠ xAI no disponible (continuando con Ollama)")
            
            # Test Ollama
            print("\n📦 Probando Ollama...")
            if not await assistant._verify_ollama():
                if assistant.xai_enabled:
                    print("  ⚠ Ollama no disponible (usará xAI como fallback)")
                else:
                    print("✗ Ni xAI ni Ollama están disponibles.")
                    sys.exit(1)
            else:
                print(f"  ✓ Ollama conectado (modelo: {assistant.ollama_model})")

            test_prompt = "Hola MARY, por favor responde con un mensaje corto de prueba."
            result = await assistant._query_ollama(test_prompt)
            print(f"\n✓ Respuesta de prueba: {result}\n")
            return

        await assistant.run()
    except KeyboardInterrupt:
        print("\n\nCerrando...")
    except Exception as e:
        print(f"\n❌ Error fatal: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    if sys.platform != "win32":
        print("Este script está optimizado para Windows 10+")
        print(f"Sistema detectado: {sys.platform}")
    
    asyncio.run(main())
