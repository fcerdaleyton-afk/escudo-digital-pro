#!/usr/bin/env python3
"""System verification script for MARY V5 Voice Assistant on Windows."""

import asyncio
import sys
import subprocess
from pathlib import Path


def check_python_version() -> bool:
    """Verify Python 3.9+"""
    version = sys.version_info
    print(f"Python Version: {version.major}.{version.minor}.{version.micro}", end=" ")
    if version.major >= 3 and version.minor >= 9:
        print("✓")
        return True
    print("✗ (requires 3.9+)")
    return False


def check_module(module_name: str, package_name: str = None) -> bool:
    """Check if a module is installed."""
    pkg = package_name or module_name
    try:
        __import__(module_name)
        print(f"  ✓ {pkg}")
        return True
    except ImportError:
        print(f"  ✗ {pkg} - run: pip install {pkg}")
        return False


def check_dependencies() -> bool:
    """Check required Python packages."""
    print("Dependencies:")
    dependencies = [
        ("pyttsx3", "pyttsx3"),
        ("speech_recognition", "SpeechRecognition"),
        ("httpx", "httpx"),
        ("asyncio", None),  # Built-in
    ]
    
    results = [check_module(mod, pkg) for mod, pkg in dependencies]
    return all(results)


def check_microphone() -> bool:
    """Verify microphone access."""
    print("Microphone:")
    try:
        import speech_recognition as sr
        try:
            with sr.Microphone() as source:
                print(f"  ✓ Microphone detected: {source.device_id}")
                return True
        except Exception as e:
            print(f"  ✗ Cannot access microphone: {e}")
            return False
    except ImportError:
        print("  ? SpeechRecognition not installed")
        return False


def check_tts() -> bool:
    """Verify text-to-speech engine."""
    print("Text-to-Speech:")
    try:
        import pyttsx3
        engine = pyttsx3.init()
        voices = engine.getProperty("voices")
        print(f"  ✓ TTS engine initialized ({len(voices)} voices available)")
        return True
    except Exception as e:
        print(f"  ✗ TTS error: {e}")
        return False


async def check_ollama() -> bool:
    """Verify local Ollama connection."""
    print("Ollama Connection:")
    try:
        import httpx
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get("http://127.0.0.1:11434/api/tags")
            if response.status_code == 200:
                data = response.json()
                models = data.get("models", [])
                if models:
                    model_names = [m.get("name") for m in models[:3]]
                    print(f"  ✓ Ollama accessible - Models: {', '.join(model_names)}")
                    return True
                else:
                    print("  ⚠ Ollama running but no models installed")
                    return False
            else:
                print(f"  ✗ Ollama HTTP error: {response.status_code}")
                return False
    except Exception as e:
        print(f"  ✗ Cannot connect to Ollama: {e}")
        print("    - Start Ollama: ollama serve")
        print("    - Check: http://127.0.0.1:11434/api/tags")
        return False


def check_system() -> bool:
    """Verify platform."""
    print("Platform:")
    if sys.platform == "win32":
        print(f"  ✓ Windows {sys.platform}")
        return True
    else:
        print(f"  ✗ {sys.platform} (requires Windows)")
        return False


def check_mary_voice_script() -> bool:
    """Verify mary_voice.py exists and is valid."""
    print("MARY Voice Script:")
    script_path = Path("mary_voice.py")
    if script_path.exists():
        try:
            with open(script_path, encoding='utf-8') as f:
                compile(f.read(), str(script_path), "exec")
            print(f"  ✓ {script_path} (syntax valid)")
            return True
        except SyntaxError as e:
            print(f"  ✗ {script_path} has syntax errors: {e}")
            return False
    else:
        print(f"  ✗ {script_path} not found")
        return False


async def main() -> None:
    """Run all checks."""
    print("=" * 60)
    print("MARY V5 Voice Assistant - System Verification")
    print("=" * 60)
    print()
    
    checks = [
        ("Python Version", check_python_version()),
        ("Dependencies", check_dependencies()),
        ("MARY Voice Script", check_mary_voice_script()),
        ("System", check_system()),
    ]
    
    print()
    
    # Hardware checks (may fail silently)
    print("Hardware (Optional):")
    check_microphone()
    check_tts()
    
    print()
    
    # Network check
    ollama_ok = await check_ollama()
    
    print()
    print("=" * 60)
    
    all_ok = all(result for _, result in checks) and ollama_ok
    
    if all_ok:
        print("✓ All checks passed! Ready to run voice assistant:")
        print("  python mary_voice.py")
    else:
        print("✗ Some checks failed. Please fix issues above.")
    
    print("=" * 60)
    
    return all_ok


if __name__ == "__main__":
    result = asyncio.run(main())
    sys.exit(0 if result else 1)
