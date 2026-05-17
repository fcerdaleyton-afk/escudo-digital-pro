"""Detect voice/audio and Ollama/Groq integrations in the repository."""
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SEARCH_PATTERNS = {
    'ollama': re.compile(r'\bollama\b', re.IGNORECASE),
    'groq': re.compile(r'\bgroq\b', re.IGNORECASE),
    'openai': re.compile(r'\bopenai\b', re.IGNORECASE),
    'whisper': re.compile(r'\bwhisper\b', re.IGNORECASE),
    'vosk': re.compile(r'\bvosk\b', re.IGNORECASE),
    'pyttsx3': re.compile(r'\bpyttsx3\b', re.IGNORECASE),
    'gTTS': re.compile(r'\bgTTS\b', re.IGNORECASE),
    'speech_recognition': re.compile(r'\bspeech_recognition\b', re.IGNORECASE),
}

def scan_files():
    findings = {k: [] for k in SEARCH_PATTERNS}

    for p in ROOT.rglob('*.py'):
        try:
            text = p.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            continue

        for name, pattern in SEARCH_PATTERNS.items():
            if pattern.search(text):
                findings[name].append(str(p.relative_to(ROOT)))

    return findings

def main():
    print(f"Scanning repository at {ROOT} for known integrations...")
    findings = scan_files()

    for key, files in findings.items():
        if files:
            print(f"Found {key} in {len(files)} file(s):")
            for f in files[:20]:
                print('  -', f)
        else:
            print(f"No {key} integrations found.")

if __name__ == '__main__':
    main()
