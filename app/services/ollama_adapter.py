"""Simple Ollama adapter.

This module provides a minimal async adapter to call a local Ollama HTTP API.
If `OLLAMA_MODEL` is not set, it will attempt to detect local models using the
`ollama list` CLI and choose the best available conversational model.
"""
import os
import re
import subprocess
import httpx

OLLAMA_URL = os.getenv('OLLAMA_URL', 'http://127.0.0.1:11434/api/generate')
OLLAMA_TIMEOUT = float(os.getenv('OLLAMA_TIMEOUT', '10'))
OLLAMA_MODEL = os.getenv('OLLAMA_MODEL', '').strip()
OLLAMA_MAX_TOKENS = int(os.getenv('OLLAMA_MAX_TOKENS', '512'))
_CACHED_MODEL: str | None = None

PREFERRED_MODELS = [
    'llama3:latest',
    'llama3.2:3b',
    'llama3',
    'llama2',
    'gpt4o',
    'gptj',
    'mistral',
]


def _parse_ollama_list(output: str) -> list[str]:
    """Parse the output of `ollama list` and return installed model names."""
    models = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith('NAME') or line.startswith('---'):
            continue
        parts = re.split(r'\s+', line)
        if not parts:
            continue
        models.append(parts[0])
    return models


def _detect_local_ollama_models() -> list[str]:
    """Detect installed Ollama models using the CLI."""
    try:
        result = subprocess.run(
            ['ollama', 'list'],
            capture_output=True,
            text=True,
            timeout=5,
            check=True
        )
        return _parse_ollama_list(result.stdout)
    except Exception:
        return []


def _select_best_model(models: list[str]) -> str | None:
    """Select the best available model from a list of installed models."""
    if not models:
        return None

    # Exact names preferred first
    for candidate in PREFERRED_MODELS:
        for model in models:
            if model == candidate:
                return model

    # Prefix matching for family names
    for candidate in PREFERRED_MODELS:
        for model in models:
            if model.startswith(candidate):
                return model

    return models[0]


def get_ollama_model() -> str | None:
    """Get the configured or auto-detected Ollama model name."""
    global _CACHED_MODEL
    if _CACHED_MODEL:
        return _CACHED_MODEL

    if OLLAMA_MODEL:
        _CACHED_MODEL = OLLAMA_MODEL
        return _CACHED_MODEL

    models = _detect_local_ollama_models()
    if not models:
        return None

    best_model = _select_best_model(models)
    _CACHED_MODEL = best_model
    return best_model


async def generate_with_ollama(prompt: str) -> str:
    """Generate a single reply using the Ollama HTTP API.

    Returns the text reply or None on failure.
    """
    if not prompt:
        return None

    model = get_ollama_model()
    if not model:
        return None

    payload = {
        'model': model,
        'prompt': prompt,
        'max_tokens': OLLAMA_MAX_TOKENS,
    }

    try:
        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
            r = await client.post(OLLAMA_URL, json=payload)
            r.raise_for_status()
            data = r.json()

            if isinstance(data, dict):
                for key in ('text', 'output', 'result'):
                    if key in data and isinstance(data[key], str):
                        return data[key]
                if 'generations' in data and isinstance(data['generations'], list) and data['generations']:
                    g = data['generations'][0]
                    if isinstance(g, dict) and 'text' in g:
                        return g['text']
            return r.text
    except Exception:
        return None
