"""
ARGUS shared config -- single source of truth for the Ollama endpoint.
Read from OLLAMA_BASE_URL (see .env.example), so every Qwen/embedding call
across the project can be pointed at a different Ollama instance (e.g. a
faster tunneled GPU instance) via one env var instead of editing every
file that used to hardcode "http://localhost:11434".
"""

import os

from dotenv import load_dotenv

load_dotenv()

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
OLLAMA_CHAT_URL = f"{OLLAMA_BASE_URL}/api/chat"
OLLAMA_EMBED_URL = f"{OLLAMA_BASE_URL}/api/embeddings"
OLLAMA_TAGS_URL = f"{OLLAMA_BASE_URL}/api/tags"

# The `ollama` Python package (used directly by agents/red.py, blue.py,
# challenger.py, memory/reflexion.py) reads OLLAMA_HOST itself. On this
# machine that's ALREADY set as a persistent Windows user/machine env var
# (0.0.0.0:11434 -- set by the native Ollama installer to control what
# interface `ollama serve` binds to) -- load_dotenv() never overrides an
# already-set OS env var by default, so .env's OLLAMA_HOST was silently
# ignored. 0.0.0.0 isn't even a valid address to *connect to* (only to
# bind), which is what actually broke (confirmed live: WinError 10049).
# Force it here so config.py stays the one real source of truth.
os.environ["OLLAMA_HOST"] = OLLAMA_BASE_URL
