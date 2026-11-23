"""Small, environment-based application configuration."""

from dataclasses import dataclass
import os
from pathlib import Path

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    database_url: str
    data_dir: Path
    ollama_url: str
    ollama_model: str
    ollama_embedding_model: str
    session_secret: str
    session_timeout_seconds: int


def get_settings() -> Settings:
    """Load settings, rejecting non-loopback model endpoints."""
    load_dotenv()
    ollama_url = os.getenv("SAPS_OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
    if ollama_url != "http://127.0.0.1:11434":
        raise ValueError("SAPS_OLLAMA_URL must point to the local Ollama service")

    return Settings(
        database_url=os.getenv("SAPS_DATABASE_URL", "sqlite:///data/saps.db"),
        data_dir=Path(os.getenv("SAPS_DATA_DIR", "data")),
        ollama_url=ollama_url,
        ollama_model=os.getenv("SAPS_OLLAMA_MODEL", "qwen2.5:3b"),
        ollama_embedding_model=os.getenv("SAPS_OLLAMA_EMBED_MODEL", "nomic-embed-text"),
        session_secret=os.getenv("SAPS_SESSION_SECRET", ""),
        session_timeout_seconds=int(os.getenv("SAPS_SESSION_TIMEOUT_SECONDS", "1800")),
    )
