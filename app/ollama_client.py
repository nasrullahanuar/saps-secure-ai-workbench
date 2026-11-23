"""Minimal Ollama adapter pinned to the configured local endpoint."""

from app.config import Settings


class LocalOllamaClient:
    def __init__(self, settings: Settings):
        if settings.ollama_url != "http://127.0.0.1:11434":
            raise ValueError("Only the local Ollama endpoint is allowed")
        import ollama

        self.chat_model = settings.ollama_model
        self.embedding_model = settings.ollama_embedding_model
        self.client = ollama.Client(host=settings.ollama_url, timeout=120, trust_env=False)

    def embed(self, texts: list[str]) -> list[list[float]]:
        response = self.client.embed(model=self.embedding_model, input=texts)
        embeddings = response.embeddings if hasattr(response, "embeddings") else response["embeddings"]
        return [list(vector) for vector in embeddings]

    def chat(self, messages: list[dict[str, str]]) -> str:
        response = self.client.chat(model=self.chat_model, messages=messages, stream=False)
        message = response.message if hasattr(response, "message") else response["message"]
        return message.content if hasattr(message, "content") else message["content"]
