"""OpenAI-compatible chat client (works with Ollama's /v1 API or a hosted provider).

The model receives tool schemas and returns proposed calls. It never receives
gateway, database, or OPA credentials.
"""
import os

import httpx


class ModelClient:
    def __init__(self, base_url: str | None = None, model: str | None = None,
                 api_key: str | None = None, timeout: float = 180.0):
        self.base_url = (base_url or os.environ.get("MODEL_BASE_URL", "http://localhost:11434/v1")).rstrip("/")
        self.model = model or os.environ.get("MODEL_NAME", "llama3.1:8b")
        self.api_key = api_key or os.environ.get("MODEL_API_KEY", "ollama")
        self._http = httpx.AsyncClient(timeout=timeout)

    async def respond(self, messages: list[dict], tools: list[dict]) -> dict:
        response = await self._http.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={"model": self.model, "messages": messages, "tools": tools, "temperature": 0},
        )
        response.raise_for_status()
        return response.json()["choices"][0]["message"]

    async def aclose(self) -> None:
        await self._http.aclose()
