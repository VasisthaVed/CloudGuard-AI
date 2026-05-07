import requests
import json
from .base import BaseAdapter, retry_on_failure

class OllamaAdapter(BaseAdapter):
    """
    Native Ollama Adapter (Local).
    """

    def __init__(self):
        self.url = "http://localhost:11434/api/chat"
        self.model = "llama3"

    @retry_on_failure()
    def complete(self, prompt: str, system_prompt: str, max_tokens: int = 500) -> str:
        try:
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ],
                "stream": False
            }
            response = requests.post(self.url, json=payload, timeout=60)
            response.raise_for_status()
            return response.json()["message"]["content"]
        except Exception as e:
            return f"Ollama Error: {str(e)}"

    @retry_on_failure()
    def chat(self, messages: list[dict]) -> str:
        try:
            payload = {
                "model": self.model,
                "messages": messages,
                "stream": False
            }
            response = requests.post(self.url, json=payload, timeout=120)
            response.raise_for_status()
            return response.json()["message"]["content"]
        except Exception as e:
            return f"Ollama Chat Error: {str(e)}"

    def get_name(self) -> str:
        return f"Ollama ({self.model})"
