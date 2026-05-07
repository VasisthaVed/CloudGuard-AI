import os
import requests
from .base import BaseAdapter, retry_on_failure

class CustomAdapter(BaseAdapter):
    """
    The Custom API Adapter — allows any company to plug in their internal LLM endpoint.
    Supports both OpenAI and Anthropic request formats.
    """

    def __init__(self):
        self.url = os.getenv("CUSTOM_API_URL")
        self.key = os.getenv("CUSTOM_API_KEY")
        self.header_name = os.getenv("CUSTOM_API_HEADER", "Authorization")
        self.model_name = os.getenv("CUSTOM_MODEL_NAME", "custom-model")
        self.format = os.getenv("CUSTOM_REQUEST_FORMAT", "openai").lower()

    def _get_headers(self):
        headers = {}
        if self.key:
            # If header is Authorization, use Bearer token format
            if self.header_name == "Authorization":
                headers[self.header_name] = f"Bearer {self.key}"
            else:
                headers[self.header_name] = self.key
        return headers

    @retry_on_failure()
    def complete(self, prompt: str, system_prompt: str, max_tokens: int = 500) -> str:
        if not self.url:
            return "Error: CUSTOM_API_URL not set."
            
        try:
            if self.format == "openai":
                payload = {
                    "model": self.model_name,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt}
                    ],
                    "max_tokens": max_tokens
                }
            elif self.format == "anthropic":
                payload = {
                    "model": self.model_name,
                    "system": system_prompt,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": max_tokens
                }
            else:
                return f"Error: Unsupported CUSTOM_REQUEST_FORMAT '{self.format}'."

            response = requests.post(self.url, json=payload, headers=self._get_headers(), timeout=30)
            response.raise_for_status()
            
            # Simple parsing — might need adjustment based on specific API
            data = response.json()
            if self.format == "openai":
                return data["choices"][0]["message"]["content"]
            else:
                return data["content"][0]["text"]
                
        except Exception as e:
            return f"Custom API Error: {str(e)}"

    @retry_on_failure()
    def chat(self, messages: list[dict]) -> str:
        if not self.url:
            return "Error: CUSTOM_API_URL not set."
            
        try:
            if self.format == "openai":
                payload = {
                    "model": self.model_name,
                    "messages": messages,
                    "max_tokens": 1000
                }
            elif self.format == "anthropic":
                # Extract system
                system = ""
                chat_msgs = []
                for m in messages:
                    if m["role"] == "system":
                        system = m["content"]
                    else:
                        chat_msgs.append(m)
                payload = {
                    "model": self.model_name,
                    "system": system,
                    "messages": chat_msgs,
                    "max_tokens": 1000
                }
            else:
                return f"Error: Unsupported CUSTOM_REQUEST_FORMAT '{self.format}'."

            response = requests.post(self.url, json=payload, headers=self._get_headers(), timeout=60)
            response.raise_for_status()
            
            data = response.json()
            if self.format == "openai":
                return data["choices"][0]["message"]["content"]
            else:
                return data["content"][0]["text"]
                
        except Exception as e:
            return f"Custom API Chat Error: {str(e)}"

    def get_name(self) -> str:
        return f"Custom ({self.model_name})"
