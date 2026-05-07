import os
from .base import BaseAdapter, retry_on_failure

class AnthropicAdapter(BaseAdapter):
    """
    Native Anthropic Adapter (Pure SDK).
    Used as a fallback or for users who prefer direct SDK access.
    """

    def __init__(self):
        self.api_key = os.getenv("ANTHROPIC_API_KEY")
        self.model = "claude-3-haiku-20240307"

    @retry_on_failure()
    def complete(self, prompt: str, system_prompt: str, max_tokens: int = 500) -> str:
        try:
            from anthropic import Anthropic
            if not self.api_key:
                return "Error: ANTHROPIC_API_KEY not found."
            
            client = Anthropic(api_key=self.api_key)
            response = client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system_prompt,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text
        except Exception as e:
            return f"Anthropic Error: {str(e)}"

    @retry_on_failure()
    def chat(self, messages: list[dict]) -> str:
        try:
            from anthropic import Anthropic
            if not self.api_key:
                return "Error: ANTHROPIC_API_KEY not found."
            
            client = Anthropic(api_key=self.api_key)
            
            # Extract system prompt
            system = ""
            chat_msgs = []
            for m in messages:
                if m["role"] == "system":
                    system = m["content"]
                else:
                    chat_msgs.append(m)

            response = client.messages.create(
                model=self.model,
                max_tokens=1000,
                system=system,
                messages=chat_msgs
            )
            return response.content[0].text
        except Exception as e:
            return f"Anthropic Chat Error: {str(e)}"

    def get_name(self) -> str:
        return f"Anthropic ({self.model})"
