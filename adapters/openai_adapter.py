import os
from .base import BaseAdapter, retry_on_failure

class OpenAIAdapter(BaseAdapter):
    """
    Native OpenAI Adapter (Pure SDK).
    """

    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.model = "gpt-4o"

    @retry_on_failure()
    def complete(self, prompt: str, system_prompt: str, max_tokens: int = 500) -> str:
        try:
            from openai import OpenAI
            if not self.api_key:
                return "Error: OPENAI_API_KEY not found."
            
            client = OpenAI(api_key=self.api_key)
            response = client.chat.completions.create(
                model=self.model,
                max_tokens=max_tokens,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ]
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"OpenAI Error: {str(e)}"

    @retry_on_failure()
    def chat(self, messages: list[dict]) -> str:
        try:
            from openai import OpenAI
            if not self.api_key:
                return "Error: OPENAI_API_KEY not found."
            
            client = OpenAI(api_key=self.api_key)
            response = client.chat.completions.create(
                model=self.model,
                max_tokens=1000,
                messages=messages
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"OpenAI Chat Error: {str(e)}"

    def get_name(self) -> str:
        return f"OpenAI ({self.model})"
