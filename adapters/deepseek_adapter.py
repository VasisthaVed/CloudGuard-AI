import os
from .base import BaseAdapter, retry_on_failure

class DeepSeekAdapter(BaseAdapter):
    """
    Native DeepSeek Adapter (Chinese AI).
    """

    def __init__(self):
        self.api_key = os.getenv("DEEPSEEK_API_KEY")
        self.model = "deepseek-chat"

    @retry_on_failure()
    def complete(self, prompt: str, system_prompt: str, max_tokens: int = 500) -> str:
        try:
            from openai import OpenAI
            if not self.api_key:
                return "Error: DEEPSEEK_API_KEY not found."
            
            client = OpenAI(
                base_url="https://api.deepseek.com",
                api_key=self.api_key,
            )
            
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
            return f"DeepSeek Error: {str(e)}"

    @retry_on_failure()
    def chat(self, messages: list[dict]) -> str:
        try:
            from openai import OpenAI
            if not self.api_key:
                return "Error: DEEPSEEK_API_KEY not found."
            
            client = OpenAI(
                base_url="https://api.deepseek.com",
                api_key=self.api_key,
            )
            
            response = client.chat.completions.create(
                model=self.model,
                max_tokens=1000,
                messages=messages
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"DeepSeek Chat Error: {str(e)}"

    def get_name(self) -> str:
        return f"DeepSeek ({self.model})"
