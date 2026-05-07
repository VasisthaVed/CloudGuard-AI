import os
import litellm
from .base import BaseAdapter, retry_on_failure

class LiteLLMAdapter(BaseAdapter):
    """
    Universal adapter using LiteLLM to support 100+ AI providers 
    (Claude, GPT, Gemini, Mistral, Ollama, etc.) with a single interface.
    """

    def __init__(self, model_override: str = None):
        # Priority: constructor arg > LITELLM_MODEL env > default
        self.model = model_override or os.getenv("LITELLM_MODEL", "anthropic/claude-3-5-sonnet-20240620")
        
        # LiteLLM handles the specific API keys from environment variables 
        # (e.g., ANTHROPIC_API_KEY, OPENAI_API_KEY) automatically.

    @retry_on_failure(retries=3, delay=1, backoff=2)
    def complete(self, prompt: str, system_prompt: str, max_tokens: int = 500) -> str:
        try:
            response = litellm.completion(
                model=self.model,
                max_tokens=max_tokens,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ]
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"LiteLLM Error ({self.model}): {str(e)}"

    @retry_on_failure(retries=3, delay=1, backoff=2)
    def chat(self, messages: list[dict]) -> str:
        try:
            response = litellm.completion(
                model=self.model,
                messages=messages
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"LiteLLM Chat Error ({self.model}): {str(e)}"

    def get_name(self) -> str:
        return f"LiteLLM ({self.model})"
