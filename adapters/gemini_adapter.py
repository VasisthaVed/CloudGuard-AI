import os
from .base import BaseAdapter, retry_on_failure

class GeminiAdapter(BaseAdapter):
    """
    Native Google Gemini Adapter (Pure SDK).
    """

    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY")
        self.model = "gemini-1.5-flash"

    @retry_on_failure()
    def complete(self, prompt: str, system_prompt: str, max_tokens: int = 500) -> str:
        try:
            import google.generativeai as genai
            if not self.api_key:
                return "Error: GEMINI_API_KEY not found."
            
            genai.configure(api_key=self.api_key)
            model = genai.GenerativeModel(
                model_name=self.model,
                system_instruction=system_prompt
            )
            response = model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Gemini Error: {str(e)}"

    @retry_on_failure()
    def chat(self, messages: list[dict]) -> str:
        try:
            import google.generativeai as genai
            if not self.api_key:
                return "Error: GEMINI_API_KEY not found."
            
            genai.configure(api_key=self.api_key)
            
            # Reconstruct history for Gemini SDK
            history = []
            for m in messages[:-1]: # All but last
                role = "model" if m["role"] == "assistant" else "user"
                if m["role"] != "system":
                    history.append({"role": role, "parts": [m["content"]]})
            
            # Find system prompt
            system = next((m["content"] for m in messages if m["role"] == "system"), "")
            
            model = genai.GenerativeModel(model_name=self.model, system_instruction=system)
            chat = model.start_chat(history=history)
            
            last_msg = messages[-1]["content"]
            response = chat.send_message(last_msg)
            return response.text
        except Exception as e:
            return f"Gemini Chat Error: {str(e)}"

    def get_name(self) -> str:
        return f"Gemini ({self.model})"
