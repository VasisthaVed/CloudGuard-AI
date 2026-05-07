import os
from .litellm_adapter import LiteLLMAdapter
from .custom_adapter import CustomAdapter
from .anthropic_adapter import AnthropicAdapter
from .openai_adapter import OpenAIAdapter
from .gemini_adapter import GeminiAdapter
from .ollama_adapter import OllamaAdapter
from .xai_adapter import xAIAdapter
from .deepseek_adapter import DeepSeekAdapter

def get_provider():
    """
    Hybrid Factory for CloudGuard v2.0.
    
    Architecture:
    1. LiteLLM (Default): Universal support for 100+ providers.
    2. Native SDKs: Direct implementations (Anthropic, OpenAI, xAI, DeepSeek, etc.)
    3. Custom: Private enterprise endpoints.
    """
    choice = os.getenv("AI_PROVIDER", "litellm").lower().strip()
    
    # 1. Enterprise Custom
    if choice == "custom":
        return CustomAdapter()

    # 1.5. Legacy alias
    if choice == "openrouter":
        # Provide a default OpenRouter model if the user didn't set LITELLM_MODEL
        model = os.getenv("LITELLM_MODEL", "openrouter/anthropic/claude-3-haiku")
        return LiteLLMAdapter(model_override=model)
        
    # 2. Auto-detection mode
    if choice == "auto":
        if os.getenv("ANTHROPIC_API_KEY"): return AnthropicAdapter()
        if os.getenv("OPENAI_API_KEY"):    return OpenAIAdapter()
        if os.getenv("GEMINI_API_KEY"):    return GeminiAdapter()
        if os.getenv("XAI_API_KEY"):       return xAIAdapter()
        if os.getenv("DEEPSEEK_API_KEY"):  return DeepSeekAdapter()
        return OllamaAdapter()

    # 2. Native SDK Fallbacks
    native_map = {
        "anthropic": AnthropicAdapter,
        "openai":    OpenAIAdapter,
        "gemini":    GeminiAdapter,
        "ollama":    OllamaAdapter,
        "xai":       xAIAdapter,
        "deepseek":  DeepSeekAdapter
    }
    
    if choice in native_map:
        return native_map[choice]()

    # 3. LiteLLM Universal (Default)
    return LiteLLMAdapter()
