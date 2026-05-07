from abc import ABC, abstractmethod
import time
import functools

def retry_on_failure(retries=3, delay=1, backoff=2):
    """
    Decorator for retrying API calls with exponential backoff.
    Works with adapter methods that return strings (where errors start with "Error" or the provider name).
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            mtries, mdelay = retries, delay
            while mtries > 0:
                result = func(*args, **kwargs)
                # Check if the result string looks like an error
                # We target transient issues (rate limits, timeouts) which usually contain these keywords
                is_error = any(kw in result.lower() for kw in ["error", "timeout", "rate limit", "overloaded", "connection"])
                # But don't retry if it's a config/auth error which are usually permanent
                is_permanent = any(kw in result.lower() for kw in ["auth", "key not found", "invalid model", "permission"])
                
                if not is_error or is_permanent or mtries == 1:
                    return result
                
                time.sleep(mdelay)
                mtries -= 1
                mdelay *= backoff
            return result
        return wrapper
    return decorator

class BaseAdapter(ABC):
    """
    Abstract Base Class for all AI providers in CloudGuard AI.
    Ensures a consistent interface for one-shot completions and multi-turn chat.
    """

    @abstractmethod
    def complete(self, prompt: str, system_prompt: str, max_tokens: int = 500) -> str:
        """
        Performs a one-shot completion. Used for generating remediation advice for findings.
        
        Args:
            prompt: The user-facing prompt (the finding details).
            system_prompt: The instructions for the AI model.
            max_tokens: Maximum length of the response.
            
        Returns:
            The raw text response from the model or an error message.
        """
        pass

    @abstractmethod
    def chat(self, messages: list[dict]) -> str:
        """
        Performs a multi-turn chat completion. Used for CloudGuard Chat Mode.
        
        Args:
            messages: A list of message dicts in the format:
                      [{"role": "system", "content": "..."}, {"role": "user", "content": "..."}]
                      
        Returns:
            The raw text response from the model or an error message.
        """
        pass

    @abstractmethod
    def get_name(self) -> str:
        """
        Returns the friendly name of the model/provider for display in UI headers.
        """
        pass
