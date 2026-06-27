import os
import logging
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from auth.models import UserAPIKey
from auth.crypto import decrypt_key

from .base import AIProvider, AIAnalysisResult

logger = logging.getLogger("aegisml.ai.manager")

class AIProviderManager:
    @staticmethod
    async def get_provider(
        provider_name: str,
        model_name: Optional[str] = None,
        user_id: Optional[str] = None,
        db: Optional[AsyncSession] = None,
        plain_key: Optional[str] = None
    ) -> AIProvider:
        
        api_key = plain_key
        
        if not api_key and user_id and db:
            stmt = select(UserAPIKey).where(
                UserAPIKey.user_id == user_id,
                UserAPIKey.provider == provider_name,
                UserAPIKey.is_active == True
            )
            result = await db.execute(stmt)
            user_key_record = result.scalar_one_or_none()
            if user_key_record:
                try:
                    api_key = decrypt_key(user_key_record.encrypted_key)
                except Exception as e:
                    logger.error(f"Failed to decrypt key for user {user_id}: {e}")
                    
        if not api_key:
            if provider_name == "openai":
                api_key = os.getenv("OPENAI_API_KEY")
            elif provider_name == "google":
                api_key = os.getenv("GOOGLE_API_KEY")
            elif provider_name == "anthropic":
                api_key = os.getenv("ANTHROPIC_API_KEY")
            elif provider_name == "ollama":
                api_key = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

        if not api_key:
            raise ValueError(f"No API key available for provider '{provider_name}'. Please provide a valid key.")

        if provider_name == "openai":
            from .openai_provider import OpenAIProvider
            return OpenAIProvider(api_key, model_name or "gpt-4o")
        elif provider_name == "google":
            from .google_provider import GoogleProvider
            return GoogleProvider(api_key, model_name or "gemini-1.5-pro")
        elif provider_name == "anthropic":
            from .anthropic_provider import AnthropicProvider
            return AnthropicProvider(api_key, model_name or "claude-3-5-sonnet-20240620")
        elif provider_name == "ollama":
            from .ollama_provider import OllamaProvider
            return OllamaProvider(api_key, model_name or "llama3")
        else:
            raise ValueError(f"Unsupported AI provider: {provider_name}")
