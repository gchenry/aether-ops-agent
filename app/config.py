import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    PROJECT_ID: str = os.getenv("PROJECT_ID", "your-gcp-project-id")
    LOCATION: str = os.getenv("LOCATION", "global")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
    SESSION_STORE_URI: str = os.getenv("SESSION_STORE_URI", "memory://local")
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    ENFORCE_SPIFFE_AUTH: bool = os.getenv("ENFORCE_SPIFFE_AUTH", "true").lower() == "true"
    EXPECTED_SPIFFE_ID: str = os.getenv("EXPECTED_SPIFFE_ID", "spiffe://aether.internal/ns/devops/sa/release-gate")
    PORT: int = int(os.getenv("PORT", "8080"))

settings = Settings()

