import os
from pydantic_settings import BaseSettings, SettingsConfigDict

_ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_ENV_FILE = os.path.join(_ROOT_DIR, ".env")

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=_ENV_FILE, extra="ignore")

    PROJECT_ID: str = os.getenv("PROJECT_ID", "your-gcp-project-id")
    LOCATION: str = os.getenv("LOCATION", "global")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
    SESSION_STORE_URI: str = os.getenv("SESSION_STORE_URI", "memory://local")
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    ENFORCE_SPIFFE_AUTH: bool = os.getenv("ENFORCE_SPIFFE_AUTH", "true").lower() == "true"
    ENFORCE_MTLS: bool = os.getenv("ENFORCE_MTLS", "true").lower() == "true"
    EXPECTED_SPIFFE_ID: str = os.getenv("EXPECTED_SPIFFE_ID", "spiffe://aether.internal/ns/devops/sa/release-gate")
    MTLS_CERT_DIR: str = os.getenv("MTLS_CERT_DIR", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "certs")))
    PORT: int = int(os.getenv("PORT", "8080"))

settings = Settings()

