from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    MONGODB_URI: str
    DATABASE_NAME: str = "secure_cloud_storage"

    JWT_SECRET: str
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60

    SUPABASE_URL: str
    SUPABASE_SERVICE_ROLE_KEY: str
    SUPABASE_BUCKET_NAME: str = "secure-files"

    RSA_PRIVATE_KEY: str = ""
    HMAC_SECRET: str

    # Google Drive OAuth. Optional so the app still starts without them;
    # /google/* endpoints answer 503 until all four are set.
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/google/callback"
    GOOGLE_TOKEN_ENCRYPTION_KEY: str = ""  # base64 of 32 random bytes

    FRONTEND_URL: str = "http://localhost:5173"
    ADMIN_EMAIL: str = ""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()