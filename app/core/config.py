from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "AntFish API"
    MONGODB_URL: str = "mongodb://localhost:27017"
    DATABASE_NAME: str = "antfish_db"
    REDIS_URL: str = "redis://localhost:6379"
    HMAC_PEPPER: str = "default_pepper"
    RESEND_API_KEY: str = ""
    EMAIL_FROM: str = "no-reply@antfish.xyz"

    # JWT Settings (RF-06.8, RNF-03)
    JWT_SECRET: str = "antfish_jwt_secret_key_change_in_production"
    JWT_REFRESH_SECRET: str = "antfish_jwt_refresh_secret_key_change_in_production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
