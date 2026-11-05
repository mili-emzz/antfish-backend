from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "AntFish API"
    MONGODB_URL: str = "mongodb://localhost:27017"
    DATABASE_NAME: str = "antfish_db"
    REDIS_URL: str = "redis://localhost:6379"
    HMAC_PEPPER: str = "default_pepper"
    RESEND_API_KEY: str = ""
    EMAIL_FROM: str = "AntFish <onboarding@resend.dev>"

    class Config:
        env_file = ".env"


settings = Settings()
