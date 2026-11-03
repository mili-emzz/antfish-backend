from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "AntFish API"
    MONGODB_URL: str = "mongodb://localhost:27017"
    DATABASE_NAME: str = "antfish_db"

    class Config:
        env_file = ".env"

settings = Settings()