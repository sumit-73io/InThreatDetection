from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    MONGODB_URL: str
    DATABASE_NAME: str
    gemini_api_key: str

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()