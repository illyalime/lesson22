from pydantic_settings import BaseSettings
from pydantic import Field
class Settings(BaseSettings):
# App
# Security
    SECRET_KEY: str = Field(..., description="JWT secret")
# Database
    DATABASE_URL: str
class Config:
        env_file = ".env"
        case_sensitive = True
# singleton
settings = Settings()