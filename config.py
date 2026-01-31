from pydantic_settings import BaseSettings
class Settings(BaseSettings):
    DATABASE_URL: str = 'postgresql://postgres:xpXazbwNkoyFiLwtWlRqIgXHnZoXxLCG@nozomi.proxy.rlwy.net:11350/railway'
class Config:
        env_file = ".env"
        case_sensitive = True
# singleton
settings = Settings()