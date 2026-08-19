import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_ENV: str = "development"
    APP_NAME: str = "GRC Privileged Access Review Engine"
    DEBUG: bool = True
    DATABASE_URL: str = "sqlite:///./grc_control.db"
    
    DEFAULT_REVIEW_MAX_AGE_DAYS: int = 90
    INACTIVE_THRESHOLD_DAYS: int = 30
    SECRET_KEY: str = "super-secret-local-prototype-key"
    
    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
