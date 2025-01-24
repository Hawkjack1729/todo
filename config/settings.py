import os

from dotenv import load_dotenv
from pydantic import Extra
from pydantic_settings import BaseSettings

# Explicitly load environment variables from the .env file
load_dotenv()


class Settings(BaseSettings):
    # MySQL Database Configuration
    DB_USER: str = os.getenv("DB_USER", "root")
    DB_PASSWORD: str = os.getenv("DB_PASSWORD", "")
    DB_HOST: str = os.getenv("DB_HOST", "localhost")
    DB_NAME: str = os.getenv("DB_NAME", "todoapp")

    # Construct SQLAlchemy MySQL connection string
    DATABASE_URL: str = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"

    # JWT and other settings remain the same
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret-key")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = Extra.allow  # Allow extra fields


settings = Settings()
