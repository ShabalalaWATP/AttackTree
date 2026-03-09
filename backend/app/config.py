from pydantic_settings import BaseSettings
from pathlib import Path
import os


class Settings(BaseSettings):
    APP_NAME: str = "AttackTree Builder"
    APP_VERSION: str = "1.0.0"
    DATABASE_URL: str = "sqlite+aiosqlite:///./attacktree.db"
    SECRET_KEY: str = "change-me-in-production-use-a-real-secret"
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]
    DATA_DIR: Path = Path(os.path.dirname(os.path.abspath(__file__))) / "data"
    UPLOAD_DIR: Path = Path("./uploads")
    MAX_UPLOAD_SIZE: int = 50 * 1024 * 1024  # 50MB
    LOG_LEVEL: str = "INFO"

    model_config = {"env_prefix": "ATB_", "env_file": ".env"}


settings = Settings()
