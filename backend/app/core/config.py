from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Richmond Sarpong CyberTech 360"
    app_env: str = "development"
    api_v1_prefix: str = "/api/v1"
    secret_key: str = "change-this-before-production"
    access_token_expire_minutes: int = 60
    database_url: str = "postgresql+psycopg://cybertech360:cybertech360_dev_password@db:5432/cybertech360"
    cors_origins: str = "http://localhost:5500,http://127.0.0.1:5500,http://localhost:8000"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @property
    def cors_origin_list(self) -> List[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
