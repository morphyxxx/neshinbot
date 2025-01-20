from pydantic import Field, HttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="NESHINBOT_")

    DEBUG: bool = Field(default=False)

    MARZNESHIN_BASE_URL: HttpUrl = Field("http://localhost:8000")
