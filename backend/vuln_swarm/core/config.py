from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import AnyHttpUrl, Field, field_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Vuln-Swarm"
    environment: str = "development"
    frontend_origin: str = "http://localhost:5173"
    cors_origins: list[str] = Field(default_factory=list)

    data_dir: Path = Field(default=Path(".data"), alias="VULN_SWARM_DATA_DIR")
    chroma_dir: Path = Field(default=Path(".data/chroma"), alias="CHROMA_DIR")
    runs_dir_name: str = "runs"
    worktrees_dir_name: str = "worktrees"

    knowledge_paths: list[Path] = Field(
        default_factory=lambda: [
            Path("Vurnabilities .pdf"),
            Path("Vurnabilities Solutions.pdf"),
            Path("knowledge"),
        ]
    )
    embedding_model: str = Field(
        default="sentence-transformers/all-MiniLM-L6-v2",
        alias="EMBEDDING_MODEL",
    )
    retrieval_top_k: int = Field(default=4, alias="RETRIEVAL_TOP_K")

    gemini_api_key: str | None = Field(default=None, alias="GEMINI_API_KEY")
    gemini_model: str = Field(default="gemini-3-flash-preview", alias="GEMINI_MODEL")
    gemini_temperature: float = Field(default=0.2, alias="GEMINI_TEMPERATURE")
    gemini_base_url: AnyHttpUrl = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
    gemini_timeout_seconds: float = 60.0
    gemini_max_tokens: int = 4096

    github_token: str | None = Field(default=None, alias="GITHUB_TOKEN")
    github_default_base_branch: str = Field(default="main", alias="GITHUB_DEFAULT_BASE_BRANCH")

    max_retry_count: int = Field(default=2, alias="MAX_RETRY_COUNT")
    max_files_per_scan: int = 1500
    max_file_bytes: int = 600_000
    max_exploit_executions: int = 5

    sandbox_docker_image: str = Field(default="python:3.12-slim", alias="SANDBOX_DOCKER_IMAGE")
    sandbox_timeout_seconds: int = Field(default=60, alias="SANDBOX_TIMEOUT_SECONDS")
    sandbox_memory: str = "512m"
    sandbox_cpus: str = "1.0"
    sandbox_network_disabled: bool = True

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (init_settings, dotenv_settings)

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, value: Any) -> list[str]:
        if value is None or value == "":
            return []
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return list(value)

    @property
    def runs_dir(self) -> Path:
        return self.data_dir / self.runs_dir_name

    @property
    def worktrees_dir(self) -> Path:
        return self.data_dir / self.worktrees_dir_name

    @property
    def resolved_cors_origins(self) -> list[str]:
        origins = self.cors_origins or [self.frontend_origin, "http://127.0.0.1:5173"]
        return [origin for origin in origins if origin != "*"]

    def ensure_directories(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.chroma_dir.mkdir(parents=True, exist_ok=True)
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self.worktrees_dir.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.ensure_directories()
    return settings
