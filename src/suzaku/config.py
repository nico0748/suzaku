"""Suzaku 設定 (pydantic-settings)。

環境変数 / `.env` から設定を読み込む。シークレットはここに直接書かない。
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Suzaku 全体の設定。"""

    model_config = SettingsConfigDict(
        env_prefix="SUZAKU_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    github_token: str | None = None
    notion_token: str | None = None
    notion_targets_db_id: str | None = None
    notion_disclosure_db_id: str | None = None

    data_dir: Path = Field(default=Path("./.suzaku"))
    evidence_dir: Path = Field(default=Path("./evidence"))
    pocs_dir: Path = Field(default=Path("./pocs"))

    log_level: str = "INFO"


_settings: Settings | None = None


def get_settings() -> Settings:
    """設定をシングルトンとして取得する。"""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    """テスト用: シングルトンを破棄して再ロードを促す。"""
    global _settings
    _settings = None
