"""Typed settings from the environment.

Two database URLs, deliberately. ``DATABASE_URL_APP`` belongs to a role that is *not* the
table owner and holds no UPDATE or DELETE on ``decision_records``; ``DATABASE_URL_MIGRATE``
belongs to the owner and is used by migrations and tests only. If the API ever connects
with the migrate DSN the append-only property silently disappears, so the two are kept as
separate settings rather than one string with a comment.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    env: str = Field(default="local", alias="DWAAR_ENV")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    # The API's connection. Non-owner role: SELECT+INSERT on decision_records only.
    database_url_app: str = Field(
        default="postgresql://dwaar_app:app_pw@localhost:5432/dwaar",
        alias="DATABASE_URL_APP",
    )
    # Owner role. Migrations and tests. NEVER the API.
    database_url_migrate: str = Field(
        default="postgresql://dwaar_owner:owner_pw@localhost:5432/dwaar",
        alias="DATABASE_URL_MIGRATE",
    )
    # Superuser. The day-6 tamper demo only — the tamper must succeed at the database
    # so the chain verifier is what catches it. See THREAT_MODEL.md.
    database_url_superuser: str = Field(
        default="postgresql://postgres:postgres_pw@localhost:5432/dwaar",
        alias="DATABASE_URL_SUPERUSER",
    )

    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")

    pool_min_size: int = Field(default=2, alias="POOL_MIN_SIZE")
    pool_max_size: int = Field(default=10, alias="POOL_MAX_SIZE")

    # Threat 12: request size cap. Enforced in middleware from day 1, not day 13.
    max_body_bytes: int = Field(default=64 * 1024, alias="MAX_BODY_BYTES")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
