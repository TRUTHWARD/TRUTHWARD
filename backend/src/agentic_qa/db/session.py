# SPDX-License-Identifier: Apache-2.0
from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from agentic_qa.infra.settings import get_settings


settings = get_settings()


def database_engine_kwargs(config: object) -> dict[str, object]:
    database_url = str(getattr(config, "database_url"))
    kwargs: dict[str, object] = {
        "future": True,
        "pool_pre_ping": True,
    }
    if database_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in database_url:
            kwargs["poolclass"] = StaticPool
        return kwargs
    kwargs.update(
        pool_size=int(getattr(config, "database_pool_size")),
        max_overflow=int(getattr(config, "database_max_overflow")),
        pool_timeout=float(getattr(config, "database_pool_timeout_seconds")),
    )
    return kwargs

engine_kwargs = database_engine_kwargs(settings)
engine = create_engine(settings.database_url, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, class_=Session)


def get_db_session() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
