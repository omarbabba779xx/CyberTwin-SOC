"""SQLAlchemy engine + session factory.

DATABASE_URL env var controls the backend:
  - PostgreSQL (production):  postgresql+psycopg2://user:pass@host:5432/cybertwin
  - SQLite (demo/dev):        sqlite:///./data/cybertwin.db  (default)
"""

from __future__ import annotations

import os
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

_DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./data/cybertwin.db")

_connect_args: dict = {}
if _DATABASE_URL.startswith("sqlite"):
    _connect_args["check_same_thread"] = False

engine = create_engine(
    _DATABASE_URL,
    connect_args=_connect_args,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency: yield a DB session and close it after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
