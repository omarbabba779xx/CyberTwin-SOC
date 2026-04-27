"""SQLAlchemy database layer.

Provides a production-ready ORM foundation on top of the existing SQLite
helper in backend/database.py. Switch to PostgreSQL by setting DATABASE_URL
in your environment:

    DATABASE_URL=postgresql+psycopg2://user:pass@localhost:5432/cybertwin

SQLite is used as a fallback for demo / local development:

    DATABASE_URL=sqlite:///./data/cybertwin.db  (default)
"""

from .session import engine, SessionLocal, get_db

__all__ = ["engine", "SessionLocal", "get_db"]
