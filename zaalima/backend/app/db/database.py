import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.core.config import get_settings

logger = logging.getLogger("zaalima.db")
settings = get_settings()

Base = declarative_base()


def get_engine(db_url: str):
    if db_url.startswith("sqlite"):
        return create_engine(
            db_url,
            connect_args={"check_same_thread": False},
        )
    return create_engine(
        db_url,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
        connect_args={"connect_timeout": 3},
    )


# Attempt initial engine setup with fallback
target_url = settings.database_url
try:
    if target_url.startswith("postgresql"):
        # Test connection with 3-second timeout
        test_engine = create_engine(
            target_url,
            pool_pre_ping=True,
            connect_args={"connect_timeout": 3},
        )
        with test_engine.connect() as conn:
            pass
        engine = test_engine
        logger.info(f"Connected to PostgreSQL database: {target_url.split('@')[-1] if '@' in target_url else target_url}")
    else:
        engine = get_engine(target_url)
except Exception as e:
    logger.warning(
        f"PostgreSQL connection to '{target_url}' could not be established ({e}). "
        f"Using local SQLite fallback 'sqlite:///./zaalima.db' so the application is fully operational."
    )
    target_url = "sqlite:///./zaalima.db"
    engine = get_engine(target_url)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables():
    """Create all database tables."""
    Base.metadata.create_all(bind=engine)
