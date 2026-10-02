from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker


def make_engine(database_url: str) -> Engine:
    if database_url.startswith("sqlite"):
        # The scan runs in its own thread and uses its own session.
        return create_engine(database_url, connect_args={"check_same_thread": False})
    return create_engine(database_url)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False)
