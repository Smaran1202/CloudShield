from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker


def make_engine(database_url: str) -> Engine:
    if database_url.startswith("sqlite"):
        # The scan runs in its own thread and uses its own session.
        # timeout is how many seconds a writer waits for another one before "database is locked".
        return create_engine(database_url, connect_args={"check_same_thread": False, "timeout": 5})
    return create_engine(database_url)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False)
