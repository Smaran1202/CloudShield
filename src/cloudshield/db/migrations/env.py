from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

from cloudshield.config import Settings
from cloudshield.db.models import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

engine = create_engine(Settings().database_url, poolclass=pool.NullPool)
with engine.connect() as connection:
    context.configure(connection=connection, target_metadata=Base.metadata)
    with context.begin_transaction():
        context.run_migrations()
