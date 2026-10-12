"""Alembic environment: knows about every model of every Saboss product."""

import os

from alembic import context

from saboss_platform import models  # noqa: F401  (registers core tables)
from saboss_platform.db import Base, make_engine
from saboss_platform.scan import models as scan_models  # noqa: F401  (registers Saboss Scan tables)

config = context.config
target_metadata = Base.metadata


def database_url() -> str:
    # An explicitly passed URL (tests, run_migrations) wins over the environment.
    configured = config.get_main_option("sqlalchemy.url")
    if config.attributes.get("explicit_url") or "SABOSS_DATABASE_URL" not in os.environ:
        return configured
    return os.environ["SABOSS_DATABASE_URL"]


def run_migrations_offline() -> None:
    context.configure(url=database_url(), target_metadata=target_metadata, literal_binds=True, render_as_batch=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = make_engine(database_url())
    with engine.connect() as connection:
        # render_as_batch lets SQLite alter tables in later migrations.
        context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
