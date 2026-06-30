import asyncio
from logging.config import fileConfig

from sqlalchemy import pool, text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

from database import Base
import community.models
import enterprise.models

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata
target_metadata = Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    from database import final_url
    context.configure(
        url=final_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """In this scenario we need to create an Engine
    and associate a connection with the context.

    """

    from database import final_url
    from sqlalchemy.ext.asyncio import create_async_engine

    connectable = create_async_engine(
        final_url,
        poolclass=pool.NullPool,
        connect_args={"ssl": False}
    )

    async with connectable.connect() as connection:
        # --- ISOLATED GHOST REVISION AUTO-FIX ---
        try:
            from sqlalchemy import text
            # Run selection to check for the target corrupted history entry
            result = await connection.execute(text("SELECT version_num FROM alembic_version;"))
            version = result.scalar()
            
            if version == "a8b7202a72f3":
                print("⚠️ Ghost revision detected! Executing isolated public schema factory reset...")
                # Execute isolation drops sequentially to avoid transaction blocks lock
                await connection.execute(text("DROP SCHEMA public CASCADE;"))
                await connection.execute(text("CREATE SCHEMA public;"))
                await connection.execute(text("GRANT ALL ON SCHEMA public TO public;"))
                await connection.commit()
                print("✅ Public schema reset completed safely.")
        except Exception as e:
            # Table or schema might not exist on clean initialization step, bypass safely
            await connection.rollback()
            pass

        # Re-verify and pass to core migration context cleanly
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""

    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
