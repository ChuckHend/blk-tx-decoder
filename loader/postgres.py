import logging
from sqlalchemy import create_engine
import psycopg2

from config.config import (
    PG_DATABASE,
    PG_HOST,
    PG_PASSWORD,
    PG_PORT,
    PG_USER,
    PG_SCHEMA
)

logger = logging.getLogger(__name__)

def pg_conn():
    conn = psycopg2.connect(
        database=PG_DATABASE,
        user=PG_USER,
        password=PG_PASSWORD,
        host=PG_HOST,
        port=PG_PORT,
    )
    return conn

def connect_pg(timeout=10):
    connection_str = "{}://{}:{}@{}:{}/{}".format(
        "postgresql", PG_USER, PG_PASSWORD, PG_HOST, PG_PORT, PG_DATABASE
    )
    return create_engine(
        connection_str,
        connect_args={"connect_timeout": timeout},
        pool_pre_ping=True
    )

def init_pg():
    engine = connect_pg()
    
    logger.info(f"Initializing postgres: {engine}")
    with engine.connect() as connection:
        # base schema
        connection.execute(
            f"CREATE SCHEMA IF NOT EXISTS {PG_SCHEMA};"
        )
        connection.execute(
            f"""
                CREATE TABLE IF NOT EXISTS {PG_SCHEMA}.filesystem_meta (
                    blk_file varchar(10) not null UNIQUE,
                    ts timestamp default current_timestamp
                )
            """
        )
        connection.execute(f'''
            CREATE TABLE IF NOT EXISTS {PG_SCHEMA}.blocks (
                ts timestamp not null,
                tx_hash varchar not null,
                num_inputs integer not null,
                inputs jsonb not null,
                num_outputs integer not null,
                outputs jsonb not null,
                output_value_satoshis bigint not null
                );
            '''
        )
