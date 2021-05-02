import os
import sys
import logging

from dotenv import load_dotenv
load_dotenv(f"./.env")

try:
    PG_USER = os.environ["PG_USER"]
    PG_PASSWORD = os.environ["PG_PASSWORD"]
    PG_HOST = os.environ["PG_HOST"]
    PG_PORT = os.environ["PG_PORT"]
    PG_DATABASE = os.environ["PG_DATABASE"]
    PG_SCHEMA = os.environ["PG_SCHEMA"]
except KeyError:
    logging.exception(
        """Postgres credentials missing. Check secrets file at ./config/secrets"""
    )
    sys.exit(1)