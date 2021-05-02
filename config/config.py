import os

from dotenv import load_dotenv

env = os.environ["ENVIRONMENT"].lower()
load_dotenv(f"config/environment.{env}")
load_dotenv(f"config/secrets")

DYNAMODB_TABLE = os.environ["DYNAMODB_TABLE"]

print(f"ENV: {env} -- DynamoDB_Table: {DYNAMODB_TABLE}")

AWS_ACCESS_KEY_ID=os.environ["AWS_ACCESS_KEY_ID"]
AWS_SECRET_ACCESS_KEY=os.environ["AWS_SECRET_ACCESS_KEY"]
AWS_DEFAULT_REGION=os.environ["AWS_DEFAULT_REGION"]

PG_USER = os.environ["PG_USER"]
PG_PASSWORD = os.environ["PG_PASSWORD"]
PG_HOST = os.environ["PG_HOST"]
PG_PORT = os.environ["PG_PORT"]
PG_DATABASE = os.environ["PG_DATABASE"]
PG_SCHEMA = os.environ["PG_SCHEMA"]