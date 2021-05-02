from dataclasses import dataclass
from datetime import datetime
from typing import List
import os
import sys
import logging
import json

from pgcopy import CopyManager
import pandas as pd
from sqlalchemy.types import JSON

from loader.postgres import pg_conn

from decoder.BTC import BlockFile
from loader.postgres import connect_pg, PG_SCHEMA, PG_DATABASE

logging.basicConfig(level=logging.DEBUG,
                    format='%(message)s %(threadName)s %(processName)s',
                    )

@dataclass
class BitcoinBlockFile:
    file_path: str

    transactions: List[dict] = None
    block_file_identifier: str = None
    blockfile: BlockFile = None

    def __post_init__(self):
        block_file = BlockFile(self.file_path)
        block_dat_file_num = self.file_path.split("/")[-1].replace("blk", "").replace(".dat", "")
        all_results = []
        for i_b, block in enumerate(block_file.get_next_block()):
            block_js = block.to_json()
            utc_time = datetime.utcfromtimestamp(block.block_header.time)
            ts = utc_time.strftime("%Y-%m-%d %H:%M:%S")
            tx_list = block_js["txs"]
            # merkle = block.block_header.merkle_hash
            for t in tx_list:
                all_results.append({
                    "ts": utc_time,
                    # "blk_file": block_dat_file_num,
                    # "merkle": merkle,
                    "tx_hash": t["tx_hash"],
                    "num_inputs": t["num_inputs"],
                    "inputs": json.dumps(t["inputs"]),
                    "num_outputs": t["num_outputs"],
                    "outputs": json.dumps(t["outputs"]),
                    "output_value_satoshis": t["output_value"]
                })
        self.blockfile = block_file
        self.transactions = all_results
        self.block_file_identifier = block_dat_file_num
    
    def to_pandas(self):
        return pd.DataFrame(self.transactions)

    def to_sql(self):
        engine = connect_pg()
        df = self.to_pandas()
        block_file_df = pd.DataFrame({"blk_file": self.block_file_identifier}, index=[0])
        logging.info(f"NUM_ROWS_TO_SQL: {df.shape[0]}")
        with engine.begin() as con:
            block_file_df.to_sql(
                "filesystem_meta",
                con=con,
                schema=PG_SCHEMA,
                if_exists="append",
                index=False
            )
            df\
                .drop_duplicates(subset=['tx_hash'])\
                .to_sql(
                    "blocks",
                    schema=PG_SCHEMA,
                    con=con,
                    if_exists="append",
                    index=False,
                    dtype={
                        'outputs': JSON,
                        'inputs': JSON,
                        }
                )

    def pg_copy(self):

        df = self.to_pandas().drop_duplicates(subset=['tx_hash'])
        cols = list(df.columns)
        num_rows = df.shape[0]
        transactions = df.to_dict(orient="records")
        rows = []
        for i in transactions:
            record = []
            for k, v in i.items():
                if isinstance(v, str):
                    use_val = v.encode("utf-8")
                else:
                    use_val = v
                record.append(use_val)
            rows.append(
                tuple(record)
            )
        num_rows = len(rows)
        logging.info(f"NUM_ROWS_TO_PG_COPY: {num_rows}")

        with pg_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"INSERT INTO filesystem_meta (blk_file) VALUES('{self.block_file_identifier}')"
            )
            mgr = CopyManager(conn, 'blocks', cols)
            mgr.copy(rows)


def parse_input() -> tuple:
    input_dir = os.environ["BTC_INPUT_DIRECTORY"]
    output_dir = os.environ["BTC_OUTPUT_DIRECTORY"]
    logging.info({
        "BTC_INPUT_DIRECTORY": input_dir,
        "BTC_OUTPUT_DIRECTORY": output_dir
    })
    if not os.path.exists(output_dir):
        logging.info(f"Created {output_dir} because it did not exist!")
        os.makedirs(output_dir)

    return input_dir, output_dir


def diff_blk_files(input_dir, output_dir):
    input_list = os.listdir(input_dir)
    input_list = [x for x in input_list if (x.endswith('.dat') and x.startswith('blk'))]
    todo = [x.replace(".dat", "") for x in input_list]

    output_list = os.listdir(output_dir)
    output_list = [x for x in output_list if (x.endswith('.json') and x.startswith('blk'))]
    completed = [x.replace("_parsed.json", "") for x in output_list]

    todo_actual = []
    for t in todo:
        if t in completed:
            logging.info(f"{t} COMPLETED...skipping")
        else:
            todo_actual.append(t)

    paths = [f"{input_dir}/{x}.dat" for x in todo_actual]

    if len(paths) == 0:
        logging.info("No files to process")
        sys.exit(0)
    paths.sort()
    return paths


def diff_sql(input_dir):
    engine = connect_pg()
    with engine.connect() as connection:
        # base schema
        rows = connection.execute(f"""
            SELECT blk_file
            FROM {PG_SCHEMA}.filesystem_meta
        """
        ).fetchall()
    blk_file_complete = [x[0] for x in rows]
    logging.info({
        "NUM_COMPLETED_FILES": len(blk_file_complete)
    })

    input_list = os.listdir(input_dir)
    input_list = [x for x in input_list if (x.endswith('.dat') and x.startswith('blk'))]
    maybe_todo = [x.replace(".dat", "").replace("blk", "") for x in input_list]

    todo = [x for x in maybe_todo if x not in blk_file_complete]
    paths = [f"{input_dir}/blk{x}.dat" for x in todo]

    if len(paths) == 0:
        logging.info("No files to process")
        sys.exit(0)
    paths.sort()

    return paths

from loader.celery import celery_app, CallbackTask
import time

@celery_app.task(base=CallbackTask)
def decode_blk_file(input_file):
    logging.info(f"STARTING: {input_file}")
    start = time.time()
    block_obj = BitcoinBlockFile(file_path=input_file)
    block_duration = time.time() - start

    sql_start = time.time()
    block_obj.pg_copy()
    sql_insert_duration = time.time() - sql_start
    logging.info({
        "COMPLETED": input_file,
        "BLOCK_DURATION": block_duration,
        "SQL_INSERT_DURATION": sql_insert_duration
    })