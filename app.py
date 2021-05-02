from loader.postgres import init_pg, connect_pg
import os
from decoder.bitcoin import (
    decode_blk_file,
    parse_input,
    diff_sql
)
from loader.celery import celery_app

if __name__ == "__main__":

    init_pg()
    input_dir, output_dir = parse_input()

    todo_list = diff_sql(input_dir)

    print({
        "NUM_FILES": len(todo_list),
    })

    for i in todo_list:
        # decode_blk_file(i)
        decode_blk_file.apply_async(
            kwargs={"input_file": i},
            queue="BLOCKS"
        )
