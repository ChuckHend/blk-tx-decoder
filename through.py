# System import
import sys
import argparse
import time
import logging
import os

# Local import
from uxto_memory import Uxto
from block import BlockFile

parser = argparse.ArgumentParser()
parser.add_argument("--db_name", '-db', help="Sqlite db name, like uxto.db")
parser.add_argument("--block_path", '-p', help="Bitcoin block data path")
parser.add_argument("--start_idx", '-s', help="Start block idx", default=0, type=int)
parser.add_argument("--end_idx", '-e', help="End block idx", default=32, type=int)
args = parser.parse_args()

# Log related configuration
logger = logging.getLogger(args.db_name.split(os.sep)[-1])
logger.setLevel(logging.DEBUG)
# create file handler which logs even debug messages
fh = logging.FileHandler('%s.log' % args.db_name.split(os.sep)[-1])
fh.setLevel(logging.INFO)
# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s \n %(message)s')
fh.setFormatter(formatter)
ch.setFormatter(formatter)
# add the handlers to the logger
logger.addHandler(fh)
logger.addHandler(ch)


def run():
    """ Go through all the txs in blocks. """
    if len(sys.argv) < 2:
        print('Usage: through.py block_path start_block_num end_block_num sql_db_path')
    else:
        # UXTO pool
        # key:tx_hash+idx, value: value of this output.
        uxto = Uxto(args.db_name)
        # The cache used to hold the tx that not in order.
        # key: tx_hash+idx
        uk_hask_key_set = set()
        block_counter = 0
        tx_counter = 0
        update_time = time.time() - time.time()
        iter_time = time.time() - time.time()
        io_time = time.time() - time.time()
        time_start = time.time()
        for i in range(args.start_idx, args.end_idx):
            block_file_name = "%s\\blk%05d.dat" % (args.block_path, i)
            block_file = BlockFile(block_file_name)
            for block in block_file.get_next_block():
                io_time = io_time + time.time() - time_start
                if block_counter % 100 == 0:
                    previous_hash = block.block_header.previous_hash
                    uxto_info = uxto.info()
                    commit_counter = uxto.commit()
                    logger.info("%d:%d %s tx_c:%d uxto_c:%d uk:%d v:%d cm:%d u_t:%.3f i_t:%.3f o_t:%.3f" % (
                        i,                     # blk index
                        block_counter,         # block index
                        previous_hash,         # The has of previous block.
                        block.tx_count,        # tx count in this block
                        uxto_info[0],          # size of uxto
                        len(uk_hask_key_set),  # size of unknown
                        uxto_info[1] / 100000000 if uxto_info[1] else 0,    # bitcoin value
                        commit_counter,        # tx change number
                        update_time,           # update Sqlite time
                        iter_time,             # iterate data time
                        io_time,               # read block time
                    ))
                    # reset
                    update_time, iter_time, io_time = 0, 0, 0

                block_counter += 1

                input_set = set()
                output_dict = {}

                time_start = time.time()
                # Collect all input and output.
                for tx in block.txs:
                    tx_counter = tx_counter + 1
                    for inp in tx.inputs:
                        if 0xffffffff != inp.tx_outId:  # not a coinbase
                            # If the tx input is in this block, obliterate the input and uxto
                            if (inp.prev_hash, inp.tx_outId) in output_dict.keys():
                                output_dict.pop((inp.prev_hash, inp.tx_outId))
                            else:
                                input_set.add((inp.prev_hash, inp.tx_outId))
                    for out in tx.outputs:
                        if (tx.tx_hash, out.idx) in uk_hask_key_set:
                            uk_hask_key_set.remove((tx.tx_hash, out.idx))
                        elif out.value > 0:  # ignore the place holder output case.
                            output_dict[(tx.tx_hash, out.idx)] = out.value
                iter_time = iter_time + time.time() - time_start

                time_start = time.time()
                # Adjust the uxto pool and uk_hask_key_set
                for uk_uxto_key in uxto.clear(input_set):
                    # print(" add %s" % uk_uxto_key)
                    uk_hask_key_set.add(uk_uxto_key)
                uxto.insert(output_dict)

                update_time = update_time + time.time() - time_start

                # Prepare to calculate the io_time.
                time_start = time.time()


if __name__ == '__main__':
    run()
