# System import
import sys
import argparse
import time
import logging
import os

# Local import
from uxto import Uxto
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


def uxto_key(tx_hash, idx):
    return "%s:%d" % (tx_hash, idx)


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
                    time_start = time.time()
                    uxto.commit()
                    commit_time = time.time() - time_start
                    logger.info("%d:%d %s tx_c:%d uxto_c:%d uk:%d v:%d u_t:%.3f i_t:%.3f o_t:%.3f c_t:%.3f" % (
                        i,                     # blk index
                        block_counter,         # block index
                        previous_hash,         # The has of previous block.
                        block.tx_count,        # tx count in this block
                        uxto_info[0],          # size of uxto
                        len(uk_hask_key_set),  # size of unknown
                        uxto_info[1] / 100000000 if uxto_info[1] else 0,
                        update_time,           # update Sqlite time
                        iter_time,             # iterate data time
                        io_time,               # read block time
                        commit_time            # Sqlite commit time
                    ))
                    # reset
                    update_time = time.time() - time.time()
                    iter_time = time.time() - time.time()
                    io_time = time.time() - time.time()

                    if block_counter % 10000 == 0:
                        logger.debug("Start to vacuum sqlite db.")
                        uxto.vacuum()
                block_counter += 1

                input_set = set()
                output_dict = {}

                time_start = time.time()
                # Collect all input and output.
                for tx in block.txs:
                    for inp in tx.inputs:
                        if 0xffffffff != inp.tx_outId:  # not a coinbase
                            inp_oxto_key = uxto_key(inp.prev_hash, inp.tx_outId)
                            # If the tx input is in this block, obliterate the input and uxto
                            if inp_oxto_key in output_dict.keys():
                                output_dict.pop(inp_oxto_key)
                            else:
                                input_set.add(inp_oxto_key)
                    for out in tx.outputs:
                        out_uxto_key = uxto_key(tx.tx_hash, out.idx)
                        if out_uxto_key in uk_hask_key_set:
                            uk_hask_key_set.remove(out_uxto_key)
                        elif out.value > 0:  # ignore the place holder output case.
                            output_dict[out_uxto_key] = out.value
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
