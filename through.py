import sys
from block import BlockFile
import datetime
from uxto import Uxto

def uxto_key(tx_hash, idx):
  return "%s:%d" % (tx_hash, idx)

def run():
  """ Go through all the txs in blocks. """
  if len(sys.argv) < 2:
    print('Usage: through.py block_path start_block_num end_block_num sql_db_path')
  else:
    # UXTO pool
    # key:tx_hash+idx, value: value of this output.
    uxto = Uxto(sys.argv[4])
    # The cache used to hold the tx that not in order.
    # key: tx_hash+idx
    uk_hask_key_set = set()
    block_counter = 0
    for i in range(int(sys.argv[2]), int(sys.argv[3])):
      block_file_name = "%s\\blk%05d.dat" % (sys.argv[1], i)
      block_file = BlockFile(block_file_name)
      for block in block_file.get_next_block():
        if block_counter % 100 == 0:
          previous_hash = block.block_header.previous_hash
          uxto_info = uxto.info()
          print("%s %d:%d %s tx_c:%d uxto_c:%d uk:%d v:%d" % (
            datetime.datetime.now().strftime("%x %X"),
            i,                  # blk index
            block_counter,      # block index
            previous_hash,      # The has of previous block.
            block.tx_count,     # tx count in this block
            uxto_info[0],       # size of uxto
            len(uk_hask_key_set),        # size of unknown
            uxto_info[1]/100000000 if uxto_info[1] else 0))
        block_counter += 1

        input_set = set()
        output_dict = {}
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
              print(" del %s" % out_uxto_key)
              uk_hask_key_set.remove(out_uxto_key)
            elif out.value > 0:             # ignore the place holder output case.
              output_dict[out_uxto_key] = out.value

        # Adjust the uxto pool and uk_hask_key_set
        for uk_uxto_key in uxto.clear(input_set):
          print(" add %s" % uk_uxto_key)
          uk_hask_key_set.add(uk_uxto_key)
        uxto.insert(output_dict)


if __name__ == '__main__':
  run()

