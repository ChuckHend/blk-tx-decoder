#!/usr/bin/python
import sys
from block import BlockFile
from datetime import datetime

def main():
  if len(sys.argv) < 2:
    print('Usage: sight.py filename')
  else:
    block_file = BlockFile(sys.argv[1])
    for block in block_file.get_next_block():
       for tx in block.txs:
           utc_time = datetime.utcfromtimestamp(block.block_header.time)
           time_str = utc_time.strftime("%Y-%m-%d %H:%M:%S")
           for output in tx.outputs:
               print("%s\t%s\t%d\t%s\t%d" % (time_str, tx.tx_hash, output.idx, output.addr, output.value))


if __name__ == '__main__':
  main()
