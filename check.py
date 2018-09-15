#!/usr/bin/python
import sys
from block import BlockFile
import datetime

# python 

def main():
  if len(sys.argv) < 2:
    print('Usage: check.py block_path start_block_num end_block_num')
  else:
    for i in range(int(sys.argv[2]), int(sys.argv[3])):
      block_file_name = "%s\\blk%05d.dat" % (sys.argv[1], i)
      block_file = BlockFile(block_file_name)

      block_counter = 0
      for block in block_file.get_next_block():
        if block_counter % 1 == 0:
          previous_hash = block.block_header.previous_hash
          print("%d\t%d\t%s\t%d\t%s" % (i, block_counter, previous_hash, block.tx_count, datetime.datetime.now().strftime("%x %X")))
        block_counter += 1

if __name__ == '__main__':
  main()
