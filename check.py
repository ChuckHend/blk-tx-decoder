#!/usr/bin/python
import sys
from block import BlockFile

def main():
  if len(sys.argv) < 2:
    print('Usage: check.py block_path start_block_num end_block_num')
  else:
    for i in range(int(sys.argv[2]), int(sys.argv[3])):
      block_file_name = "%s\\blk%05d.dat" % (sys.argv[1], i)
      block_file = BlockFile(block_file_name)
      for block in block_file.get_next_block():
        previous_hash = block.block_header.previous_hash
        merkle_hash = block.block_header.merkle_hash
        print("%d\t%s\t%s" % (i, previous_hash, merkle_hash))

if __name__ == '__main__':
  main()
