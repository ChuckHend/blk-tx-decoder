#!/usr/bin/python
import sys
from block import BlockFile

def main():
  if len(sys.argv) < 2:
    print('Usage: sight.py filename')
  else:
    block_file = BlockFile(sys.argv[1])
    for block in block_file.get_next_block():
      previous_hash = block.block_header.previous_hash
      merkle_hash = block.block_header.merkle_hash
      print("%s\t%s" % (previous_hash, merkle_hash))

if __name__ == '__main__':
  main()
