import struct
from hashlib import sha256


def uint1(stream):
  return ord(stream.read(1))


def uint2(stream):
  # H represents unsigned short
  return struct.unpack('H', stream.read(2))[0]


def uint4(stream):
  # I represents unsigned int
  return struct.unpack('I', stream.read(4))[0]


def uint8(stream):
  # Q represents unsigned long long
  return struct.unpack('Q', stream.read(8))[0]


def hash4(stream):
  return stream.read(8)


def hash32(stream):
  # follow the practice in blockchain.info and blockexplorer.com
  return stream.read(32)[::-1]


def time(stream):
  time = uint4(stream)
  return time


def varint(stream):
  size = uint1(stream)

  if size < 0xfd:
    return size
  if size == 0xfd:
    return uint2(stream)
  if size == 0xfe:
    return uint4(stream)
  if size == 0xff:
    return uint8(stream)
  return -1

def hash_tx(tx_bytes):
  hash_bytes = sha256(sha256(tx_bytes).digest()).digest()[::-1]
  return hashStr(hash_bytes)

def hashStr(bytes):
  return ''.join(("%02x" % a) for a in bytes)

def convert_hex_to_ascii(h):
  chars_in_reverse = []
  while h != 0x0:
    chars_in_reverse.append(chr(h & 0xFF))
    h = h >> 8

  chars_in_reverse.reverse()
  return ''.join(chars_in_reverse)
