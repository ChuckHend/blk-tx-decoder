#!/usr/bin/env python
# https://en.bitcoin.it/wiki/Protocol_documentation#Addresses

import hashlib
import base58
import struct


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
  hash_bytes = hashlib.sha256(hashlib.sha256(tx_bytes).digest()).digest()[::-1]
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

def gen_addr(hash_code):
    key_hash = '00' + hash_code
    # Obtain signature:
    sha = hashlib.sha256()
    sha.update( bytearray.fromhex(key_hash) )
    checksum = sha.digest()
    sha = hashlib.sha256()
    sha.update(checksum)
    checksum = sha.hexdigest()[0:8]
    address = (base58.b58encode( bytes(bytearray.fromhex(key_hash + checksum)))).decode('utf-8')
    return address, key_hash, checksum

def hash160(hex_str):
    """
    See 'compressed form' at https://en.bitcoin.it/wiki/Protocol_documentation#Signatures
    """
    sha = hashlib.sha256()
    rip = hashlib.new('ripemd160')
    sha.update(hex_str)
    rip.update(sha.digest())
    return rip.hexdigest()  # .hexdigest() is hex ASCII

def pubkey_to_address(pubkey):
    compress_pubkey = False
    if compress_pubkey:
        if ord(bytearray.fromhex(pubkey[-2:])) % 2 == 0:
            pubkey_compressed = '02'
        else:
            pubkey_compressed = '03'
        pubkey_compressed += pubkey[2:66]
        hex_str = bytearray.fromhex(pubkey_compressed)
    else:
        hex_str = bytearray.fromhex(pubkey)

    # Obtain key:
    return gen_addr(hash160(hex_str))


# address = RIPEMD160(SHA256(pubKey))
# Genesis 
# 04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f
# 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
# https://www.blockchain.com/btc/address/1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
if __name__=='__main__':
    pubkey = '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f'
    ret_value = pubkey_to_address(pubkey)
    print ( "checksum = \t" + ret_value[2] )
    print ( "key_hash = \t" + ret_value[1] )
    print ( "bitcoin address = \t" + ret_value[0])
    hash_code = '482f0027662731277fdfa3b7f639c976a3bab11e'
    print(gen_addr(hash_code)[0])

