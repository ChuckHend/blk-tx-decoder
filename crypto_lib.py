#!/usr/bin/env python
# https://en.bitcoin.it/wiki/Protocol_documentation#Addresses

import hashlib
import base58


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

# See 'compressed form' at https://en.bitcoin.it/wiki/Protocol_documentation#Signatures
def hash160(hex_str):
    sha = hashlib.sha256()
    rip = hashlib.new('ripemd160')
    sha.update(hex_str)
    rip.update(sha.digest())
    return rip.hexdigest()  # .hexdigest() is hex ASCII

def pubkey_to_address(pubkey):
    compress_pubkey = False
    if (compress_pubkey):
        if (ord(bytearray.fromhex(pubkey[-2:])) % 2 == 0):
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

