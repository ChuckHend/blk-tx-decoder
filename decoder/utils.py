from datetime import datetime
from dataclasses import dataclass
import base58
import binascii
import hashlib
import json
import logging
import mmap
import os
import struct
import sys

from pgcopy import CopyManager
import pandas as pd
from sqlalchemy.types import JSON

from config.config import (
    PG_SCHEMA,
)
from decoder.constants import *
from loader.postgres import pg_conn, connect_pg


@dataclass
class BlockFile:
    block_filename: str

    transactions: list[dict] = None
    block_file_identifier: str = None
    blockchain: mmap.mmap = None

    def __post_init__(self):

        with open(self.block_filename, 'rb', buffering=16 * 1024 * 1024) as f:
            size = os.path.getsize(f.name)
            self.blockchain = mmap.mmap(f.fileno(), size, access=mmap.ACCESS_READ)

    def get_next_block(self):
        while True:
            block = Block(self.blockchain)
            if block.is_ready:
                yield block
            else:
                break
    
    def get_all_blocks(self) -> None:
        block_dat_file_num = self.block_filename.split("/")[-1].replace("blk", "").replace(".dat", "")
        all_results = []
        for i_b, block in enumerate(self.get_next_block()):
            block_js = block.to_json()
            utc_time = datetime.utcfromtimestamp(block.block_header.time)
            ts = utc_time.strftime("%Y-%m-%d %H:%M:%S")
            tx_list = block_js["txs"]
            # merkle = block.block_header.merkle_hash
            for t in tx_list:
                all_results.append({
                    "ts": utc_time,
                    # "blk_file": block_dat_file_num,
                    # "merkle": merkle,
                    "tx_hash": t["tx_hash"],
                    "num_inputs": t["num_inputs"],
                    "inputs": json.dumps(t["inputs"]),
                    "num_outputs": t["num_outputs"],
                    "outputs": json.dumps(t["outputs"]),
                    "output_value_satoshis": t["output_value"]
                })
        self.transactions = all_results
        self.block_file_identifier = block_dat_file_num

    def to_pandas(self):
        return pd.DataFrame(self.transactions)

    def to_sql(self):
        engine = connect_pg()
        df = self.to_pandas()
        block_file_df = pd.DataFrame({"blk_file": self.block_file_identifier}, index=[0])
        logging.info(f"NUM_ROWS_TO_SQL: {df.shape[0]}")
        with engine.begin() as con:
            block_file_df.to_sql(
                "filesystem_meta",
                con=con,
                schema=PG_SCHEMA,
                if_exists="append",
                index=False
            )
            df\
                .drop_duplicates(subset=['tx_hash'])\
                .to_sql(
                    "blocks",
                    schema=PG_SCHEMA,
                    con=con,
                    if_exists="append",
                    index=False,
                    dtype={
                        'outputs': JSON,
                        'inputs': JSON,
                        }
                )

    def pg_copy(self):

        df = self.to_pandas().drop_duplicates(subset=['tx_hash'])
        cols = list(df.columns)
        num_rows = df.shape[0]
        transactions = df.to_dict(orient="records")
        rows = []
        for i in transactions:
            record = []
            for k, v in i.items():
                if isinstance(v, str):
                    use_val = v.encode("utf-8")
                else:
                    use_val = v
                record.append(use_val)
            rows.append(
                tuple(record)
            )
        num_rows = len(rows)
        logging.info(f"NUM_ROWS_TO_PG_COPY: {num_rows}")

        with pg_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"INSERT INTO filesystem_meta (blk_file) VALUES('{self.block_file_identifier}')"
            )
            mgr = CopyManager(conn, 'blocks', cols)
            mgr.copy(rows)

class BlockHeader:
    def __init__(self, blockchain):
        self.version = uint4(blockchain)
        self.previous_hash = hashStr(hash32(blockchain))
        self.merkle_hash = hashStr(hash32(blockchain))
        self.time = uint4(blockchain)
        self.bits = uint4(blockchain)
        self.nonce = uint4(blockchain)

    def to_json(self):
        return {
            "ver": self.version,
            "prev_hash": self.previous_hash,
            "merkle_root": self.merkle_hash,
            "timestamp": self.decode_time(self.time),
            "difficulty": self.bits,
            "nonce": self.nonce
        }

    def decode_time(self, time):
        utc_time = datetime.utcfromtimestamp(time)
        return utc_time.strftime("%Y-%m-%d %H:%M:%S.%f+00:00 (UTC)")


class Block:
    def __init__(self, blockchain):
        self.blockchain = blockchain
        self.is_ready = True
        self.magic_num = 0
        self.block_size = 0
        self.block_header = ''
        self.tx_count = 0
        self.txs = []

        if self.has_length(8):
            self.magic_num = uint4(self.blockchain)
            self.block_size = uint4(self.blockchain)
        else:
            self.is_ready = False
            return

        if self.has_length(self.block_size):
            self.set_header()
            self.tx_count = varint(self.blockchain)
            self.txs = []
        else:
            self.is_ready = False

        self.tx_pos = self.blockchain.tell()
        for i in range(0, self.tx_count):
            tx = Tx(self.blockchain)
            self.txs.append(tx)

    def get_block_size(self):
        return self.block_size

    def has_length(self, size):
        cur_pos = self.blockchain.tell()
        self.blockchain.seek(0, 2)
        total_file_size = self.blockchain.tell()
        self.blockchain.seek(cur_pos)

        if total_file_size - cur_pos < size:
            return False
        else:
            return True

    def set_header(self):
        self.block_header = BlockHeader(self.blockchain)
    
    def to_json(self):
        return {
            "magic_no": self.magic_num,
            "block_size": self.block_size,
            "block_header": self.block_header.to_json(),
            "tx_count": self.tx_count,
            "txs": [t.to_json() for t in self.txs],
        }

class Tx:
    def __init__(self, blockchain):
        start_pos = blockchain.tell()
        self.version = uint4(blockchain)
        check_pos = blockchain.tell()

        # Segwit - https://en.bitcoin.it/wiki/Transaction
        # BIP141 - https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#specification
        tx_in_pos = blockchain.tell()
        marker = uint1(blockchain)
        flag = uint1(blockchain)
        is_segwit = False
        if marker != 0 or flag != 1:
            blockchain.seek(check_pos)
        else:
            is_segwit = True
            tx_in_pos = blockchain.tell()

        self.inCount = varint(blockchain)
        self.inputs = []
        self.seq = 1
        for i in range(0, self.inCount):
            self.inputs.append(TxInput(blockchain, i))
        self.outCount = varint(blockchain)
        self.outputs = []
        if self.outCount > 0:
            for i in range(0, self.outCount):
                self.outputs.append(TxOutput(blockchain, i))
        segwit_pos = blockchain.tell()
        # For segwit
        if is_segwit:
            for i in range(0, self.inCount):
                num_op = varint(blockchain)
                for n in range(0, num_op):
                    op_code = varint(blockchain)
                    _ = hashStr(blockchain.read(op_code))
        raw_lock_time = blockchain.read(4)
        self.lock_time = struct.unpack('I', raw_lock_time)[0]
        cur_pos = blockchain.tell()
        blockchain.seek(start_pos)
        if is_segwit:
            raw_version = blockchain.read(4)
            blockchain.read(2)
            raw_in_out = blockchain.read(segwit_pos - tx_in_pos)
            self.raw_bytes = raw_version + raw_in_out + raw_lock_time
        else:
            self.raw_bytes = blockchain.read(cur_pos - start_pos)
        blockchain.seek(cur_pos)
        self.tx_hash = hash_tx(self.raw_bytes)
    
    def to_json(self):
        return {
            "seq": self.seq,
            "tx_hash": self.tx_hash,
            "num_inputs": self.inCount,
            "inputs": [i.to_json() for i in self.inputs],
            "num_outputs": self.outCount,
            "outputs": [i.to_json() for i in self.outputs],
            "lock_time": self.lock_time,
            "output_value": sum([o.value for o in self.outputs])
        }


class TxInput:
    def __init__(self, blockchain, idx):
        self.idx = idx
        self.prev_hash = hashStr(hash32(blockchain))
        self.tx_outId = uint4(blockchain)
        self.script_len = varint(blockchain)
        self.script_sig = blockchain.read(self.script_len)
        self.seqNo = uint4(blockchain)
        self.decode_script_sig(self.script_sig)
    
    def to_json(self):
        return {
            "prev_hash": self.prev_hash,
            "prev_idx": self.idx,
            # "script_len": self.script_len,
            "hex_str": self.hex_str,
            # "PubKey": self.pub_key,
            "addr": pubkey_to_address(self.hex_str[2:2 + int(self.hex_str[0:2], 16) * 2])[0],
            # "seq": self.seqNo
        }

    def decode_script_sig(self, data):
        sb = []
        self.hex_str = hashStr(data)
        # segwit
        if len(self.hex_str) == 0:
            self.pub_key = ""
            return
        if 0xffffffff == self.tx_outId:  # Coinbase
            self.pub_key = str(bytes.fromhex(self.hex_str))
            return
        script_len = int(self.hex_str[0:2], 16)
        script_len *= 2
        script = self.hex_str[2:2 + script_len]
        sb.append("  Script: " + script)
        try:
            if SIGHASH_ALL != int(self.hex_str[script_len:script_len + 2], 16):  # should be 0x01
                self.pub_key = ""
            else:
                self.pub_key = self.hex_str[2 + script_len + 2:2 + script_len + 2 + 66]
        except:
            self.pub_key = ""

    def decode_out_idx(self, idx):
        sb = []
        s = ""
        if idx == 0xffffffff:
            sb.append("  [Coinbase] Text: %s" % self.prev_hash)
        else:
            sb.append("  Prev. Tx Hash: %s" % self.prev_hash)
        return "%8x" % idx, sb


class TxOutput:
    def __init__(self, blockchain, idx):
        self.idx = idx
        self.value = uint8(blockchain)
        self.script_len = varint(blockchain)
        self.pubkey = blockchain.read(self.script_len)
        self.addr = "UNKNOWN"
        self.decode_scriptpubkey(self.pubkey)
    
    def to_json(self):
        return {
            "value_satoshi": self.value,
            # "script_len": self.script_len,
            # "ScriptPubKey": self.addr,
            "addr": self.addr
        }

    def decode_scriptpubkey(self, data):
        ''' https://en.bitcoin.it/wiki/Script '''
        hexstr = hashStr(data) 
        # Get the first two bytes.
        # which might some problem.
        # https://www.blockchain.com/btc/tx/7bd54def72825008b4ca0f4aeff13e6be2c5fe0f23430629a9d484a1ac2a29b8
        try:
            op_idx = int(hexstr[0:2], 16)
        except:
            self.type = "EXCEPTION"
            self.addr = "UNKNOWN"
            return
        try:
            op_code = OPCODE_NAMES[op_idx]
        except KeyError:
            if op_idx == 65:
                self.type = "P2PK"
                # Obsoleted pay to pubkey directly
                # For detail see: https://en.bitcoin.it/wiki/Script#Obsolete_pay-to-pubkey_transaction
                pub_key_len = op_idx
                op_code_tail = OPCODE_NAMES[int(hexstr[2 + pub_key_len * 2:2 + pub_key_len * 2 + 2], 16)]
                self.pubkey_human = "Pubkey OP_CODE: None Bytes:%s tail_op_code:%s %d" % (
                pub_key_len, op_code_tail, op_idx)
                self.addr = pubkey_to_address(hexstr[2:2 + pub_key_len * 2])[0]
            else:
                # Some times people will push data directly
                # e.g: https://www.blockchain.com/btc/tx/d65bb24f6289dad27f0f7e75e80e187d9b189a82dcf5a86fb1c6f8ff2b2c190f
                self.type = "UN"
                pub_key_len = op_idx
                self.pubkey_human = "PUSH_DATA:%s" % hexstr[2:2 + pub_key_len * 2]
                self.addr = "UNKNOWN"
            return
        try:
            if op_code == "OP_DUP":
                self.type = "P2PKHA"
                # P2PKHA pay to pubkey hash mode
                # For detail see: https://en.bitcoin.it/wiki/Script#Standard_Transaction_to_Bitcoin_address_.28pay-to-pubkey-hash.29
                op_code2 = OPCODE_NAMES[int(hexstr[2:4], 16)]
                pub_key_len = int(hexstr[4:6], 16)
                op_code_tail2 = OPCODE_NAMES[int(hexstr[6 + pub_key_len * 2:6 + pub_key_len * 2 + 2], 16)]
                op_code_tail_last = OPCODE_NAMES[int(hexstr[6 + pub_key_len * 2 + 2:6 + pub_key_len * 2 + 4], 16)]
                self.pubkey_human = "%s %s %s %s %s" % (
                op_code, op_code2, hexstr[6:6 + pub_key_len * 2], op_code_tail2, op_code_tail_last)
                self.addr = gen_addr(hexstr[6:6 + pub_key_len * 2])[0]
            elif op_code == "OP_HASH160":
                self.type = "P2SH"
                # P2SHA pay to script hash
                # https://en.bitcoin.it/wiki/Transaction#Pay-to-Script-Hash
                pub_key_len = int(hexstr[2:4], 16)
                op_code_tail = OPCODE_NAMES[int(hexstr[4 + pub_key_len * 2:4 + pub_key_len * 2 + 2], 16)]
                hash_code = hexstr[4:4 + pub_key_len * 2]
                self.pubkey_human = "%s %s %s" % (op_code, hash_code, op_code_tail)
                self.addr = hash_code
            elif op_code == "OP_RETURN":
                self.type = "OP_RETURN"
                pub_key_len = int(hexstr[2:4], 16)
                hash_code = hexstr[4:4 + pub_key_len * 2]
                self.pubkey_human = "OP_RETURN %s" % (hash_code)
                self.addr = hash_code
            else:  # TODO extend for multi-signature parsing
                self.type = "UN"
                self.pubkey_human = "Need to extend multi-signaturer parsing %x" % int(hexstr[0:2], 16) + op_code
                self.addr = "UNKNOWN"
        except:
            self.type = "ERROR"
            self.addr = "UNKNOWN"

def publicKeyDecode(pub):
    pub = pub[2:-2]
    hash1 = hashlib.sha256(binascii.unhexlify(pub))
    hash2 = hashlib.new('ripemd160', hash1.digest())
    padded = (b'\x00') + hash2.digest()
    hash3 = hashlib.sha256(padded)
    hash4 = hashlib.sha256(hash3.digest())
    padded += hash4.digest()[:4]
    return base58.b58encode(padded)

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
    sha.update(bytearray.fromhex(key_hash))
    checksum = sha.digest()
    sha = hashlib.sha256()
    sha.update(checksum)
    checksum = sha.hexdigest()[0:8]
    address = (base58.b58encode(bytes(bytearray.fromhex(key_hash + checksum)))).decode('utf-8')
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

