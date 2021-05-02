from datetime import datetime
from dataclasses import dataclass
import base58
import binascii
import hashlib
import json
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
from loader.postgres import pg_conn, connect_pg

@dataclass
class BlockFile:
    block_filename: str

    transactions: list[dict] = None
    block_file_identifier: str = None

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
    
    def get_all_blocks(self):
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
            "pub_key_decoded": publicKeyDecode(self.hex_str).decode("utf-8"),
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
            "ScriptPubKey": self.addr,
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

# ===----------------------------------------------------------------------===

SIGHASH_ALL          = 0x01
SIGHASH_NONE         = 0x02
SIGHASH_SINGLE       = 0x03
SIGHASH_ANYONECANPAY = 0x80

TX_NONSTANDARD = 'non-standard'
TX_PUBKEY      = 'pubkey'
TX_PUBKEYHASH  = 'pubkey-hash'
TX_SCRIPTHASH  = 'script-hash'
TX_MULTISIG    = 'multi-sig'

# ===----------------------------------------------------------------------===

# push value
OP_0         = 0x00
OP_FALSE     = OP_0
OP_PUSHDATA1 = 0x4c
OP_PUSHDATA2 = 0x4d
OP_PUSHDATA4 = 0x4e
OP_1NEGATE   = 0x4f
OP_RESERVED  = 0x50
OP_1         = 0x51
OP_TRUE      = OP_1
OP_2         = 0x52
OP_3         = 0x53
OP_4         = 0x54
OP_5         = 0x55
OP_6         = 0x56
OP_7         = 0x57
OP_8         = 0x58
OP_9         = 0x59
OP_10        = 0x5a
OP_11        = 0x5b
OP_12        = 0x5c
OP_13        = 0x5d
OP_14        = 0x5e
OP_15        = 0x5f
OP_16        = 0x60

# control
OP_NOP      = 0x61
OP_VER      = 0x62
OP_IF       = 0x63
OP_NOTIF    = 0x64
OP_VERIF    = 0x65
OP_VERNOTIF = 0x66
OP_ELSE     = 0x67
OP_ENDIF    = 0x68
OP_VERIFY   = 0x69
OP_RETURN   = 0x6a

# stack ops
OP_TOALTSTACK   = 0x6b
OP_FROMALTSTACK = 0x6c
OP_2DROP        = 0x6d
OP_2DUP         = 0x6e
OP_3DUP         = 0x6f
OP_2OVER        = 0x70
OP_2ROT         = 0x71
OP_2SWAP        = 0x72
OP_IFDUP        = 0x73
OP_DEPTH        = 0x74
OP_DROP         = 0x75
OP_DUP          = 0x76
OP_NIP          = 0x77
OP_OVER         = 0x78
OP_PICK         = 0x79
OP_ROLL         = 0x7a
OP_ROT          = 0x7b
OP_SWAP         = 0x7c
OP_TUCK         = 0x7d

# splice ops
OP_CAT    = 0x7e
OP_SUBSTR = 0x7f
OP_LEFT   = 0x80
OP_RIGHT  = 0x81
OP_SIZE   = 0x82

# bit logic
OP_INVERT      = 0x83
OP_AND         = 0x84
OP_OR          = 0x85
OP_XOR         = 0x86
OP_EQUAL       = 0x87
OP_EQUALVERIFY = 0x88
OP_RESERVED1   = 0x89
OP_RESERVED2   = 0x8a

# numeric
OP_1ADD      = 0x8b
OP_1SUB      = 0x8c
OP_2MUL      = 0x8d
OP_2DIV      = 0x8e
OP_NEGATE    = 0x8f
OP_ABS       = 0x90
OP_NOT       = 0x91
OP_0NOTEQUAL = 0x92

OP_ADD    = 0x93
OP_SUB    = 0x94
OP_MUL    = 0x95
OP_DIV    = 0x96
OP_MOD    = 0x97
OP_LSHIFT = 0x98
OP_RSHIFT = 0x99

OP_BOOLAND            = 0x9a
OP_BOOLOR             = 0x9b
OP_NUMEQUAL           = 0x9c
OP_NUMEQUALVERIFY     = 0x9d
OP_NUMNOTEQUAL        = 0x9e
OP_LESSTHAN           = 0x9f
OP_GREATERTHAN        = 0xa0
OP_LESSTHANOREQUAL    = 0xa1
OP_GREATERTHANOREQUAL = 0xa2
OP_MIN                = 0xa3
OP_MAX                = 0xa4

OP_WITHIN = 0xa5

# crypto
OP_RIPEMD160           = 0xa6
OP_SHA1                = 0xa7
OP_SHA256              = 0xa8
OP_HASH160             = 0xa9
OP_HASH256             = 0xaa
OP_CODESEPARATOR       = 0xab
OP_CHECKSIG            = 0xac
OP_CHECKSIGVERIFY      = 0xad
OP_CHECKMULTISIG       = 0xae
OP_CHECKMULTISIGVERIFY = 0xaf

# expansion
OP_NOP1  = 0xb0
OP_NOP2  = 0xb1
OP_NOP3  = 0xb2
OP_NOP4  = 0xb3
OP_NOP5  = 0xb4
OP_NOP6  = 0xb5
OP_NOP7  = 0xb6
OP_NOP8  = 0xb7
OP_NOP9  = 0xb8
OP_NOP10 = 0xb9

# template matching params
OP_SMALLINTEGER = 0xfa
OP_PUBKEYS      = 0xfb
OP_PUBKEYHASH   = 0xfd
OP_PUBKEY       = 0xfe

OP_INVALIDOPCODE = 0xff

# ===----------------------------------------------------------------------===

VALID_OPCODES = set([
    OP_1NEGATE,
    OP_RESERVED,
    OP_1,
    OP_2,
    OP_3,
    OP_4,
    OP_5,
    OP_6,
    OP_7,
    OP_8,
    OP_9,
    OP_10,
    OP_11,
    OP_12,
    OP_13,
    OP_14,
    OP_15,
    OP_16,

    OP_NOP,
    OP_VER,
    OP_IF,
    OP_NOTIF,
    OP_VERIF,
    OP_VERNOTIF,
    OP_ELSE,
    OP_ENDIF,
    OP_VERIFY,
    OP_RETURN,

    OP_TOALTSTACK,
    OP_FROMALTSTACK,
    OP_2DROP,
    OP_2DUP,
    OP_3DUP,
    OP_2OVER,
    OP_2ROT,
    OP_2SWAP,
    OP_IFDUP,
    OP_DEPTH,
    OP_DROP,
    OP_DUP,
    OP_NIP,
    OP_OVER,
    OP_PICK,
    OP_ROLL,
    OP_ROT,
    OP_SWAP,
    OP_TUCK,

    OP_CAT,
    OP_SUBSTR,
    OP_LEFT,
    OP_RIGHT,
    OP_SIZE,

    OP_INVERT,
    OP_AND,
    OP_OR,
    OP_XOR,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_RESERVED1,
    OP_RESERVED2,

    OP_1ADD,
    OP_1SUB,
    OP_2MUL,
    OP_2DIV,
    OP_NEGATE,
    OP_ABS,
    OP_NOT,
    OP_0NOTEQUAL,

    OP_ADD,
    OP_SUB,
    OP_MUL,
    OP_DIV,
    OP_MOD,
    OP_LSHIFT,
    OP_RSHIFT,

    OP_BOOLAND,
    OP_BOOLOR,
    OP_NUMEQUAL,
    OP_NUMEQUALVERIFY,
    OP_NUMNOTEQUAL,
    OP_LESSTHAN,
    OP_GREATERTHAN,
    OP_LESSTHANOREQUAL,
    OP_GREATERTHANOREQUAL,
    OP_MIN,
    OP_MAX,

    OP_WITHIN,

    OP_RIPEMD160,
    OP_SHA1,
    OP_SHA256,
    OP_HASH160,
    OP_HASH256,
    OP_CODESEPARATOR,
    OP_CHECKSIG,
    OP_CHECKSIGVERIFY,
    OP_CHECKMULTISIG,
    OP_CHECKMULTISIGVERIFY,

    OP_NOP1,
    OP_NOP2,
    OP_NOP3,
    OP_NOP4,
    OP_NOP5,
    OP_NOP6,
    OP_NOP7,
    OP_NOP8,
    OP_NOP9,
    OP_NOP10,

    OP_SMALLINTEGER,
    OP_PUBKEYS,
    OP_PUBKEYHASH,
    OP_PUBKEY,
])

OPCODE_NAMES = {
    OP_0 : 'OP_0',
    OP_PUSHDATA1 : 'OP_PUSHDATA1',
    OP_PUSHDATA2 : 'OP_PUSHDATA2',
    OP_PUSHDATA4 : 'OP_PUSHDATA4',
    OP_1NEGATE : 'OP_1NEGATE',
    OP_RESERVED : 'OP_RESERVED',
    OP_1 : 'OP_1',
    OP_2 : 'OP_2',
    OP_3 : 'OP_3',
    OP_4 : 'OP_4',
    OP_5 : 'OP_5',
    OP_6 : 'OP_6',
    OP_7 : 'OP_7',
    OP_8 : 'OP_8',
    OP_9 : 'OP_9',
    OP_10 : 'OP_10',
    OP_11 : 'OP_11',
    OP_12 : 'OP_12',
    OP_13 : 'OP_13',
    OP_14 : 'OP_14',
    OP_15 : 'OP_15',
    OP_16 : 'OP_16',
    OP_NOP : 'OP_NOP',
    OP_VER : 'OP_VER',
    OP_IF : 'OP_IF',
    OP_NOTIF : 'OP_NOTIF',
    OP_VERIF : 'OP_VERIF',
    OP_VERNOTIF : 'OP_VERNOTIF',
    OP_ELSE : 'OP_ELSE',
    OP_ENDIF : 'OP_ENDIF',
    OP_VERIFY : 'OP_VERIFY',
    OP_RETURN : 'OP_RETURN',
    OP_TOALTSTACK : 'OP_TOALTSTACK',
    OP_FROMALTSTACK : 'OP_FROMALTSTACK',
    OP_2DROP : 'OP_2DROP',
    OP_2DUP : 'OP_2DUP',
    OP_3DUP : 'OP_3DUP',
    OP_2OVER : 'OP_2OVER',
    OP_2ROT : 'OP_2ROT',
    OP_2SWAP : 'OP_2SWAP',
    OP_IFDUP : 'OP_IFDUP',
    OP_DEPTH : 'OP_DEPTH',
    OP_DROP : 'OP_DROP',
    OP_DUP : 'OP_DUP',
    OP_NIP : 'OP_NIP',
    OP_OVER : 'OP_OVER',
    OP_PICK : 'OP_PICK',
    OP_ROLL : 'OP_ROLL',
    OP_ROT : 'OP_ROT',
    OP_SWAP : 'OP_SWAP',
    OP_TUCK : 'OP_TUCK',
    OP_CAT : 'OP_CAT',
    OP_SUBSTR : 'OP_SUBSTR',
    OP_LEFT : 'OP_LEFT',
    OP_RIGHT : 'OP_RIGHT',
    OP_SIZE : 'OP_SIZE',
    OP_INVERT : 'OP_INVERT',
    OP_AND : 'OP_AND',
    OP_OR : 'OP_OR',
    OP_XOR : 'OP_XOR',
    OP_EQUAL : 'OP_EQUAL',
    OP_EQUALVERIFY : 'OP_EQUALVERIFY',
    OP_RESERVED1 : 'OP_RESERVED1',
    OP_RESERVED2 : 'OP_RESERVED2',
    OP_1ADD : 'OP_1ADD',
    OP_1SUB : 'OP_1SUB',
    OP_2MUL : 'OP_2MUL',
    OP_2DIV : 'OP_2DIV',
    OP_NEGATE : 'OP_NEGATE',
    OP_ABS : 'OP_ABS',
    OP_NOT : 'OP_NOT',
    OP_0NOTEQUAL : 'OP_0NOTEQUAL',
    OP_ADD : 'OP_ADD',
    OP_SUB : 'OP_SUB',
    OP_MUL : 'OP_MUL',
    OP_DIV : 'OP_DIV',
    OP_MOD : 'OP_MOD',
    OP_LSHIFT : 'OP_LSHIFT',
    OP_RSHIFT : 'OP_RSHIFT',
    OP_BOOLAND : 'OP_BOOLAND',
    OP_BOOLOR : 'OP_BOOLOR',
    OP_NUMEQUAL : 'OP_NUMEQUAL',
    OP_NUMEQUALVERIFY : 'OP_NUMEQUALVERIFY',
    OP_NUMNOTEQUAL : 'OP_NUMNOTEQUAL',
    OP_LESSTHAN : 'OP_LESSTHAN',
    OP_GREATERTHAN : 'OP_GREATERTHAN',
    OP_LESSTHANOREQUAL : 'OP_LESSTHANOREQUAL',
    OP_GREATERTHANOREQUAL : 'OP_GREATERTHANOREQUAL',
    OP_MIN : 'OP_MIN',
    OP_MAX : 'OP_MAX',
    OP_WITHIN : 'OP_WITHIN',
    OP_RIPEMD160 : 'OP_RIPEMD160',
    OP_SHA1 : 'OP_SHA1',
    OP_SHA256 : 'OP_SHA256',
    OP_HASH160 : 'OP_HASH160',
    OP_HASH256 : 'OP_HASH256',
    OP_CODESEPARATOR : 'OP_CODESEPARATOR',
    OP_CHECKSIG : 'OP_CHECKSIG',
    OP_CHECKSIGVERIFY : 'OP_CHECKSIGVERIFY',
    OP_CHECKMULTISIG : 'OP_CHECKMULTISIG',
    OP_CHECKMULTISIGVERIFY : 'OP_CHECKMULTISIGVERIFY',
    OP_NOP1 : 'OP_NOP1',
    OP_NOP2 : 'OP_NOP2',
    OP_NOP3 : 'OP_NOP3',
    OP_NOP4 : 'OP_NOP4',
    OP_NOP5 : 'OP_NOP5',
    OP_NOP6 : 'OP_NOP6',
    OP_NOP7 : 'OP_NOP7',
    OP_NOP8 : 'OP_NOP8',
    OP_NOP9 : 'OP_NOP9',
    OP_NOP10 : 'OP_NOP10',
    OP_SMALLINTEGER : 'OP_SMALLINTEGER',
    OP_PUBKEYS : 'OP_PUBKEYS',
    OP_PUBKEYHASH : 'OP_PUBKEYHASH',
    OP_PUBKEY : 'OP_PUBKEY',
}
