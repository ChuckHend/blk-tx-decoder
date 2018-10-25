from crypto_lib import *
from opcode import *
from datetime import datetime

class BlockFile:
  def __init__(self, block_filename):
    self.block_filename = block_filename
    self.blockchain = open(block_filename, 'rb', buffering=16*1024*1024)

  def get_next_block(self):
    while True:
      block = Block(self.blockchain)
      if block.is_ready:
        yield block
      else:
        break

class BlockHeader:
  def __init__(self, blockchain):
    self.version = uint4(blockchain)
    self.previous_hash = hashStr(hash32(blockchain))
    self.merkle_hash = hashStr(hash32(blockchain))
    self.time = uint4(blockchain)
    self.bits = uint4(blockchain)
    self.nonce = uint4(blockchain)

  def to_string(self):
    sb = []
    sb.append("Version: %d" % self.version)
    sb.append("Previous Hash: %s" % self.previous_hash)
    sb.append("Merkle Root: %s" % self.merkle_hash)
    sb.append("Time stamp: %s" % self.decode_time(self.time))
    sb.append("Difficulty: %d" % self.bits)
    sb.append("Nonce: %s" % self.nonce)
    return sb

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

  def is_ready(self):
    return self.is_ready;

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

  def to_string(self):
    sb = []
    sb.append("Magic No: \t%8x" % self.magic_num)
    sb.append("Block size: \t%d" % self.block_size)
    sb.append("### Block Header ###")
    sb.extend(self.block_header.to_string())
    sb.append("### Tx Count: %d ###" % self.tx_count)
    for tx in self.txs:
      sb.extend(tx.to_string())
    sb.append("###### End of all %d transactins #######" % self.tx_count)
    sb.append('')
    return sb

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
          op_code=varint(blockchain)
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

  def to_string(self):
    sb=[]
    sb.append("=" * 20 + " No. %s " % self.seq + "Transaction " + "=" * 20)
    sb.append("=%s=" % self.tx_hash)
    sb.append("Tx Version: %d" % self.version)
    sb.append("Inputs: %d" % self.inCount)
    for i in self.inputs:
      sb.extend(i.to_string())

    sb.append("Outputs: %d" % self.outCount)
    for o in self.outputs:
      sb.extend(o.to_string())
    sb.append("Lock Time: %d" % self.lock_time)
    return sb

class TxInput:
  def __init__(self, blockchain, idx):
    self.idx = idx
    self.prev_hash = hashStr(hash32(blockchain))
    self.tx_outId = uint4(blockchain)
    self.script_len = varint(blockchain)
    self.script_sig = blockchain.read(self.script_len)
    self.seqNo = uint4(blockchain)
    self.decode_script_sig(self.script_sig)


  def to_string(self):
    sb = []
    sb.append("  Tx Previous has: %s - %d" % (self.prev_hash, self.idx))
    sb.append("  Script Length: %d" % self.script_len)
    sb.append("  %s" % self.hex_str)
    sb.append("  PubKey: %s" % self.pub_key)
    sb.append("  Sequence: %8x" % self.seqNo)
    return sb

  def decode_script_sig(self, data):
    sb = []
    self.hex_str = hashStr(data)
    # segwit
    if len(self.hex_str) == 0:
      self.pub_key=""
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

  def to_string(self):
    sb = []
    sb.append("Value: %d" % self.value + " Satoshi")
    sb.append("Script Len: %d" % self.script_len)
    sb.append("ScriptPubkey: %s" % self.addr)
    sb.append("Addr: %s" % self.addr)
    return sb

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
      if op_idx==65:
        self.type = "P2PK"
        # Obsoleted pay to pubkey directly
        # For detail see: https://en.bitcoin.it/wiki/Script#Obsolete_pay-to-pubkey_transaction
        pub_key_len = op_idx
        op_code_tail = OPCODE_NAMES[int(hexstr[2 + pub_key_len * 2:2 + pub_key_len * 2 + 2], 16)]
        self.pubkey_human = "Pubkey OP_CODE: None Bytes:%s tail_op_code:%s %d" % (pub_key_len, op_code_tail, op_idx)
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
        self.pubkey_human = "%s %s %s %s %s" % (op_code, op_code2,  hexstr[6:6 + pub_key_len * 2], op_code_tail2, op_code_tail_last)
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

