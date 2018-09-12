from blocktools import *
from opcode import *
from datetime import datetime
import crypto_lib

class BlockFile:
  def __init__(self, block_filename):
    self.block_filename = block_filename
    self.blockchain = open(block_filename, 'rb')

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
    self.merkleHash = hashStr(hash32(blockchain))
    self.time = uint4(blockchain)
    self.bits = uint4(blockchain)
    self.nonce = uint4(blockchain)

  def to_string(self):
    sb = []
    sb.append("Version: %d" % self.version)
    sb.append("Previous Hash: %s" % self.previous_hash)
    sb.append("Merkle Root: %s" % self.merkleHash)
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
    self.magicNum = 0
    self.block_size = 0
    self.block_header = ''
    self.txCount = 0
    self.txs = []

    if self.has_length(8):
      self.magicNum = uint4(self.blockchain)
      self.block_size = uint4(self.blockchain)
    else:
      self.is_ready = False
      return

    if self.has_length(self.block_size):
      self.set_header()
      self.txCount = varint(self.blockchain)
      self.txs = []
    else:
      self.is_ready = False
    self.tx_pos = self.blockchain.tell()
    for i in range(0, self.txCount):
      tx = Tx(self.blockchain)
      self.txs.append(tx)

  def get_next_tx(self):
    self.blockchain.seek(self.tx_pos)
    for i in range(0, self.txCount):
      tx = Tx(self.blockchain)
      tx.seq = i
      yield tx

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
    sb.append("Magic No: \t%8x" % self.magicNum)
    sb.append("Block size: \t%d" % self.block_size)
    sb.append("### Block Header ###")
    sb.extend(self.block_header.to_string())
    sb.append("### Tx Count: %d ###" % self.txCount)
    for tx in self.get_next_tx():
      sb.extend(tx.to_string())
    sb.append("###### End of all %d transactins #######" % self.txCount)
    sb.append('')
    return sb

class Tx:
  def __init__(self, blockchain):
    start_pos = blockchain.tell()
    self.version = uint4(blockchain)
    check_pos = blockchain.tell()
    # For segwit
    # https://en.bitcoin.it/wiki/Transaction
    dummy1 = uint1(blockchain)
    dummy2 = uint1(blockchain)
    if dummy1 != 0 or dummy2 != 1:
      blockchain.seek(check_pos)
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
    # For segwit
    if dummy1 == 0 and dummy2 == 1:
      for i in range(0, self.inCount): 
        num_op = uint1(blockchain)
        for n in range(0, num_op):
          op_code=uint1(blockchain)
          _ = hashStr(blockchain.read(op_code))
    self.lockTime = uint4(blockchain)
    cur_pos = blockchain.tell()
    blockchain.seek(start_pos)
    self.raw_bytes = blockchain.read(cur_pos - start_pos)
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
    sb.append("Lock Time: %d" % self.lockTime)
    return sb


class TxInput:
  def __init__(self, blockchain, idx):
    self.idx = idx
    self.prev_hash = hash32(blockchain)
    self.tx_outId = uint4(blockchain)
    self.script_len = varint(blockchain)
    self.script_sig = blockchain.read(self.script_len)
    self.seqNo = uint4(blockchain)

  def to_string(self):
    sb = []
    sb.append("  Tx Previous has: %s" % hashStr(self.prev_hash))
    idx, temp_sb = self.decode_out_idx(self.tx_outId)
    sb.extend(temp_sb)
    sb.append("  Script Length: %d" % self.script_len)
    hexstr, temp_sb = self.decode_script_sig(self.script_sig)
    sb.extend(temp_sb)
    sb.append("  Sequence: %8x" % self.seqNo)
    return sb

  def decode_script_sig(self, data):
    sb = []
    hexstr = hashStr(data)
    if 0xffffffff == self.tx_outId:  # Coinbase
      sb.append("  Script raw:%s decode:%s" % (hexstr, str(bytes.fromhex(hexstr))))
      return str(bytes.fromhex(hexstr)), sb
    script_len = int(hexstr[0:2], 16)
    script_len *= 2
    script = hexstr[2:2 + script_len]
    sb.append("  Script: " + script)
    if SIGHASH_ALL != int(hexstr[script_len:script_len + 2], 16):  # should be 0x01
      sb.append("  Script op_code is not SIGHASH_ALL")
      return hexstr, sb
    else:
      pubkey = hexstr[2 + script_len + 2:2 + script_len + 2 + 66]
      sb.append("  InPubkey: " + pubkey)
      return hexstr, sb

  def decode_out_idx(self, idx):
    sb = []
    s = ""
    if idx == 0xFFFFFFFF:
      s = "Coinbase with special index"
      sb.append("  [Coinbase] Text: %s" % hashStr(self.prev_hash))
    else:
      sb.append("  Prev. Tx Hash: %s" % hashStr(self.prev_hash))
    return "%8x" % idx + s, sb


class TxOutput:
  def __init__(self, blockchain, idx):
    self.idx = idx
    self.value = uint8(blockchain)
    self.script_len = varint(blockchain)
    self.pubkey = blockchain.read(self.script_len)
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
    op_idx = int(hexstr[0:2], 16)
    try:
      op_code = OPCODE_NAMES[op_idx]
    except KeyError:
      self.type = "P2PK"
      # Obsoleted pay to pubkey directly
      # For detail see: https://en.bitcoin.it/wiki/Script#Obsolete_pay-to-pubkey_transaction
      pub_key_len = op_idx
      op_code_tail = OPCODE_NAMES[int(hexstr[2 + pub_key_len * 2:2 + pub_key_len * 2 + 2], 16)]
      self.pubkey_human = "Pubkey OP_CODE: None Bytes:%s tail_op_code:%s" % (pub_key_len, op_code_tail)
      self.addr = crypto_lib.pubkey_to_address(hexstr[2:2 + pub_key_len * 2])[0]
      return
    if op_code == "OP_DUP":
      self.type = "P2PKHA"
      # P2PKHA pay to pubkey hash mode
      # For detail see: https://en.bitcoin.it/wiki/Script#Standard_Transaction_to_Bitcoin_address_.28pay-to-pubkey-hash.29
      op_code2 = OPCODE_NAMES[int(hexstr[2:4], 16)]
      pub_key_len = int(hexstr[4:6], 16)
      op_code_tail2 = OPCODE_NAMES[int(hexstr[6 + pub_key_len * 2:6 + pub_key_len * 2 + 2], 16)]
      op_code_tail_last = OPCODE_NAMES[int(hexstr[6 + pub_key_len * 2 + 2:6 + pub_key_len * 2 + 4], 16)]
      self.pubkey_human = "%s %s %s %s %s" % (op_code, op_code2,  hexstr[6:6 + pub_key_len * 2], op_code_tail2, op_code_tail_last)
      self.addr = crypto_lib.gen_addr(hexstr[6:6 + pub_key_len * 2])[0]
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
      self.type = "RETRUN"
      pub_key_len = int(hexstr[2:4], 16)
      hash_code = hexstr[4:4 + pub_key_len * 2]
      self.pubkey_human = "RETRUN %s" % (hash_code)
      self.addr = hash_code
    else:  # TODO extend for multi-signature parsing
      self.type = "UNKNOWN"
      self.pubkey_human = "  Need to extend multi-signaturer parsing %x" % int(hexstr[0:2], 16) + op_code
      self.addr = "UNKNOWN"

