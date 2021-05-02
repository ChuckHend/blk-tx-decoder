import sys, os
import hashlib
import json
import datetime


from joblib import Parallel, delayed
import multiprocessing

def parse_input():
    try:
        dirA = sys.argv[1]
        dirB = sys.argv[2]
    except IndexError as e:
        dirA = './'
        dirB = './'
        print("Reading blocks from current directory")
        print("Writing text to current directory")

    fList = os.listdir(dirA)
    fList = [x for x in fList if (x.endswith('.dat') and x.startswith('blk'))]
    fList.sort()

    return dirA, dirB, fList

def HexToInt(s):
    t = ''
    if s == '':
        r = 0
    else:
        t = '0x' + s
        r = int(t,16)
    return r

def hex_to_date(h):
    unixtime = HexToInt(h)
    return str( datetime.datetime.fromtimestamp(unixtime) )

def reverse(input):
    L = len(input)
    if (L % 2) != 0:
        return None
    else:
        Res = ''
        L = L // 2
        for i in range(L):
            T = input[i*2] + input[i*2+1]
            Res = T + Res
            T = ''
        return (Res)

def merkle_root(lst): # https://gist.github.com/anonymous/7eb080a67398f648c1709e41890f8c44
    sha256d = lambda x: hashlib.sha256(hashlib.sha256(x).digest()).digest()
    hash_pair = lambda x, y: sha256d(x[::-1] + y[::-1])[::-1]
    if len(lst) == 1: return lst[0]
    if len(lst) % 2 == 1:
        lst.append(lst[-1])
    return merkle_root([hash_pair(x,y) for x, y in zip(*[iter(lst)]*2)])

def parallel(dirA, dirB, fList):
    num_cores = multiprocessing.cpu_count()
    Parallel(n_jobs=num_cores)(delayed(blk_to_txt)(dirA, dirB, i) for i in fList)

def blk_to_txt(dirA, dirB ,nameSrc):

    out_list = []

    nameRes = nameSrc.replace('.dat','.json')
    a = 0
    t = dirA + nameSrc
    print ('Start ' + t + ' at ' + str(datetime.datetime.now()))
    f = open(t,'rb')
    tmpHex = ''
    fSize = os.path.getsize(t)
    while f.tell() != fSize:
        
        block_dict = {}

        for j in range(4):
            b = f.read(1)
            b = b.hex().upper()
            tmpHex = b + tmpHex
        tmpHex = ''
        for j in range(4):
            b = f.read(1)
            b = b.hex().upper()
            tmpHex = b + tmpHex

        block_dict['BLOCK_SIZE'] = tmpHex

        tmpHex = ''
        tmpPos3 = f.tell()
        while f.tell() != tmpPos3 + 80:
            b = f.read(1)
            b = b.hex().upper()
            tmpHex = tmpHex + b
        
        tmpHex = bytes.fromhex(tmpHex)
        tmpHex = hashlib.new('sha256', tmpHex).digest()
        tmpHex = hashlib.new('sha256', tmpHex).digest()
        tmpHex = tmpHex.hex()
        tmpHex = tmpHex.upper()
        tmpHex = reverse(tmpHex)
        block_dict['SHA256_CURRENT'] = tmpHex
        f.seek(tmpPos3,0)

        # Version Number
        tmpHex = ''
        for j in range(4):
            b = f.read(1)
            b = b.hex().upper()
            tmpHex = b + tmpHex
        block_dict['VERSION_NUM'] = tmpHex

        # Previous SHA256 Hash
        tmpHex = ''
        for j in range(32):
            b = f.read(1)
            b = b.hex().upper()
            tmpHex = b + tmpHex
        block_dict['SHA256_PREVIOUS'] = tmpHex

        # MerkleRoot
        tmpHex = ''
        for j in range(32):
            b = f.read(1)
            b = b.hex().upper()
            tmpHex = b + tmpHex
        MerkleRoot = tmpHex
        block_dict['MERKLEROOT'] = MerkleRoot

        # Block timestamp
        tmpHex = ''
        for j in range(4):
            b = f.read(1)
            b = b.hex().upper()
            tmpHex = b + tmpHex
        block_dict['TIMESTAMP'] = hex_to_date(tmpHex)
        
        # Difficulty
        tmpHex = ''
        for j in range(4):
            b = f.read(1)
            b = b.hex().upper()
            tmpHex = b + tmpHex
        block_dict['DIFFICULTY'] = tmpHex
        
        # Nonce
        tmpHex = ''
        for j in range(4):
            b = f.read(1)
            b = b.hex().upper()
            tmpHex = b + tmpHex
        block_dict['NONCE'] = tmpHex
        
        # Transaction Count
        tmpHex = ''
        b = f.read(1)
        bInt = int(b.hex(),16)
        c = 0
        if bInt < 253:
            c = 1
            tmpHex = b.hex().upper()
        if bInt == 253: c = 3
        if bInt == 254: c = 5
        if bInt == 255: c = 9
        for j in range(1,c):
            b = f.read(1)
            b = b.hex().upper()
            tmpHex = b + tmpHex
        txCount = int(tmpHex,16)
        block_dict['TX_COUNT'] = str(txCount)

        tmpHex = ''
        tmpPos1 = 0
        tmpPos2 = 0
        RawTX = ''

        # start transactions
        tx_hashes = []
        transactions = {}
        
        for k in range(txCount):
            
            tx_dict = {} # a single transaction

            # Transaction Version
            tmpPos1 = f.tell()
            for j in range(4):
                b = f.read(1)
                b = b.hex().upper()
                tmpHex = b + tmpHex
            tx_dict['TX_VERSION'] = tmpHex

            RawTX = reverse(tmpHex)
            tmpHex = ''
            b = f.read(1)
            tmpB = b.hex().upper()
            bInt = int(b.hex(),16)
            Witness = False
            if bInt == 0:
                tmpB = ''
                c = 0
                c = f.read(1)
                bInt = int(c.hex(),16)
                c = 0
                c = f.read(1)
                bInt = int(c.hex(),16)
                tmpB = c.hex().upper()
                Witness = True
            block_dict['WITNESS'] = Witness

            # Input count
            c = 0
            if bInt < 253:
                c = 1
                tmpHex = hex(bInt)[2:].upper().zfill(2)
                tmpB = ''
            if bInt == 253: c = 3
            if bInt == 254: c = 5
            if bInt == 255: c = 9
            for j in range(1,c):
                b = f.read(1)
                b = b.hex().upper()
                tmpHex = b + tmpHex
            inCount = int(tmpHex,16)
            block_dict['INPUT_COUNT'] = tmpHex

            tmpHex = tmpHex + tmpB
            RawTX = RawTX + reverse(tmpHex)
            tmpHex = ''
            inputs = []
            for m in range(inCount):

                i_input = []

                # Tx from hash
                for j in range(32):
                    b = f.read(1)
                    b = b.hex().upper()
                    tmpHex = b + tmpHex
                i_input.append( {'TX_FROM_HASH' : tmpHex} )
                
                # Number outputs
                RawTX = RawTX + reverse(tmpHex)
                tmpHex = ''
                for j in range(4):
                    b = f.read(1)
                    b = b.hex().upper()
                    tmpHex = b + tmpHex
                i_input.append( {"N_OUTPUT" : tmpHex} )


                RawTX = RawTX + reverse(tmpHex)
                tmpHex = ''
                b = f.read(1)
                tmpB = b.hex().upper()
                bInt = int(b.hex(),16)
                c = 0
                if bInt < 253:
                    c = 1
                    tmpHex = b.hex().upper()
                    tmpB = ''
                if bInt == 253: c = 3
                if bInt == 254: c = 5
                if bInt == 255: c = 9
                for j in range(1,c):
                    b = f.read(1)
                    b = b.hex().upper()
                    tmpHex = b + tmpHex
                scriptLength = int(tmpHex,16)
                tmpHex = tmpHex + tmpB
                RawTX = RawTX + reverse(tmpHex)
                tmpHex = ''
                for j in range(scriptLength):
                    b = f.read(1)
                    b = b.hex().upper()
                    tmpHex = tmpHex + b
                i_input.append( {"INPUT_SCRIPT" : tmpHex})
                
                RawTX = RawTX + tmpHex
                tmpHex = ''
                for j in range(4):
                    b = f.read(1)
                    b = b.hex().upper()
                    tmpHex = tmpHex + b
                i_input.append( {"SEQ_NO" : tmpHex})

                RawTX = RawTX + tmpHex
                tmpHex = ''

                inputs.append( i_input )
            tx_dict['INPUTS'] = inputs
            del inputs

            b = f.read(1)
            tmpB = b.hex().upper()
            bInt = int(b.hex(),16)
            c = 0
            if bInt < 253:
                c = 1
                tmpHex = b.hex().upper()
                tmpB = ''
            if bInt == 253: c = 3
            if bInt == 254: c = 5
            if bInt == 255: c = 9
            for j in range(1,c):
                b = f.read(1)
                b = b.hex().upper()
                tmpHex = b + tmpHex
            outputCount = int(tmpHex,16)
            tmpHex = tmpHex + tmpB
            RawTX = RawTX + reverse(tmpHex)
            tmpHex = ''

            outputs = []
            for m in range(outputCount):
                i_output = []

                for j in range(8):
                    b = f.read(1)
                    b = b.hex().upper()
                    tmpHex = b + tmpHex
                Value = tmpHex
                RawTX = RawTX + reverse(tmpHex)
                tmpHex = ''
                b = f.read(1)
                tmpB = b.hex().upper()
                bInt = int(b.hex(),16)
                c = 0
                if bInt < 253:
                    c = 1
                    tmpHex = b.hex().upper()
                    tmpB = ''
                if bInt == 253: c = 3
                if bInt == 254: c = 5
                if bInt == 255: c = 9
                for j in range(1,c):
                    b = f.read(1)
                    b = b.hex().upper()
                    tmpHex = b + tmpHex
                scriptLength = int(tmpHex,16)
                tmpHex = tmpHex + tmpB
                RawTX = RawTX + reverse(tmpHex)
                tmpHex = ''
                for j in range(scriptLength):
                    b = f.read(1)
                    b = b.hex().upper()
                    tmpHex = tmpHex + b
                i_output.append({"VALUE" : str( int( Value, 16)/100000000 )})
                i_output.append({'OUTPUT_SCRIPT' : tmpHex})
                
                RawTX = RawTX + tmpHex
                tmpHex = ''
            
                outputs.append( i_output )

            tx_dict['OUTPUTS'] = outputs
            del outputs
            
            if Witness == True:
                for m in range(inCount):
                    tmpHex = ''
                    b = f.read(1)
                    bInt = int(b.hex(),16)
                    c = 0
                    if bInt < 253:
                        c = 1
                        tmpHex = b.hex().upper()
                    if bInt == 253: c = 3
                    if bInt == 254: c = 5
                    if bInt == 255: c = 9
                    for j in range(1,c):
                        b = f.read(1)
                        b = b.hex().upper()
                        tmpHex = b + tmpHex
                    WitnessLength = int(tmpHex,16)
                    tmpHex = ''
                    for j in range(WitnessLength):
                        tmpHex = ''
                        b = f.read(1)
                        bInt = int(b.hex(),16)
                        c = 0
                        if bInt < 253:
                            c = 1
                            tmpHex = b.hex().upper()
                        if bInt == 253: c = 3
                        if bInt == 254: c = 5
                        if bInt == 255: c = 9
                        for j in range(1,c):
                            b = f.read(1)
                            b = b.hex().upper()
                            tmpHex = b + tmpHex
                        WitnessItemLength = int(tmpHex,16)
                        tmpHex = ''
                        for p in range(WitnessItemLength):
                            b = f.read(1)
                            b = b.hex().upper()
                            tmpHex = b + tmpHex
                        tmpHex = ''
            Witness = False
            
            # Lock time
            for j in range(4):
                b = f.read(1)
                b = b.hex().upper()
                tmpHex = b + tmpHex
            tx_dict['LOCK_TIME'] = tmpHex

            # TX hash
            RawTX = RawTX + reverse(tmpHex)
            tmpHex = ''
            tmpHex = RawTX
            tmpHex = bytes.fromhex(tmpHex)
            tmpHex = hashlib.new('sha256', tmpHex).digest()
            tmpHex = hashlib.new('sha256', tmpHex).digest()
            tmpHex = tmpHex.hex()
            tmpHex = tmpHex.upper()
            tmpHex = reverse(tmpHex)
            tx_dict['TX_HASH'] = tmpHex
            transactions[tmpHex] = tx_dict

            tx_hashes.append(tmpHex)
            tmpHex = ''
            RawTX = ''

        block_dict['TRANSACTIONS'] = transactions
        del transactions

        a += 1
        # tx_hashes = [h.decode('hex') for h in tx_hashes]
        tx_hashes = [bytes.fromhex(h) for h in tx_hashes]
        tmpHex = merkle_root(tx_hashes).hex().upper()
        if tmpHex != MerkleRoot:
            print ('Merkle roots does not match! >',MerkleRoot,tmpHex)
        tmpHex = ''
        out_list.append(block_dict)

    with open(dirB + nameRes, 'w') as f:
        json.dump(out_list, f)
    #     for line in out_list:
    #         f.write(json.dumps(line) + '\n')
    # f.close()


def loop(dirA, dirB, fList):

    for i in fList:
        nameSrc = i
        nameRes = nameSrc.replace('.dat','.txt')
        resList = []
        a = 0
        t = dirA + nameSrc
        resList.append('Start ' + t + ' in ' + str(datetime.datetime.now()))
        print ('Start ' + t + ' in ' + str(datetime.datetime.now()))
        f = open(t,'rb')
        tmpHex = ''
        fSize = os.path.getsize(t)
        while f.tell() != fSize:
            for j in range(4):
                b = f.read(1)
                b = b.hex().upper()
                tmpHex = b + tmpHex
            tmpHex = ''
            for j in range(4):
                b = f.read(1)
                b = b.hex().upper()
                tmpHex = b + tmpHex
            resList.append('Block size = ' + tmpHex)
            tmpHex = ''
            tmpPos3 = f.tell()
            while f.tell() != tmpPos3 + 80:
                b = f.read(1)
                b = b.hex().upper()
                tmpHex = tmpHex + b
            # tmpHex = tmpHex.decode('hex')
            tmpHex = bytes.fromhex(tmpHex)
            tmpHex = hashlib.new('sha256', tmpHex).digest()
            tmpHex = hashlib.new('sha256', tmpHex).digest()
            tmpHex = tmpHex.hex()
            tmpHex = tmpHex.upper()
            tmpHex = reverse(tmpHex)
            resList.append('SHA256 hash of the current block hash = ' + tmpHex)
            f.seek(tmpPos3,0)
            tmpHex = ''
            for j in range(4):
                b = f.read(1)
                b = b.hex().upper()
                tmpHex = b + tmpHex
            resList.append('Version number = ' + tmpHex)
            tmpHex = ''
            for j in range(32):
                b = f.read(1)
                b = b.hex().upper()
                tmpHex = b + tmpHex
            resList.append('SHA256 hash of the previous block hash = ' + tmpHex)
            tmpHex = ''
            for j in range(32):
                b = f.read(1)
                b = b.hex().upper()
                tmpHex = b + tmpHex
            resList.append('MerkleRoot hash = ' + tmpHex)
            MerkleRoot = tmpHex
            tmpHex = ''
            for j in range(4):
                b = f.read(1)
                b = b.hex().upper()
                tmpHex = b + tmpHex
            resList.append('Time stamp > ' + tmpHex)
            tmpHex = ''
            for j in range(4):
                b = f.read(1)
                b = b.hex().upper()
                tmpHex = b + tmpHex
            resList.append('Difficulty = ' + tmpHex)
            tmpHex = ''
            for j in range(4):
                b = f.read(1)
                b = b.hex().upper()
                tmpHex = b + tmpHex
            resList.append('Random number > ' + tmpHex)
            tmpHex = ''
            b = f.read(1)
            bInt = int(b.hex(),16)
            c = 0
            if bInt < 253:
                c = 1
                tmpHex = b.hex().upper()
            if bInt == 253: c = 3
            if bInt == 254: c = 5
            if bInt == 255: c = 9
            for j in range(1,c):
                b = f.read(1)
                b = b.hex().upper()
                tmpHex = b + tmpHex
            txCount = int(tmpHex,16)
            resList.append('Transactions count = ' + str(txCount))
            resList.append('')
            tmpHex = ''
            tmpPos1 = 0
            tmpPos2 = 0
            RawTX = ''
            tx_hashes = []
            for k in range(txCount):
                tmpPos1 = f.tell()
                for j in range(4):
                    b = f.read(1)
                    b = b.hex().upper()
                    tmpHex = b + tmpHex
                resList.append('transactionVersionNumber = ' + tmpHex)
                RawTX = reverse(tmpHex)
                tmpHex = ''
                b = f.read(1)
                tmpB = b.hex().upper()
                bInt = int(b.hex(),16)
                Witness = False
                if bInt == 0:
                    tmpB = ''
                    c = 0
                    c = f.read(1)
                    bInt = int(c.hex(),16)
                    c = 0
                    c = f.read(1)
                    bInt = int(c.hex(),16)
                    tmpB = c.hex().upper()
                    Witness = True
                    resList.append('Witness activated >>')
                c = 0
                if bInt < 253:
                    c = 1
                    tmpHex = hex(bInt)[2:].upper().zfill(2)
                    tmpB = ''
                if bInt == 253: c = 3
                if bInt == 254: c = 5
                if bInt == 255: c = 9
                for j in range(1,c):
                    b = f.read(1)
                    b = b.hex().upper()
                    tmpHex = b + tmpHex
                inCount = int(tmpHex,16)
                resList.append('Inputs count = ' + tmpHex)
                tmpHex = tmpHex + tmpB
                RawTX = RawTX + reverse(tmpHex)
                tmpHex = ''
                for m in range(inCount):
                    for j in range(32):
                        b = f.read(1)
                        b = b.hex().upper()
                        tmpHex = b + tmpHex
                    resList.append('TX from hash = ' + tmpHex)
                    RawTX = RawTX + reverse(tmpHex)
                    tmpHex = ''
                    for j in range(4):
                        b = f.read(1)
                        b = b.hex().upper()
                        tmpHex = b + tmpHex
                    resList.append('N output = ' + tmpHex)
                    RawTX = RawTX + reverse(tmpHex)
                    tmpHex = ''
                    b = f.read(1)
                    tmpB = b.hex().upper()
                    bInt = int(b.hex(),16)
                    c = 0
                    if bInt < 253:
                        c = 1
                        tmpHex = b.hex().upper()
                        tmpB = ''
                    if bInt == 253: c = 3
                    if bInt == 254: c = 5
                    if bInt == 255: c = 9
                    for j in range(1,c):
                        b = f.read(1)
                        b = b.hex().upper()
                        tmpHex = b + tmpHex
                    scriptLength = int(tmpHex,16)
                    tmpHex = tmpHex + tmpB
                    RawTX = RawTX + reverse(tmpHex)
                    tmpHex = ''
                    for j in range(scriptLength):
                        b = f.read(1)
                        b = b.hex().upper()
                        tmpHex = tmpHex + b
                    resList.append('Input script = ' + tmpHex)
                    RawTX = RawTX + tmpHex
                    tmpHex = ''
                    for j in range(4):
                        b = f.read(1)
                        b = b.hex().upper()
                        tmpHex = tmpHex + b
                    resList.append('sequenceNumber = ' + tmpHex)
                    RawTX = RawTX + tmpHex
                    tmpHex = ''
                b = f.read(1)
                tmpB = b.hex().upper()
                bInt = int(b.hex(),16)
                c = 0
                if bInt < 253:
                    c = 1
                    tmpHex = b.hex().upper()
                    tmpB = ''
                if bInt == 253: c = 3
                if bInt == 254: c = 5
                if bInt == 255: c = 9
                for j in range(1,c):
                    b = f.read(1)
                    b = b.hex().upper()
                    tmpHex = b + tmpHex
                outputCount = int(tmpHex,16)
                tmpHex = tmpHex + tmpB
                resList.append('Outputs count = ' + str(outputCount))
                RawTX = RawTX + reverse(tmpHex)
                tmpHex = ''
                for m in range(outputCount):
                    for j in range(8):
                        b = f.read(1)
                        b = b.hex().upper()
                        tmpHex = b + tmpHex
                    Value = tmpHex
                    RawTX = RawTX + reverse(tmpHex)
                    tmpHex = ''
                    b = f.read(1)
                    tmpB = b.hex().upper()
                    bInt = int(b.hex(),16)
                    c = 0
                    if bInt < 253:
                        c = 1
                        tmpHex = b.hex().upper()
                        tmpB = ''
                    if bInt == 253: c = 3
                    if bInt == 254: c = 5
                    if bInt == 255: c = 9
                    for j in range(1,c):
                        b = f.read(1)
                        b = b.hex().upper()
                        tmpHex = b + tmpHex
                    scriptLength = int(tmpHex,16)
                    tmpHex = tmpHex + tmpB
                    RawTX = RawTX + reverse(tmpHex)
                    tmpHex = ''
                    for j in range(scriptLength):
                        b = f.read(1)
                        b = b.hex().upper()
                        tmpHex = tmpHex + b
                    resList.append('Value = ' + str( int( Value, 16)/100000000 ) )
                    resList.append('Output script = ' + tmpHex)
                    RawTX = RawTX + tmpHex
                    tmpHex = ''
                if Witness == True:
                    for m in range(inCount):
                        tmpHex = ''
                        b = f.read(1)
                        bInt = int(b.hex(),16)
                        c = 0
                        if bInt < 253:
                            c = 1
                            tmpHex = b.hex().upper()
                        if bInt == 253: c = 3
                        if bInt == 254: c = 5
                        if bInt == 255: c = 9
                        for j in range(1,c):
                            b = f.read(1)
                            b = b.hex().upper()
                            tmpHex = b + tmpHex
                        WitnessLength = int(tmpHex,16)
                        tmpHex = ''
                        for j in range(WitnessLength):
                            tmpHex = ''
                            b = f.read(1)
                            bInt = int(b.hex(),16)
                            c = 0
                            if bInt < 253:
                                c = 1
                                tmpHex = b.hex().upper()
                            if bInt == 253: c = 3
                            if bInt == 254: c = 5
                            if bInt == 255: c = 9
                            for j in range(1,c):
                                b = f.read(1)
                                b = b.hex().upper()
                                tmpHex = b + tmpHex
                            WitnessItemLength = int(tmpHex,16)
                            tmpHex = ''
                            for p in range(WitnessItemLength):
                                b = f.read(1)
                                b = b.hex().upper()
                                tmpHex = b + tmpHex
                            resList.append('Witness ' + str(m) + ' ' + str(j) + ' ' + str(WitnessItemLength) + ' ' + tmpHex)
                            tmpHex = ''
                Witness = False
                for j in range(4):
                    b = f.read(1)
                    b = b.hex().upper()
                    tmpHex = b + tmpHex
                resList.append('Lock time = ' + tmpHex)
                RawTX = RawTX + reverse(tmpHex)
                tmpHex = ''
                tmpHex = RawTX
                # tmpHex = tmpHex.decode('hex')
                tmpHex = bytes.fromhex(tmpHex)
                tmpHex = hashlib.new('sha256', tmpHex).digest()
                tmpHex = hashlib.new('sha256', tmpHex).digest()
                tmpHex = tmpHex.hex()
                tmpHex = tmpHex.upper()
                tmpHex = reverse(tmpHex)
                resList.append('TX hash = ' + tmpHex)
                tx_hashes.append(tmpHex)
                tmpHex = ''
                resList.append('')
                RawTX = ''
            a += 1
            tx_hashes = [bytes.fromhex(h) for h in tx_hashes]
            tmpHex = merkle_root(tx_hashes).hex().upper()
            if tmpHex != MerkleRoot:
                print ('Merkle roots does not match! >',MerkleRoot,tmpHex)
            tmpHex = ''
        f.close()
        f = open(dirB + nameRes,'w')
        for j in resList:
            f.write(j + '\n')
        f.close()
    nameSrc = ''
    nameRes = ''
    dirA= ''
    dirB = ''
    tmpC = ''
    resList = []
    fList = []

import binascii
import hashlib
import base58

def P2PKHToAddress(pkscript, istestnet=False):
    pub = pkscript[6:-4] # get pkhash, inbetween first 3 bytes and last 2 bytes
    p = '00' + pub # prefix with 00 if it's mainnet
    if istestnet:
        p = '6F' + pub # prefix with 0F if it's testnet
    h1 = hashlib.sha256(binascii.unhexlify(p))
    h2 = hashlib.new('sha256', h1.digest())
    h3 = h2.hexdigest()
    a = h3[0:8] # first 4 bytes
    c = p + a # add first 4 bytes to beginning of pkhash
    d = int(c, 16) # string to decimal
    b = d.to_bytes((d.bit_length() + 7) // 8, 'big') # decimal to bytes
    address = base58.b58encode(b) # bytes to base58
    if not istestnet:
        address = '1' + address # prefix with 1 if it's mainnet
    return address
        
if __name__ == '__main__':
    dirA, dirB, fList = parse_input()

    # blk_to_txt(dirA, dirB, fList[0])

    parallel(dirA, dirB, fList)


def find_change(txs: list):
    all_txs = {}
    for i, tx in enumerate(txs):
        tx_hash = tx["tx_hash"]
        input_addrs = set()
        output_addrs = set()

        for t in tx["inputs"]:
            input_addrs.add(
                t["pub_key_decoded"]
            )
        for t in tx["outputs"]:
            output_addrs.add(
                t["addr"]
            )
        all_txs[tx_hash] = {
            "inputs": input_addrs,
            "outputs": output_addrs
        }
        for ia in input_addrs:
            if ia in output_addrs:
                print(i)
    return all_txs
