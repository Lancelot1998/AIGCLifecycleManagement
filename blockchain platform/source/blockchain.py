# -*- coding: utf-8 -*-
"""
    blockchain
    ~~~~~~~~~~

    Implements blockchain data structure and rules of validation

    :author: hank
"""

import hashlib
import time
import struct
from typing import List, Tuple, NewType
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import \
    Encoding, PublicFormat, load_pem_public_key, load_der_private_key, load_pem_private_key
from cryptography.hazmat.backends import default_backend
from source.utility import n_bytes
from source.errors import *
from cryptography.hazmat.primitives import hashes, hmac
from enum import Enum, unique
from functools import reduce
from source.utility import bin2int
import queue
import threading
import os
import json
import sys
import random
import time
import ctypes
import codecs

CPU = NewType('CPU', int)
RAM = NewType('RAM', int)
BANDWIDTH = NewType('BANDWIDTH', int)
ASSET = NewType('ASSET', float)
PUBLIC_KEY_HASH = NewType('PUBLIC_KEY_HASH', bytes)
TXID = NewType('TXID', bytes)
OUTPUT_INDEX = NewType('OUTPUT_INDEX', int)
SIGNATURE = NewType('SIGNATURE', bytes)

BLENGTH_PUBLIC_KEY_HASH = 32
BLENGTH_INT = 4
BLENGTH_TXID = 32
BLENGTH_DOUBLE = 8
BLENGTH_BLOCKHASH = 32
BLENGTH_PUBKEY = 174
BLOCK_CYCLE = 500
INIT_HASH = b'G\xfdk\x88\xda5\xff\x8c\x97t\x9f\xcb\xe0\xa8\x07S\x8b9t:.9\x1d\xee\xf4\xb1\xda\xd1r\xaf\xfcu'

ll = ctypes.cdll.LoadLibrary
lib = ll("./lib.so")

input_ = bytes("DAG_input.txt", "utf-8")
output_ = bytes("DAG_output.txt", "utf-8")


class TransInput:

    def __init__(self, trans_input: List[Tuple[TXID, OUTPUT_INDEX]], public_key_hash: PUBLIC_KEY_HASH) \
            -> None:
        self.content = trans_input
        self.public_key_hash = public_key_hash
        self.b = self.__tobin()

    def __getitem__(self, item) -> Tuple[TXID, OUTPUT_INDEX]:
        return self.content[item]

    def __tobin(self) -> bytes:
        b = bytes()
        for ipt in self.content:
            b += ipt[0] + struct.pack('=i', ipt[1])
        b += self.public_key_hash
        return b

    def show_input(self):
        result = dict()
        result["public_key_hash"] = self.public_key_hash
        # result["content"] = self.content
        result['content'] = [{'txid': i, 'index': j} for i, j in self.content]

    @classmethod
    def unpack(cls, b: bytes) -> 'TransInput':
        Verify.trans_input_checker(b)
        public_key_hash = b[-BLENGTH_PUBLIC_KEY_HASH:]
        b_content = n_bytes(b[:-BLENGTH_PUBLIC_KEY_HASH], BLENGTH_TXID + BLENGTH_INT)
        content = list(map(lambda i: (i[:BLENGTH_TXID], struct.unpack('=i', i[-BLENGTH_INT:])[0]), b_content))
        return cls(content, PUBLIC_KEY_HASH(public_key_hash))

    def show_transinput(self) -> dict:
        transinput_result = dict()
        # convert public_key_hash to hexadecimal
        temp = ""
        for i, data in enumerate(self.public_key_hash):
            a = str(hex(self.public_key_hash[i]))[2:]
            temp += a.zfill(2)
        c = '0x' + temp
        transinput_result["public_key_hash"] = c
        # convert TXID to hexadecimal
        result = []
        for i, data in enumerate(self.content):
            temp = ""
            for d, k in enumerate(self.content[i][0]):
                a = str(hex(self.content[i][0][d]))[2:]
                temp += a.zfill(2)
            c = '0x' + temp
            result.append((c, self.content[i][1]))
        transinput_result["content"] = [{'txid': i, 'index': j} for i, j in result]
        return transinput_result


class TransOutput:
    def __init__(self, trans_output: List[Tuple[ASSET, PUBLIC_KEY_HASH]]) -> None:
        self.content = trans_output
        self.b = self.__tobin()

    def __tobin(self) -> bytes:
        b = bytes()
        for opt in self.content:
            b += struct.pack('=d', opt[0]) + opt[1]
        return b

    def __getitem__(self, item) -> Tuple[ASSET, PUBLIC_KEY_HASH]:
        return self.content[item]

    @classmethod
    def unpack(cls, b: bytes) -> 'TransOutput':
        Verify.trans_output_checker(b)
        b_content = n_bytes(b, BLENGTH_DOUBLE + BLENGTH_PUBLIC_KEY_HASH)
        content = list(
            map(lambda i: tuple((*list(struct.unpack('=d', i[:BLENGTH_DOUBLE])), i[-BLENGTH_PUBLIC_KEY_HASH:])),
                b_content)
        )
        return cls(content)

    def show_transoutput(self) -> dict:
        transoutput_result = dict()
        result = []
        # convert PUBLIC_KEY_HASH to hexadecimal
        for i, data in enumerate(self.content):
            temp = ""
            for d, k in enumerate(self.content[i][1]):
                a = str(hex(self.content[i][1][d]))[2:]
                temp += a.zfill(2)
            c = "0x" + temp
            result.append((self.content[i][0], c))
        transoutput_result["content"] = result
        return transoutput_result


class Transaction:

    def __init__(self, ipt: TransInput, opt: TransOutput, version: int = 1) -> None:
        self.public_key = None
        self.signature = None
        self.version = version
        self.timestamp = None
        self.txid = None
        self.b = bytes()
        self.ipt = ipt
        self.opt = opt
        self.length = None

    @staticmethod
    def __sign(data: bytes, private_key: ec.EllipticCurvePrivateKey) -> SIGNATURE:
        return private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    def ready(self, private_key: ec.EllipticCurvePrivateKey):
        self.public_key = private_key.public_key()
        self.timestamp = time.time()
        self.signature = Transaction.__sign(struct.pack('=f', self.timestamp) + self.ipt.b + self.opt.b, private_key)
        self.txid, content = self.__hash_trans()
        self.b = self.__tobin(content)
        self.length = len(self.b)

    def __tobin(self, content: bytes) -> bytes:
        return self.txid + content

    def __hash_trans(self) -> Tuple[bytes, bytes]:
        b_public_key = self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        content = struct.pack(
            '=id3i', self.version, self.timestamp, len(b_public_key), len(self.ipt.b), len(self.opt.b)
        ) + b_public_key + self.ipt.b + self.opt.b + self.signature

        sha = hashlib.sha256()
        sha.update(content)
        return sha.digest(), content

    @classmethod
    def unpack(cls, b: bytes) -> 'Transaction':
        Verify.transaction_checker(b)

        txid = b[:BLENGTH_TXID]

        version, timestamp, len_b_public_key, len_ipt_b, len_opt_b = \
            struct.unpack('=id3i', b[BLENGTH_TXID:BLENGTH_TXID + 4 * BLENGTH_INT + BLENGTH_DOUBLE])

        length_ = BLENGTH_TXID + 4 * BLENGTH_INT + BLENGTH_DOUBLE
        b_public_key = b[length_:length_ + len_b_public_key]
        public_key = load_pem_public_key(b_public_key, default_backend())

        length_ += len_b_public_key

        ipt_b = b[length_:length_ + len_ipt_b]
        ipt = TransInput.unpack(ipt_b)

        length_ += len_ipt_b
        opt_b = b[length_:length_ + len_opt_b]
        opt = TransOutput.unpack(opt_b)

        length_ += len_opt_b
        signature = b[length_:]

        transaction = cls(ipt, opt)
        transaction.txid = txid
        transaction.version = version
        transaction.timestamp = timestamp
        transaction.signature = signature
        transaction.b = b
        transaction.length = len(b)
        transaction.public_key = public_key
        return transaction

    def show_trans(self) -> dict:
        trans_result = dict()
        trans_result["public_key"] = str(self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
                                         encoding="utf-8")
        # convert signature to hexadecimal
        q = ""
        for i, data in enumerate(self.signature):
            a = str(hex(self.signature[i]))[2:]
            q += a.zfill(2)
        c = "0x" + q
        trans_result["signature"] = c
        trans_result["version"] = self.version
        trans_result["timestamp"] = self.timestamp
        # convert txid to hexadecimal
        q = ""
        for i, data in enumerate(self.txid):
            a = str(hex(self.txid[i]))[2:]
            q += a.zfill(2)
        c = "0x" + q
        trans_result["txid"] = c
        trans_result["trans_input"] = self.ipt.show_transinput()
        trans_result["trans_output"] = self.opt.show_transoutput()
        trans_result["length"] = self.length
        return trans_result


class Attachment:

    def __init__(self) -> None:
        self.b = b''
        self.content = b''
        self.rdy = False

    def add_data(self, data: bytes):
        if self.rdy is False:
            self.content += data
        else:
            raise ModificationAfterReady

    def ready(self):
        length_ = struct.pack('=i', len(self.content))
        self.b = length_ + self.content
        self.rdy = True

    @classmethod
    def unpack(cls, b: bytes) -> 'Attachment':
        Verify.attachment_checker(b)
        length_ = struct.unpack('=i', b[:BLENGTH_INT])[0]
        at = cls()
        at.add_data(b[BLENGTH_INT:BLENGTH_INT + length_])
        at.ready()
        return at


class BlockData:
    """
    Data contained in basic block objects, including transactions and attachment
    """

    def __init__(self, transaction: List[Transaction], attachment: Attachment) -> None:
        self.trans = transaction
        self.attachment = attachment
        self.b = self.__tobin()

    def __tobin(self) -> bytes:
        size = len(self.attachment.b)
        for t in self.trans:
            size += BLENGTH_INT + len(t.b)

        b = bytearray(size)
        p = 0
        b[p:p + len(self.attachment.b)] = bytearray(self.attachment.b)
        p += len(self.attachment.b)
        for t in self.trans:
            # b = b''.join([b, struct.pack('=i', t.length), t.b])
            # b += struct.pack('=i', t.length) + t.b
            b[p:p + BLENGTH_INT] = bytearray(struct.pack('=i', t.length))
            p += BLENGTH_INT
            b[p:p + t.length] = bytearray(t.b)
            p += t.length
        return bytes(b)

    @classmethod
    def unpack(cls, b: bytes) -> 'BlockData':
        Verify.blockdata_checker(b)
        at = Attachment.unpack(b)
        length_ = struct.unpack('=i', b[:BLENGTH_INT])[0] + BLENGTH_INT

        transaction = []
        while length_ < len(b):
            trans_length = struct.unpack('=i', b[length_:length_ + BLENGTH_INT])[0]
            length_ += BLENGTH_INT

            transaction.append(Transaction.unpack(b[length_:length_ + trans_length]))
            length_ += trans_length

        return cls(transaction, at)


class LightBlockData:
    """
    corresponding to BlockData
    """

    def __init__(self, trans_txid, attachment: Attachment) -> None:
        self.attachment = attachment
        self.trans_txid = trans_txid
        self.b = self.__tobin()

    def __tobin(self) -> bytes:
        size = len(self.attachment.b)
        for t in self.trans_txid:
            size += BLENGTH_INT + len(t)

        b = bytearray(size)
        p = 0
        b[p:p + len(self.attachment.b)] = bytearray(self.attachment.b)
        p += len(self.attachment.b)
        for t in self.trans_txid:
            b[p:p + BLENGTH_INT] = bytearray(struct.pack('=i', len(t)))
            p += BLENGTH_INT
            b[p:p + len(t)] = t
            p += len(t)
        return bytes(b)

    @classmethod
    def unpack(cls, b: bytes) -> 'LightBlockData':
        Verify.light_blockdata_checker(b)
        at = Attachment.unpack(b)
        length_ = struct.unpack('=i', b[:BLENGTH_INT])[0] + BLENGTH_INT

        trans_txid = []
        while length_ < len(b):
            trans_txid_length = struct.unpack('=i', b[length_:length_ + BLENGTH_INT])[0]
            length_ += BLENGTH_INT

            trans_txid.append(b[length_:length_ + trans_txid_length])
            length_ += trans_txid_length

        return cls(trans_txid, at)


class Block:

    def __init__(self, index: int, timestamp: float, blockdata: BlockData, previous_hash: bytes, nonce=None) -> None:
        self.index = index
        self.timestamp = timestamp
        self.data = blockdata
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash, content = self.__hash_block()
        self.b = self.__tobin(content)

    def __hash_block(self) -> Tuple[bytes, bytes]:
        sha = hashlib.sha256()
        content = struct.pack('=idi', self.index, self.timestamp, self.nonce) + self.data.b + self.previous_hash
        sha.update(content)
        return sha.digest(), content

    def __tobin(self, content: bytes) -> bytes:
        return self.hash + content

    @classmethod
    def unpack(cls, b: bytes) -> 'Block':
        Verify.block_checker(b)
        blockhash = b[:BLENGTH_BLOCKHASH]
        index, timestamp, nonce = \
            struct.unpack('=idi', b[BLENGTH_BLOCKHASH: BLENGTH_BLOCKHASH + BLENGTH_INT + BLENGTH_DOUBLE + BLENGTH_INT])
        previous_hash = b[-BLENGTH_BLOCKHASH:]
        b_data = b[BLENGTH_BLOCKHASH + BLENGTH_INT + BLENGTH_DOUBLE + BLENGTH_INT: -BLENGTH_BLOCKHASH]
        data = BlockData.unpack(b_data)

        block = cls(index, timestamp, data, previous_hash, nonce)
        block.hash = blockhash
        block.b = b
        return block

    def show_block(self) -> dict:
        block_result = dict()
        block_result["index"] = self.index
        block_result["timestamp"] = self.timestamp
        block_result["nonce"] = self.nonce
        # convert previous_hash to hexadecimal
        temp = ""
        for i, data in enumerate(self.previous_hash):
            a = str(hex(self.previous_hash[i]))[2:]
            temp += a.zfill(2)
        c = "0x" + temp
        block_result["previous_hash"] = c
        # convert hash to hexadecimal
        temp = ""
        for i, data in enumerate(self.hash):
            a = str(hex(self.hash[i]))[2:]
            temp += a.zfill(2)
        c = "0x" + temp
        block_result["hash"] = c
        length = len(self.data.trans)
        result = []
        for i in range(length):
            result.append(self.data.trans[i].show_trans())
        block_result["data"] = {"transaction": result, "attachment": str(self.data.attachment.content,
                                                                         encoding="utf-8")}
        info = """Block-info:
        index:         %d
        timestamp:     %f
        nonce:         %d
        previous_hash: %s
        hash:          %s
        data:""" % (block_result["index"], block_result["timestamp"], block_result["nonce"],
                    block_result["previous_hash"], block_result["hash"])
        # print(info)
        for i in range(len(self.data.trans)):
            info = """        transaction:
              trans[%d]:
                 public_key:  %s
                 signature:   %s
                 version:     %d
                 timestamp:   %f
                 txid:        %s
                 input:
                      public_key_hash:  %s
                      content:          %s
                 output:
                      content:          %s
                 length:                %d
        attachment:            %s
            """ % (i, block_result["data"]["transaction"][i]["public_key"], block_result["data"]["transaction"] \
                [i]["signature"], block_result["data"]["transaction"][i]["version"], block_result["data"] \
                                          ["transaction"][i]["timestamp"],
                   block_result["data"]["transaction"][i]["txid"], block_result["data"] \
                                          ["transaction"][i]["trans_input"]["public_key_hash"],
                   block_result["data"]["transaction"][i] \
                                          ["trans_input"]["content"],
                   block_result["data"]["transaction"][i]["trans_output"]["content"],
                   block_result["data"]["transaction"][i]["length"], block_result["data"]["attachment"])
            # print(info)
        return block_result


class MacroBlockHeader:
    """
    testing version, still lacking a list of prev_hash (voting edge, ref edge)
    """

    def __init__(self, index: int, timestamp: float, public_key_hash: bytes, parent_hash: list, nonce=None) -> None:
        self.index = index
        self.timestamp = timestamp
        self.nonce = nonce
        self.public_key_hash = public_key_hash
        self.parent_hash = parent_hash
        self.hash, content = self.__hash_macro_block_header()
        self.b = self.__tobin(content)

    def __tobin(self, content: bytes) -> bytes:
        result = b''
        for i in self.parent_hash:
            result += i
        return self.hash + content + result + self.public_key_hash

    def __hash_macro_block_header(self) -> Tuple[bytes, bytes]:
        sha = hashlib.sha256()
        content = struct.pack('=idi', self.index, self.timestamp, self.nonce)
        sha.update(content)
        return sha.digest(), content

    @classmethod
    def unpack(cls, b: bytes) -> 'MacroBlockHeader':
        macro_block_header_hash = b[:BLENGTH_BLOCKHASH]
        index, timestamp, nonce = \
            struct.unpack('=idi', b[BLENGTH_BLOCKHASH: BLENGTH_BLOCKHASH + BLENGTH_INT + BLENGTH_DOUBLE + BLENGTH_INT])

        parent_hash = list()
        len_ = int(len(b[BLENGTH_BLOCKHASH + BLENGTH_INT + BLENGTH_DOUBLE + BLENGTH_INT:-BLENGTH_BLOCKHASH]) / 32)
        length = BLENGTH_BLOCKHASH + BLENGTH_INT + BLENGTH_DOUBLE + BLENGTH_INT
        for i in range(len_):
            parent_hash.append(b[length + 32 * i:length + 32 * (i + 1)])

        public_key_hash = b[-BLENGTH_BLOCKHASH:]

        macro_block_header = cls(index, timestamp, public_key_hash, parent_hash, nonce)
        macro_block_header.hash = macro_block_header_hash
        macro_block_header.b = b
        return macro_block_header

    def show_macro_block_header(self) -> dict():
        macro_block_header_result = dict()
        macro_block_header_result["index"] = self.index
        macro_block_header_result["timestamp"] = self.timestamp
        macro_block_header_result['public_key_hash'] = self.public_key_hash
        macro_block_header_result['parent_hash'] = self.parent_hash
        macro_block_header_result["nonce"] = self.nonce
        # convert hash to hexadecimal
        temp = ""
        for i, data in enumerate(self.hash):
            a = str(hex(self.hash[i]))[2:]
            temp += a.zfill(2)
        c = "0x" + temp
        macro_block_header_result["hash"] = c

        return macro_block_header_result


class MacroBlockBody:
    """
    testing version
    """

    def __init__(self, hash_: bytes, ref_hash: list, trans: Transaction) -> None:
        self.public_key = None
        self.signature = None
        self.hash = hash_
        self.ref_hash = ref_hash
        self.trans = trans
        self.b = None

    def __tobin(self, content: bytes) -> bytes:
        sy = self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        return self.hash + content + self.trans.b + struct.pack('i', len(self.trans.b)) + self.signature + \
               struct.pack('i', len(self.signature)) + sy

    @staticmethod
    def __sign(data: bytes, private_key: ec.EllipticCurvePrivateKey) -> SIGNATURE:
        return private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    def ready(self, private_key: ec.EllipticCurvePrivateKey):
        content = b''
        for i in self.ref_hash:
            content += i
        self.public_key = private_key.public_key()
        self.signature = MacroBlockBody.__sign(content, private_key)
        self.b = self.__tobin(content)

    @classmethod
    def unpack(cls, b: bytes) -> 'MacroBlockBody':
        macro_block_body_hash = b[:BLENGTH_BLOCKHASH]
        public_key = b[-BLENGTH_PUBKEY:]
        len_ = struct.unpack('i', b[-(BLENGTH_PUBKEY + BLENGTH_INT):-BLENGTH_PUBKEY])[0]
        signature = b[-(BLENGTH_PUBKEY + BLENGTH_INT + len_):-(BLENGTH_PUBKEY + BLENGTH_INT)]
        ref_hash = list()
        len__ = struct.unpack('i', b[-(BLENGTH_PUBKEY + BLENGTH_INT + len_ + BLENGTH_INT):
                                     -(BLENGTH_PUBKEY + BLENGTH_INT + len_)])[0]
        trans = Transaction.unpack(b[-(BLENGTH_PUBKEY + BLENGTH_INT + len_ + BLENGTH_INT + len__):
                                     -(BLENGTH_PUBKEY + BLENGTH_INT + len_ + BLENGTH_INT)])
        length_ = int(len(b[BLENGTH_BLOCKHASH:-(BLENGTH_PUBKEY + BLENGTH_INT + len_ + BLENGTH_INT + len__)]) / 32)
        for i in range(length_):
            ref_hash.append(b[BLENGTH_BLOCKHASH + i * 32:BLENGTH_BLOCKHASH + (i + 1) * 32])

        macro_block_body = cls(macro_block_body_hash, ref_hash, trans)
        macro_block_body.b = b
        public_key = load_pem_public_key(public_key, default_backend())
        macro_block_body.public_key = public_key
        macro_block_body.signature = signature
        return macro_block_body

    def show_macro_block_body(self) -> dict():
        macro_block_body_result = dict()
        macro_block_body_result["ref_hash"] = self.ref_hash
        macro_block_body_result["signature"] = self.signature
        macro_block_body_result['public_key'] = \
            self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        macro_block_body_result['trans'] = self.trans.show_trans()
        # convert hash to hexadecimal
        temp = ""
        for i, data in enumerate(self.hash):
            a = str(hex(self.hash[i]))[2:]
            temp += a.zfill(2)
        c = "0x" + temp
        macro_block_body_result["hash"] = c

        return macro_block_body_result


class MacroChain:
    """
    Chain structure of MacroBlockHeaders, and the temp_pool of MicroBlocks
    """

    def __init__(self):
        self.chain_ = queue.Queue()
        self.ref_micro_block = dict()
        self.main_chain = list()
        self.length = 0
        self.micro_block_num = 0
        self.micro_block_pool = list()

        self.mutex = threading.Lock()

        self.accepted_macro_block_headers = dict()
        self.accepted_micro_blocks = dict()
        self.accepted_macro_block_bodies = dict()
        self.accepted_macro_block_header_hash = list()
        self.micro_block_in_chain_ = dict()

        self.utxo = UTXOTable()
        self.utxo_two = UTXOTable()
        self.invalid_trans = list()

        # currently useless
        self.succeed_ = list()
        self.failed_ = list()

        # for test
        self.accepted_macro_block_headers[INIT_HASH] = 1
        macro_block_header = MacroBlockHeader(0, 0, b'0x', [], 0)
        macro_block_header.hash = INIT_HASH
        self.chain_.put(macro_block_header)

    def add_macro_block_header(self, macro_block_header: MacroBlockHeader):

        if macro_block_header.hash in self.accepted_macro_block_headers.keys():
            self.accepted_macro_block_headers[macro_block_header.hash] += 1
            # print('end in add macro_block_header wrong')
            return False
        self.accepted_macro_block_headers[macro_block_header.hash] = 1

        if not Verify.add_macro_block_header_verifier(self, macro_block_header):
            # print('end in add macro_block_header wrong')
            return False

        with self.mutex:
            self.chain_.put(macro_block_header)
            self.accepted_macro_block_header_hash.append(macro_block_header.hash)

        print('add one...')
        self.length += 1
        print('length=', self.length)

        print('macro_block_header.hash', macro_block_header.hash)
        print('timestamp', macro_block_header.timestamp)

        print('end in add macro_block_header right')
        return True

    def add_micro_block(self, micro_block) -> bool:
        """
        this function only serves as appending micro_blocks to pool, and doesn't validate trans inside
        :param micro_block: pending micro_block
        :return: the result
        """

        if micro_block.hash in self.accepted_micro_blocks.keys():
            self.accepted_micro_blocks[micro_block.hash] += 1
            # print('end in add micro_block wrong')
            return False
        self.accepted_micro_blocks[micro_block.hash] = 1

        if not Verify.add_micro_block_verifier(micro_block):
            # print('end in add micro_block wrong')
            return False
        # print('end in add micro_block right')
        with self.mutex:
            self.micro_block_pool.append(micro_block)

        self.micro_block_num += 1
        print('trans_num', len(micro_block.data.trans))

        return True

    def add_macro_block_body(self, macro_block_body: MacroBlockBody):

        if not Verify.add_macro_block_body_verifier(self, macro_block_body) or \
                not Verify.add_macro_block_body_verifier_two(self, macro_block_body):
            # print('end in add macro_block_body wrong')
            return False
        print('end in add macro_block_body right')

        return True

    def add_trans(self, hash_):
        print("adding trans", len(self.ref_micro_block[hash_]))

        temppool = TransPoolTwo(self)

        for i in self.ref_micro_block[hash_]:
            if i.hash in self.micro_block_in_chain_.keys():
                self.micro_block_in_chain_[i.hash] += 1
            else:
                self.micro_block_in_chain_[i.hash] = 1

        for i in self.ref_micro_block[hash_]:
            if self.micro_block_in_chain_[i.hash] <= 1:
                for trans in i.data.trans:
                    if trans.version == 1:
                        if not temppool.add(trans):
                            print('error3')
                            if trans not in self.invalid_trans:
                                self.invalid_trans.append(trans)

        # update the UTXOTable
        for i in self.ref_micro_block[hash_]:
            if self.micro_block_in_chain_[i.hash] <= 1:
                for trans in i.data.trans:
                    if trans not in self.invalid_trans:
                        if trans.version == 1:
                            self.utxo.delete(trans)
                            self.utxo_two.delete_two(trans)

        for i in self.ref_micro_block[hash_]:
            if self.micro_block_in_chain_[i.hash] <= 1:
                for trans in i.data.trans:
                    if trans not in self.invalid_trans:
                        self.utxo.add(trans)
                        self.utxo_two.add_two(trans, PUBLIC_KEY_HASH(hash_))
                    else:
                        self.invalid_trans.remove(trans)

        print('end over', len(self.ref_micro_block[hash_]), '\n')
        self.invalid_trans.clear()


class MacroChainDAG:
    """
    DAG structure of MacroBlockHeaders, and the temp_pool of MicroBlocks
    """

    def __init__(self):
        self.chain_ = queue.Queue()
        self.chain = dict()
        self.pivot_chain = queue.Queue()
        self.ref_micro_block = dict()
        self.main_chain = list()
        self.length = 0
        self.micro_block_num = 0
        self.micro_block_pool = list()
        self.tips = list()

        self.mutex = threading.Lock()

        self.accepted_macro_block_headers = dict()
        self.accepted_micro_blocks = dict()
        self.accepted_macro_block_bodies = dict()
        self.micro_block_in_chain_ = dict()
        self.accepted_macro_block_header_hash = list()

        self.utxo = UTXOTable()
        self.utxo_two = UTXOTable()
        self.invalid_trans = list()
        self.succeed_ = list()
        self.failed_ = list()

        # just for test
        self.accepted_macro_block_headers[INIT_HASH] = 1
        macro_block_header = MacroBlockHeader(0, 0, b'0x', [], 0)
        macro_block_header.hash = INIT_HASH
        self.ref_micro_block[INIT_HASH] = list()
        self.chain_.put(macro_block_header)
        self.pivot_chain.put(INIT_HASH)
        self.chain[INIT_HASH] = list()

    def add_macro_block_header(self, macro_block_header: MacroBlockHeader):

        if macro_block_header.hash in self.accepted_macro_block_headers.keys():
            self.accepted_macro_block_headers[macro_block_header.hash] += 1
            print('end in add macro_block_header wrong1')
            return False
        with self.mutex:
            fd_ = open('timestamp.txt', 'a')
            fd_.writelines(str(self.length) + '\t' + str(macro_block_header.hash) + str(time.time()) + '\t' + '\n')
            fd_.close()
        self.accepted_macro_block_headers[macro_block_header.hash] = 1

        if not Verify.add_macro_block_header_verifier_dag(self, macro_block_header):
            print('end in add macro_block_header wrong2')
            return False

        self.chain[macro_block_header.parent_hash[0]].append(macro_block_header.hash)
        self.chain[macro_block_header.hash] = list()

        for i in self.chain.keys():
            if len(self.chain[i]) == 0:
                self.tips.append(i)
            else:
                if i in self.tips:
                    self.tips.remove(i)
        self.in_operations()
        with self.mutex:
            lib.test(BLOCK_CYCLE, input_, output_)
        self.out_operations()
        result = dict()
        result_local = list()
        chain_test = list(self.pivot_chain.queue)
        chain_test_ = list(self.chain_.queue)
        chain_test_.append(macro_block_header)
        for i in self.chain.keys():
            if i not in chain_test:
                result[i] = list()
        for i in result.keys():
            for i_ in chain_test_:
                if i in i_.parent_hash:
                    if i_.hash in self.pivot_chain.queue:
                        result[i].append(i_)
            if len(result[i]) == 0:
                pass
            else:
                for j in result[i]:
                    result_local.append(chain_test.index(j.hash))
                for j in chain_test_:
                    if j.hash == i:
                        chain_test.insert(min(result_local), j)
                        result_local.clear()
                        break

        for i in result.keys():
            if len(result[i]) == 0:
                k = 0
                for k in chain_test_:
                    if k.hash == i:
                        break
                for index, j in enumerate(chain_test):
                    z = 0
                    for z in chain_test_:
                        if z.hash == j:
                            break
                    if k.timestamp >= z.timestamp:
                        pass
                    else:
                        chain_test.insert(index, k.hash)
                        break

        flag = 1
        l_ = min(len(chain_test), len(self.chain_.queue))
        i_ = 0
        while flag == 1:
            if i_ < l_:
                if self.chain_.queue[i_].hash == chain_test[i_]:
                    i_ += 1
                else:
                    flag = 0
            else:
                flag = 0

        self.accepted_macro_block_header_hash.clear()
        for i in range(i_):
            self.accepted_macro_block_header_hash.append(self.chain_.queue[i].hash)

        with self.mutex:
            for i in range(len(self.chain_.queue) - i_):
                if self.chain_.queue[i_ + i].hash in self.ref_micro_block.keys():
                    for q in (self.ref_micro_block[self.chain_.queue[i_ + i].hash]):
                        self.trans_retrieve(q)
            for i in range(len(self.chain_.queue) - i_):
                self.chain_.queue.pop()
            for i in range(len(chain_test) - i_):
                if chain_test[i_ + i] in self.ref_micro_block.keys():
                    self.add_trans(chain_test[i_ + i])
                for j in chain_test_:
                    if j.hash == chain_test[i_ + i]:
                        self.chain_.put(j)
                        self.accepted_macro_block_header_hash.append(j.hash)
                        break

        self.length += 1
        print('length=', self.length)

        print('macro_block_header.hash', macro_block_header.hash)
        print('timestamp', macro_block_header.timestamp)

        print('end in add macro_block_header right')
        return True

    def add_micro_block(self, micro_block) -> bool:
        """
        this function only serves as appending micro_blocks to pool, and doesn't validate trans inside
        :param micro_block: pending micro_block
        :return: the result
        """

        if micro_block.hash in self.accepted_micro_blocks.keys():
            self.accepted_micro_blocks[micro_block.hash] += 1
            # print('end in add micro_block wrong')
            return False
        self.accepted_micro_blocks[micro_block.hash] = 1

        if not Verify.add_micro_block_verifier(micro_block):
            # print('end in add micro_block wrong')
            return False
        # print('end in add micro_block right')
        with self.mutex:
            self.micro_block_pool.append(micro_block)

        # print('add one...')
        self.micro_block_num += 1
        print('trans_num', len(micro_block.data.trans))

        return True

    def add_macro_block_body(self, macro_block_body: MacroBlockBody):
        print('add in add')
        if Verify.add_macro_block_body_verifier_dag(self, macro_block_body) and \
                Verify.add_macro_block_body_verifier_two_dag(self, macro_block_body):
            # print('end in add macro_block_body wrong')
            return True

        return False

    def add_trans(self, hash_):
        print("adding trans", len(self.ref_micro_block[hash_]))
        temppool = TransPoolDAG(self)

        for i in self.ref_micro_block[hash_]:
            if i.hash in self.micro_block_in_chain_.keys():
                self.micro_block_in_chain_[i.hash] += 1
            else:
                self.micro_block_in_chain_[i.hash] = 1

        for i in self.ref_micro_block[hash_]:
            if self.micro_block_in_chain_[i.hash] <= 1:
                # print(len(i.data.trans))
                for trans in i.data.trans:
                    if trans.version == 1:
                        if not temppool.add(trans):
                            print('error3')
                            if trans not in self.invalid_trans:
                                self.invalid_trans.append(trans)

        for i in self.ref_micro_block[hash_]:
            if self.micro_block_in_chain_[i.hash] <= 1:
                # update the UTXOTable
                for trans in i.data.trans:
                    if trans not in self.invalid_trans:
                        if trans.version == 1:
                            self.utxo.delete(trans)
                            self.utxo_two.delete_two(trans)

        for i in self.ref_micro_block[hash_]:
            if self.micro_block_in_chain_[i.hash] <= 1:
                for trans in i.data.trans:
                    if trans not in self.invalid_trans:
                        self.utxo.add(trans)
                        self.utxo_two.add_two(trans, PUBLIC_KEY_HASH(hash_))
                    else:
                        self.invalid_trans.remove(trans)

        print('end over', len(self.ref_micro_block[hash_]), '\n')
        self.invalid_trans.clear()

    def in_operations(self):
        with self.mutex:
            fd_ = open('DAG_input.txt', 'w')
            fd_.writelines(str(INIT_HASH) + '\n')
            for i in self.chain.items():
                if len(i[1]) > 0:
                    for i_ in i[1]:
                        fd_.writelines(str(i[0].replace(b' ', b'ECS')) + ' ')
                        fd_.writelines(str(i_.replace(b' ', b'ECS')) + '\n')
            fd_.close()

    def out_operations(self):
        with self.mutex:
            self.pivot_chain.queue.clear()
            fd_ = open('DAG_output.txt', 'r')
            for index, line in enumerate(fd_.readlines()):
                if index == 0:
                    pass
                else:
                    temp = bytes(line.rstrip()[2:-1], encoding='utf-8').replace(b'ECS', b' ')
                    temp = codecs.escape_decode(temp)[0]
                    self.pivot_chain.put(temp)
            fd_.close()

    def trans_retrieve(self, i_):
        if i_.hash in self.micro_block_in_chain_.keys():
            self.micro_block_in_chain_[i_.hash] -= 1
        for trans in i_.data.trans:
            for j in range(len(trans.opt.content)):
                if self.utxo_two.exist((trans.txid, j)):
                    del self.utxo_two.utxo[(trans.txid, j)]
                if self.utxo.exist((trans.txid, j)):
                    del self.utxo.utxo[(trans.txid, j)]
                else:
                    pass
            for j in range(len(trans.ipt.content)):
                if trans.ipt.content[j] in self.utxo_two.txo.keys():
                    if self.utxo_two.txo[trans.ipt.content[j]][1] in self.accepted_macro_block_header_hash:
                        self.utxo_two.utxo[trans.ipt.content[j]] = self.utxo_two.txo[trans.ipt.content[j]]
                        del self.utxo_two.txo[trans.ipt.content[j]]
                        self.utxo.utxo[trans.ipt.content[j]] = self.utxo.txo[trans.ipt.content[j]]
                        del self.utxo.txo[trans.ipt.content[j]]
                    else:
                        pass
                else:
                    pass


class MicroBlock(Block):
    """
    Different from Block, MicroBlock.hash is a random value
    """
    pass


class LightBlock:
    """
    A lightweight block-bade object for broadcast
    """

    def __init__(self, index: int, timestamp: float, lightblockdata: LightBlockData, previous_hash: bytes,
                 hash_: bytes, nonce=None) -> None:
        self.index = index
        self.timestamp = timestamp
        self.data = lightblockdata
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = hash_
        content = struct.pack('=idi', self.index, self.timestamp, self.nonce) + self.data.b + self.previous_hash
        self.b = self.__tobin(content)

    def __tobin(self, content: bytes) -> bytes:
        return self.hash + content

    @classmethod
    def unpack(cls, b: bytes) -> 'LightBlock':
        blockhash = b[:BLENGTH_BLOCKHASH]
        index, timestamp, nonce = \
            struct.unpack('=idi', b[BLENGTH_BLOCKHASH: BLENGTH_BLOCKHASH + BLENGTH_INT + BLENGTH_DOUBLE + BLENGTH_INT])
        previous_hash = b[-BLENGTH_BLOCKHASH:]
        b_data = b[BLENGTH_BLOCKHASH + BLENGTH_INT + BLENGTH_DOUBLE + BLENGTH_INT: -BLENGTH_BLOCKHASH]
        data = LightBlockData.unpack(b_data)

        block = cls(index, timestamp, data, previous_hash, blockhash, nonce)
        block.hash = blockhash
        block.b = b
        return block


class UTXOTable:
    """
    A table maintains the states of UTXO
    """

    def __init__(self):
        self.utxo = dict()
        self.mutex = threading.Lock()
        self.txo = dict()

    def add(self, transaction: Transaction) -> None:
        """
        add all outputs of a transaction to the table
        :param transaction: a transaction
        :return: None
        """
        with self.mutex:
            for index, opt in zip(range(len(transaction.opt.content)), transaction.opt.content):
                self.utxo[(transaction.txid, index)] = {'amount': opt[0],
                                                        'to': opt[1]}

    def add_two(self, transaction: Transaction, hash_: PUBLIC_KEY_HASH) -> None:
        """
        add all outputs of a transaction to the table
        :param transaction: a transaction
        :param hash_: the hash of block
        :return: None
        """
        with self.mutex:
            for index, opt in zip(range(len(transaction.opt.content)), transaction.opt.content):
                self.utxo[(transaction.txid, index)] = ({'amount': opt[0], 'to': opt[1]}, hash_)

    def exist(self, utxo: Tuple[bytes, int]) -> bool:
        """
        return if the utxo exists in the table
        :param utxo: tuple(txid, index)
        :return: True | False
        """
        with self.mutex:
            return utxo in self.utxo

    def delete(self, transaction: Transaction) -> None:
        """
        delete UTXOs that transaction referenced from the table
        :param transaction: a transaction
        :return: None
        """
        with self.mutex:
            for ipt in transaction.ipt.content:
                self.txo[ipt] = self.utxo[ipt]
                del self.utxo[ipt]

    def delete_two(self, transaction: Transaction) -> dict:
        """
        delete UTXOs that transaction referenced from the table
        :param transaction: a transaction
        :return: None
        """
        with self.mutex:
            delete_result = dict()

            for ipt in transaction.ipt.content:
                if self.utxo[ipt][1] in delete_result:
                    delete_result[self.utxo[ipt][1]] += 1
                else:
                    delete_result[self.utxo[ipt][1]] = 1
                self.txo[ipt] = self.utxo[ipt]
                del self.utxo[ipt]
            return delete_result

    def info(self, utxo: Tuple[bytes, int], block: bool = True) -> dict:
        """
        return information of an UTXO
        :param utxo: tuple(txid, index)
        :param block: None
        :return: dict contain 'amount' and 'to' of the UTXO
        """
        if block:
            with self.mutex:
                return self.utxo[utxo]
        else:
            return self.utxo[utxo]

    def check(self, utxo: Tuple[bytes, int], amount: int, receiver: bytes) -> bool:
        """
        validate the UTXO
        :param utxo: tuple(txid, index)
        :param amount: amount of assets
        :param receiver: the receiver of assets
        :return: True if pass the validation | False if the utxo does not exist or has invalid amount or receiver
        """
        with self.mutex:
            if utxo in self.utxo:
                return self.info(utxo, block=False)['amount'] == amount \
                       and self.info(utxo, block=False)['to'] == receiver
        return False


class Blockchain:
    """
    b'-----BEGIN PRIVATE KEY-----\n
    MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQg64DiDBUkuGC5rrTfH6uy\n
    Ht6vhvHrMHj3Gm64SZtdqtKhRANCAATMIeaIK4vT0ni00F6GGW40qioinPFgXjsj\n
    6sZGivW9Ipj+zcDfPc7RxZuFeKFmbtVaUXZ877DM4C8ELZs2DPVQ\n
    -----END PRIVATE KEY-----\n'
    b'-----BEGIN PUBLIC KEY-----\n
    MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEzCHmiCuL09J4tNBehhluNKoqIpzxYF47\n
    I+rGRor1vSKY/s3A3z3O0cWbhXihZm7VWlF2fO+wzOAvBC2bNgz1UA==\n
    -----END PUBLIC KEY-----\n'
    pubkey hash (the first transaction in genesis block pay 42 to this address):
    b'\x8b\x8dZ\x80\xde\x82k\xe1>0F\xf4\xbbh\x93\x04\xef\x8e\x9b\xe2\xb2\xd9\xe1\x9c\x80\x10H\xb6\xa1\xfd\x02\xbf'
    """

    def __init__(self) -> None:
        # b = b'\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06\xf5{\x89^4\x1b\xb3\x95z\x04}\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E'
        # priv_key = load_der_private_key(
        #     b'0\x81\x84\x02\x01\x000\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81\x04\x00\n\x04m0k\x02\x01\x01\x04 '
        #     b'\xa6qo\xd3\x95}e\xeb\x0f\xa2\xc3U\xa5\xf2v\x85\x19\xbc@\xf7\xfd\xcb^\xa2\xe3\x96N\xff\nh\xd0\x85\xa1D'
        #     b'\x03B\x00\x04\xecm\xa8\x92U@;\xb3\xe6\x90\xec\x05+*\x11-\x16b\x8e\xba\xe5\x12\xb4\x93x\xea\xce\x11'
        #     b'\xccNPq\xb5\xcb\x08\xc6`\xb2\xd3Y]o\xbciz\xad\xd2\xf4\xc3\x1c,\xaa\x19xs{\x8c\xa9a\xc7\x03\xcb\x18^',
        #     None,
        #     default_backend()
        # )
        # ipt = TransInput([(b, 0)], b)
        # opt = TransOutput([(42, b'\x8b\x8dZ\x80\xde\x82k\xe1>0F\xf4\xbbh\x93\x04\xef\x8e'
        #                         b'\x9b\xe2\xb2\xd9\xe1\x9c\x80\x10H\xb6\xa1\xfd\x02\xbf')])
        # trans = Transaction(ipt, opt)
        # trans.ready(priv_key)
        #
        #
        # at = Attachment()
        # at.add_data(b'')
        # at.ready()
        # bd = BlockData([trans], at)
        # block = Block(0, 0, bd, bytes(32), 0)
        #
        # print('trans', trans.txid)
        # print('block', block.b)

        # genesis block
        block = Block.unpack(b'G\xfdk\x88\xda5\xff\x8c\x97t\x9f\xcb\xe0\xa8\x07S\x8b9t:.9\x1d\xee\xf4\xb1\xda\xd1r\xaf'
                             b'\xfcu\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                             b'\x99\x01\x00\x00O\x1e,-\xe1\xa0!\x16D\x87\xcc\x923\xf7\xf6\xca\xad\xd1\t\x8eV\xdc\xe8t}N'
                             b'\xfa\x8af\xbe\xe7\xef\x01\x00\x00\x00\x89\x92N\xd8h\xb5\xd6A\xae\x00\x00\x00D\x00\x00'
                             b'\x00(\x00\x00\x00-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE7G2oklVAO7P'
                             b'mkOwFKyoRLRZijrrlErST\neOrOEcxOUHG1ywjGYLLTWV1vvGl6rdL0wxwsqhl4c3uMqWHHA8sYXg==\n-----EN'
                             b'D PUBLIC KEY-----\n\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06\xf5{\x89^4\x1b\xb3\x95z\x04}'
                             b'\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E\x00\x00\x00\x00\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06'
                             b'\xf5{\x89^4\x1b\xb3\x95z\x04}\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E\x00\x00\x00\x00\x00'
                             b'\x00E@\x8b\x8dZ\x80\xde\x82k\xe1>0F\xf4\xbbh\x93\x04\xef\x8e\x9b\xe2\xb2\xd9\xe1\x9c\x80'
                             b'\x10H\xb6\xa1\xfd\x02\xbf0E\x02!\x00\xfa\xff2\x10\x08\x18\xce~\x10\xb3\xe5\xc7y\xfd]\xd4'
                             b'\x13tj\x9bx\n3-\xef\xe5\t\xe3\xd6R+\x16\x02 \x17L\x07\xb5E c\xc8\xf5l\xc7\xc1\xa7BM'
                             b'\xbb0Y/\x9b\x89\xb0a_9\x0bi\xe2*\x0b\xda\xf9\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                             b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

        # set block.hash to '0x1' to enable the function of sort test
        # block.hash = b'0x000000000000000000000000000001'

        self.chain = queue.Queue()
        self.chain.put(block)
        self.UTXO_num = dict()
        self.utxo = UTXOTable()
        self.length = 0
        self.size_ = sys.getsizeof(block.b)
        self.invalid_trans = list()
        self.accepted_blocks = dict()
        self.accepted_blocks_hash = list()
        self.mutex = threading.Lock()

        for trans in block.data.trans:
            self.utxo.add(trans)

        self.utxo_two = UTXOTable()
        for trans in block.data.trans:
            self.utxo_two.add_two(trans, PUBLIC_KEY_HASH(block.hash))
            self.UTXO_num[block.hash] = 0
            self.UTXO_num[block.hash] += len(trans.opt.content)

        self.accepted_blocks_hash.append(block.hash)

    def add_block(self, block: Block) -> bool:
        if block.hash in self.accepted_blocks.keys():
            self.accepted_blocks[block.hash] += 1
            print('end in add block wrong')
            return False
        self.accepted_blocks[block.hash] = 1
        with self.mutex:
            fd_ = open('timestamp.txt', 'a')
            fd_.writelines(str(self.length) + '\t' + str(block.hash) + '\t\t' + str(time.time()) + '\n')
            fd_.close()

        if not Verify.add_block_verifier(self, block):
            print('end in add block wrong')
            return False

        with self.mutex:
            self.chain.put(block)
            self.accepted_blocks_hash.append(block.hash)
        print('add one...')
        self.length += 1
        print('trans_num', len(block.data.trans))

        temppool = TransPool(self)
        for trans in block.data.trans:
            if trans.version == 1:
                if not temppool.add(trans):
                    print('error3')
                    if trans not in self.invalid_trans:
                        self.invalid_trans.append(trans)

        print('hash1', block.hash)
        print('prev_hash', block.previous_hash)
        print('blockchain', self.chain.queue[-1].hash)
        print('timestamp', block.timestamp)
        print('invalid trans', len(self.invalid_trans))

        for tran in block.data.trans:
            if tran in self.invalid_trans:
                print('invalid')
        self.size_ += sys.getsizeof(block.b)

        # update the UTXOTable
        for trans in block.data.trans:
            if trans not in self.invalid_trans:
                if trans.version == 1:
                    self.utxo.delete(trans)
                    del_result = self.utxo_two.delete_two(trans)
                    for key in del_result.keys():
                        self.UTXO_num[key] -= del_result[key]  # key :block hash

        # result = list()
        # for index, data in enumerate(self.chain.queue):
        #     if self.UTXO_num[data.hash] == 0:
        #         result.append(index)
        #         self.UTXO_num.pop(data.hash)
        # for num in result[::-1]:
        #     self.chain.queue.remove(self.chain.queue[num])

        self.UTXO_num[block.hash] = 0
        for trans in block.data.trans:
            if trans not in self.invalid_trans:
                self.utxo.add(trans)
                self.utxo_two.add_two(trans, PUBLIC_KEY_HASH(block.hash))
                self.UTXO_num[block.hash] += len(trans.opt.content)
            else:
                self.invalid_trans.remove(trans)

        self.invalid_trans.clear()
        print('end in add block right')
        return True

    def size(self) -> int:
        return self.chain.qsize()

    def search_block(self, hash_: bytes = None, timestamp: float = None, index: int = None) -> Block:
        if hash_ is not None:
            return [block for block in self.chain.queue if block.hash == hash_].pop()

        if timestamp is not None:
            return [block for block in self.chain.queue if block.timestamp == timestamp].pop()

        if index is not None:
            return [block for block in self.chain.queue if block.index == index].pop()

        raise BlockNotInChain

    def search_transaction(self, txid: bytes = None, timestamp: float = None) -> Transaction:
        for block in self.chain.queue:
            for trans in block:
                if txid is not None:
                    if trans.txid == txid:
                        return trans
                if timestamp is not None:
                    if trans.timestamp == timestamp:
                        return trans
        raise TransNotInChain


class TransPool:
    """
    the thread-safe pool of transactions
    """

    def __init__(self, chain: Blockchain):
        self.trans = queue.Queue()
        self.utxo = UTXOTable()
        self.chain = chain
        self.ipt = []

    def add(self, transaction) -> bool:
        """add a transaction to the pool"""
        if isinstance(transaction, bytes):
            transaction = Transaction.unpack(transaction)

        """
        The following conditions 2 guarantee that a new transaction can use UTXO in transpool
        (by giving both self.utxo and self.chain.utxo to checkers)
        But this behavior is not recommended (the used UTXO may not exist in all nodes' transpool)

        Also the condition 2 does not prevent the double-spending in transpool, e.g.,
                Wrong:
        |-- UTXO--|   |-- pool--|
        |---------|   |---------|
        |----A----|   |--A<-B---|
        |---------|   |--A<-C---|
        |---------|   |---------|
                  OK:
        |-- UTXO--|   |-- pool--|
        |---------|   |---------|
        |----A<-B-|   |---------|
        |---------|   |--A<-C---|
        |---------|   |---------|

        because the codes here do not change the UTXO table of the blockchain.

        So I use a extra list recording all inputs of transactions that are in the UTXO table of transpool
        and add the condition 3
        """

        validation = [
            Verify.sig_checker(transaction),
            Verify.double_spend_checker([self.utxo, self.chain.utxo], transaction),
            Verify.transpool_double_spend_checker(self.ipt, transaction),
            Verify.balance_checker([self.utxo, self.chain.utxo], transaction)
        ]
        # print(validation)
        if validation[0] \
                and validation[1] \
                and validation[2] \
                and validation[3]:

            self.utxo.add(transaction)  # add all outputs in transaction to the UTXO table of transpool
            self.trans.put(transaction)

            return True
        else:
            print(validation)
            return False

    def retrieve(self, num: int) -> List[Transaction]:
        """
        get transactions in the pool
        :param num: number of transactions to be retrieved
        :return: a list of transactions
        """
        num = min(self.trans.qsize(), num)

        result = []
        for i in range(num):
            result.append(self.trans.get())

        return result

    def retrieve_serialized(self, num: int) -> List[bytes]:
        """
        get transactions in the pool with serialized format
        :param num:  number of transactions to be retrieved
        :return: a byte string of the retrieved transactions
        """
        return [trans.b for trans in self.retrieve(num)]

    def read(self) -> List[Transaction]:
        """
        read all the transactions in the pool
        :return: a list of transactions
        """
        return list(self.trans.queue)

    def read_serialized(self) -> List[bytes]:
        """
        read all the transactions in the pool
        :return: a list of binary transactions
        """
        result = self.read()
        print('trans=', len(result))
        return [trans.b for trans in self.read()]

    def simply_read_serialized(self) -> List[bytes]:
        """
        read all the transactions in the pool
        :return: a list of binary trans.txid
        """
        return [trans.txid for trans in self.read()]

    def remove(self, block: Block):
        """
        remove all transactions in the pool when the new block comes
        :param block: the new block (currently make no sense)
        :return: None
        """
        trans_in_pool = self.read()
        trans_in_block = []
        for t in block.data.trans:
            trans_in_block.append(t.txid)
        result = []
        for i, t in enumerate(trans_in_pool):
            if t.txid in trans_in_block:
                result.append(i)
        for i in result[::-1]:
            self.trans.queue.remove(self.trans.queue[i])


class TransPoolTwo:
    """
    the thread-safe pool of transactions
    """

    def __init__(self, chain: MacroChain):
        self.trans = queue.Queue()
        self.utxo = UTXOTable()
        self.chain = chain
        self.ipt = list()
        self.used = list()
        self.mutex = threading.Lock()

    def add(self, transaction) -> bool:
        """add a transaction to the pool"""
        if isinstance(transaction, bytes):
            transaction = Transaction.unpack(transaction)

        """
        The following conditions 2 guarantee that a new transaction can use UTXO in transpool
        (by giving both self.utxo and self.chain.utxo to checkers)
        But this behavior is not recommended (the used UTXO may not exist in all nodes' transpool)

        Also the condition 2 does not prevent the double-spending in transpool, e.g.,
                Wrong:
        |-- UTXO--|   |-- pool--|
        |---------|   |---------|
        |----A----|   |--A<-B---|
        |---------|   |--A<-C---|
        |---------|   |---------|
                  OK:
        |-- UTXO--|   |-- pool--|
        |---------|   |---------|
        |----A<-B-|   |---------|
        |---------|   |--A<-C---|
        |---------|   |---------|

        because the codes here do not change the UTXO table of the blockchain.

        So I use a extra list recording all inputs of transactions that are in the UTXO table of transpool
        and add the condition 3
        """

        validation = [
            Verify.sig_checker(transaction),
            Verify.double_spend_checker([self.utxo, self.chain.utxo], transaction),
            Verify.transpool_double_spend_checker(self.ipt, transaction),
            Verify.balance_checker([self.utxo, self.chain.utxo], transaction)
        ]
        # print(validation)
        if validation[0] \
                and validation[1] \
                and validation[2] \
                and validation[3]:

            self.utxo.add(transaction)  # add all outputs in transaction to the UTXO table of transpool

            for ipt in transaction.ipt.content:
                self.ipt.append(ipt)
            self.trans.put(transaction)
            # print(validation, transaction.show_trans())
            return True
        else:
            print(validation, transaction.show_trans())
            return False

    def retrieve(self, num: int) -> List[Transaction]:
        """
        get transactions in the pool
        :param num: number of transactions to be retrieved
        :return: a list of transactions
        """
        num = min(self.trans.qsize(), num)

        result = []
        for i in range(num):
            result.append(self.trans.get())

        return result

    def retrieve_serialized(self, num: int) -> List[bytes]:
        """
        get transactions in the pool with serialized format
        :param num:  number of transactions to be retrieved
        :return: a byte string of the retrieved transactions
        """
        return [trans.b for trans in self.retrieve(num)]

    def read(self) -> List[Transaction]:
        """
        read all the transactions in the pool
        :return: a list of transactions
        """
        result = list(self.trans.queue)
        result_ = list()
        for i in result:
            if i.txid not in self.used:
                result_.append(i)
        return result_

    def read_serialized(self) -> List[bytes]:
        """
        read all the transactions in the pool
        :return: a list of binary transactions
        """
        result = self.read()
        if len(result) > 1000:
            result = result[0:999]

        for i in result:
            self.used.append(i.txid)
        # print('trans=', len(result))
        return [trans.b for trans in result]

    def simply_read_serialized(self) -> List[bytes]:
        """
        read all the transactions in the pool
        :return: a list of binary trans.txid
        """
        return [trans.txid for trans in self.read()]

    def remove(self, block: MicroBlock):
        """
        remove all transactions in the pool when the new block comes
        :param block: the new block (currently make no sense)
        :return: None
        """
        trans_in_pool = self.read()
        trans_in_block = []
        for t in block.data.trans:
            trans_in_block.append(t.txid)
        result = []
        for i, t in enumerate(trans_in_pool):
            if t.txid in trans_in_block:
                result.append(i)
        for i in result[::-1]:
            self.trans.queue.remove(self.trans.queue[i])


class TransPoolDAG:
    """
    the thread-safe pool of transactions
    """

    def __init__(self, chain: MacroChainDAG):
        self.trans = queue.Queue()
        self.utxo = UTXOTable()
        self.chain = chain
        self.ipt = list()
        self.used = list()
        self.mutex = threading.Lock()

    def add(self, transaction) -> bool:
        """add a transaction to the pool"""
        if isinstance(transaction, bytes):
            transaction = Transaction.unpack(transaction)

        """
        The following conditions 2 guarantee that a new transaction can use UTXO in transpool
        (by giving both self.utxo and self.chain.utxo to checkers)
        But this behavior is not recommended (the used UTXO may not exist in all nodes' transpool)

        Also the condition 2 does not prevent the double-spending in transpool, e.g.,
                Wrong:
        |-- UTXO--|   |-- pool--|
        |---------|   |---------|
        |----A----|   |--A<-B---|
        |---------|   |--A<-C---|
        |---------|   |---------|
                  OK:
        |-- UTXO--|   |-- pool--|
        |---------|   |---------|
        |----A<-B-|   |---------|
        |---------|   |--A<-C---|
        |---------|   |---------|

        because the codes here do not change the UTXO table of the blockchain.

        So I use a extra list recording all inputs of transactions that are in the UTXO table of transpool
        and add the condition 3
        """

        validation = [
            Verify.sig_checker(transaction),
            Verify.double_spend_checker([self.utxo, self.chain.utxo], transaction),
            Verify.transpool_double_spend_checker(self.ipt, transaction),
            Verify.balance_checker([self.utxo, self.chain.utxo], transaction)
        ]
        # print(validation)
        if validation[0] \
                and validation[1] \
                and validation[2] \
                and validation[3]:

            self.utxo.add(transaction)  # add all outputs in transaction to the UTXO table of transpool

            for ipt in transaction.ipt.content:
                self.ipt.append(ipt)
            self.trans.put(transaction)

            return True
        else:
            print(validation, transaction.show_trans())
            return False

    def retrieve(self, num: int) -> List[Transaction]:
        """
        get transactions in the pool
        :param num: number of transactions to be retrieved
        :return: a list of transactions
        """
        num = min(self.trans.qsize(), num)

        result = []
        for i in range(num):
            result.append(self.trans.get())

        return result

    def retrieve_serialized(self, num: int) -> List[bytes]:
        """
        get transactions in the pool with serialized format
        :param num:  number of transactions to be retrieved
        :return: a byte string of the retrieved transactions
        """
        return [trans.b for trans in self.retrieve(num)]

    def read(self) -> List[Transaction]:
        """
        read all the transactions in the pool
        :return: a list of transactions
        """
        result = list(self.trans.queue)
        result_ = list()
        for i in result:
            if i.txid not in self.used:
                result_.append(i)
        return result_

    def read_serialized(self) -> List[bytes]:
        """
        read all the transactions in the pool
        :return: a list of binary transactions
        """
        result = self.read()
        if len(result) > 1000:
            result = result[0:999]

        for i in result:
            self.used.append(i.txid)
        # print('trans=', len(result))
        return [trans.b for trans in result]

    def simply_read_serialized(self) -> List[bytes]:
        """
        read all the transactions in the pool
        :return: a list of binary trans.txid
        """
        return [trans.txid for trans in self.read()]

    def remove(self, block: MicroBlock):
        """
        remove all transactions in the pool when the new block comes
        :param block: the new block (currently make no sense)
        :return: None
        """
        trans_in_pool = self.read()
        trans_in_block = []
        for t in block.data.trans:
            trans_in_block.append(t.txid)
        result = []
        for i, t in enumerate(trans_in_pool):
            if t.txid in trans_in_block:
                result.append(i)
        for i in result[::-1]:
            self.trans.queue.remove(self.trans.queue[i])


class Verify:
    def __init__(self):
        pass

    @staticmethod
    def add_block_verifier(blockchain: Blockchain, block: Block) -> bool:
        if block.previous_hash != blockchain.chain.queue[-1].hash:
            # print('error2')

            return False

        # todo: nonce validation
        # the above 'target' is a property of blockchain, should be calculated from the previous blocks.

        # to validate the transactions in the block
        # reuse validation rules written in the TransPool
        # target = (2 ** 234 - 1).to_bytes(32, byteorder='big')
        # sha = hashlib.sha256()
        # sha.update(block.previous_hash)
        # sha.update(struct.pack('=I', block.nonce))
        # hash_ = sha.digest()
        # sha = hashlib.sha256()
        # sha.update(hash_)
        # hash_ = sha.digest()
        # if hash_ >= target:
        #     return False

        return True

    @staticmethod
    def add_macro_block_header_verifier(macro_chain: MacroChain, macro_block_header: MacroBlockHeader) -> bool:
        for i in macro_block_header.parent_hash:
            if i in macro_chain.accepted_macro_block_headers:
                pass
            else:
                return False
        # just for linear
        if macro_block_header.parent_hash[0] != macro_chain.chain_.queue[-1].hash:
            return False
        return True

    @staticmethod
    def add_macro_block_header_verifier_dag(macro_chain: MacroChainDAG, macro_block_header: MacroBlockHeader) -> bool:
        for i in macro_block_header.parent_hash:
            if i in macro_chain.accepted_macro_block_headers:
                pass
            else:
                return False

        return True

    @staticmethod
    def add_macro_block_body_verifier(macro_chain: MacroChain, macro_block_body: MacroBlockBody) -> bool:
        print('verify macro_block_body', macro_block_body.show_macro_block_body())
        # print(len(macro_block_body.ref_hash))
        for i in macro_block_body.ref_hash:
            if i not in macro_chain.accepted_micro_blocks:
                return False
        return True

    @staticmethod
    def add_macro_block_body_verifier_dag(macro_chain: MacroChainDAG, macro_block_body: MacroBlockBody) -> bool:
        print('verify macro_block_body', macro_block_body.hash)
        # print(len(macro_block_body.ref_hash))
        for i in macro_block_body.ref_hash:
            if i not in macro_chain.accepted_micro_blocks:
                return False
        return True

    @staticmethod
    def add_macro_block_body_verifier_two(macro_chain: MacroChain, macro_block_body: MacroBlockBody) -> bool:
        # for i in macro_chain.chain.keys():
        for i in macro_chain.chain_.queue:
            if i.hash == macro_block_body.hash:
                b_pubkey = macro_block_body.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

                sha = hashlib.sha256()
                sha.update(b_pubkey)
                public_key_hash = sha.digest()

                if i.public_key_hash != public_key_hash:

                    return False
                else:
                    content = b''
                    for i_ in macro_block_body.ref_hash:
                        content += i_
                    try:
                        macro_block_body.public_key.verify(macro_block_body.signature,
                                                           content, ec.ECDSA(hashes.SHA256()))
                    except (Exception):
                        print('\n sig\n ')
                        return False

                    else:
                        return True
        print('not find')
        return False

    @staticmethod
    def add_macro_block_body_verifier_two_dag(macro_chain: MacroChainDAG, macro_block_body: MacroBlockBody) -> bool:
        # for i in macro_chain.chain.keys():
        for i in macro_chain.chain_.queue:
            if i.hash == macro_block_body.hash:
                b_pubkey = macro_block_body.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

                sha = hashlib.sha256()
                sha.update(b_pubkey)
                print(b_pubkey)
                public_key_hash = sha.digest()

                if i.public_key_hash != public_key_hash:
                    return False
                else:
                    content = b''
                    for i_ in macro_block_body.ref_hash:
                        content += i_
                    try:
                        macro_block_body.public_key.verify(macro_block_body.signature,
                                                           content, ec.ECDSA(hashes.SHA256()))
                    except (Exception):
                        print('sig')
                        return False

                    else:
                        return True
        print('not find')
        return False

    @staticmethod
    def add_micro_block_verifier(micro_block: MicroBlock) -> bool:
        # micro_block needn't be verified
        return True

    @staticmethod
    def __hash_checker(data: bytes, hash_: bytes) -> bool:
        sha = hashlib.sha256()
        sha.update(data)
        return sha.digest() == hash_

    @staticmethod
    def block_checker(b: bytes):
        if Verify.__hash_checker(b[32:], b[:32]) is False:
            raise BlockHashError()

    @staticmethod
    def double_spend_checker(utxo_tables: List[UTXOTable], trans: Transaction) -> bool:
        """
        check if the transaction spends one or more outputs twice compared to the given UTXO tables
        :param utxo_tables: List of UTXO tables
        :param trans: a transaction
        :return: True no double spending | False double spending
        """
        if trans.version == 1:
            for i in trans.ipt.content:
                search = [table.exist(i) for table in utxo_tables]
                if not reduce(lambda x, y: x or y, search):
                    print('double')

                    return False
        return True

    @staticmethod
    def transpool_double_spend_checker(ipts: List, trans: Transaction) -> bool:
        """
        check if any input of the trans exists in ipts
        :param ipts: a list of inputs
        :param trans: a transaction
        :return: True no double spending | False double spending
        """

        return not reduce(lambda x, y: x or y, [i in ipts for i in trans.ipt.content])

    @staticmethod
    def sig_checker(trans: Transaction) -> bool:
        try:
            trans.public_key.verify(trans.signature,
                                    struct.pack('=f', trans.timestamp) + trans.ipt.b + trans.opt.b,
                                    ec.ECDSA(hashes.SHA256()))
        except (Exception):
            print('sig')
            return False
        else:
            return True

    @staticmethod
    def balance_checker(utxo_tables: List[UTXOTable], trans: Transaction) -> bool:
        """
        check the balance between inputs and outputs.
        Note that this function assumes that the trans pass the double spending validation
        and does not check the existence of trans in UTXO
        :param utxo_tables: List of UTXO tables
        :param trans: a transaction
        :return: True if the inputs and outputs balance | False if the inputs and outputs do not balance
        """
        b_pubkey = trans.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

        sha = hashlib.sha256()
        sha.update(b_pubkey)
        public_key_hash = sha.digest()
        amount = 0

        if trans.version == 0:
            return True

        if trans.version == '0':
            return True

        if public_key_hash != trans.ipt.public_key_hash:
            # print('error 1')
            return False

        for i in trans.ipt.content:
            for table in utxo_tables:
                if table.exist(i):
                    if not table.info(i)['to'] == trans.ipt.public_key_hash:  # check if the UTXO is to this pubkey hash
                        print('error 2')
                        print(table.info(i)['to'])
                        print(trans.ipt.public_key_hash)
                        return False
                    amount += table.info(i)['amount']  # get the amount of UTXO
                    break
        for opt in trans.opt.content:
            amount -= opt[0]
        if amount != 0:  # inputs and outputs are imbalance
            print('error 3, amount=', amount)
            return False

        return True

    @staticmethod
    def trans_input_checker(b: bytes):
        pass

    @staticmethod
    def trans_output_checker(b: bytes):
        pass

    @staticmethod
    def transaction_checker(b: bytes):
        if Verify.__hash_checker(b[BLENGTH_TXID:], b[:BLENGTH_TXID]) is False:
            raise TransactionHashError()

    @staticmethod
    def attachment_checker(b: bytes):
        pass

    @staticmethod
    def blockdata_checker(b: bytes):
        pass

    @staticmethod
    def light_blockdata_checker(b: bytes):
        pass

