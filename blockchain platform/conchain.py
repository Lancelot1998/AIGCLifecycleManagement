# -*- coding: utf-8 -*-
"""
    conchain
    ~~~~~~~~~~

    Implements blockchain consensus mechanisms

    :author: hank
"""
from source.transfer import MsgType, PeerManager, recv_parser, send_handler, batch_handler, batch_parser
from source.blockchain import *
from cryptography.hazmat.primitives.serialization import \
    Encoding, PublicFormat, load_pem_public_key, load_der_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from random import randrange, seed
import struct
import hashlib
from queue import Queue
import socketserver
import socket
import concurrent.futures
from multiprocessing import Value, Pool, Lock
from functools import partial
from typing import List
import time
import requests
import random
import sys

MINE_TOP = 2 ** 31
MINE_SWITCH = Value('i', 1)


def mine(prev_hash, target):
    return PoWServer.mine(prev_hash, target)


class PoWServer(socketserver.ThreadingMixIn, socketserver.TCPServer):

    def __init__(self, server_name: str, server_address, handler, chainbase_address_):
        self.name = server_name
        self.prev_hash = b''
        self.target = (2 ** 234 - 1).to_bytes(32, byteorder='big')
        self.chainbase_address = chainbase_address_
        self.peer = PeerManager()
        self.workers = Pool()
        self.trans_size = 0
        self.trans_size_ = 0
        self.cache = []
        self.block_received = []
        self.ass_chain = dict()

        super().__init__(server_address, handler, bind_and_activate=True)

    def serve_forever(self, poll_interval=0.5):

        self.init_prev_hash()

        self.start_miner()

        super().serve_forever()

    def start_miner(self):
        self.__set_mine(True)
        print('ok')
        ore = self.workers.apply_async(mine,
                                       args=(self.prev_hash, self.target),
                                       callback=partial(self.on_new_block_mined, self))

    @staticmethod
    def stop_miner():
        PoWServer.__set_mine(False)

    @staticmethod
    def on_new_block_mined(self: 'PoWServer', result):
        """
        try to add the block that the server itself mines to the chainbase
        :param self: the instance of PoWServer
        :param result: Future object contains mining result
        :return: None
        """
        prev_hash_, target_, nonce = result

        if prev_hash_ == self.prev_hash and target_ == self.target:

            if nonce < 0:  # mining is stopped by stop_miner
                return

            block = self.make_block(nonce)  # mining stops because a nonce have been found
            # lightblock = self.make_lightblock(block)
            self.trans_size += sys.getsizeof(block.b)
            # self.trans_size_ += sys.getsizeof(lightblock.b)
            print('block mined:')
            print(block.show_block())
            # print(self.trans_size)
            # print(self.trans_size_)
            self.peer.sendall_block(msgtype=MsgType.TYPE_NEW_BLOCK, content=block.b)
            # self.peer.sendall_block(msgtype=MsgType.TYPE_NEW_LIGHTBLOCK, content=lightblock.b)
            if self.add_block(block) is True:
                self.prev_hash = block.hash
                self.start_miner()  # start a new miner
            else:
                print('\n\nwrong\n\n')
                self.init_target()
                self.start_miner()

    def on_new_block_received(self, block):
        print('block received')
        block = Block.unpack(block)
        if self.add_block(block):
            self.block_received.append(block)
            print('try to stop current miner')
            self.stop_miner()  # stop current miner
            self.prev_hash = block.hash
            self.peer.sendall_block(msgtype=MsgType.TYPE_NEW_BLOCK, content=block.b)
            print('try to start a new miner')
            self.start_miner()  # start a new miner

    # def on_new_lightblock_received(self, lightblock):
    #     print('lightblock received')
    #     lightblock = LightBlock.unpack(lightblock)
    #     if self.add_lightblock(lightblock):
    #         print('add light block succeed')
    #         print('try to stop current miner')
    #         self.stop_miner()  # stop current miner
    #         self.prev_hash = lightblock.hash
    #         self.peer.sendall_block(msgtype=MsgType.TYPE_NEW_LIGHTBLOCK, content=lightblock.b)
    #         print('try to start a new miner')
    #         self.start_miner()  # start a new miner

    def init_prev_hash(self):
        """get previous hash from chainbase when initializing"""
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(self.chainbase_address)
            s.sendall(send_handler(MsgType.TYPE_BLOCK_PREVIOUS_HASH, b''))
            *_, msgtype, content = recv_parser(s)

            self.prev_hash = content
            print('prev_hash = ', content)

    def init_target(self):
        pass

    def make_block(self, nonce) -> Block:
        trans = self.__get_trans()
        if len(trans) > 1000:
            trans = trans[:1000]
        info = Attachment()
        info.add_data(b'mined by ' + self.name.encode())
        info.ready()

        block = Block(0,  # todo: get index
                      timestamp=time.time(),
                      blockdata=BlockData(trans, info),
                      previous_hash=self.prev_hash,
                      nonce=nonce)
        return block

    # @staticmethod
    # def make_lightblock(block) -> LightBlock:
    #     trans_txid = []
    #     print('making lightblock.....', time.time())
    #     for t in block.data.trans:
    #         trans_txid.append(t.txid)
    #     info = block.data.attachment
    #
    #     lightblock = LightBlock(0,  # todo: get index
    #                             timestamp=block.timestamp,
    #                             lightblockdata=LightBlockData(trans_txid, info),
    #                             previous_hash=block.previous_hash,
    #                             hash=block.hash,
    #                             nonce=block.nonce)
    #     print('ok', time.time())
    #     return lightblock

    def add_block(self, block: Block) -> bool:
        """
        add the block to the chainbase
        :param block: binary block
        :return: True | False
        """
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(self.chainbase_address)
            s.sendall(send_handler(MsgType.TYPE_BLOCK_WRITE, block.b))
            *_, msgtype, content = recv_parser(s)

        return msgtype == MsgType.TYPE_RESPONSE_OK

    # def add_lightblock(self, lightblock: LightBlock) -> bool:
    #     """
    #     add the lightblock to the chainbase
    #     :param lightblock: binary lightblock
    #     :return: True | False
    #     """
    #     with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
    #         s.connect(self.chainbase_address)
    #         s.sendall(send_handler(MsgType.TYPE_LIGHTBLOCK_WRITE, lightblock.b))
    #         *_, msgtype, content = recv_parser(s)
    #
    #     return msgtype == MsgType.TYPE_RESPONSE_OK

    def acquire_block(self):
        pass

    @staticmethod
    def __keep_mining() -> bool:
        if MINE_SWITCH.value == 1:
            return True
        else:
            return False

    @staticmethod
    def __set_mine(state: bool):
        if state:
            MINE_SWITCH.value = 1
        else:
            MINE_SWITCH.value = 0

    def __get_trans(self) -> List[Transaction]:
        # self.chainbase_address
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(self.chainbase_address)
            s.sendall(send_handler(MsgType.TYPE_TRANS_READ, b''))
            *_, msgtype, content = recv_parser(s)

            trans = []

            if msgtype == MsgType.TYPE_RESPONSE_OK:
                trans += batch_parser(content)

            private_key = ec.generate_private_key(ec.SECP256K1, default_backend())
            public_key = private_key.public_key()
            public_key = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            sha = hashlib.sha256()
            sha.update(public_key)
            public_key_hash = sha.digest()
            ipt = TransInput([(TXID(public_key_hash), OUTPUT_INDEX(0))], public_key_hash)
            fd_ = open('ad1.txt', 'r')
            for index, line in enumerate(fd_.readlines()):
                if index == 0:
                    line = line.rstrip()
                    pr, pu = line.split('ENDDING')
                    temp = bytes(pu[2:-1], encoding='utf-8')
                    temp = temp.replace(b'\r\n', b'\n')
                    public_key = temp.replace(b'\\n', b'\n')
                    sha = hashlib.sha256()
                    sha.update(public_key)
                    public_key_hash = sha.digest()
                    break
            fd_.close()
            opt = TransOutput([(ASSET(20), public_key_hash)])
            tran = Transaction(ipt, opt, 0)
            tran.ready(private_key)
            trans.append(tran.b)
            # result = self.get_miner_credit(public_key_hash, 5)
            # print(result)
            print('len = ', len(trans))
            return [Transaction.unpack(t) for t in trans]

    @staticmethod
    def mine(prev_hash, target):
        """
        find a valid nonce
        :param prev_hash:
        :param target:
        :return: Tuple of (prev_hash, target, nonce)
        """
        seed()
        initial = randrange(0, MINE_TOP)  # [0, 2**32]
        print('mining')

        for nonce in range(initial, MINE_TOP):
            if not PoWServer.__keep_mining():
                print('stop mining')
                return prev_hash, target, -1
            hash_ = PoWServer.__calc_hash(prev_hash, nonce)

            if hash_ < target:
                return prev_hash, target, nonce

        for nonce in range(0, initial):
            if not PoWServer.__keep_mining():
                print('stop mining')
                return prev_hash, target, -1

            hash_ = PoWServer.__calc_hash(prev_hash, nonce)

            if hash_ < target:
                return prev_hash, target, nonce

    @staticmethod
    def __calc_hash(prev_hash, nonce: int) -> bytes:  # calculate SHA256(SHA256(prev_hash+nonce))
        sha = hashlib.sha256()
        sha.update(prev_hash)
        sha.update(struct.pack('=I', nonce))
        hash_ = sha.digest()
        sha = hashlib.sha256()
        sha.update(hash_)
        hash_ = sha.digest()

        return hash_

    # def get_miner_credit(self, public_key_hash, num) -> List:
    #     with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
    #         s.connect(self.chainbase_address)
    #         p = time.time() * 100000000
    #         print(struct.pack('=d', p))
    #         s.sendall(send_handler(MsgType.TYPE_MINER_CREDIT, batch_handler([public_key_hash, struct.pack('=d', num),
    #                                                                          struct.pack('=d', p)])))
    #         *_, msgtype, content = recv_parser(s)
    #         result = batch_parser(content)
    #     return result


class PowHandler(socketserver.StreamRequestHandler):
    def handle(self):
        handlers = {
            MsgType.TYPE_NEW_BLOCK: self.server.on_new_block_received,

            MsgType.TYPE_BLOCK_READ: self.server.acquire_block,

            MsgType.TYPE_NODE_DISCOVER: self.server.peer.peer_discover

            # MsgType.TYPE_NEW_LIGHTBLOCK: self.server.on_new_lightblock_received,

            # MsgType.TYPE_MINER_CREDIT: self.server.get_miner_credit
        }

        *_, msgtype, content = recv_parser(self.request)

        handlers[msgtype](content)


if __name__ == '__main__':
    # import sys

    # address = ('localhost', int(sys.argv[2]))
    # chainbase_address = sys.argv[1]
    #
    # with PoWServer(sys.argv[4], address, PowHandler, chainbase_address) as server:
    #     server.peer.peer_discover(('localhost', int(sys.argv[3])))
    #     fd = open('peer.txt', 'w')
    #     fd.writelines(['127.0.0.1:23390\n'])
    #     fd.close()
    #     server.serve_forever()

    address = ('0.0.0.0', 22300)
    chainbase_address = 'node1'

    with PoWServer('node1', address, PowHandler, chainbase_address) as server:
        server.peer.peer_discover(('47.102.40.141', 22300))  # 1
        server.peer.peer_discover(('47.101.72.223', 22300))  # 2
        server.peer.peer_discover(('47.101.195.81', 22300))  # 3
        server.serve_forever()
