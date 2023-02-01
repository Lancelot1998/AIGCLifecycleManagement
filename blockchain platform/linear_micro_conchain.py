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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_private_key
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


def mine(target):
    return PoWServer.mine(target)


class PoWServer(socketserver.ThreadingMixIn, socketserver.TCPServer):

    def __init__(self, server_name: str, server_address, handler, chainbase_address_):
        self.name = server_name
        self.prev_hash = b''
        self.target = (2 ** 236 - 1).to_bytes(32, byteorder='big')
        self.chainbase_address = chainbase_address_
        self.peer = PeerManager()
        self.workers = Pool()

        super().__init__(server_address, handler, bind_and_activate=True)

    def serve_forever(self, poll_interval=0.5):

        self.start_miner()

        super().serve_forever()

    def start_miner(self):
        self.__set_mine(True)
        print('ok')
        ore = self.workers.apply_async(mine,
                                       args=(self.target,),
                                       callback=partial(self.on_new_micro_block_mined, self))

    @staticmethod
    def stop_miner():
        PoWServer.__set_mine(False)

    @staticmethod
    def on_new_micro_block_mined(self: 'PoWServer', result):
        """
        try to add the block that the server itself mines to the chainbase
        :param self: the instance of PoWServer
        :param result: Future object contains mining result
        :return: None
        """
        target_, nonce = result

        if target_ == self.target:

            if nonce < 0:  # mining is stopped by stop_miner
                return

            micro_block = self.make_micro_block(nonce)

            print('micro_block mined:')
            print(micro_block.show_block())
            self.peer.sendall_block(msgtype=MsgType.TYPE_NEW_MICRO_BLOCK, content=micro_block.b)

            if self.add_micro_block(micro_block) is True:
                self.start_miner()
            else:
                self.start_miner()

    def on_new_macro_block_header_received(self, macro_block_header):
        print('macro_block_header received')
        macro_block_header = MacroBlockHeader.unpack(macro_block_header)
        if self.add_macro_block_header(macro_block_header):
            self.peer.sendall_block(msgtype=MsgType.TYPE_NEW_MACRO_BLOCK_HEADER, content=macro_block_header.b)

    def on_new_macro_block_body_received(self, macro_block_body):
        print('macro_block_body received')
        macro_block_body = MacroBlockBody.unpack(macro_block_body)
        if self.add_macro_block_body(macro_block_body):
            self.peer.sendall_block(msgtype=MsgType.TYPE_NEW_MACRO_BLOCK_BODY, content=macro_block_body.b)

    def on_new_micro_block_received(self, micro_block):
        # print('micro_block received')
        micro_block = MicroBlock.unpack(micro_block)
        if self.add_micro_block(micro_block):
            self.peer.sendall_block(msgtype=MsgType.TYPE_NEW_MICRO_BLOCK, content=micro_block.b)

    def init_target(self):
        pass

    def make_micro_block(self, nonce) -> MicroBlock:
        trans = self.__get_trans()
        info = Attachment()
        info.add_data(b'mined by ' + self.name.encode())
        info.ready()

        micro_block = MicroBlock(0,  # todo: get index
                                 timestamp=time.time(),
                                 blockdata=BlockData(trans, info),
                                 previous_hash=bytes(32),
                                 nonce=nonce)
        return micro_block

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
                if index == 2:
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
            opt = TransOutput([(ASSET(20), PUBLIC_KEY_HASH(public_key_hash))])
            tran = Transaction(ipt, opt, 0)
            tran.ready(private_key)
            trans.append(tran.b)
            # result = self.get_miner_credit(public_key_hash, 5)
            # print(result)
            print('len = ', len(trans))
            return [Transaction.unpack(t) for t in trans]

    def add_macro_block_header(self, macro_block_header: MacroBlockHeader) -> bool:
        """
        add the macro_block_header to the chainbase
        :param macro_block_header: binary macro_block_header
        :return: True | False
        """
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(self.chainbase_address)
            s.sendall(send_handler(MsgType.TYPE_MACRO_BLOCK_HEADER_WRITE, macro_block_header.b))
            *_, msgtype, content = recv_parser(s)

        return msgtype == MsgType.TYPE_RESPONSE_OK

    def add_micro_block(self, micro_block: MicroBlock) -> bool:
        """
        add the micro_block to the chainbase
        :param micro_block: binary micro_block
        :return: True | False
        """
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(self.chainbase_address)
            s.sendall(send_handler(MsgType.TYPE_MICRO_BLOCK_WRITE, micro_block.b))
            *_, msgtype, content = recv_parser(s)

        return msgtype == MsgType.TYPE_RESPONSE_OK

    def add_macro_block_body(self, macro_block_body: MacroBlockBody) -> bool:
        """
        add the macro_block_body to the chainbase
        :param macro_block_body: binary macro_block_body
        :return: True | False
        """
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(self.chainbase_address)
            s.sendall(send_handler(MsgType.TYPE_MACRO_BLOCK_BODY_WRITE, macro_block_body.b))
            *_, msgtype, content = recv_parser(s)

        return msgtype == MsgType.TYPE_RESPONSE_OK

    def get_parent_hash(self) -> list:
        """
        get pivot chain macro_block_header and tips in local DAG
        :return: a list of hash (the first hash refers to voting edge, others refer to reference edges)
        """
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(self.chainbase_address)
            s.sendall(send_handler(MsgType.TYPE_GET_PARENT_HASH, None))
            *_, msgtype, content = recv_parser(s)
        result = list()
        len_ = int(len(content) / 32)
        for i in range(len_):
            result.append(content[i * 32:(i + 1) * 32])
        return result

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

    @staticmethod
    def mine(target):
        """
        find a valid nonce
        :param target:
        :return: Tuple of (target, nonce)
        """
        seed()
        initial = randrange(0, MINE_TOP)  # [0, 2**32]
        print('mining')
        for nonce in range(initial, MINE_TOP):
            if not PoWServer.__keep_mining():
                print('stop mining')
                return target, -1
            hash_ = PoWServer.__calc_hash(time.time(), nonce)

            if hash_ < target:
                return target, nonce

        for nonce in range(0, initial):
            if not PoWServer.__keep_mining():
                print('stop mining')
                return target, -1

            hash_ = PoWServer.__calc_hash(time.time(), nonce)

            if hash_ < target:
                return target, nonce

    @staticmethod
    def __calc_hash(timestamp, nonce: int) -> bytes:  # calculate SHA256(SHA256(prev_hash+nonce))
        sha = hashlib.sha256()
        sha.update(struct.pack('=d', timestamp))
        sha.update(struct.pack('=I', nonce))
        hash_ = sha.digest()
        sha = hashlib.sha256()
        sha.update(hash_)
        hash_ = sha.digest()

        return hash_


class PowHandler(socketserver.StreamRequestHandler):
    def handle(self):
        handlers = {

            MsgType.TYPE_NODE_DISCOVER: self.server.peer.peer_discover,

            MsgType.TYPE_NEW_MACRO_BLOCK_HEADER: self.server.on_new_macro_block_header_received,

            MsgType.TYPE_NEW_MACRO_BLOCK_BODY: self.server.on_new_macro_block_body_received,

            MsgType.TYPE_NEW_MICRO_BLOCK: self.server.on_new_micro_block_received

        }

        *_, msgtype, content = recv_parser(self.request)

        handlers[msgtype](content)


if __name__ == '__main__':

    address = ('0.0.0.0', 22300)
    chainbase_address = 'node1'

    with PoWServer('node1', address, PowHandler, chainbase_address) as server:
        server.peer.peer_discover(('129.211.110.239', 22300))  # 1
        server.peer.peer_discover(('', 22300))
        server.peer.peer_discover(('', 22300))
        server.peer.peer_discover(('', 22300))
        server.peer.peer_discover(('', 22300))
        server.peer.peer_discover(('', 22300))
        server.peer.peer_discover(('', 22300))
        server.peer.peer_discover(('', 22300))
        server.peer.peer_discover(('', 22300))
        server.peer.peer_discover(('', 22300))
        server.serve_forever()
