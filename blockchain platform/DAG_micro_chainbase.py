# -*- coding: utf-8 -*-
"""
    chainbase
    ~~~~~~~~~

    Implements backend of blockchain

    :author: hank
"""

from source.blockchain import *
from source.transfer import MsgType, recv_parser, send_handler, batch_handler, batch_parser
from source.errors import *
from source.utility import bin2int
from source.Trans import trans_to_json
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import socketserver
import random
import sys
import struct
import time
import requests
import ctypes


class ChainMsgHandler(socketserver.StreamRequestHandler):

    def handle(self):
        """
        handle messages from webchain and conchain
        :return: None
        """

        handlers = {
            # write the submitted transaction to the transpool
            MsgType.TYPE_TRANS_WRITE: self.processor_trans_write,

            # provide transactions in the transpool
            MsgType.TYPE_TRANS_READ: self.processor_trans_read,

            # search the transaction that has the given txid
            MsgType.TYPE_TRANS_SEARCH_TXID: self.processor_trans_search_txid,

            # return the previous hash for constructing nonce
            MsgType.TYPE_BLOCK_PREVIOUS_HASH: self.processor_prev_hash,

            # send back blocks whose indexes locate in [start, end]
            MsgType.TYPE_BLOCK_READ: self.processor_block_read,

            # create Trans
            MsgType.TYPE_TRANS_MAKE: self.processor_trans_make,

            # write macro_block_header in blockchain
            MsgType.TYPE_MACRO_BLOCK_HEADER_WRITE: self.processor_macro_block_header_write,

            # append macro_block_body to corresponding macro_block_header
            MsgType.TYPE_MACRO_BLOCK_BODY_WRITE: self.processor_macro_block_body_write,

            # write micro_block and append it to corresponding macro_block_header
            MsgType.TYPE_MICRO_BLOCK_WRITE: self.processor_micro_block_write,

            # get current parent blocks for pending block
            MsgType.TYPE_GET_PARENT_HASH: self.processor_get_parent_hash

        }

        *_, msgtype, content = recv_parser(self.request)

        handlers[msgtype](content)

    def processor_get_parent_hash(self, content):
        content = self.server.macro_chain.pivot_chain.queue[-1]
        for i in self.server.macro_chain.tips:
            if i != self.server.macro_chain.pivot_chain.queue[-1]:
                content += i
        self.request.sendall(send_handler(MsgType.TYPE_RESPONSE_OK, content))

    def processor_trans_write(self, content):
        result = self.server.transpool.add(content)
        if result:
            _ = send_handler(MsgType.TYPE_RESPONSE_OK, b'')

        else:
            print('false')
            _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')

        self.request.sendall(_)

    def processor_trans_read(self, content):
        result = self.server.transpool.read_serialized()
        if len(result) > 0:
            _ = send_handler(MsgType.TYPE_RESPONSE_OK, batch_handler(result))
        else:
            _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')

        self.request.sendall(_)

    def processor_micro_block_write(self, content):
        try:
            micro_block = MicroBlock.unpack(content)
        except Exception:
            _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'micro_block unpack error')
        else:
            result = self.server.macro_chain.add_micro_block(micro_block)

            if result:
                for i_ in self.server.cached_macro_block_body:
                    if micro_block.hash in i_.ref_hash:
                        self.parentless_macro_block_body_process(i_)
                for i in micro_block.data.trans:
                    if i.txid not in self.server.transpool.used:
                        self.server.transpool.used.append(i.txid)
                _ = send_handler(MsgType.TYPE_RESPONSE_OK, b'')
            else:
                if self.server.macro_chain.accepted_micro_blocks[micro_block.hash] >= 1:
                    pass
                else:
                    pass
                _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')

        finally:
            self.request.sendall(_)

    def processor_trans_search_txid(self, content):
        try:
            trans = self.server.blockchain.search_transaction(content)
        except TransNotInChain:
            _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')
        else:
            _ = send_handler(MsgType.TYPE_RESPONSE_OK, trans.b)
        finally:
            self.request.sendall(_)

    def processor_prev_hash(self, content):
        self.request.sendall(send_handler(MsgType.TYPE_RESPONSE_OK, self.server.macro_chain.chain.queue[-1].hash))

    def processor_block_read(self, content):
        start = bin2int(content[:4])
        end = bin2int(content[4:8])
        # do the search
        result = []
        for i in range(start, end):
            # if start <= server.blockchain.chain.queue[i].index <= end:
            result.append(self.server.blockchain.chain.queue[i].b)
        # send back result
        self.request.sendall(send_handler(MsgType.TYPE_RESPONSE_OK, batch_handler(result)))

    def processor_trans_make(self, content):
        i_ = 0
        add_from = 2
        add_to = 0
        add_to_two = random.randint(0, 1)
        _address = [add_from, add_to,  add_to_two]
        result = dict()
        # print(_address)
        fd = open('ad1.txt', 'r')
        line = fd.readlines()
        for i in _address:
            line_ = line[i].rstrip()
            pr, pu = line_.split('ENDDING')
            temp = bytes(pu[2:-1], encoding='utf-8')
            temp = temp.replace(b'\r\n', b'\n')
            public_key = temp.replace(b'\\n', b'\n')
            temp = bytes(pr[2:-1], encoding='utf-8')
            temp = temp.replace(b'\r\n', b'\n')
            private_key = temp.replace(b'\\n', b'\n')
            sha = hashlib.sha256()
            sha.update(public_key)
            public_key_hash = sha.digest()
            result[i] = [public_key, private_key, public_key_hash]
        fd.close()

        for utxo in self.server.macro_chain.utxo.utxo.items():
            if utxo[1]['to'] == result[_address[0]][2] and utxo[0] not in self.server.Used:
                self.server.Used.append(utxo[0])
                # print('utxo', utxo)
                i_ = 1
                private_key = serialization.load_pem_private_key(result[_address[0]][1], None,
                                                                 backend=default_backend())
                ipt = TransInput([utxo[0]], result[_address[0]][2])
                opt = TransOutput([(utxo[1]['amount']/2, result[_address[1]][2]), (utxo[1]['amount']/2,
                                                                                   result[_address[2]][2])])
                tran = Transaction(ipt, opt)
                tran.ready(private_key)
                content = trans_to_json(tran)
                requests.post('http://:8000/transaction_post', data=content)
                requests.post('http://:8000/transaction_post', data=content)
                requests.post('http://:8000/transaction_post', data=content)
                requests.post('http://:8000/transaction_post', data=content)
                requests.post('http://:8000/transaction_post', data=content)
                requests.post('http://:8000/transaction_post', data=content)
                requests.post('http://:8000/transaction_post', data=content)
                requests.post('http://:8000/transaction_post', data=content)
                requests.post('http://:8000/transaction_post', data=content)
                requests.post('http://:8000/transaction_post', data=content)

                _ = send_handler(MsgType.TYPE_RESPONSE_OK, tran.b)
                self.request.sendall(_)
                break
        if i_ == 0:
            _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')
            self.request.sendall(_)
        else:
            pass

    def processor_macro_block_header_write(self, content):
        try:
            macro_block_header = MacroBlockHeader.unpack(content)
        except Exception:
            _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'macro_block_header unpack error')
        else:
            result = self.server.macro_chain.add_macro_block_header(macro_block_header)
            if self.server.macro_chain.accepted_macro_block_headers[macro_block_header.hash] == 1:
                for i in self.server.cached_macro_block_body:
                    if i.hash == macro_block_header.hash:
                        self.parentless_macro_block_body_process(i)
            if result:
                for i in self.server.cached_macro_block_header:
                    if macro_block_header.hash in i.parent_hash:
                        self.parentless_macro_block_header_process()
                _ = send_handler(MsgType.TYPE_RESPONSE_OK, b'')
            else:
                print('failed1', macro_block_header.hash)

                if self.server.macro_chain.accepted_macro_block_headers[macro_block_header.hash] > 1:
                    print('pass')
                else:
                    if macro_block_header not in self.server.cached_macro_block_header:
                        self.server.cached_macro_block_header.append(macro_block_header)
                _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')

        finally:
            self.request.sendall(_)

    def trans_retrieve(self, i_: MicroBlock):
        if i_.hash in self.server.macro_chain.micro_block_in_chain_.keys():
            self.server.macro_chain.micro_block_in_chain_[i_.hash] -= 1
        for trans in i_.data.trans:
            for j in range(len(trans.opt.content)):
                if self.server.macro_chain.utxo_two.exist((trans.txid, j)):
                    del self.server.macro_chain.utxo_two.utxo[(trans.txid, j)]
                if self.server.macro_chain.utxo.exist((trans.txid, j)):
                    del self.server.macro_chain.utxo.utxo[(trans.txid, j)]
                else:
                    pass
            for j in range(len(trans.ipt.content)):
                if trans.ipt.content[j] in self.server.macro_chain.utxo_two.txo.keys():
                    if self.server.macro_chain.utxo_two.txo[trans.ipt.content[j]][1] in \
                            self.server.macro_chain.accepted_macro_block_header_hash:
                        self.server.macro_chain.utxo_two.utxo[trans.ipt.content[j]] = self.server. \
                            macro_chain.utxo_two.txo[trans.ipt.content[j]]
                        del self.server.macro_chain.utxo_two.txo[trans.ipt.content[j]]
                        self.server.macro_chain.utxo.utxo[trans.ipt.content[j]] = self.server. \
                            macro_chain.utxo.txo[trans.ipt.content[j]]
                        del self.server.macro_chain.utxo.txo[trans.ipt.content[j]]
                    else:
                        pass
                else:
                    pass

    def processor_macro_block_body_write(self, content):
        i_ = 0
        try:
            macro_block_body = MacroBlockBody.unpack(content)
        except Exception:
            print('false')
            _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'macro_block_body unpack error')
        else:
            if macro_block_body.hash in self.server.macro_chain.accepted_macro_block_bodies.keys():
                self.server.macro_chain.accepted_macro_block_bodies[macro_block_body.hash] += 1
            else:
                self.server.macro_chain.accepted_macro_block_bodies[macro_block_body.hash] = 1
            if self.server.macro_chain.accepted_macro_block_bodies[macro_block_body.hash] > 1:
                print('pass body')
                _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')
            else:
                result = Verify.add_macro_block_body_verifier_dag(self.server.macro_chain, macro_block_body)
                if not result:
                    # micro_blocks of macro_block_body is lacking
                    print('lacking micro_block')
                    if macro_block_body not in self.server.cached_macro_block_body:
                        self.server.cached_macro_block_body.append(macro_block_body)
                    _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')
                else:
                    self.server.macro_chain.ref_micro_block[macro_block_body.hash] = list()
                    for i_ in self.server.macro_chain.micro_block_pool:
                        if i_.hash in macro_block_body.ref_hash:
                            self.server.macro_chain.ref_micro_block[macro_block_body.hash].append(i_)

                    result_ = self.server.macro_chain.add_macro_block_body(macro_block_body)
                    if result_:
                        if self.server.macro_chain.chain_.queue[-1].hash == macro_block_body.hash:
                            with self.server.mutex:
                                self.server.macro_chain.add_trans(macro_block_body.hash)
                                for k in self.server.macro_chain.ref_micro_block[macro_block_body.hash]:
                                    self.server.transpool.remove(k)

                        else:
                            for index, i in enumerate(self.server.macro_chain.chain_.queue):
                                if i.hash == macro_block_body.hash:
                                    i_ = index
                                    break
                            with self.server.mutex:
                                for i in range(len(self.server.macro_chain.chain_.queue) - i_):
                                    if self.server.macro_chain.chain_.queue[i_ + i].hash in \
                                            self.server.macro_chain.accepted_macro_block_header_hash:
                                        self.server.macro_chain.accepted_macro_block_header_hash.\
                                            remove(self.server.macro_chain.chain_.queue[i_ + i].hash)
                                for i in range(len(self.server.macro_chain.chain_.queue) - i_):
                                    if self.server.macro_chain.chain_.queue[i_ + i].hash in \
                                            self.server.macro_chain.ref_micro_block.keys():
                                        for q in (self.server.macro_chain.ref_micro_block[self.server.macro_chain.
                                                  chain_.queue[i_ + i].hash]):
                                            self.trans_retrieve(q)
                                for i in range(len(self.server.macro_chain.chain_.queue) - i_):
                                    if self.server.macro_chain.chain_.queue[i_ + i].hash in \
                                            self.server.macro_chain.ref_micro_block.keys():
                                        self.server.macro_chain.\
                                            add_trans(self.server.macro_chain.chain_.queue[i_ + i].hash)
                                for i in range(len(self.server.macro_chain.chain_.queue) - i_):
                                    if self.server.macro_chain.chain_.queue[i_ + i].hash in \
                                            self.server.macro_chain.accepted_macro_block_header_hash:
                                        self.server.macro_chain.accepted_macro_block_header_hash.\
                                            append(self.server.macro_chain.chain_.queue[i_ + i].hash)
                                for k in self.server.macro_chain.ref_micro_block[macro_block_body.hash]:
                                    self.server.transpool.remove(k)

                        if macro_block_body in self.server.cached_macro_block_body:
                            self.server.cached_macro_block_body.remove(macro_block_body)
                        _ = send_handler(MsgType.TYPE_RESPONSE_OK, b'')

                    else:
                        if macro_block_body not in self.server.cached_macro_block_body:
                            self.server.cached_macro_block_body.append(macro_block_body)
                        _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')

        finally:
            self.request.sendall(_)

    def parentless_macro_block_header_process(self):
        print('parentless')
        flag = 1
        if len(self.server.cached_macro_block_header) != 0:
            while flag > 0:
                for i in self.server.cached_macro_block_header:
                    if i.hash in self.server.macro_chain.accepted_macro_block_headers.keys():
                        del self.server.macro_chain.accepted_macro_block_headers[i.hash]
                    result = self.server.macro_chain.add_macro_block_header(i)
                    if result:
                        self.server.cached_macro_block_header.remove(i)
                        i_ = 0
                        for index, j in enumerate(self.server.macro_chain.chain_.queue):
                            if j.hash == i.hash:
                                i_ = index
                                break
                        for k in range(len(self.server.macro_chain.chain_.queue) - i_):
                            if self.server.macro_chain.chain_.queue[i_ + k].hash in \
                                    self.server.macro_chain.accepted_macro_block_header_hash:
                                self.server.macro_chain.accepted_macro_block_header_hash. \
                                    remove(self.server.macro_chain.chain_.queue[i_ + k].hash)
                        for k in range(len(self.server.macro_chain.chain_.queue) - i_):
                            if self.server.macro_chain.chain_.queue[i_ + k].hash in \
                                    self.server.macro_chain.ref_micro_block.keys():
                                for q in (self.server.macro_chain.ref_micro_block[self.server.macro_chain.chain_.
                                          queue[i_ + k].hash]):
                                    self.trans_retrieve(q)
                        for k in range(len(self.server.macro_chain.chain_.queue) - i_):
                            if self.server.macro_chain.chain_.queue[i_ + k].hash in \
                                    self.server.macro_chain.ref_micro_block.keys():
                                self.server.macro_chain.add_trans(self.server.macro_chain.chain_.queue[i_ + k].hash)
                        for k in self.server.macro_chain.ref_micro_block[i.hash]:
                            self.server.transpool.remove(k)

                        if len(self.server.cached_macro_block_header) == 0:
                            flag = 0
                        else:
                            flag = 1
                        break
                    flag = 0

    def parentless_macro_block_body_process(self, macro_block_body: MacroBlockBody):
        if macro_block_body.hash in self.server.macro_chain.accepted_macro_block_bodies.keys():
            del self.server.macro_chain.accepted_macro_block_bodies[macro_block_body.hash]
            self.processor_macro_block_body_write(macro_block_body.b)


class ChainBaseServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """
    Server class to provide chain service
    """
    macro_chain = MacroChainDAG()
    Used = list()
    cached_macro_block_header = list()
    cached_macro_block_body = list()
    transpool = TransPoolDAG(macro_chain)
    used_trans = dict()
    mutex = threading.Lock()


if __name__ == '__main__':
    address = 'node1'
    print(address)
    with ChainBaseServer(address, ChainMsgHandler) as server:
        server.serve_forever()

