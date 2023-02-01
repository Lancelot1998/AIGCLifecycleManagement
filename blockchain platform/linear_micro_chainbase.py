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

            # write the submitted block (the result of consensus) to the blockchain
            # MsgType.TYPE_BLOCK_WRITE: self.processor_block_write,

            # convert the lightblock to normal block and write it to the blockchain
            # MsgType.TYPE_LIGHTBLOCK_WRITE: self.processor_lightblock_write,

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

        self.request.sendall(send_handler(MsgType.TYPE_RESPONSE_OK, self.server.macro_chain.chain_.queue[-1].hash))

    def processor_trans_write(self, content):
        result = self.server.transpool.add(content)
        tran = Transaction.unpack(content)
        # print(tran.show_trans())
        # print('ok3')
        if result:
            a = Transaction.unpack(content)
            _ = send_handler(MsgType.TYPE_RESPONSE_OK, b'')
            # print('trans_received')
            # print(a.timestamp)
            # print(time.time())
            # print(len(self.server.transpool.trans.queue))
        else:
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
                # c = 0
                # for i in self.server.macro_chain.micro_block_pool:
                #     c += sys.getsizeof(i.b)
                for i_ in self.server.cached_macro_block_body:
                    if micro_block.hash in i_.ref_hash:
                        self.parentless_macro_block_body_process(i_)
                for i in micro_block.data.trans:
                    if i.txid not in self.server.transpool.used:
                        self.server.transpool.used.append(i.txid)
                _ = send_handler(MsgType.TYPE_RESPONSE_OK, b'')
            else:
                # print('failed1', micro_block.hash)
                if self.server.macro_chain.accepted_micro_blocks[micro_block.hash] >= 1:
                    # print('pass')
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
        add_to = 2
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
                # print('1')
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

                if macro_block_header.hash in self.server.macro_chain.accepted_macro_block_header_hash or \
                        self.server.macro_chain.accepted_macro_block_headers[macro_block_header.hash] >= 1:
                    print('pass')
                else:
                    for i in self.server.ass_chain:
                        if macro_block_header.parent_hash[0] == i.hash:
                            flag = 1
                            self.server.ass_chain[macro_block_header] = (flag, i)
                            self.longest_chain(macro_block_header)
                            break

                    for i in self.server.macro_chain.chain_.queue:
                        if macro_block_header.parent_hash[0] == i.hash:
                            flag = 0
                            self.server.ass_chain[macro_block_header] = (flag, i)
                            break

                    if macro_block_header not in self.server.cached_macro_block_header and macro_block_header not in \
                            self.server.ass_chain.keys():
                        self.server.cached_macro_block_header.append(macro_block_header)
                _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')

        finally:
            self.request.sendall(_)

    def ass_chain_length(self, macro_block_header):
        flag = 1
        num = 0
        ruf_chain = list()

        while flag == 1:
            if macro_block_header in self.server.ass_chain.keys():
                ruf_chain.append(macro_block_header)
                flag = self.server.ass_chain[macro_block_header][0]
                macro_block_header = self.server.ass_chain[macro_block_header][1]
                num += 1
            else:
                flag = 0
        return num, macro_block_header, ruf_chain

    def main_chain_length(self, macro_block_header):
        num = 0
        i = -1
        main_chain = list()
        while i < 0:
            if self.server.macro_chain.chain_.queue[i] == macro_block_header:
                # main_chain.append(block_received[i])
                break
            else:
                main_chain.append(self.server.macro_chain.chain_.queue[i])
                i -= 1
                num += 1
        return num, main_chain

    def longest_chain(self, macro_block_header):
        print('o j b k ---')
        num_ass, macro_block_header, ruf_chain = self.ass_chain_length(macro_block_header)
        num_main, main_chain = self.main_chain_length(macro_block_header)
        if num_main >= num_ass:
            pass
        else:
            # delete blocks in ruf_chain
            for i in ruf_chain:
                del self.server.ass_chain[i]
            # delete blocks in main_chain
            for i in main_chain:
                self.server.macro_chain.chain_.queue.remove(i)
                self.server.macro_chain.accepted_macro_block_header_hash.remove(i.hash)
                self.server.macro_chain.length -= 1
                # if i.hash in self.server.blockchain.UTXO_num:
                #     del self.server.blockchain.UTXO_num[i]
            k = 0
            for i in main_chain[::-1]:
                if k == 0:
                    self.server.ass_chain[i] = (1, macro_block_header)
                    k += 1
                else:
                    self.server.ass_chain[i] = (0, main_chain[-k])
                    k += 1
                # deal with trans
                if i.hash in self.server.macro_chain.ref_micro_block.keys():
                    for i_ in self.server.macro_chain.ref_micro_block[i.hash]:
                        self.trans_retrieve(i_)

            for i in ruf_chain[::-1]:
                if i.hash in self.server.macro_chain.accepted_macro_block_headers.keys():
                    del self.server.macro_chain.accepted_macro_block_headers[i.hash]

                self.server.macro_chain.add_macro_block_header(i)
                if i.hash in self.server.macro_chain.ref_micro_block.keys():
                    self.server.macro_chain.add_trans(i.hash)

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
                            self.server.macro_chain.accepted_blocks_hash:
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
        flag = 0
        i_ = 0
        try:
            macro_block_body = MacroBlockBody.unpack(content)
        except Exception:
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
                result = Verify.add_macro_block_body_verifier(self.server.macro_chain, macro_block_body)
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
                                    if self.server.macro_chain.chain_.queue[i_ + i].hash not in \
                                            self.server.macro_chain.accepted_macro_block_header_hash:
                                        self.server.macro_chain.accepted_macro_block_header_hash.\
                                            append(self.server.macro_chain.chain_.queue[i_ + i].hash)
                            for k in self.server.macro_chain.ref_micro_block[macro_block_body.hash]:
                                self.server.transpool.remove(k)

                        if macro_block_body in self.server.cached_macro_block_body:
                            self.server.cached_macro_block_body.remove(macro_block_body)
                        _ = send_handler(MsgType.TYPE_RESPONSE_OK, b'')

                    else:
                        for i in self.server.ass_chain.keys():
                            if i.hash == macro_block_body.hash:
                                flag = 1
                                break
                        if flag == 0:
                            for i in self.server.cached_macro_block_header:
                                if i.hash == macro_block_body.hash:
                                    flag = 1
                                    break

                        if flag == 0 and macro_block_body not in self.server.cached_macro_block_body:
                            self.server.cached_macro_block_body.append(macro_block_body)
                        if flag == 1 and macro_block_body in self.server.cached_macro_block_body:
                            self.server.cached_macro_block_body.remove(macro_block_body)
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
                    result1 = self.ass_func_for_pbp(i, result)
                    if result or result1:
                        self.server.cached_macro_block_header.remove(i)
                        if result:
                            if i.hash in self.server.macro_chain.ref_micro_block.keys():
                                with self.server.mutex:
                                    self.server.macro_chain.add_trans(i.hash)

                        if len(self.server.cached_macro_block_header) == 0:
                            flag = 0
                        else:
                            flag = 1
                        break
                    flag = 0

    def ass_func_for_pbp(self, macro_block_header, result: bool):
        if result:
            return False
        else:
            for i in self.server.ass_chain:
                if macro_block_header.previous_hash == i.hash:
                    self.server.ass_chain[macro_block_header] = (1, i)
                    return True
            for i in self.server.macro_chain.chain_.queue:
                if macro_block_header.parent_hash[0] == i.hash:
                    self.server.ass_chain[macro_block_header] = (0, i)
                    return True
        return False

    def parentless_macro_block_body_process(self, macro_block_body: MacroBlockBody):
        if macro_block_body.hash in self.server.macro_chain.accepted_macro_block_bodies.keys():
            del self.server.macro_chain.accepted_macro_block_bodies[macro_block_body.hash]
            self.processor_macro_block_body_write(macro_block_body.b)


class ChainBaseServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """
    Server class to provide chain service
    """
    macro_chain = MacroChain()
    Used = list()
    cached_macro_block_header = list()
    cached_macro_block_body = list()
    blockchain = Blockchain()
    transpool = TransPoolTwo(macro_chain)
    ass_chain = dict()
    mutex = threading.Lock()


if __name__ == '__main__':
    address = 'node1'
    print(address)
    with ChainBaseServer(address, ChainMsgHandler) as server:
        server.serve_forever()


