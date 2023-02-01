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
import threading
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
            MsgType.TYPE_BLOCK_WRITE: self.processor_block_write,

            # convert the lightblock to normal block and write it to the blockchain
            # MsgType.TYPE_LIGHTBLOCK_WRITE: self.processor_lightblock_write,

            # search the transaction that has the given txid
            MsgType.TYPE_TRANS_SEARCH_TXID: self.processor_trans_search_txid,

            # return the previous hash for constructing nonce
            MsgType.TYPE_BLOCK_PREVIOUS_HASH: self.processor_prev_hash,

            # send back blocks whose indexes locate in [start, end]
            MsgType.TYPE_BLOCK_READ: self.processor_block_read,

            # create Trans
            MsgType.TYPE_TRANS_MAKE: self.processor_trans_make

            # get miner's credit
            # MsgType.TYPE_MINER_CREDIT: self.processor_miner_credit,

        }

        *_, msgtype, content = recv_parser(self.request)

        handlers[msgtype](content)

    def processor_trans_write(self, content):
        result = self.server.transpool.add(content)
        print(len(self.server.transpool.chain.chain.queue))
        # tran = Transaction.unpack(content)
        # print(tran.show_trans())
        # print('ok3')
        if result:
            _ = send_handler(MsgType.TYPE_RESPONSE_OK, b'')

        else:
            _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')

        self.request.sendall(_)

    # def processor_miner_credit(self, content):
    #     info = batch_parser(content)
    #     print(info)
    #     if info[0] in self.server.Address.keys():
    #         self.server.Address[info[0]][0] += struct.unpack('=d', info[1])[0]
    #         if struct.unpack('=d', info[1])[0] != 0:
    #             self.server.Address[info[0]][1] = struct.unpack('=d', info[2])[0] / 100000000
    #     else:
    #         self.server.Address[info[0]] = [struct.unpack('=d', info[1])[0], struct.unpack('=d', info[2])[0] /
    #                                         100000000]
    #     result = [struct.pack('=d', self.server.Address[info[0]][0]), struct.pack('=d',
    #                                                                               self.server.Address[info[0]][1])]
    #     result = batch_handler(result)
    #     _ = send_handler(MsgType.TYPE_RESPONSE_OK, result)
    #     # print(self.server.Address)
    #     self.request.sendall(_)

    def processor_trans_read(self, content):
        result = self.server.transpool.read_serialized()
        if len(result) > 0:
            _ = send_handler(MsgType.TYPE_RESPONSE_OK, batch_handler(result))
        else:
            _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')

        self.request.sendall(_)

    def processor_block_write(self, content):
        with self.server.mutex:
            a = time.time()
            try:
                block = Block.unpack(content)
            except Exception:
                _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'block unpack error')
            else:

                print('receive block', block.hash, block.data.attachment.content, a)
                result = self.server.blockchain.add_block(block)
                # self.server.Trans_num += len(block.data.trans)
                # for trans in block.data.trans:
                #     self.server.Trans_size += sys.getsizeof(trans.txid)
                # print('trans_num = ', self.server.Trans_num)
                # print('trans_size = ', self.server.Trans_size)
                # c = 0
                # for block in self.server.blockchain.chain.queue:
                #     c += sys.getsizeof(block.b)
                # print(c)
                # print(self.server.blockchain.size_)
                # print('nnn')

                print(result)
                if result:
                    print("chain length1 = ", self.server.blockchain.length + 1)
                    print('real length = ', len(self.server.blockchain.chain.queue))
                    self.server.transpool.remove(block)
                    self.parentless_block_process()
                    _ = send_handler(MsgType.TYPE_RESPONSE_OK, b'')
                else:
                    print('failed1', block.hash)
                    if block.hash in self.server.blockchain.accepted_blocks_hash or \
                            self.server.blockchain.accepted_blocks[block.hash] > 1:
                        print('pass')
                        print(block.hash)
                        print(self.server.blockchain.accepted_blocks[block.hash])
                    else:
                        print('\nin\n')
                        for i in self.server.ass_chain:
                            if block.previous_hash == i.hash:
                                flag = 1
                                self.server.ass_chain[block] = (flag, i)
                                self.longest_chain(block)
                                break

                        for i in self.server.blockchain.chain.queue:
                            if block.previous_hash == i.hash:
                                flag = 0
                                self.server.ass_chain[block] = (flag, i)
                                break

                        if block not in self.server.cache and block not in self.server.ass_chain.keys():
                            self.server.cache.append(block)

                    _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')

            finally:
                self.request.sendall(_)
                print('all end', a)

    def ass_chain_length(self, block):
        flag = 1
        num = 0
        ruf_chain = list()
        # ruf_chain.append(block)
        while flag == 1:
            if block in self.server.ass_chain.keys():
                ruf_chain.append(block)
                flag = self.server.ass_chain[block][0]
                block = self.server.ass_chain[block][1]
                num += 1
            else:
                flag = 0
        return num, block, ruf_chain

    def main_chain_length(self, block):
        num = 0
        i = -1
        main_chain = list()
        while i < 0:
            if self.server.blockchain.chain.queue[i] == block:
                # main_chain.append(block_received[i])
                break
            else:
                main_chain.append(self.server.blockchain.chain.queue[i])
                i -= 1
                num += 1
        return num, main_chain

    def longest_chain(self, block):
        print('o j b k ---')
        num_ass, block, ruf_chain = self.ass_chain_length(block)
        num_main, main_chain = self.main_chain_length(block)
        if num_main >= num_ass:
            pass
        else:
            # delete blocks in ruf_chain
            for i in ruf_chain:
                del self.server.ass_chain[i]
            # delete blocks in main_chain
            for i in main_chain:
                self.server.blockchain.chain.queue.remove(i)
                self.server.blockchain.accepted_blocks_hash.remove(i.hash)
                self.server.blockchain.length -= 1
                # if i.hash in self.server.blockchain.UTXO_num:
                #     del self.server.blockchain.UTXO_num[i]
            k = 0
            for i in main_chain[::-1]:
                if k == 0:
                    self.server.ass_chain[i] = (1, block)
                    k += 1
                else:
                    self.server.ass_chain[i] = (0, main_chain[-k])
                    k += 1
                # deal with trans
                for trans in i.data.trans:
                    for j in range(len(trans.opt.content)):
                        if self.server.blockchain.utxo_two.exist((trans.txid, j)):
                            del self.server.blockchain.utxo_two.utxo[(trans.txid, j)]
                        if self.server.blockchain.utxo.exist((trans.txid, j)):
                            del self.server.blockchain.utxo.utxo[(trans.txid, j)]
                        else:
                            pass
                    for j in range(len(trans.ipt.content)):
                        if trans.ipt.content[j] in self.server.blockchain.utxo_two.txo.keys():
                            if self.server.blockchain.utxo_two.txo[trans.ipt.content[j]][1] in \
                                    self.server.blockchain.accepted_blocks_hash:
                                self.server.blockchain.utxo_two.utxo[trans.ipt.content[j]] = self.server.\
                                    blockchain.utxo_two.txo[trans.ipt.content[j]]
                                del self.server.blockchain.utxo_two.txo[trans.ipt.content[j]]
                                self.server.blockchain.utxo.utxo[trans.ipt.content[j]] = self.server. \
                                    blockchain.utxo.txo[trans.ipt.content[j]]
                                del self.server.blockchain.utxo.txo[trans.ipt.content[j]]
                                # if self.server.blockchain.utxo_two.utxo[trans.ipt.content[j]][1] in \
                                #         self.server.blockchain.UTXO_num.keys():
                                #     self.server.blockchain. \
                                #         UTXO_num[self.server.blockchain.utxo_two.utxo[trans.ipt.content[j]][1]] += 1
                                # else:
                                #     self.server.blockchain. \
                                #         UTXO_num[self.server.blockchain.utxo_two.utxo[trans.ipt.content[j]][1]] = 1
                            else:
                                pass
                        else:
                            pass
            for i in ruf_chain[::-1]:
                if i.hash in self.server.blockchain.accepted_blocks.keys():
                    del self.server.blockchain.accepted_blocks[i.hash]

                self.server.blockchain.add_block(i)

    def parentless_block_process(self):
        print('parentless')
        flag = 1
        if len(self.server.cache) != 0:
            while flag > 0:
                for i in self.server.cache:
                    if i.hash in self.server.blockchain.accepted_blocks.keys():
                        del self.server.blockchain.accepted_blocks[i.hash]
                    result = self.server.blockchain.add_block(i)
                    result1 = self.ass_func_for_pbp(result, i)
                    if result or result1:
                        print('process one')
                        self.server.cache.remove(i)
                        if len(self.server.cache) == 0:
                            flag = 0
                        else:
                            flag = 1
                        break
                    flag = 0

    def ass_func_for_pbp(self, result, block):
        if result:
            return False
        else:
            for i in self.server.ass_chain:
                if block.previous_hash == i.hash:
                    self.server.ass_chain[block] = (1, i)
                    return True
            for i in self.server.blockchain.chain_.queue:
                if block.previous_hash == i.hash:
                    self.server.ass_chain[block] = (0, i)
                    return True
        return False

    # def processor_lightblock_write(self, content):
    #     try:
    #         lightblock = LightBlock.unpack(content)
    #         # print('light = ', lightblock.hash)
    #     except Exception:
    #         _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'lightblock unpack error')
    #     else:
    #         block = self.processor_block_type_convert(lightblock)
    #         # print(block.show_block())
    #         result = self.server.blockchain.add_block(block)
    #         # print(result)
    #         # print("chain length = ", self.server.blockchain.length + 1)
    #         print("chain length = ", len(self.server.blockchain.chain.queue))
    #         # for i in self.server.blockchain.chain.queue:
    #         #     print(i.show_block())
    #         #     print(len(i.data.trans))
    #         # print(sys.getsizeof(self.server.blockchain.chain.queue))
    #         # print('nnn')
    #         # print(self.server.blockchain.size_)
    #         # print(server.blockchain.utxo_two.utxo)
    #         # print(server.blockchain.UTXO_num)
    #         if result:
    #             a = len(self.server.blockchain.chain.queue)
    #             # print('all succeed, block.trans =', self.server.blockchain.chain.queue[a - 1].timestamp)
    #             self.server.transpool.remove(block)
    #             _ = send_handler(MsgType.TYPE_RESPONSE_OK, b'')
    #         else:
    #             _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')
    #     finally:
    #         self.request.sendall(_)

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
        self.request.sendall(send_handler(MsgType.TYPE_RESPONSE_OK, self.server.blockchain.chain.queue[-1].hash))

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

    # def processor_block_type_convert(self, lightblock: LightBlock) -> Block:
    #     print('unpack...', time.time())
    #     transaction = []
    #     # print(lightblock.data.trans_txid)
    #     trans_in_pool = self.server.transpool.read()
    #     # print(len(trans_in_pool))
    #     for t in trans_in_pool:
    #         # print(t.txid)
    #         if t.txid in lightblock.data.trans_txid:
    #             transaction.append(t)
    #
    #     block = Block(0,
    #                   timestamp=lightblock.timestamp,
    #                   blockdata=BlockData(transaction, lightblock.data.attachment),
    #                   previous_hash=lightblock.previous_hash,
    #                   nonce=lightblock.nonce)
    #     block.hash = lightblock.hash
    #     print('trans_len', len(transaction))
    #     print('block finished...', time.time())
    #     return block

    def processor_trans_make(self, content):
        i_ = 0
        # add_from = random.randint(0, 1)
        add_from = 0
        if add_from > 2:
            add_from = 0
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

        for utxo in self.server.blockchain.utxo.utxo.items():
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
                requests.post('http://47.102.40.141:8000/transaction_post', data=content)
                requests.post('http://47.101.72.223:8000/transaction_post', data=content)
                requests.post('http://47.101.195.81:8000/transaction_post', data=content)

                if result[_address[0]][2] in self.server.Address.keys():
                    self.server.Address[result[_address[0]][2]][0] -= len(tran.b) \
                                                                          * self.server.throughput / (1000 * 2 * 4)
                    self.server.Address[result[_address[0]][2]][1] = time.time()
                else:
                    self.server.Address[result[_address[0]][2]] = [100, time.time()]
                _ = send_handler(MsgType.TYPE_RESPONSE_OK, tran.b)

                self.request.sendall(_)

                break
        if i_ == 0:
            # print('0')
            _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')
            self.request.sendall(_)
        else:
            pass


class ChainBaseServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """
    Server class to provide chain service
    """
    blockchain = Blockchain()
    transpool = TransPool(blockchain)
    Used = []
    Trans_num = 0
    Trans_size = 0
    Address = dict()
    throughput_list = []
    throughput = 0
    usage = 0
    useful = 0
    ass_block = dict()
    cache = []
    mutex = threading.Lock()
    ass_chain = dict()


if __name__ == '__main__':
    address = 'node1'
    print(address)
    with ChainBaseServer(address, ChainMsgHandler) as server:
        server.serve_forever()

