"""
    conchain
    ~~~~~~~~~~

    Implements blockchain consensus mechanisms

    :author:
"""
from source.transfer import MsgType, PeerManager, recv_parser, send_handler
import socketserver
import socket
from multiprocessing import Pool
from source.Trans import *
import time
import requests
import hashlib
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


class PoWServer(socketserver.ThreadingMixIn, socketserver.TCPServer):

    def __init__(self, server_name: str, server_address, handler, chainbase_address):
        self.name = server_name
        self.chainbase_address = chainbase_address
        self.peer = PeerManager()
        self.workers = Pool()

        super().__init__(server_address, handler, bind_and_activate=True)

    def serve_forever(self, poll_interval=5):

        self.create()

        super().serve_forever()

    def create(self):
        print('ok')
        while True:
            try:
                # sleep for the remaining seconds of interval
                print('ok')
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                    s.connect(self.chainbase_address)
                    s.sendall(send_handler(MsgType.TYPE_TRANS_MAKE, b''))
                    *_, msgtype, content = recv_parser(s)
                print('content')
                print(content)
                if content == b'':
                    time.sleep(0.1)
                else:
                    sha = hashlib.sha256()
                    sha.update(content[BLENGTH_TXID:])
                    print(content[:BLENGTH_TXID])
                    print('sha')
                    print(sha.digest())
                    time.sleep(0.01)
            except Exception as e:
                print('error')
                time.sleep(0.1)
            finally:
                pass


class PowHandler(socketserver.StreamRequestHandler):
    def handle(self):
        handlers = {}
        *_, msgtype, content = recv_parser(self.request)

        handlers[msgtype](content)


if __name__ == '__main__':
    address = ('0.0.0.0', 11390)
    chainbase_address = 'node1'

    with PoWServer('generator', address, PowHandler, chainbase_address) as server:
        server.serve_forever()
