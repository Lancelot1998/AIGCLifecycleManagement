from typing import List, Tuple, NewType, Iterator
from source.utility import n_bytes
from source.blockchain import Transaction, BLENGTH_INT
import struct
from functools import reduce
from enum import Enum, unique
import socket
import time
import sys

PIECE = 4096
LENGTH_HEADER = 64  # 4 len + 4 type + 56 blank(if heartbeat or PBFT, these are content)
LENGTH_TYPE = 4


@unique
class MsgType(Enum):
    TYPE_NORMAL = struct.pack('=i', 0)
    TYPE_HEARTBEAT = struct.pack('=i', 1)
    TYPE_PRE_PREPARE = struct.pack('=i', 2)
    TYPE_PREPARE = struct.pack('=i', 3)
    TYPE_COMMIT = struct.pack('=i', 4)
    TYPE_TRANS = struct.pack('=i', 5)
    TYPE_TRANS_WRITE = struct.pack('=i', 6)
    TYPE_TRANS_RETRIEVE = struct.pack('=i', 7)
    TYPE_BLOCK_WRITE = struct.pack('=i', 8)
    TYPE_RESPONSE_OK = struct.pack('=i', 9)
    TYPE_RESPONSE_ERROR = struct.pack('=i', 10)
    TYPE_TRANS_READ = struct.pack('=i', 11)
    TYPE_TRANS_SEARCH = struct.pack('=i', 12)
    TYPE_BLOCK_PREVIOUS_HASH = struct.pack('=i', 13)
    TYPE_TRANS_SEARCH_TXID = struct.pack('=i', 14)
    TYPE_BLOCK_READ = struct.pack('=i', 15)
    TYPE_NEW_BLOCK = struct.pack('=i', 16)
    TYPE_NODE_DISCOVER = struct.pack('=i', 17)
    TYPE_LIGHTBLOCK_WRITE = struct.pack('=i', 18)
    TYPE_NEW_LIGHTBLOCK = struct.pack('=i', 19)
    TYPE_TRANS_MAKE = struct.pack('=i', 20)
    TYPE_MINER_CREDIT = struct.pack('=i', 21)
    TYPE_MACRO_BLOCK_HEADER_WRITE = struct.pack('=i', 22)
    TYPE_MACRO_BLOCK_BODY_WRITE = struct.pack('=i', 23)
    TYPE_MICRO_BLOCK_WRITE = struct.pack('=i', 24)
    TYPE_NEW_MACRO_BLOCK_HEADER = struct.pack('=i', 25)
    TYPE_NEW_MACRO_BLOCK_BODY = struct.pack('=i', 26)
    TYPE_NEW_MICRO_BLOCK = struct.pack('=i', 27)
    TYPE_GET_PARENT_HASH = struct.pack('=i', 28)


def b_block_pack(block: bytes) -> List[bytes]:
    p = len(block) % PIECE
    packages = n_bytes(block[:-p], PIECE)
    packages.append(block[-p:])
    return packages


def batch_handler(batch: List) -> bytes:
    """
    process a list of binary content to a binary string
    :param batch: a list of binary content
    :return: the content can be feed to send_handler()
    """
    length = [struct.pack('=i', len(individual)) for individual in batch]
    return reduce(lambda x, y: x + y, [l + c for l, c in zip(length, batch)])


def batch_parser(batch: bytes) -> List:
    """
    process a received binary string to a list of binary content
    :param batch: received binary string
    :return: a list of binary content
    """
    result = []
    i = 0
    while i < len(batch):
        l = struct.unpack('=i', batch[i:i+BLENGTH_INT])[0]
        i = i + l + BLENGTH_INT
        result.append(batch[i-l:i])
    return result


def send_handler(type: MsgType, content) -> bytes:
    """
    pack content to be sent
    :param type: content type
    :param content: binary content
    :return: packed content can be send directly
    """
    payload = b''.join((struct.pack('=i', len(content)), type.value,
                        bytes(LENGTH_HEADER - BLENGTH_INT - LENGTH_TYPE), content))
    return payload


def recv_parser(request):
    header = request.recv(LENGTH_HEADER)
    length, msgtype = header_parser(header)
    content = recv_content(length, request)

    return header, length, msgtype, content


def header_parser(header: bytes):
    if len(header) != LENGTH_HEADER:
        print('header', len(header))
    assert len(header) == LENGTH_HEADER

    length = struct.unpack('=i', header[:4])[0]
    msgtype = MsgType(header[4:8])

    return length, msgtype


def recv_content(length: int, request) -> bytes:
    content = bytes()
    l = 0

    while l < length:
        piece = request.recv(min(PIECE, length - l))
        content += piece
        l += len(piece)

    return content


class PeerManager:
    def __init__(self):
        self.peers = []

    def peer_discover(self, address: Tuple[str, int]):
        self.peers.append(address)

    def sendall_block(self, msgtype: MsgType, content: bytes):
        for p in self.peers:

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(p)
                s.sendall(send_handler(msgtype, content))