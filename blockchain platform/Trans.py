import json
from source.blockchain import *
import struct
from typing import List, Tuple, NewType
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import \
    Encoding, PublicFormat, load_pem_public_key, load_der_private_key
from cryptography.hazmat.backends import default_backend


def bytes_to_tuple(message: bytes) -> Tuple:
    length = len(message) // 4
    last = len(message) % 4
    for i in range((4 - last) % 4):
        message += b'\x00'
    if last == 0:
        form = '%di' % length
    else:
        length += 1
        form = '%di' % length
    return (4 - last) % 4, struct.unpack(form, message)


def list_to_bytes(message: List) -> bytes:
    test = b''
    for i in range(len(message[1])):
        test += struct.pack('i', message[1][i])
    if message[0] == 0:
        return test
    else:
        return test[:-message[0]]


def trans_to_json(trans: Transaction):
    result = trans.show_trans()
    result['signature'] = bytes_to_tuple(trans.signature)
    result['txid'] = bytes_to_tuple(trans.txid)
    result['trans_input']['public_key_hash'] = bytes_to_tuple(trans.ipt.public_key_hash)
    _input = []
    for i in trans.ipt.content:
        _input.append((bytes_to_tuple(i[0]), i[1]))
    result['trans_input']['content'] = _input
    result['trans_input']['b'] = bytes_to_tuple(trans.ipt.b)
    _output = []
    for i in trans.opt.content:
        _output.append((i[0], bytes_to_tuple(i[1])))
    result['trans_output']['content'] = _output
    result['trans_output']['b'] = bytes_to_tuple(trans.opt.b)
    result['trans_b'] = bytes_to_tuple(trans.b)
    return json.dumps(result)


def json_to_trans(result) -> Transaction:
    result = json.loads(result)
    result['txid'] = list_to_bytes(result['txid'])
    result['signature'] = list_to_bytes(result['signature'])
    result['trans_input']['public_key_hash'] = list_to_bytes(result['trans_input']['public_key_hash'])
    _input = []
    for i in result['trans_input']['content']:
        _input.append((list_to_bytes(i[0]), i[1]))
    result['trans_input']['content'] = _input
    result['trans_input']['b'] = list_to_bytes(result['trans_input']['b'])
    _output = []
    for i in result['trans_output']['content']:
        _output.append((i[0], list_to_bytes(i[1])))
    result['trans_output']['content'] = _output
    result['trans_output']['b'] = list_to_bytes(result['trans_output']['b'])
    result['trans_b'] = list_to_bytes(result['trans_b'])
    # make transaction
    trans_output = TransOutput(result['trans_output']['content'])
    trans_output.b = result['trans_output']['b']
    trans_input = TransInput(result['trans_input']['content'], result['trans_input']['public_key_hash'])
    trans_input.b = result['trans_input']['b']
    transaction = Transaction(trans_input, trans_output)
    transaction.signature = result['signature']
    transaction.txid = result['txid']
    transaction.timestamp = result['timestamp']
    transaction.public_key = serialization.load_pem_public_key(result['public_key'].encode(encoding='utf-8'),
                                                               backend=default_backend())
    transaction.b = result['trans_b']
    transaction.length = result['length']
    transaction.ipt = trans_input
    transaction.opt = trans_output
    return transaction


