# -*- coding: utf-8 -*-
"""
    webchain
    ~~~~~~~~

    a frontend based on flask which helps users to submit transactions to the blockchain

    :author: hank
"""

from flask import Flask, request, jsonify
from source.blockchain import *
from source.transfer import send_handler, MsgType, recv_parser, batch_parser
from source.utility import *
import struct
import socket
import hashlib
import requests
from binascii import unhexlify
from source.Trans import *

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import time

app = Flask(__name__)
chainbase_address = None


@app.route("/", methods=['GET', 'POST'])
def hello():
    return 'hello'


@app.route("/transaction", methods=['GET', 'POST'])
def transaction():
    if request.method == 'GET':
        return r'<!DOCTYPE html><html><body><form action="/transaction" method=POST>' \
               r'To:<br><input type="text" name="to" value=""><br>Amount:<br><input ' \
               r'type="text" name="amount" value="" pattern="+[0-9]"><br>Private Key:<br><textarea rows="4" ' \
               r'cols="20" name="prikey" value=""></textarea><br>Input(TxID,index;):<br><textarea rows="4" cols="20" ' \
               r'name="input" value=""></textarea><br><input type="submit" value="Submit"></form> </body></html>'
    else:
        receiver = request.form['to']
        amount = int(request.form['amount'])
        prikey = request.form['prikey'].encode()
        ipt = request.form['input']

        ipt, index = ipt.split(',')

        ipt = unhexlify(ipt)
        index = int(index)

        prikey = prikey.replace(b'\r\n', b'\n')
        prikey = prikey.replace(b'\\n', b'\n')

        private_key = load_pem_private_key(prikey, None, default_backend())
        public_key = private_key.public_key()
        serialized_public = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo)
        sha = hashlib.sha256()
        sha.update(serialized_public)
        public_key_hash = sha.digest()

        t_input = TransInput([(TXID(ipt), OUTPUT_INDEX(index))], public_key_hash)
        t_output = TransOutput([(ASSET(amount), PUBLIC_KEY_HASH(unhexlify(receiver)))])
        trans = Transaction(t_input, t_output)
        trans.ready(private_key)
        result = trans_to_json(trans)

        fd = open('peer.txt', 'r')
        for line in fd.readlines():
            if line != '\n':
                print('http://' + line.rstrip() + '/transaction_post')
                r = requests.post('http://' + line.rstrip() + '/transaction_post', data=result)
                print(r.text)
        fd.close()

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:  # submit the valid transaction

            s.connect(chainbase_address)
            s.sendall(send_handler(MsgType.TYPE_TRANS_WRITE, trans.b))
            *_, msgtype, content = recv_parser(s)
        if msgtype == MsgType.TYPE_RESPONSE_OK:
            return 'ok'
        else:
            print(trans.show_trans())
            return 'error'


@app.route("/block", methods=['GET'])
def block():
    start = request.args.get('start', type=int)
    end = request.args.get('end', type=int)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(chainbase_address)
        s.sendall(send_handler(MsgType.TYPE_BLOCK_READ, struct.pack('=i', start)+struct.pack('=i', end)))
        *_, msgtype, content = recv_parser(s)

        content = batch_parser(content)
        block = [Block.unpack(i).show_block() for i in content]

    return jsonify(block)


@app.route("/transaction_post", methods=['GET', 'POST'])
def transaction_post():
    temp = str(request.get_data(), encoding='utf-8')
    trans = json_to_trans(temp)
    print(trans.timestamp)
    print(time.time())
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:  # submit the valid transaction

        s.connect(chainbase_address)
        s.sendall(send_handler(MsgType.TYPE_TRANS_WRITE, trans.b))
        *_, msgtype, content = recv_parser(s)
    # print('end.....')
    # print(content)
    if msgtype == MsgType.TYPE_RESPONSE_OK:
        return 'ok'
    else:
        return 'error'


if __name__ == "__main__":
    chainbase_address = 'node1'
    app.run()
