# -*- coding: utf-8 -*-
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

fd = open('ad1.txt', 'r+')
for i in range(110):
    private_key = ec.generate_private_key(ec.SECP256K1, default_backend())
    public_key = private_key.public_key()
    sy = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    sha = hashlib.sha256()
    sha.update(sy)
    public_key_hash = sha.digest()
    serialized_private = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                   format=serialization.PrivateFormat.PKCS8,
                                                   encryption_algorithm=serialization.NoEncryption())

    fd.writelines(str(serialized_private) + 'ENDDING')
    fd.writelines(str(sy) + '\n')
    # print(serialized_private)
    # print(sy)
    # print(len(public_key_hash))
fd.close()

fd = open('ad1.txt', 'r')
for index, line in enumerate(fd.readlines()):
    print(index)
    line = line.rstrip()
    pr, pu = line.split('ENDDING')
    temp = bytes(pr[2:-1], encoding='utf-8')
    temp = temp.replace(b'\r\n', b'\n')
    private_key = temp.replace(b'\\n', b'\n')
    temp = bytes(pu[2:-1], encoding='utf-8')
    temp = temp.replace(b'\r\n', b'\n')
    public_key = temp.replace(b'\\n', b'\n')
    print(private_key)
    print(public_key)
fd.close()


