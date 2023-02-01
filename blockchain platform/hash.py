import hashlib
import time
import struct
from random import randrange, seed
MINE_TOP = 2 ** 31
import struct
i = 0
print(time.time())
while i <= 1000000:
    sha = hashlib.sha256()
    sha.update(b'\x0000000\x03\x34\x5f0000defsfaefefee')
    sha.digest()
    i += 1
print(time.time())
#
# i = 0
# print(time.time())
# while i <= 1000000:
#     sha = hashlib.sha256()
#     sha.update(b'\x00')
#     sha.update(struct.pack('=I', 45))
#     hash_ = sha.digest()
#     sha = hashlib.sha256()
#     sha.update(hash_)
#     hash_ = sha.digest()
#     i += 1
# print(time.time())

prev_hash = b'\x00\x34\x12\x32\56\x34fefeljesjfelijesnffsj2'


def __calc_hash(prev_hash, nonce: int) -> bytes:  # calculate SHA256(SHA256(prev_hash+nonce))
    sha = hashlib.sha256()
    sha.update(prev_hash)
    sha.update(struct.pack('=I', nonce))
    hash_ = sha.digest()
    sha = hashlib.sha256()
    sha.update(hash_)
    hash_ = sha.digest()

    return hash_


# target = (3 * 2 ** 235 - 60 ** 40).to_bytes(32, byteorder='big')
# print(target)
# seed()
# print(time.time())
# initial = randrange(0, MINE_TOP)  # [0, 2**32]
# print('mining')
# for nonce in range(initial, MINE_TOP):
#
#     hash_ = __calc_hash(prev_hash, nonce)
#     if hash_ < target:
#         print('ok')
#         print(time.time())
#         break
#
#
# for nonce in range(0, initial):
#
#     hash_ = __calc_hash(prev_hash, nonce)
#
#     if hash_ < target:
#         print('ok')
#         print(time.time())
#         break
#
# if (3 * 2 ** 235 - 60 ** 40).to_bytes(32, byteorder='big') < (3 * 2 ** 235 - 1).to_bytes(32, byteorder='big'):
#     print('okll')
