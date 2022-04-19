#!/usr/bin/python3

# Run me like this:
# $ python3 bleichenbacher.py "eecs388+uniqname+100.00"

from roots import *

import hashlib
import sys


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} MESSAGE", file=sys.stderr)
        sys.exit(-1)
    message = sys.argv[1]

    #
    # TODO: Forge a signature
    #

    # you can construct an integer whose most significant bytes have the correct format, 
    # including the digest of the target message, and set the last 201 bytes to 00. 
    # Then take the cube root, rounding as appropriate.
    magic = "3031300d0960864801650304020105000420"
    magic_bytes = bytes.fromhex(magic)
    # print(magic_bytes)
    sig_bits = bytes.fromhex('0001FF00')
    m = hashlib.sha3_256()
    m.update(message.encode('utf8'))
    y = ""
    for i in range(201):
        y += "00"
    # print(b)
    rand_bytes = bytes.fromhex(y)
    b = sig_bits + magic_bytes + m.digest() + rand_bytes
    forged_signature = bytes_to_integer(b)
    print(bytes_to_base64(integer_to_bytes(forged_signature, 256)))
