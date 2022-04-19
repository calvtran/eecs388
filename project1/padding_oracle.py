#!/usr/bin/python3

# Run me like this:
# $ python3 padding_oracle.py "https://project1.eecs388.org/uniqname/paddingoracle/verify" "5a7793d3..."

import json
from pymd5 import _decode
import sys
import time
from typing import Union, Dict, List

import requests

# Create one session for each oracle request to share. This allows the
# underlying connection to be re-used, which speeds up subsequent requests!
s = requests.session()


def oracle(url: str, messages: List[bytes]) -> List[Dict[str, str]]:
    while True:
        try:
            r = s.post(url, data={"message": [m.hex() for m in messages]})
            r.raise_for_status()
            return r.json()
        # Under heavy server load, your request might time out. If this happens,
        # the function will automatically retry in 10 seconds for you.
        except requests.exceptions.RequestException as e:
            sys.stderr.write(str(e))
            sys.stderr.write("\nRetrying in 10 seconds...\n")
            time.sleep(10)
            continue
        except json.JSONDecodeError as e:
            sys.stderr.write("It's possible that the oracle server is overloaded right now, or that provided URL is wrong.\n")
            sys.stderr.write("If this keeps happening, check the URL. Perhaps your uniqname is not set.\n")
            sys.stderr.write("Retrying in 10 seconds...\n\n")
            time.sleep(10)
            continue


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} ORACLE_URL CIPHERTEXT_HEX", file=sys.stderr)
        sys.exit(-1)
    oracle_url, message = sys.argv[1], bytes.fromhex(sys.argv[2])

    if oracle(oracle_url, [message])[0]["status"] != "valid":
        print("Message invalid", file=sys.stderr)

    #
    # TODO: Decrypt the message
    #   1. Figure out padding; mess with bytes until we get MAC Error
    #   2. Change padding
    #   3. Figure out next byte

    # print(message)
    cipher = []
    for b in range(int(len(message)/16)):
        cipher.append('{:02x}'.format(int.from_bytes(message[b*16:(b+1)*16], 'big')))
        # print(cipher[b])

    # Figure out padding
    start = len(message) - 17
    for i in range(start, -1, -1):
        msg = message[:i] + (255).to_bytes(1, byteorder='big') + message[i+1:]
        flag = oracle(oracle_url, [msg])[0]["status"]
        if (flag == "invalid_mac"):
            pad = (start - i)
            break

    d = []
    for j in range(len(cipher)-1):
        d.append([])
    plaintext = []

    for c in range(start-pad+1, start+1, 1):
        byte_c = message[c]
        d_c = byte_c ^ pad
        d[int(c/16)].append(d_c)
        plaintext.insert(0, hex(pad))

    curr_pad = pad
    for i in range(start-curr_pad, -1, -1):

        if (i + 1) % 16 == 0:
            curr_pad = 0 
            start -= 16

        new_c = bytes()

        # Change Padding
        if curr_pad > 0:
            for c in range(start-curr_pad+1, start+1, 1):
                byte_c = message[c]
                d_c = d[int(c/16)][c-(start-curr_pad+1)]
                new_c_i = d_c ^ (curr_pad+1)
                new_c += new_c_i.to_bytes(1, 'big')
        else:
            new_c_i = message[c]
            new_c += new_c_i.to_bytes(1, 'big')

        messages = []
        for c_i_prime in range(0, 256):
            if curr_pad > 0:
                messages.append(message[:i] + c_i_prime.to_bytes(1, 'big') + new_c + message[start+1:(start+17)])
            else:
                messages.append(message[:i] + c_i_prime.to_bytes(1, 'big') + message[start+1:(start+17)])

        msgs = oracle(oracle_url, messages)
        flag = next(m for m in msgs if m["status"] == "invalid_mac")['status']
        c_i_prime = next((i for i, m in enumerate(msgs) if m["status"] == "invalid_mac"), None)

        if (flag == "invalid_mac"):
            d_i = c_i_prime ^ (curr_pad+1)
            c_i = message[i]
            p = c_i ^ d_i
            plaintext.insert(0, hex(p))
            d[int(i/16)].insert(0, d_i)
        curr_pad += 1

plaintext = plaintext[:-32-pad]
m = ''
for i in range(len(plaintext)):
    m += bytes.fromhex(plaintext[i][2:]).decode()

print(m)