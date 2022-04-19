#!/usr/bin/python3

# Run me like this:
# $ python3 len_ext_attack.py "https://project1.eecs388.org/cktran/lengthextension/api?token=...."

import sys
from urllib.parse import quote

import pymd5
from pymd5 import md5, padding


class ParsedURL:
    def __init__(self, url: str):
        # prefix is the slice of the URL from "https://" to "token=", inclusive.
        self.prefix = url[:url.find('=') + 1]
        self.token = url[url.find('=') + 1:url.find('&')]
        # suffix starts at the first "command=" and goes to the end of the URL
        self.suffix = url[url.find('&') + 1:]


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} URL_TO_EXTEND", file=sys.stderr)
        sys.exit(-1)

    url = ParsedURL(sys.argv[1])

    #
    # TODO: Modify the URL
    #
    com = "&command=UnlockSafes"

    length_m = 8 + len(url.suffix)
    bits = (length_m + len(padding(length_m * 8))) * 8

    h = md5(state=bytes.fromhex(url.token), count=512)
    h.update(com)
    newToken = h.hexdigest()

    modified_url = url.prefix + newToken + '&' + url.suffix + quote(padding(length_m * 8)) + com
    print(modified_url)
    # https://project1.eecs388.org/cktran/lengthextension/api?token=cb6d09ea7091140c739a4ed1b42cb76b&command=SprinklersPowerOn