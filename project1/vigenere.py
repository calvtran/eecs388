#!/usr/bin/python3

# Run me like this:
# $ cat ciphertext_file | python3 vigenere.py

import sys

# taken from Wikipedia
letter_freqs = {
    "A": .08167, "B": .01492, "C": .02782, "D": .04253, "E": .12702, "F": .02228,
    "G": .02015, "H": .06094, "I": .06996, "J": .00153, "K": .00772, "L": .04025,
    "M": .02406, "N": .06749, "O": .07507, "P": .01929, "Q": .00095, "R": .05987,
    "S": .06327, "T": .09056, "U": .02758, "V": .00978, "W": .02360, "X": .00150,
    "Y": .01974, "Z": .00074
}

alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'


def shift_letter(c: str, key: str) -> str:
    """Shift character c by key positions."""
    return alphabet[(alphabet.index(c) - alphabet.index(key)) % 26]


def decipher(cipher: str, key: str) -> str:
    """Decipher vigenere cipher using key."""
    message = ''
    for i in range(len(cipher)):
        message += shift_letter(cipher[i], key[i % len(key)])
    return message


if __name__ == "__main__":
    cipher = sys.stdin.read().replace("\n", "").replace(" ", "").upper()

    #
    # TODO: Find the key
    #

    key = "TODO"
    print(key)
