#!/usr/bin/env python3

"""
Usage:
    kise.py [-h] [-d FILE | -e FILE]

Options:
    -h, --help      Show help message
    -d, --decrypt   Decrypt document
    -e, --encrypt   Encrypt document
"""

from docopt import docopt
from getpass import getpass

BEGIN_CHAR = 0x20
END_CHAR = 0x7E

class Vigenere_Cipher:

    def __init__(self, key):

        self.key = list(key)
        self.index = 0

    def encode(self, data):

        d = ord(data);
        k = ord(self.key[self.index]) - BEGIN_CHAR
        self.index = (self.index + 1) % len(self.key)

        if d < BEGIN_CHAR or d > END_CHAR:
            return data

        enc_res = d + k
        if enc_res > END_CHAR:
            enc_res = enc_res - (END_CHAR + 1) + BEGIN_CHAR

        return chr(enc_res)


    def decode(self, data):

        d = ord(data);
        k = ord(self.key[self.index]) - BEGIN_CHAR
        self.index = (self.index + 1) % len(self.key)

        if d < BEGIN_CHAR or d > END_CHAR:
            return data

        enc_res = d - k
        if enc_res < BEGIN_CHAR:
            enc_res = enc_res - BEGIN_CHAR + (END_CHAR + 1)

        return chr(enc_res)


args = docopt(__doc__)

if args['--encrypt']:

    key = getpass()
    vc = Vigenere_Cipher(key)

    with open(args['FILE']) as f:
        s = f.read()

    for c in s:
        print(vc.encode(c), end='')


elif args['--decrypt']:

    key = getpass()
    vc = Vigenere_Cipher(key)

    with open(args['FILE']) as f:
        s = f.read()

    for c in s:
        print(vc.decode(c), end='')

