#!/usr/bin/env python3

from sys import argv
from getpass import getpass
import subprocess
import tempfile

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

key = getpass()
vc = Vigenere_Cipher(key)

if argv[1] == 'enc':

    with open(argv[2]) as f:
        for c in f.read():
            print(vc.encode(c), end='')

elif argv[1] == 'dec':

    with open(argv[2]) as f:
        for c in f.read():
            print(vc.decode(c), end='')

elif argv[1] == 'edit':

    with tempfile.NamedTemporaryFile(delete=True) as tmp:

        plain = ''
        with open(argv[2]) as f:
            for c in f.read():
               plain += vc.decode(c)

        tmp.write(plain.encode())
        tmp.seek(0)

        proc = subprocess.Popen(['vim', tmp.name], close_fds=True)
        proc.communicate()

        enc = ''
        vc2 = Vigenere_Cipher(key)
        for c in tmp.read():
            enc += vc2.encode(chr(c))

        with open(argv[2], 'wb') as f:
            f.write(enc.encode())

