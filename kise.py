#!/usr/bin/env python3

import argparse
import base64
import os
import subprocess
import tempfile

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from getpass import getpass

class Kise:

    def __init__(self, pwd=b'', salt=b''):
        self.key = b''
        self.pwd = pwd if pwd != b'' else getpass().encode()
        self.salt = salt if salt != b'' else os.urandom(16)
        self.calc_secret_key()

    def calc_secret_key(self):
        """ Calculate secret key from salt and password
        """

        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), 
                         length=32, 
                         salt=self.salt, 
                         iterations=400000)

        self.key = base64.urlsafe_b64encode(kdf.derive(self.pwd))

    def encrypt(self, data: bytes) -> bytes:
        """ Use secret key to encrypt data.

        Args:
            data: Data in byte format that want to encrypt

        Returns:
            The encrypted bytes
        """

        fernet = Fernet(self.key)

        return fernet.encrypt(data)

    def encrypt_file(self, src_file: str, dst_file: str):
        """ Thansform data in src_file to be encrypted and store in dst_file.

        Args:
            src_file: The original plaintext file
            dst_file: File to store ciphertext
        """

        with open(src_file, 'rb') as f:
            enc_data = self.encrypt(f.read())

        with open(dst_file, 'wb') as f:
            salt_b64 = base64.b64encode(self.salt)
            f.write(salt_b64 + b',' + enc_data)

    def decrypt(self, enc_data: bytes) -> bytes:
        """ Use secret key to decrypt data.

        Args:
            enc_data: Data in byte format that want to decrypt

        Returns:
            The decrypted bytes

        Raises:
            Exception that means invalid password
        """

        fernet = Fernet(self.key)

        try:
            return fernet.decrypt(enc_data)
        except:
            raise Exception('Incorrect password')


    def decrypt_file(self, src_file, dst_file=None):
        """ Thansform data in src_file to be decrypted and store in dst_file.

        If dst_file is None, then show the contents on standard output.

        Args:
            src_file: The original plaintext file
            dst_file: File to store ciphertext
        """

        with open(src_file, 'rb') as f:
            salt_b64, enc_data = f.read().decode().split(',')

            self.salt = base64.b64decode(salt_b64)
            enc_data = enc_data.encode()

            self.calc_secret_key()

        data = self.decrypt(enc_data)

        if dst_file:
            with open(dst_file, 'wb') as f:
                f.write(data)
        else:
            print(data.decode(), end='')


def enc_handler(args):
    k = Kise()
    k.encrypt_file(args.src_file, args.dst_file)

def dec_handler(args):
    k = Kise()
    k.decrypt_file(args.src_file, args.dst_file)

def edit_handler(k, args):
    k = Kise()
    with tempfile.NamedTemporaryFile(delete=True) as tmp:

        k.decrypt(args.src_file, tmp.name)

        proc = subprocess.Popen(['vim', tmp.name], close_fds=True)
        proc.communicate()

        k.encrypt(tmp.name, args.src_file)

def parse_argument():

    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers(dest='operation')

    dec_parser = subparser.add_parser('dec', help='Decrypt file')
    dec_parser.add_argument('-s', '--src_file', required=True)
    dec_parser.add_argument('-d', '--dst_file')
    dec_parser.set_defaults(func=dec_handler)

    enc_parser = subparser.add_parser('enc', help='Encrypt file')
    enc_parser.add_argument('-s', '--src_file', required=True)
    enc_parser.add_argument('-d', '--dst_file', required=True)
    enc_parser.set_defaults(func=enc_handler)

    edit_parser = subparser.add_parser('edit', help='Edit encrypted file')
    edit_parser.add_argument('-s', '--src_file', required=True)
    edit_parser.set_defaults(func=edit_handler)

    return parser.parse_args()


if __name__ == '__main__':

    args = parse_argument()
    args.func(args)
