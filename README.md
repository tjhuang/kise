KISE means Keep It Simple Encrypt.

## Prerequisites

```bash
$ pip install cryptography==3.3
```


## Encrypt file
$ kise.py enc -s test.txt -d test.enc
Password:

## Decrypt file
$ kise.py dec -s test.enc
Password:
Hello World

## Edit encrypted file
$ kise.py edit -s test.enc
