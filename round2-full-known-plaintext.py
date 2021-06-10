import os, random
from itertools import product
from aes import AES
from utils import *

KEY = b"\x40\x7E\x15\x16\x28\x08\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C"
# Using random key will take very long time (2**32 key check)
#KEY = os.urandom(16)

# Full 2-round encryption (including last MixColumns)
def encrypt(plaintext):
    aes = AES(KEY, 2)
    key_expand = aes._key_matrices

    state = aes.encrypt_block(plaintext)
    state = bytes2matrix(state)
    add_round_key(state, key_expand[-1])
    mix_columns(state)
    add_round_key(state, key_expand[-1])
    
    return matrix2bytes(state)

# Generate 3 random plaintext and encrypt them
def generate_random_plaintext_ciphertext_pair():
    # Just to prevent differential of two plaintext contains \x00 byte
    while True:
        p1 = os.urandom(16)
        p2 = os.urandom(16)
        p3 = os.urandom(16)

        if 0 not in xor(p1, p2) and 0 not in xor(p1, p3):
            break

    c1 = encrypt(p1)
    c2 = encrypt(p2)
    c3 = encrypt(p3)

    if not os.path.isdir("data"):
        os.mkdir("data")

    open("data/p1.bin", "wb").write(p1)
    open("data/p2.bin", "wb").write(p2)
    open("data/p3.bin", "wb").write(p3)
    open("data/c1.bin", "wb").write(c1)
    open("data/c2.bin", "wb").write(c2)
    open("data/c3.bin", "wb").write(c3)

print("[+] Generate random 3 known-plaintext ciphertext pairs...")
generate_random_plaintext_ciphertext_pair()

# Running our attack on round2-full-3-known-plaintext
print("[+] Running Attack in subshell...")
os.system("./round2-full-3-known-plaintext data/p1.bin data/p2.bin data/p3.bin data/c1.bin data/c2.bin data/c3.bin")

# We get our Round Key 1 in data/output.bin
try:
    rk1 = open("data/output.bin", "rb").read()

    print("[+] Inverse Key Expansion...")
    master_key = inv_key_expansion(rk1, 1)

    print("[+] Recovered AES key:", master_key)
    print("[+] REAL KEY         :", KEY)
except Exception as e:
    print("[-] Attack failed :(")
    pass