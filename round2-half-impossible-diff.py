import os, random
from Crypto.Util.strxor import strxor
from itertools import product
from aes import AES
from utils import *

#KEY = b"\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C"
KEY = os.urandom(16)

# Encryption oracle
def encrypt(plaintext):
    aes = AES(KEY, 2)
    return aes.encrypt_block(plaintext)

# Decryption check
def decrypt(ciphertext, key):
    aes = AES(key, 2)
    return aes.decrypt_block(ciphertext)


def generate_sbox_different_distribution_table():
    table = {}
    for i in range(256):
        for j in range(256):
            diff = i ^ j
            diff_sbox = sbox[i] ^ sbox[j]

            if diff in table:
                if diff_sbox not in table[diff]:
                    table[diff].append(diff_sbox)
            else:
                table[diff] = [diff_sbox]

    return table

# Inverse state from ciphertext to start of Round 2 
def inv_last_round(s, k):
    state = bytes2matrix(s)
    round_key = bytes2matrix(k)
    add_round_key(state, round_key)
    inv_shift_rows(state)
    inv_sub_bytes(state)

    return matrix2bytes(state)

# Generate list impossible state at the end of round 1 based from SBOX Different Distribution Table
def generate_impossible_state(differential):
    impossible = []
    for i in range(4):
        impossible.append([])
        for j in range(256):
            if j not in sbox_ddt[differential[i]]:
                impossible[i].append(j)

    impossible_state = []
    for i in range(4):
        
        for j in impossible[i]:
            state = bytes2matrix(b'\x00'*(i) + bytes([j]) + b'\x00'*(15-i))
            shift_rows(state)
            mix_columns(state)
            impossible_state.append(matrix2bytes(state))
            
    return impossible_state

def generate_256_list():
    result = []
    for i in range(256):
        result.append(i)

    return result

# Generate 5 chosen-plaintext such that each of their differential byte is unique
# So we can make 10 differential pairs from only 5 chosen-plaintext
def generate_sample_pair(n=5):

    while True:
        bs = []
        for i in range(n):
            bs.append(os.urandom(4))

        is_unique = True
        for i in range(4):
            exclude = []
            for j in range(n-1):
                for k in range(j+1, n):
                    check = bs[j][i] ^ bs[k][i]
                    if check not in exclude:
                        exclude.append(check)
                    else:
                        is_unique = False

        if is_unique:
            pairs = []
            ctx = []

            # Calls encryption oracle
            for i in range(n):
                p = bytes(bs[i]) + b'\x00'*12
                ctx.append(encrypt(p))

            for i in range(n-1):
                for j in range(i+1, n):
                    p1 = bytes(bs[i]) + b'\x00'*12
                    p2 = bytes(bs[j]) + b'\x00'*12
                    pairs.append([p1, p2, ctx[i], ctx[j]])

            return pairs

# ShiftRows 1 round
shifted_round1 = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]

# Generate Sbox Different Distribution Table
sbox_ddt = generate_sbox_different_distribution_table()

# Generate random sample of chosen-plaintext pairs that has unique XOR difference
print("[+] Retrieve 5 plaintext-ciphertext pairs from encryption oracle...")
test_pair = generate_sample_pair()
impossible_key = [None] * 16

# Iterate over sample of chosen-plaintext
for plaintext1, plaintext2, ciphertext1, ciphertext2 in test_pair:

    print("[+] Checking impossible state from differential pair...")

    # Calculate XOR difference of plaintext and differential ciphertext 
    plain_diff = xor(plaintext1, plaintext2)
    enc_diff = xor(ciphertext1, ciphertext2)


    # Generate impossible start of round 2 state from pair sample
    impossible_state = generate_impossible_state(plain_diff)

    # Brute-force last round key one byte at time by comparing against impossible_state
    for i in range(16):
        if impossible_key[i] is None:
            impossible_key[i] = []

        shifted_index = shifted_round1[i]
        for j in range(256):
            if j in impossible_key[i]:
                continue

            # Inverse ciphertext to start of round 2 (ciphertext -> AddRoundKey -> InvShiftRows -> InvSubBytes)
            guess_key = b'\x00'*(i) + bytes([j]) + b'\x00'*(15-i)
            inv_a = inv_last_round(ciphertext1, guess_key)
            inv_b = inv_last_round(ciphertext2, guess_key)
            inv_diff = xor(inv_a, inv_b)
            
            # Check if inv_diff contained in one of impossible_state
            for k in impossible_state:
                if inv_diff[shifted_index] == k[shifted_index]:
                    impossible_key[i].append(j)

# Get possible_key by substracting all 256 possible value with impossible_key
list_256 = generate_256_list()
possible_key = []
for imp_key in impossible_key:
    possible_key.append(list(set(list_256) - set(imp_key)))

all_possible_key = product(*possible_key)

# Enumerate all remaining possible_key
ciphertext_check = ciphertext1
for possible_round_key in all_possible_key:
    
    master_key = inv_key_expansion(list(possible_round_key), 2)
    
    decrypt_check = decrypt(ciphertext_check, master_key)
    if decrypt_check == test_pair[-1][0]:
        print('[+] Possible Master Key:', master_key)
        print('[+] Actual Master Key  :', KEY)
        break