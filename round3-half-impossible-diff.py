import os, random
from itertools import product
from aes import AES
from utils import *

#KEY = b"\x00\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C"
KEY = os.urandom(16)

def encrypt(plaintext):
    aes = AES(KEY, 3)
    return aes.encrypt_block(plaintext)

def decrypt(ciphertext, key):
    aes = AES(key, 3)
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

def inv_last_round(s, k):
    state = bytes2matrix(s)
    round_key = bytes2matrix(k)
    add_round_key(state, round_key)
    inv_shift_rows(state)
    inv_sub_bytes(state)

    return matrix2bytes(state)

def generate_256_list():
    result = []
    for i in range(256):
        result.append(i)

    return result

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

def round1_to_round2(s):
    state = bytes2matrix(s)
    sub_bytes(state)
    shift_rows(state)
    mix_columns(state)

    return matrix2bytes(state)

def generate_sample_pair(n=5):

    while True:
        bs = []
        for i in range(n):
            bs.append(os.urandom(1))

        is_unique = True
        exclude = []
        for i in range(n-1):
            for j in range(i+1, n):
                check = bs[i][0] ^ bs[j][0]
                if check not in exclude:
                    exclude.append(check)
                else:
                    is_unique = False

        if is_unique:
            pairs = []
            ctx = []

            # Calls encryption oracle
            for i in range(n):
                p = bytes(bs[i]) + b'\x00'*15
                ctx.append(encrypt(p))

            for i in range(n-1):
                for j in range(i+1, n):
                    p1 = bytes(bs[i]) + b'\x00'*15
                    p2 = bytes(bs[j]) + b'\x00'*15
                    pairs.append([p1, p2, ctx[i], ctx[j]])

            return pairs

shifted = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]

sbox_ddt = generate_sbox_different_distribution_table()



print('[+] Retrieve 5 plaintext-ciphertext pairs from encryption oracle...')
test_pair = generate_sample_pair()

impossible_key = [None] * 256
possible_rk0 = -1
for x in range(256):
    print('[+] Testing Rk0 = '+str(x))
    impossible_key[x] = [None] * 16

    for p1, p2, c1, c2 in test_pair:
        
        p1_xor_p2 = xor(p1, p2)
        ciphertext_a = c1
        ciphertext_b = c2
        
        round0_key = bytes([x]) + b'\x00'*(15)
        a_ = xor(p1, round0_key)
        b_ = xor(p2, round0_key)
        a_ = round1_to_round2(a_)
        b_ = round1_to_round2(b_)

        plain_diff = xor(a_, b_)
        
        impossible_state = generate_impossible_state(plain_diff)

        # Brute-force last round key one byte at time by comparing against impossible_state
        for i in range(16):
            if impossible_key[x][i] is None:
                impossible_key[x][i] = []

            shifted_index = shifted[i]
            for j in range(256):
                if j in impossible_key[x][i]:
                    continue

                # Inverse ciphertext to start of round 3 (ciphertext -> AddRoundKey -> InvShiftRows -> InvSubBytes)
                guess_key = b'\x00'*(i) + bytes([j]) + b'\x00'*(15-i)
                inv_a = inv_last_round(ciphertext_a, guess_key)
                inv_b = inv_last_round(ciphertext_b, guess_key)
                inv_diff = xor(inv_a, inv_b)

                # Check if inv_diff contained in one of impossible_state
                for imp in impossible_state:
                    if inv_diff[shifted_index] == imp[shifted_index]:
                        impossible_key[x][i].append(j)

    # Check if any byte position in impossible_key contains all possible bytes, if False then x is the correct RoundKey 0
    n = []
    for z in range(16):
        n.append(len(impossible_key[x][z]))
    
    if 256 not in n:
        print('[+] Found correct Rk0')
        possible_rk0 = x
        break

# Get possible_key by substracting all 256 possible value with impossible_key
list_256 = generate_256_list()
possible_key = []
for imp_key in impossible_key[possible_rk0]:
    possible_key.append(list(set(list_256) - set(imp_key)))
    
all_possible_key = product(*possible_key)

# Enumerate all remaining possible_key
ciphertext_check = test_pair[0][2]
for possible_round_key in all_possible_key:
    
    master_key = inv_key_expansion(list(possible_round_key), 3)
    
    decrypt_check = decrypt(ciphertext_check, master_key)
    if decrypt_check == test_pair[0][0]:
        print('[+] Possible Master Key:', master_key)
        print('[+] Actual Master Key  :', KEY)
        break