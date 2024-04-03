import os, random
from itertools import product
from aes import AES
from utils import *

KEY = os.urandom(16)

# 1-round AES Encryption (including last MixColumns)
def encrypt(plaintext):
    aes = AES(KEY, 1)
    key_expand = aes._key_matrices

    state = aes.encrypt_block(plaintext)
    state = bytes2matrix(state)
    add_round_key(state, key_expand[-1])
    mix_columns(state)
    add_round_key(state, key_expand[-1])
    
    return matrix2bytes(state)

# Decryption check
def decrypt(ciphertext, key):
    aes = AES(key, 1)
    key_expand = aes._key_matrices
    state = bytes2matrix(ciphertext)
    add_round_key(state, key_expand[-1])
    inv_mix_columns(state)
    add_round_key(state, key_expand[-1])

    return aes.decrypt_block(matrix2bytes(state))

def solve(k0_0, k0_12, k0_13, k0_14, k0_15, P, C):
    x = [None] * 16
    y = [None] * 16
    z = [None] * 16
    w = [None] * 16

    k0 = [None] * 16
    k1 = [None] * 16

    k0[0] = k0_0
    k0[12] = k0_12
    k0[13] = k0_13
    k0[14] = k0_14
    k0[15] = k0_15

    
    x[0] = k0[0] ^ P[0]
    x[12] = k0[12] ^ P[12]
    x[13] = k0[13] ^ P[13]
    x[14] = k0[14] ^ P[14]
    x[15] = k0[15] ^ P[15]

    y[0] = sbox[x[0]]
    y[12] = sbox[x[12]]
    y[13] = sbox[x[13]]
    y[14] = sbox[x[14]]
    y[15] = sbox[x[15]]

    z[0] = y[0]
    z[12] = y[12]
    z[9] = y[13]
    z[6] = y[14]
    z[3] = y[15]


    wcol2_xor_wcol3 = [
        C[8] ^ C[12] ^ k0[12],
        C[9] ^ C[13] ^ k0[13],
        C[10] ^ C[14] ^ k0[14],
        C[11] ^ C[15] ^ k0[15],
    ]

    tmp = [wcol2_xor_wcol3, [0]*4,[0]*4,[0]*4]
    inv_mix_columns(tmp)
    zcol2_xor_zcol3 = tmp[0]

    z[8] = zcol2_xor_zcol3[0] ^ z[12]
    y[8] = z[8]
    x[8] = inv_sbox[y[8]]
    k0[8] = P[8] ^ x[8]


    z[13] = zcol2_xor_zcol3[1] ^ z[9]
    y[1] = z[13]
    x[1] = inv_sbox[y[1]]
    k0[1] = P[1] ^ x[1]

    # step 5
    subword_k0_col3 = [sbox[k0[13]],sbox[k0[14]],sbox[k0[15]],sbox[k0[12]]]
    k1[0] = k0[0] ^ subword_k0_col3[0] ^ 1 # rcon
    k1[1] = k0[1] ^ subword_k0_col3[1]

    # step 6
    w[0] = k1[0] ^ C[0]
    w[1] = k1[1] ^ C[1]

    # step 7
    a = z[:4]
    b = w[:4]

    early_return = True
    for i in range(256):
        for j in range(256):
            a[1] = i
            a[2] = j

            t = a[:]
            mix_single_column(t)

            if b[0] == t[0] and b[1] == t[1]:
                z[1] = i
                z[2] = j
                w[2] = t[2]
                w[3] = t[3]

                early_return = False
                break

    if early_return:
        return False

    # step 8
    k1[2] = w[2] ^ C[2]
    k1[3] = w[3] ^ C[3]

    # step 9
    k0[2] = k1[2] ^ subword_k0_col3[2]
    k0[3] = k1[3] ^ subword_k0_col3[3]

    # step 10
    y[5]  = z[1]
    y[10] = z[2]

    # step 11
    x[5] = inv_sbox[y[5]]
    x[10] = inv_sbox[y[10]]

    # step 12
    k0[5]  = x[5] ^ P[5]
    k0[10] = x[10] ^ P[10]

    # step 14
    x[2] = k0[2] ^ P[2]
    x[3] = k0[3] ^ P[3]

    # step 15
    y[2] = sbox[x[2]]
    y[3] = sbox[x[3]]

    # step 16
    z[10] = y[2]
    z[7] = y[3]


    # step 13
    z[14] = zcol2_xor_zcol3[2] ^ z[10]
    y[6] = z[14]
    x[6] = inv_sbox[y[6]]
    k0[6] = x[6] ^ P[6]

    # step 17
    k1[5] = k1[1] ^ k0[5]
    k1[6] = k1[2] ^ k0[6]

    # step 18
    w[5] = k1[5] ^ C[5]
    w[6] = k1[6] ^ C[6]

    # step 19
    a = z[4:8]
    b = w[4:8]


    early_return = True
    for i in range(256):
        for j in range(256):
            a[0] = i
            a[1] = j

            t = a[:]
            mix_single_column(t)

            if b[1] == t[1] and b[2] == t[2]:
                z[4] = i
                z[5] = j
                w[4] = t[0]
                w[7] = t[3]

                early_return = False
                break

    if early_return:
        return False


    # step 20
    k1[4] = w[4] ^ C[4]
    k1[7] = w[7] ^ C[7]

    # step 21
    k1[8] = k1[4] ^ k0[8]
    k1[10] = k1[6] ^ k0[10]

    # step 22
    k1[12] = k1[8] ^ k0[12]
    k1[14] = k1[10] ^ k0[14]


    # step 23
    w[8] = k1[8] ^ C[8]
    w[10] = k1[10] ^ C[10]
    w[12] = k1[12] ^ C[12]
    w[14] = k1[14] ^ C[14]


    # step 24
    a = z[8:12]
    b = w[8:12]

    early_return = True
    for i in range(256):
        a[3] = i

        t = a[:]
        mix_single_column(t)

        if b[0] == t[0] and b[2] == t[2]:
            z[11] = i
            w[9] = t[1]
            w[11] = t[3]

            early_return = False
            break

    if early_return:
        return False


    # step 25
    a = z[12:]
    b = w[12:]

    early_return = True
    for i in range(256):
        a[3] = i

        t = a[:]
        mix_single_column(t)

        if b[0] == t[0] and b[2] == t[2]:
            z[15] = i
            w[13] = t[1]
            w[15] = t[3]

            early_return = False
            break

    if early_return:
        return False

    # step 26
    try:
        k1[9] = w[9] ^ C[9]
        k1[11] = w[11] ^ C[11]
        k1[13] = w[13] ^ C[13]
        k1[15] = w[15] ^ C[15]
    except Exception as e:
        return False

    master_key = inv_key_expansion(k1, 1)

    check = decrypt(C, master_key)

    if check == P:
        return master_key

def generate_256_list():
    result = []
    for i in range(256):
        result.append(i)

    return result

# Generate 2 random plaintext and encrypt them
def generate_random_plaintext_ciphertext_pair():
    p = os.urandom(16)
    c = encrypt(p)

    return p, c

print("[+] Generate 1 random plaintext-ciphertext pair")
plaintext, ciphertext = generate_random_plaintext_ciphertext_pair()

# As proof of concept and speed up things, k0, k12, and k13 are fixed
k0 = KEY[0]
k12 = KEY[12]
k13 = KEY[13]

all_possible_bytes = generate_256_list()
all_keys = product(all_possible_bytes, repeat=2)

print("[*] Brute-force 2^16 possible bytes...")
for k14, k15 in all_keys:
    check = solve(k0, k12, k13, k14, k15, plaintext, ciphertext)
    if check:
        print('[+] Possible Master Key:', check)
        print('[+] Actual Master Key  :', KEY)
        break