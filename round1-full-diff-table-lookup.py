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

# InvMixColumns -> InvShiftRows of ciphertext differential
def inv_last_round(s):
    state = bytes2matrix(s)
    inv_mix_columns(state)
    inv_shift_rows(state)

    return matrix2bytes(state)

def generate_sbox_ddt():
    table = [[]] * 256
    for i in range(256):
        for j in range(256):
            diff_input = i ^ j
            diff_output = sbox[i] ^ sbox[j]

            if len(table[diff_input]) != 0:
                table[diff_input][diff_output].update(set([i, j]))
            else:
                table[diff_input] = [set() for _ in range(256)]
                table[diff_input][diff_output] = set([i, j])

    return table

# Generate 2 random plaintext and encrypt them
def generate_random_plaintext_ciphertext_pair():
    p1 = os.urandom(16)
    p2 = os.urandom(16)
    c1 = encrypt(p1)
    c2 = encrypt(p2)

    return (p1, p2), (c1, c2)

# Generate random known plaintext and its corresponding ciphertext
print("[+] Generate 2 random plaintext-ciphertext pairs")
plaintext, ciphertext = generate_random_plaintext_ciphertext_pair()

# Get plaintext differential and ciphertext differential
ptx_diff = xor(plaintext[0], plaintext[1])
ctx_diff = xor(ciphertext[0], ciphertext[1])

# If there's 0 byte in plaintext differential, key on that byte will hard to be recovered (there will be 256 byte possibilities)
if 0 in ptx_diff:
    print("[-] There's \\x00 in plaintext difference. Key recovery will take much longer time")
    exit()

# Apply InvShiftRows on ciphertext differential
# If FULL ROUND is used (MixColumns used on last round), we can also apply InvMixColumns before InvShiftRows
ctx_diff = inv_last_round(ctx_diff)

possible_key = []

sbox_ddt = generate_sbox_ddt()

# Perform differential against sbox
print("[+] Lookup possible byte using SBOX DDT...")
for i in range(16):
    possible_key.append([])
    possible_xy = sbox_ddt[ptx_diff[i]][ctx_diff[i]]
    for x in possible_xy:
        possible_key[i].append(x ^ plaintext[0][i])


print("[+] Enumerate remaining possible key...")
all_possible_key = product(*possible_key)

# Enumerate all remaining possible key and check if decryption results to equal plaintext
recovered_key = b''
for possible_key in all_possible_key:
    check = decrypt(ciphertext[0], bytes(possible_key))
    if check == plaintext[0]:
        recovered_key = bytes(possible_key)
        break

# Output
print('[+] Recovered Key:', recovered_key)
print('[+] REAL KEY     :', KEY)