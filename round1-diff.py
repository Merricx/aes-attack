import os, random
from itertools import product
from aes import AES
from utils import *

KEY = os.urandom(16)

# 1-round AES Encryption 
def encrypt(plaintext):
    aes = AES(KEY, 1)
    
    return aes.encrypt_block(plaintext)

# Decryption check
def decrypt(ciphertext, key):
    aes = AES(key, 1)
    
    return aes.decrypt_block(ciphertext)

# InvShiftRows of ciphertext differential
def remove_shift_rows(s):
    state = bytes2matrix(s)
    inv_shift_rows(state)

    return matrix2bytes(state)

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
ctx_diff = remove_shift_rows(ctx_diff)

possible_key = []

# Perform differential against sbox
# this is can be improved
print("[+] Brute all possible byte using SBOX differential...")
for i in range(16):
    possible_key.append([])
    for j in range(256):
        for k in range(256):
            if j == k:
                continue

            input_diff = j ^ k

            # Only take input differential that equal to plaintext differential
            if input_diff == ptx_diff[i]:

                # Testing each of the input into SBOX and get the output differential
                sbox_output1 = sbox[j]
                sbox_output2 = sbox[k]
                sbox_output_diff = sbox_output1 ^ sbox_output2
                
                # If SBOX output differential equal to ciphertext differential, we get the correct possible key
                # Possible key for each key index will always be 2 possible byte (except for 0 differential)
                if sbox_output_diff == ctx_diff[i]:
                    possible_key[i].append(j ^ plaintext[0][i])


print("[+] Enumerate remaining possible key...")
all_possible_key = product(
    possible_key[0],
    possible_key[1],
    possible_key[2],
    possible_key[3],
    possible_key[4],
    possible_key[5],
    possible_key[6],
    possible_key[7],
    possible_key[8],
    possible_key[9],
    possible_key[10],
    possible_key[11],
    possible_key[12],
    possible_key[13],
    possible_key[14],
    possible_key[15]
)

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