import os, random, time
from itertools import product
from aes import AES
from utils import *

#KEY = b"\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C"
KEY = os.urandom(16)

def encrypt(plaintext):
    aes = AES(KEY, 4)
    return aes.encrypt_block(plaintext)

def decrypt(ciphertext, key):
    aes = AES(key, 4)
    return aes.decrypt_block(ciphertext)

def get_key_expansion():
    aes = AES(KEY, 4)
    return aes._key_matrices

def generate_256_list():
    result = []
    for i in range(256):
        result.append(i)

    return result

def reverse_state(state, guess_key):
    state = bytes2matrix(state)
    round_key = bytes2matrix(guess_key)
    add_round_key(state, round_key)
    inv_shift_rows(state)
    inv_sub_bytes(state)

    return matrix2bytes(state)

true_key = get_key_expansion()[-1]
true_key = true_key[0]+true_key[1]+true_key[2]+true_key[3]

shifted = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
sample_len = 1

print('[+] Retrieve '+str(sample_len)+' delta-set from encryption oracle...')
delta_set = [None] * sample_len
for i in range(sample_len):
    delta_set[i] = []
    rand_chr = bytes([random.randint(0,255)]) * 15
    for j in range(256):
        ciphertext = encrypt(bytes([j]) + rand_chr)
        delta_set[i].append(ciphertext)



print('[+] Perform SQUARE Attack against delta-set...')
possible_key = [None] * 16
for i in range(16):
    possible_key[i] = []
    all_keys = generate_256_list()
    shifted_index = shifted[i]
    
    second = False
    for delta in delta_set:
        for j in all_keys:
            if second and j not in possible_key[i]:
                continue

            reversed_delta_set = []
            for k in delta:
                check = reverse_state(k, b"\x00"*(i) + bytes([j]) + b"\x00"*(15-i))
                reversed_delta_set.append(check)

            xor_sum = 0
            for b in reversed_delta_set:
                xor_sum ^= b[shifted_index]

            if second:
                if xor_sum != 0:
                    possible_key[i].remove(j)
            else:
                if xor_sum == 0:
                    print(f"[+] Found new possible key[{i}]: ", j)
                    possible_key[i].append(j)
                
        if len(possible_key[i]) == 1:
            break
        second = True

all_possible_key = product(*possible_key)

ciphertext_check = encrypt(b'\x00'*16) # can be replaced with one of delta-set

print("[+] Enumerate all remaining possible keys...")
for possible_round_key in all_possible_key:
    
    master_key = inv_key_expansion(list(possible_round_key), 4)
    
    decrypt_check = decrypt(ciphertext_check, master_key)
    if decrypt_check == b'\x00'*16:
        print('[+] Actual Master Key  :', KEY)
        print('[+] Possible Master Key:', master_key)
        break