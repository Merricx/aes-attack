# AES Attack

My playground and implementation of known practical Attack on some AES variant.

# Notes

These implementation are somewhat dirty and obviously can be improved further.
All attacks are implemented in Python, but some attack with high time complexity are wrapped with C.

All implementation are full-key recovery of AES key.

Time complexity is the maximum trials needed to guess one byte of key. It is not exact and just rough estimation.

# Reduced-Round AES

Reduced round variant of AES.

List of attack ordered from 1-round to 5-round. Each round divided into **Half Round** and **Full Round**.
**Half Round** is when last round does not make use of `MixColumns` while **Full Round** is when last round does make use of `MixColumns` before last `AddRoundKey`.


## 1 Round

#### `round1-full-diff-brute-force.py`

Attack: Differential  
Model: Known-Plaintext Attack  
Data: 2 plaintext-ciphertext pairs  
Time: `2**16`  

With at least 2 plaintext-ciphertext pairs, this is just `plaintext -> SBOX -> ciphertext` that can be solved easily using differential cryptanalysis. This attack can be applied to both full 1-round and omitted last `MixColumns`

#### `round1-full-diff-table-lookup.py`

Attack: Differential  
Model: Known-Plaintext Attack  
Data: 2 plaintext-ciphertext pairs  
Time: `2**16`  

Similar with previous attack, but slightly optimized to use S-Box DDT lookup instead of brute-force.

####

## 2 Rounds

### Half Round

#### `round2-half-impossible-diff.py`

Attack: Impossible Differential  
Model: Chosen-Plaintext Attack  
Data: 5 plaintext-ciphertext pairs  
Time: `2**8`  

Impossible differential attack based on SBOX Differential Distribution Table  

### Full Round

#### `round2-full-3-known-plaintext.py`

Attack: Differential  
Model: Known-Plaintext Attack  
Data: 3 plaintext-ciphertext pairs  
Time: `2**32`  

Implementation of Low Data Complexity attack by [Bouillaguet et al.](https://eprint.iacr.org/2010/633.pdf). This attack use `round2-full-3-known-plaintext.c` that wrapped in python script.

Compile the c code into binary first before running the python script

```
gcc aes.c round2-full-3-known-plaintext.c -o round2-full-3-known-plaintext -lpthread
```

#### `round2-full-impossible-diff.py`

Attack: Impossible Differential  
Model: Chosen-Plaintext Attack  
Data: 5 plaintext-ciphertext pairs  
Time: `2**8`  

This is just modified version of `round2-half-impossible-diff.py` in full 2-round AES with swapping of `AddRoundKey` and `MixColumns` operation.

## 3 Rounds

### Half Round

#### `round3-half-impossible-diff.py`
  
Attack: Impossible Differential  
Model: Chosen-Plaintext Attack  
Data: 5 plaintext-ciphertext pairs  
Time: `2**16`  

This is the extension of `round2-half-impossible-diff.py` attack by adding 1 round at the beginning  

### Full Round

#### `round3-full-impossible-diff.py`

Attack: Impossible Differential  
Model: Chosen-Plaintext Attack  
Data: 5 plaintext-ciphertext pairs  
Time: `2**16`  

This is just modified version of `round3-half-impossible-diff.py` in full 3-round AES with swapping of `AddRoundKey` and `MixColumns` operation.

## 4 Rounds

### Half Round

#### `round4-square.py`
  
Attack: Square  
Model: Chosen-Plaintext Attack  
Data: 1 delta-set (256 chosen-plaintext) (more delta-set will be better)  
Time: `2**8`  

See amazing tutorial of Square Attack by David Wong on https://www.davidwong.fr/blockbreakers/square.html  

### Full Round

#### `round4-full-square.py`

Attack: Square  
Model: Chosen-Plaintext Attack  
Data: 1 delta-set (256 chosen-plaintext) (more delta-set will be better)  
Time: `2**8`  

This is just modified version of `round4-square.py` in full 4-round AES with swapping of `AddRoundKey` and `MixColumns` operation.

