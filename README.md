# AES Attack

My playground and implementation of known practical Attack on some AES variant.

# Notes

These implementation are somewhat dirty and obviously can be improved further.
All attacks are implemented in Python, but some attack with high time complexity are wrapped with C.

All implementation are full-key recovery of AES key.


# Reduced-Round AES

Reduced round variant of AES.

List of attack ordered from 1-round to 5-round. Each round divided into **No MixCols** and **Full Round**.
**No MixCols** is when last round does not make use of `MixColumns` while **Full Round** is when last round does make use of `MixColumns` before last `AddRoundKey`.


## 1 Round

#### `round1-diff.py`

Attack: Differential  
Model: Known-Plaintext Attack  
Data: 2 plaintext-ciphertext pairs  
Time: `2**8`  

With at least 2 plaintext-ciphertext pairs, this is just `plaintext -> SBOX -> ciphertext` that can be solved easily using differential cryptanalysis. This attack can be applied to both full 1-round and omitted last `MixColumns`

## 2 Rounds

### No MixCols

#### `round2-impossible-diff.py`

Attack: Impossible Differential  
Model: Chosen-Plaintext Attack  
Data: 5 plaintext-ciphertext pairs  
Time: `2**8`  

Impossible differential attack based on SBOX Differential Distribution Table  

### Full Round

#### `round2-full-known-plaintext.py`

Attack: Differential  
Model: Known-Plaintext Attack  
Data: 3 plaintext-ciphertext pairs  
Time: `2**32`  

Implementation of Low Data Complexity attack by [Bouillaguet et al.](https://eprint.iacr.org/2010/633.pdf). This attack use `round2-full-3-known-plaintext.c` that wrapped in python script. 

## 3 Rounds

### No MixCols

#### `round3-impossible-diff.py`
  
Attack: Impossible Differential  
Model: Chosen-Plaintext Attack  
Data: 5 plaintext-ciphertext pairs  
Time: `2**16`  

This is the extension of `round2-impossible-diff.py` attack by adding 1 round at the beginning  

### Full Round

*TODO*

## 4 Rounds

### No MixCols

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

## 5 Rounds

### No MixCols

#### `round5-mixture.py`
  
Attack: Mixture Differential  
Model: Chosen-Plaintext Attack  
Data: `2**21.5` chosen-plaintext  
Time: `2**21.5`  

This is the current best known chosen-plaintext attack on 5-round AES by [Bar-On et al.](https://eprint.iacr.org/2018/527.pdf) (2018)

# References

- Bar-On, A., Dunkelman, O., Keller, N. et al. Improved Key Recovery Attacks on Reduced-Round AES with Practical Data and Memory Complexities. J Cryptol 33, 1003–1043 (2020). [PDF](https://eprint.iacr.org/2018/527.pdf)
- Bouillaguet, Charles & Derbez, Patrick & Dunkelman, Orr & Keller, Nathan & Rijmen, Vincent & Fouque, Pierre-Alain. Low-data complexity attacks on AES. IACR Cryptology ePrint Archive (2010). [PDF](https://eprint.iacr.org/2010/633.pdf)
