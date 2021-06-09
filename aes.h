#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>
#include <stddef.h>

// #define the macros below to 1/0 to enable/disable the mode of operation.
//
// CBC enables AES encryption in CBC-mode of operation.
// CTR enables encryption in counter-mode.
// ECB enables the basic ECB 16-byte block algorithm. All can be enabled simultaneously.

// The #ifndef-guard allows it to be configured before #include'ing or at compile time.
#ifndef CBC
  #define CBC 1
#endif

#ifndef ECB
  #define ECB 1
#endif

#ifndef CTR
  #define CTR 1
#endif


#define AES128 1
//#define AES192 1
//#define AES256 1

#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only

#if defined(AES256) && (AES256 == 1)
    #define AES_KEYLEN 32
    #define AES_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
    #define AES_KEYLEN 24
    #define AES_keyExpSize 208
#else
    #define AES_KEYLEN 16   // Key length in bytes
    #define AES_keyExpSize 176
#endif

typedef uint8_t state_t[4][4];

struct AES_ctx
{
  uint8_t RoundKey[AES_keyExpSize];
};

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key, uint8_t r);
void AES_encrypt(const struct AES_ctx* ctx, uint8_t* buf, uint8_t r);
void AES_decrypt(const struct AES_ctx* ctx, uint8_t* buf, uint8_t r);


void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key, uint8_t round);
void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey);
void SubBytes(state_t* state);
void InvSubBytes(state_t* state);
void ShiftRows(state_t* state);
void InvShiftRows(state_t* state);
void MixColumns(state_t* state);
void InvMixColumns(state_t* state);

void Cipher(state_t* state, const uint8_t* RoundKey, uint8_t nr);
void InvCipher(state_t* state, const uint8_t* RoundKey, uint8_t nr);

#endif // _AES_H_
