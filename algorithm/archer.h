#ifndef _ARCHER_H_
#define _ARCHER_H_

#include <stdlib.h>
#include <gmp.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>

#define SM2_C1C2C3 16
#define SM2_C1C3C2 64


typedef struct EcPrivateKey {
    uint8_t d[32];
} EcPrivateKey;

typedef struct EcPublicKey {
    uint8_t x[32];
    uint8_t y[32];
} EcPublicKey;

typedef struct EcSignature {
    uint8_t r[32];
    uint8_t s[32];
} EcSignature;

typedef struct Hash32 {
    uint8_t h[32];
} Hash32;


// secp256k1 sign algorithm
void secp256k1_privateKey_to_publicKey(EcPrivateKey *sk, EcPublicKey *pk);
void secp256k1_sign(EcPrivateKey *sk, const uint8_t *msg, size_t msg_len, EcSignature *sig);
int secp256k1_verify(EcPublicKey *pk, const uint8_t *msg, size_t msg_len, EcSignature *sig);
int secp256k1_get_v(EcSignature *sig);
void secp256k1_recover_public_key(EcSignature *sig, const uint8_t *msg, size_t msg_len, EcPublicKey *pk);


// sm2 crypto
void sm2_key_gen(EcPrivateKey *sk, EcPublicKey *pk);
void sm2_encrypt(EcPublicKey *pk, const uint8_t *msg, size_t msg_len, int mode, uint8_t **out, size_t *out_len);
int sm2_decrypt(EcPrivateKey *sk, const uint8_t *cipher, size_t cipher_len, int mode, uint8_t **out, size_t *out_len);

// sm2 sign algorithm
void sm2p256v1_privateKey_to_publicKey(EcPrivateKey *sk, EcPublicKey *pk);
void sm2p256v1_sign(EcPrivateKey *sk, const uint8_t *msg, size_t msg_len, EcSignature *sig);
int sm2p256v1_verify(EcPublicKey *pk, const uint8_t *msg, size_t msg_len, EcSignature *sig);

// hash
void keccak256(const uint8_t *content, uint32_t content_len, Hash32 *hash);
void sha256(const uint8_t *content, uint32_t content_len, Hash32 *hash);
void sm3(const uint8_t *content, uint32_t content_len, Hash32 *hash);

// sm4
void sm4_encrypt(const uint8_t user_key[16], const uint8_t *in, const size_t in_size, uint8_t **out, size_t *out_size);
int sm4_decrypt(const uint8_t user_key[16], const uint8_t *in, const size_t in_size, uint8_t **out, size_t *out_size);


#endif