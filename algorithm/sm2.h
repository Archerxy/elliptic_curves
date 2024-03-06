#ifndef _SM2_P256_V1_H_
#define _SM2_P256_V1_H_

#include "ec_point.h"
#include "sm3.h"

// sm2 crypto
void sm2_key_gen(EcPrivateKey *sk, EcPublicKey *pk);
void sm2_encrypt(EcPublicKey *pk, const uint8_t *msg, size_t msg_len, int mode, uint8_t **out, size_t *out_len);
int sm2_decrypt(EcPrivateKey *sk, const uint8_t *cipher, size_t cipher_len, int mode, uint8_t **out, size_t *out_len);

// sm2 sign algorithm
// void sm2p256v1_init();
void sm2p256v1_privateKey_to_publicKey(EcPrivateKey *sk, EcPublicKey *pk);
void sm2p256v1_sign(EcPrivateKey *sk, const uint8_t *msg, size_t msg_len, EcSignature *sig);
int sm2p256v1_verify(EcPublicKey *pk, const uint8_t *msg, size_t msg_len, EcSignature *sig);

#endif