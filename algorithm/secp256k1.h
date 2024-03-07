#ifndef _SEC_P256_K1_H_
#define _SEC_P256_K1_H_

#include "ec_point.h"
#include "keccak256.h"

// secp256k1 algorithm
// void secp256k1_init();
void secp256k1_privateKey_to_publicKey(EcPrivateKey *sk, EcPublicKey *pk);
void secp256k1_sign(EcPrivateKey *sk, const uint8_t *msg, size_t msg_len, EcSignature *sig);
int secp256k1_verify(EcPublicKey *pk, const uint8_t *msg, size_t msg_len, EcSignature *sig);
int secp256k1_get_v(EcSignature *sig);
void secp256k1_recover_publicKey(EcSignature *sig, const uint8_t *msg, size_t msg_len, EcPublicKey *pk);

#endif