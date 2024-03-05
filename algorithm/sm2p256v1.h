#ifndef _SM2_P256_V1_H_
#define _SM2_P256_V1_H_

#include "ec_point.h"
#include "sm3.h"

// sm2 algorithm
// void sm2p256v1_init();
void sm2p256v1_privateKey_to_publicKey(EcPrivateKey *sk, EcPublicKey *pk);
void sm2p256v1_sign(EcPrivateKey *sk, uint8_t *msg, size_t msg_len, EcSignature *sig);
int sm2p256v1_verify(EcPublicKey *pk, uint8_t *msg, size_t msg_len, EcSignature *sig);

#endif