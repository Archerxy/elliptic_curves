#include "archer.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define HEX_CHECK(h) ((48<=h)&&(h<=57)||(65<=h&&h<=57)||(97<=h&&h<=102))

static void print_uints(const char *name, uint8_t *bs, size_t len) {
    char m[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    int b0, b1;
    printf(name);
    for(int i = 0; i < len; i++) {
        b0 = (bs[i] >> 4) & 0xf;
        b1 = bs[i] & 0xf;
        printf("%c%c",m[b0], m[b1]);
    }
    printf("\n");
    fflush(stdout);
}


static void print_mpz(const char *name, mpz_t n) {
    char *hex = mpz_get_str(NULL, 16, n);
    printf("%s%s\n", name, hex);
    fflush(stdout);
}

void sm2CostTest() {
    printf("****begin sm2 sign cost test****\n");
    uint8_t d[32] = {29, -3, 74, 47, 123, 64, 41, 123, 67, -9, 89, 16, 84, 115, 18, -8, -41, -97, -57, 36, 103, 60, 115, -123, -5, -38, -97, 127, 32, -21, -25, 2};
    uint8_t p[64] = {124, -111, 78, 61, -127, 10, -126, -115, 18, -118, 16, 64, 63, -12, 77, 32, 8, 95, -32, 73, 36, 98, 63, -81, -1, -112, -45, -87, -119, -31, -91, -5, -76, 120, -20, -101, -57, 45, -115, -110, -52, -50, 83, -74, -117, -113, -38, -51, -125, 18, -42, -84, 59, -33, -105, -3, 23, -8, 83, 51, 45, 74, -31, -105};
	

    int count = 10000;
    EcPrivateKey sk;
    EcPublicKey pk;
    // EcSignature *sig = calloc(count, sizeof(EcSignature));
    EcSignature sig;

    memcpy(sk.d, d, 32);
    memcpy(pk.x, p, 32);
    memcpy(pk.y, &(p[32]), 32);
    printf("****start sm2 sign cost test****\n");
    clock_t t1, t2, t3, t4;
    t1 = clock();
    for(int i = 0; i < count; i++) {
        sm2p256v1_sign(&sk, d, 32, &sig);
    }
    t2 = clock();
    printf("sm2 sign result:\n round: %d\n cost: %llums\n", count, t2 - t1);
    printf("****start sm2 verify cost test****\n");
    t3 = clock();
    for(int i = 0; i < count; i++) {
        int ret = sm2p256v1_verify(&pk, d, 32, &sig);
        if(!ret) {
            printf("round[%d] verify failed\n", i);
        }
    }
    t4 = clock();
    printf("sm2 verify result:\n round: %d\n cost: %llums\n", count, t4 - t3);
}

void secTest() {
    printf("****begin secp256k1 sign test****\n");
    uint8_t d[32] = {29, -3, 74, 47, 123, 64, 41, 123, 67, -9, 89, 16, 84, 115, 18, -8, -41, -97, -57, 36, 103, 60, 115, -123, -5, -38, -97, 127, 32, -21, -25, 2};
    uint8_t p[64] = {36, 117, -87, 86, -21, 0, 78, 37, -128, -38, -1, -36, -74, -16, 60, -55, -46, 47, -29, -101, 95, 53, 113, 31, 0, 37, -46, 89, -70, -126, 10, -86, 44, -69, -127, -11, -19, 120, -83, 90, 46, 81, 15, -101, -16, -87, -106, -67, -33, -23, 18, 54, -67, 36, 99, 11, 59, -73, -96, 99, -98, 95, -115, -68};
	
    EcPrivateKey sk;
    EcPublicKey pk;
    EcSignature sig;
    memcpy(sk.d, d, 32);
    memcpy(pk.x, p, 32);
    memcpy(pk.y, &(p[32]), 32);
    printf("****start secp256k1 sign****\n");
    secp256k1_sign(&sk, d, 32, &sig);
    printf("****after secp256k1 sign****\n");
    print_uints("sig = ", (uint8_t *)&sig, 64);
    int ret = secp256k1_verify(&pk, d, 32, &sig);
    printf("ret = %d\n", ret);

    print_uints("pk = ", p, 64);
    EcPublicKey pk_new;
    secp256k1_recover_publicKey(&sig, d, 32, &pk_new);
    print_uints("pk_new = ", (uint8_t *)&pk_new, 64);
}

void sm2Test() {
    printf("****begin sm2 sign test****\n");
    uint8_t d[32] = {29, -3, 74, 47, 123, 64, 41, 123, 67, -9, 89, 16, 84, 115, 18, -8, -41, -97, -57, 36, 103, 60, 115, -123, -5, -38, -97, 127, 32, -21, -25, 2};
    uint8_t p[64] = {124, -111, 78, 61, -127, 10, -126, -115, 18, -118, 16, 64, 63, -12, 77, 32, 8, 95, -32, 73, 36, 98, 63, -81, -1, -112, -45, -87, -119, -31, -91, -5, -76, 120, -20, -101, -57, 45, -115, -110, -52, -50, 83, -74, -117, -113, -38, -51, -125, 18, -42, -84, 59, -33, -105, -3, 23, -8, 83, 51, 45, 74, -31, -105};
	
    EcPrivateKey sk;
    EcPublicKey pk;
    EcSignature sig;
    memcpy(sk.d, d, 32);
    memcpy(pk.x, p, 32);
    memcpy(pk.y, &(p[32]), 32);
    printf("****start sm2 sign****\n");
    sm2p256v1_sign(&sk, d, 32, &sig);
    printf("****after sm2 sign****\n");
    print_uints("sig = ", (uint8_t *)&sig, 64);
    int ret = sm2p256v1_verify(&pk, d, 32, &sig);
    printf("ret = %d\n", ret);
}

void sm4Test() {
    uint8_t key[16] = "keys0123456789ab";
    const char *text = "nihao,shijie,.:.";
    uint8_t *cipher = NULL, *de_text = NULL;
    size_t cipher_len = 0, de_text_len = 0;
    sm4_encrypt(key, text, strlen(text), &cipher, &cipher_len);
    printf("text_len = %d, ciper_len = %d\n", strlen(text), cipher_len);
    print_uints("cipher = ", cipher, cipher_len);

    if(sm4_decrypt(key, cipher, cipher_len, &de_text, &de_text_len)) {
        printf("de_text_len = %d\n", de_text_len);
        char txt[de_text_len + 1];
        memcpy(txt, de_text, de_text_len);
        txt[de_text_len] = '\0';
        print_uints("de = ", de_text, de_text_len);
        printf("txt = %s", txt);
    } else {
        printf("decrypt failed\n");
    }

    free(cipher);
    free(de_text);
}

void sm2CryptoTest() {
    printf("****begin sm2 crypto test****\n");
    EcPrivateKey sk;
    EcPublicKey pk;
    const uint8_t *msg = "nihao,dashabi";
    uint8_t *cipher, *text;
    size_t cipher_l, text_l;

    sm2_key_gen(&sk, &pk);
    printf("****start sm2 crypto test****\n");
    sm2_encrypt(&pk, msg, strlen(msg), SM2_C1C3C2, &cipher, &cipher_l);
    print_uints("cipher = ", cipher, cipher_l);
    if(sm2_decrypt(&sk, cipher, cipher_l, SM2_C1C3C2, &text, &text_l)) {
        char txt[text_l + 1];
        memcpy(txt, text, text_l);
        txt[text_l] = '\0';
        printf("sm2 encrypt success. l = %d, txt = %s\n", text_l, txt);
    } else {
        printf("sm2 encrypt failed\n");
    }
}

// gcc test.c -L. -lalg -O3 -o test.exe
int main() {

    // sm2Test();
    // secTest();
    // sm4Test();

    sm2CostTest();

    sm2CryptoTest();

    return 0;
}