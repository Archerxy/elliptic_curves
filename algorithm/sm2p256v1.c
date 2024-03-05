#include "sm2p256v1.h"

typedef struct sm2p256v1_curve {
    mpz_t p, a, b, gx, gy, n;
} sm2p256v1_curve;

static pthread_mutex_t _sm2p256v1_lock = PTHREAD_MUTEX_INITIALIZER;
static sm2p256v1_curve *_sm2p256v1 = NULL;

// userId = "1234567812345678"
static void sm2p256v1_get_za(uint8_t *x, uint8_t *y, uint8_t *msg, size_t msg_len, Hash32 *out) {
    uint8_t base[146] = {0,-128,49,50,51,52,53,54,55,56,49,50,51,52,53,54,55,
                56,-1,-1,-1,-2,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                -1,-1,-1,0,0,0,0,-1,-1,-1,-1,-1,-1,-1,-4,40,-23,-6,-98,
                -99,-97,94,52,77,90,-98,75,-49,101,9,-89,-13,-105,-119,
                -11,21,-85,-113,-110,-35,-68,-67,65,77,-108,14,-109,50,
                -60,-82,44,31,25,-127,25,95,-103,4,70,106,57,-55,-108,
                -113,-29,11,-65,-14,102,11,-31,113,90,69,-119,51,76,116,
                -57,-68,55,54,-94,-12,-10,119,-100,89,-67,-50,-29,107,
                105,33,83,-48,-87,-121,124,-58,42,71,64,2,-33,50,-27,33,
                57,-16,-96};
    uint8_t input[210];
    memcpy(input, base, 146);
    memcpy(&(input[146]), x, 32);
    memcpy(&(input[146 + 32]), y, 32);
    Hash32 z;
    sm3(input, 210, &z);
    uint8_t *e = malloc(32 + msg_len);
    memcpy(e, z.h, 32);
    memcpy(&(e[32]), msg, msg_len);
    sm3(e, 32 + msg_len, out);
    free(e);
}

static void sm2p256v1_cal_rs(mpz_t d, mpz_t e, mpz_t r, mpz_t s) {
    uint8_t raw_k[32];
    uint16_t seed = (uint16_t) ((int64_t) raw_k);
    ec_random_k(raw_k, seed++);
    mpz_t k, kx, ky;
    mpz_init(k);
    mpz_init(kx);
    mpz_init(ky);
    mpz_import(k, 32, 1, 1, 0, 0, raw_k);
    ec_point_mul(kx, ky, k, _sm2p256v1->p, _sm2p256v1->a, _sm2p256v1->b, _sm2p256v1->gx, _sm2p256v1->gy);
    mpz_add(kx, kx, e);
    mpz_mod(kx, kx, _sm2p256v1->n);
    mpz_add(ky, kx, e);
    while(!mpz_cmp(ky, _sm2p256v1->n)) {
        ec_random_k(raw_k, seed++);
        mpz_import(k, 32, 1, 1, 0, 0, raw_k);
        ec_point_mul(kx, ky, k, _sm2p256v1->p, _sm2p256v1->a, _sm2p256v1->b, _sm2p256v1->gx, _sm2p256v1->gy);
        mpz_add(kx, kx, e);
        mpz_mod(kx, kx, _sm2p256v1->n);
        mpz_add(ky, kx, e);
    }
    mpz_set(r, kx);
    mpz_mul(s, kx, d);
    mpz_sub(s, k, s);
    mpz_mod(s, s, _sm2p256v1->n);

    mpz_add_ui(kx, d, 1);
    mpz_invert(kx, kx, _sm2p256v1->n);
    mpz_mul(s, s, kx);
    mpz_mod(s, s, _sm2p256v1->n);

    mpz_clear(k);
    mpz_clear(kx);
    mpz_clear(ky);
}

static void sm2p256v1_init() {
    pthread_mutex_lock(&_sm2p256v1_lock);
    if(!_sm2p256v1) {
        _sm2p256v1 = (sm2p256v1_curve *)malloc(sizeof(sm2p256v1_curve));
        mpz_init_set_str(_sm2p256v1->p, "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff", 16);
        mpz_init_set_str(_sm2p256v1->a, "fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc", 16);
        mpz_init_set_str(_sm2p256v1->b, "28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93", 16);
        mpz_init_set_str(_sm2p256v1->gx, "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7", 16);
        mpz_init_set_str(_sm2p256v1->gy, "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0", 16);
        mpz_init_set_str(_sm2p256v1->n, "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123", 16);
    }
    pthread_mutex_unlock(&_sm2p256v1_lock);
}

void sm2p256v1_privateKey_to_publicKey(EcPrivateKey *sk, EcPublicKey *pk) {    
    if(!sk || !pk) {
        return ;
    }

    sm2p256v1_init();

    mpz_t x, y, d;
    mpz_init(x);
    mpz_init(y);
    mpz_init(d);
    mpz_import(d, 32, 1, 1, 0, 0, sk->d);
    ec_point_mul(x, y, d, _sm2p256v1->p, _sm2p256v1->a, _sm2p256v1->b, _sm2p256v1->gx, _sm2p256v1->gy);
    
    uint8_t xc[32], yc[32];
    size_t lx = 32, ly = 32;
    mpz_export(xc, &lx, 1, 1, 0, 0, x);
    mpz_export(yc, &ly, 1, 1, 0, 0, y);

    memcpy(pk->x, &(xc[32-lx]), lx);
    memcpy(pk->y, &(yc[32-ly]), ly);

    mpz_clear(x);
    mpz_clear(y);
    mpz_clear(d);
}

void sm2p256v1_sign(EcPrivateKey *sk, uint8_t *msg, size_t msg_len, EcSignature *sig) {
    if(!sk || !msg || !sig) {
        return ;
    }

    sm2p256v1_init();

    EcPublicKey pk;
    Hash32 za;
    sm2p256v1_privateKey_to_publicKey(sk, &pk);
    sm2p256v1_get_za(pk.x, pk.y, msg, msg_len, &za);

    mpz_t d, e, r, s;
    mpz_init(r);
    mpz_init(s);

    mpz_init(d);
    mpz_init(e);
    mpz_import(d, 32, 1, 1, 0, 0, sk->d);
    mpz_import(e, 32, 1, 1, 0, 0, za.h);

    sm2p256v1_cal_rs(d, e, r, s);

    size_t lr = 32, ls = 32;
    uint8_t rc[32], sc[32];
    mpz_export(rc, &lr, 1, 1, 0, 0, r);
    mpz_export(sc, &ls, 1, 1, 0, 0, s);
    
    memcpy(sig->r, &(rc[32-lr]), lr);
    memcpy(sig->s, &(sc[32-ls]), ls);

    mpz_clear(r);
    mpz_clear(s);
    mpz_clear(d);
    mpz_clear(e);
}


int sm2p256v1_verify(EcPublicKey *pk, uint8_t *msg, size_t msg_len, EcSignature *sig) {
    if(!pk || !msg || !sig) {
        return 0;
    }

    sm2p256v1_init();

    int ret = 0;
    Hash32 za;
    sm2p256v1_get_za(pk->x, pk->y, msg, msg_len, &za);

    mpz_t x, y, e, r, s, b0x, b0y, b1x, b1y;
    mpz_init(x);
    mpz_init(y);
    mpz_init(e);
    mpz_init(r);
    mpz_init(s);
    mpz_init(b0x);
    mpz_init(b0y);
    mpz_init(b1x);
    mpz_init(b1y);

    mpz_import(x, 32, 1, 1, 0, 0, pk->x);
    mpz_import(y, 32, 1, 1, 0, 0, pk->y);
    mpz_import(e, 32, 1, 1, 0, 0, za.h);
    mpz_import(r, 32, 1, 1, 0, 0, sig->r);
    mpz_import(s, 32, 1, 1, 0, 0, sig->s);

    ec_point_mul(b0x, b0y, s, _sm2p256v1->p, _sm2p256v1->a, _sm2p256v1->b, _sm2p256v1->gx, _sm2p256v1->gy);
    mpz_add(s, r, s);
    mpz_mod(s, s, _sm2p256v1->n);
    ec_point_mul(b1x, b1y, s, _sm2p256v1->p, _sm2p256v1->a, _sm2p256v1->b, x, y);
    ec_point_add(x, y, b0x, b0y, b1x, b1y, _sm2p256v1->p);
    mpz_add(x, x, e);
    mpz_mod(x, x, _sm2p256v1->n);
    ret = !(mpz_cmp(x, r));

    mpz_clear(x);
    mpz_clear(y);
    mpz_clear(e);
    mpz_clear(r);
    mpz_clear(s);
    mpz_clear(b0x);
    mpz_clear(b0y);
    mpz_clear(b1x);
    mpz_clear(b1y);

    return ret;
}