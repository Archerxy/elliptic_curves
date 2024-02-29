#include "alg.h"
#include "cal.h"
#include <time.h>
#include <stdio.h>

void privPubTest() {
    printf("****begin priv pub test****\n");

    const char *priv_key_hex = "062ac77cfcfe801ca274701dd74d97b39a6210028fa3d7c884f7731e69f167c0";
    uint8_t priv_key[32];
    char pub_key_hex[129] = {'\0'};
    calHexToBytes(priv_key_hex, 64, priv_key);
    sm2PrivateKeyToPublicKey(priv_key_hex, pub_key_hex);
    printf("pubHex = %s\n", pub_key_hex);
}



void testHmacSha256() {
    const char *msg = "nihao,shijie";
    uint8_t ret[32]; 
    char hex[65] = {'\0'};
    sha256((uint8_t*)msg, 12, ret);
    calBytesToHex(ret, 32, hex);
    printf("hex = %s\n", hex);


    const char *key = "123456789012345678901234567890123456789012345678901234567890123";
    hmacSha256((uint8_t*)key, 63, (uint8_t*)msg, 12, ret);
    calBytesToHex(ret, 32, hex);
    printf("hex = %s\n", hex);
}

void sm3Test() {
    printf("****begin sm3 test****\n");

    const char *content_hex = "7b22636f6e74726163744e616d65223a226e657768656c6c6f79696e7975222c22636f6e747261637456657273696f6e223a22392e31222c22636f6e74726163744d6574686f64223a227570646174655369676e537461746528737472696e672c75696e7432353629222c226d6574686f64506172616d223a5b2237303535383539363038383535373737323830222c2231225d2c227472616e73616374696f6e54696d65223a22323032332d30352d31322031373a31353a3530227d";
    const int len = 394;
    // const char *content_hex = "4206bdc23e21d5ff483fa50e3307bbbe499746eabed5ac8efcd8b77f28249843d8b2a8873131b28e7bfd31d266c6cc21b3c165a2c4df9b898bbe250eff2b500a";
    // const int len = 128;
    // const char *content_hex = "";
    // const int len = 0;

    uint8_t content[len/2], hash[32];
    char hash_hex[65] = {'\0'};
    calHexToBytes(content_hex, len, content);
    sm3(content, len/2, hash);
    calBytesToHex(hash, 32, hash_hex);
    printf("hash = %s\n", hash_hex);
}

void signTest() {
    printf("****begin sign test****\n");

    const char *priv_key_hex = "799ddb697a9f30f4ed73e5129b1c514ca3345d0960ed7313462f440e6834e169";
    const char *hash_hex = "548adbc674e6e82fc6b46862feef5cc970ef3828662e9cfee66bf23c47f5f251";
    uint8_t priv_key[32], hash[32];
    char sig_hex[129] = {'\0'};
    calHexToBytes(priv_key_hex, 64, priv_key);
    calHexToBytes(hash_hex, 64, hash);
    sm2Sign(priv_key_hex, hash, 32, sig_hex);
    printf("sig = %s\n", sig_hex);
}

void verifyTest() {
    const char *sig_hex = "e618993a543cfa228f0c9b71159cb03a98a6b7f201b3bc776c65a82f88391d91aac52d14aef139958b4b1deb1c6989f04d5f619ccb9c2b1e1a66abb8c90d81a8";
    const char *pub_key_hex = "585979996184e9d652dfc7aa90c3cf94ff6df42dcecd478e9fc36f3d58aeb08e8f091044a62869b22cca6729fd3266b35301c947e63ebfaacd8728a92ff7627a";
    const char *content_hex = "31a7048b7240a0fa29148cef77b5cc023588997c1cc23fa4d798ecd84ec520ea";
    uint8_t content[32];
    calHexToBytes(content_hex, 64, content);
    int ret = sm2Verify(pub_key_hex, content, 32, sig_hex);
    printf("verify ret = %s\n", ret?"true":"false");
}

void ecPrivPubTest() {
    printf("****begin ec priv pub test****\n");

    const char *priv_key_hex = "7297d04a21342d8055111fe1c57e7626c8837e83f88301ad35e91b5f9f9d8197";
    uint8_t priv_key[32];
    char pub_key_hex[129] = {'\0'};
    calHexToBytes(priv_key_hex, 64, priv_key);
    ecPrivateKeyToPublicKey(priv_key_hex, pub_key_hex);
    printf("pubHex = %s\n", pub_key_hex);
}


void ecSignTest() {
    printf("****begin ec sign test****\n");

    const char *priv_key_hex = "7297d04a21342d8055111fe1c57e7626c8837e83f88301ad35e91b5f9f9d8197";
    const char *msg_hex = "ffffd04a21342d8055111fe1c57e7626c8837e83f88301ad35e91b5f9f9d8197";
    uint8_t msg[32];
    char sig_hex[131] = {'\0'};
    calHexToBytes(msg_hex, 64, msg);
    if(!ecSign(priv_key_hex, msg, 32, sig_hex)) {
        printf("sign failed.\n");
    } else {
        printf("sig = %s\n", sig_hex);
    }
}


void ecVerifyTest() {
    const char *sig_hex = "e82c473c924af6828c4ecbf2277373412544a344f57e0b3ac98a3083224cb498acc3a4bc54246bbcd6496b4eca0180a6c5c4d92bd8a5390d7144bf50cb1e992500";
    const char *pub_key_hex = "4ac1846cf62d3d1386ed7c26f0f251457adbd2f89466df9e37421c8d743e560665f027be426847215d34cbeac367031fc906a89daa81978d8d57ff3eb3a288bf";
    const char *content_hex = "7297d04a21342d8055111fe1c57e7626c8837e83f88301ad35e91b5f9f9d8197";
    uint8_t content[32];
    calHexToBytes(content_hex, 64, content);
    int ret = ecVerify(pub_key_hex, content, 32, sig_hex);
    printf("verify ret = %s\n", ret?"true":"false");
}

void ecRecoverTest() {
    // const char *sig_hex = "d2790f40e286419bf20b0083470d25e6206969472a1c00851d5efd81839c32db74884f8115c309921a4dbed388d3f65f55709044949512afb98e3b69b4d7749201";
    const char *sig_hex = "3fbd52b3cc4de31fa55424c4addb7e39037317db299b009db8c4b1a506c76ba75660cf33316c015a8d9442c42daa709cb07fd02626e9b27b16943d977b391c0a01";
    const char *pub_key_hex_ori = "4ac1846cf62d3d1386ed7c26f0f251457adbd2f89466df9e37421c8d743e560665f027be426847215d34cbeac367031fc906a89daa81978d8d57ff3eb3a288bf";
    const char *content_hex = "7297d04a21342d8055111fe1c57e7626c8837e83f88301ad35e91b5f9f9d8197";
    char pub_key_hex[129] = {0};
    pub_key_hex[128] = '\0';
    uint8_t content[32];
    calHexToBytes(content_hex, 64, content);
    if(ecRecoverToPublicKey(content, 32, sig_hex, pub_key_hex)) {
        printf("pub_key_hex = %s\n", pub_key_hex);
    } else {
        printf("recover failed.\n");
    }
}

void timeCostTest() {
    //445d2809fe27b641a221348246c073657fec80c4e062a5a14f6f8e5d49a5bd3e	eafa187eb8eeddf376d108c2adf8f39ea0e46a70c79d32b0e3f3044d71cab600
    const char *priv_key_hex = "8eafb6212ab392a6dd05047eda30f8fe2285b71740c7ff2176e512759ca319e4";
    const char *msg_hex = "a82257af0a8689aafd0e16e60be8cf24624e67662e641c040f255db39c73cef3";
    uint8_t msg[32];
    int fail_count = 0,count = 10;
    char sig_hex[131] = {0};
    sig_hex[130] = '\0';
    clock_t t0, t1;
    calHexToBytes(msg_hex, 64, msg);

    t0 = clock();
    for(int i = 0; i < count; i++) {
        if(!ecSign(priv_key_hex, msg, 32, sig_hex)) {
            fail_count++;
        }
        printf("sig = %s\n", sig_hex);
    }
    t1 = clock();
    printf("total cost: %ld ", t1-t0);
    printf("avg cost: %f ", ((float)(t1-t0)/(float)count));
    printf("fail count: %d\n", fail_count);
}


void testFastMul() {
    AlgCurve curve;
    mpz_init_set_str(curve.p,
        "115792089237316195423570985008687907853269984665640564039457584007908834671663", 10);
    mpz_init_set_str(curve.n,
        "115792089237316195423570985008687907852837564279074904382605163141518161494337", 10);
    mpz_init_set_str(curve.a, 
        "0", 10);
    mpz_init_set_str(curve.b, 
        "7", 10);
    mpz_init_set_str(curve.gx,
        "55066263022277343669578718895168534326250603453777594175500187360389116729240", 10);
    mpz_init_set_str(curve.gy,
        "32670510020758816978083085130507043184471273380659243275938904335757337482424", 10);


    mpz_t a0, a1, a2, b0, b1, b2, num, r0, r1, r2;

    mpz_init_set_ui(a0, 123456l);
    mpz_init_set_ui(a1, 234567l);
    mpz_init_set_ui(a2, 345678l);
    mpz_init_set_ui(b0, 456789l);
    mpz_init_set_ui(b1, 567890l);
    mpz_init_set_ui(b2, 678901l);
    mpz_init_set_ui(num, 12345678l);
    mpz_init(r0);
    mpz_init(r1);
    mpz_init(r2);
    // calFastDoubleOld(&curve, a0, a1, a2, &r0, &r1, &r2);
    // calFastAddOld(&curve, a0, a1, a2, b0, b1, b2, &r0, &r1, &r2);
    // calFastMulOld(&curve, a0, a1, a2, num, &r0, &r1, &r2);
    {
        printf("r0 = %s\n", mpz_get_str(NULL, 16, r0));
        printf("r1 = %s\n", mpz_get_str(NULL, 16, r1));
        printf("r2 = %s\n", mpz_get_str(NULL, 16, r2));
    }

    mpz_set_ui(a0, 123456l);
    mpz_set_ui(a1, 234567l);
    mpz_set_ui(a2, 345678l);
    mpz_set_ui(b0, 456789l);
    mpz_set_ui(b1, 567890l);
    mpz_set_ui(b2, 678901l);
    mpz_set_ui(num, 12345678l);
    mpz_set_ui(r0, 0l);
    mpz_set_ui(r1, 0l);
    mpz_set_ui(r2, 0l);
    // calFastDouble(&curve, a0, a1, a2, &r0, &r1, &r2);
    // calFastAdd(&curve, a0, a1, a2, b0, b1, b2, &r0, &r1, &r2);
    // calFastMul(&curve, a0, a1, a2, num, &r0, &r1, &r2);
    {
        printf("r0 = %s\n", mpz_get_str(NULL, 16, r0));
        printf("r1 = %s\n", mpz_get_str(NULL, 16, r1));
        printf("r2 = %s\n", mpz_get_str(NULL, 16, r2));
    }


    
    mpz_clear(curve.p);
    mpz_clear(curve.n);
    mpz_clear(curve.a);
    mpz_clear(curve.b);
    mpz_clear(curve.gx);
    mpz_clear(curve.gy);
    mpz_clear(a0);
    mpz_clear(a1);
    mpz_clear(a2);
    mpz_clear(num);
    mpz_clear(r0);
    mpz_clear(r1);
    mpz_clear(r2);
}

// ./configure --prefix=/usr/local --enable-cxx
// make CFLAGS="${CFLAGS -fPIC}"

// ./configure --prefix=/e/projects/cppProject/gmp/build --enable-cxx

// gcc -fPIC test.c sm2p256v1.c sm3.c cal.c keccak256.c secp256k1.c hmac_sha256.c -lgmp -o test.exe
// gcc -fPIC -shared sm2p256v1.c sm3.c cal.c keccak256.c secp256k1.c hmac_sha256.c -lgmp -o libxy_alg_linux.so
// gcc -fPIC -o test.exe test.c -L./ -lcrossxy


// ar -x libgmp.a
// gcc -fPIC -c ../sm2p256v1.c ../sm3.c ../cal.c ../keccak256.c ../secp256k1.c ../hmac_sha256.c -O3
// ar -cr libxy_alg_win32.lib  *.o
int main() {
    // testHmacSha256();
    // sm3Test();

    // privPubTest();
    // signTest();
    // verifyTest();

    // ecPrivPubTest();
    // ecSignTest();
    // ecVerifyTest();
    // ecRecoverTest();


    // timeCostTest();
    uint8_t a = 126;
    printf("size(uint8_t) = %d", sizeof(a));
    return 1;
}