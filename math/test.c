#include <stdint.h>
#include <stdio.h>
#include <gmp.h>
#include <string.h>


void math_point_mul(mpz_t x, mpz_t y, mpz_t d, mpz_t p, mpz_t a, mpz_t b, mpz_t gx, mpz_t gy) {
  char *bits = mpz_get_str(NULL, 2, d);
  uint32_t len = strlen(bits);
  mpz_t inv, k, tx, ty;
  mpz_init(inv);
  mpz_init(k);
  mpz_init_set(tx, gx);
  mpz_init_set(ty, gy);
  {
        printf("bits len = %d\n", len);
  }
  for(int i = 1; i < len; i++) {

    /**double**/ 
    mpz_mul_ui(inv, ty, 2);
    mpz_invert(inv, inv, p);
        // printf("double inv = %s\n", mpz_get_str(NULL, 16, inv));
    mpz_mul(k, tx, tx);
    mpz_mul_ui(k, k, 3);
    mpz_add(k, k, a);
    mpz_mul(k, k, inv);
    mpz_mod(k, k, p);
        // printf("double k = %s\n", mpz_get_str(NULL, 16, k));
    //x
    mpz_pow_ui(x, k, 2);
    mpz_sub(x, x, tx);
    mpz_sub(x, x, tx);
    mpz_mod(x, x, p);
    //y
    mpz_sub(y, tx, x);
    mpz_mul(y, y, k);
    mpz_sub(y, y, ty);
    mpz_mod(y, y, p);
    
    mpz_set(tx, x);
    mpz_set(ty, y);

    // {
    //     printf("double x = %s\n", mpz_get_str(NULL, 16, x));
    //     printf("double y = %s\n", mpz_get_str(NULL, 16, y));
    // }
    /**add**/
    if(bits[i] == '1') {

      mpz_sub(inv, tx, gx);
      mpz_invert(inv, inv, p);
      mpz_sub(k, ty, gy);
      mpz_mul(k, k, inv);
      mpz_mod(k, k, p);

      mpz_pow_ui(x, k, 2);
      mpz_sub(x, x, tx);
      mpz_sub(x, x, gx);
      mpz_mod(x, x, p);

      mpz_sub(y, tx, x);
      mpz_mul(y, y, k);
      mpz_sub(y, y, ty);
      mpz_mod(y, y, p);
      
      mpz_set(tx, x);
      mpz_set(ty, y);
      
        // {
        //     printf("add x = %s\n", mpz_get_str(NULL, 16, x));
        //     printf("add y = %s\n", mpz_get_str(NULL, 16, y));
        // }
    }
  }
  mpz_clear(inv);
  mpz_clear(k);
  mpz_clear(tx);
  mpz_clear(ty);
}


void math_point_add(mpz_t x, mpz_t y, mpz_t x1, mpz_t y1, mpz_t x2, mpz_t y2, mpz_t p) {
  mpz_t t, k;
  mpz_init(t);
  mpz_init(k);

  mpz_sub(t, x1, x2);
  mpz_invert(t, t, p);
  {
    printf("inv = %s\n", mpz_get_str(NULL, 16, t));
  }
  mpz_sub(k, y1, y2);
  mpz_mul(k, k, t);
  mpz_mod(k, k, p);

  {
    printf("k = %s\n", mpz_get_str(NULL, 16, k));
  }

  mpz_pow_ui(x, k, 2);
  mpz_sub(x, x, x1);
  mpz_sub(x, x, x2);
  mpz_mod(x, x, p);

  mpz_sub(y, x1, x);
  mpz_mul(y, y, k);
  mpz_sub(y, y, y1);
  mpz_mod(y, y, p);

  mpz_clear(k);
  mpz_clear(t);
}

void pointAddTest() {
    mpz_t x, y, p, x1, y1, x2, y2, x3, y3, _0;
    mpz_init(x);
    mpz_init(y);
    mpz_init(p);
    mpz_init(x1);
    mpz_init(y1);
    mpz_init(x2);
    mpz_init(y2);
    mpz_init(x3);
    mpz_init(y3);
    mpz_init_set_si(_0, 0);

    uint8_t X1[32] = {193, 86, 173, 31, 249, 127, 234, 100, 15, 178, 137, 177, 143, 110, 122, 108, 53, 224, 114, 161, 197, 196, 34, 44, 242, 145, 136, 10, 113, 188, 247, 120};
    uint8_t Y1[32] = {88, 100, 215, 195, 45, 187, 82, 220, 181, 30, 239, 180, 0, 9, 53, 99, 132, 13, 222, 97, 111, 41, 164, 147, 188, 66, 43, 205, 90, 59, 83, 138};
    
    uint8_t X3[32] = {193, 86, 173, 31, 249, 127, 234, 100, 15, 178, 137, 177, 143, 110, 122, 108, 53, 224, 114, 161, 197, 196, 34, 44, 242, 145, 136, 10, 113, 188, 247, 120};
    uint8_t Y3[32] = {88, 100, 215, 195, 45, 187, 82, 220, 181, 30, 239, 180, 0, 9, 53, 99, 132, 13, 222, 97, 111, 41, 164, 147, 188, 66, 43, 205, 90, 59, 83, 138};
    
    
    uint8_t X2[32] = {182, 29, 100, 135, 35, 208, 82, 249, 157, 230, 145, 249, 167, 246, 93, 25, 251, 53, 134, 224, 36, 198, 202, 116, 133, 104, 14, 45, 255, 122, 116, 116};
    uint8_t Y2[32] = {8, 224, 165, 79, 28, 196, 49, 170, 22, 22, 229, 65, 7, 97, 149, 243, 174, 127, 160, 25, 10, 235, 162, 123, 45, 101, 1, 96, 125, 50, 226, 243};

    uint8_t P[32] = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 252, 47};

    // uint8_t P[32] = {255, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255};

    mpz_import(p, 32, 1, 1, 0, 0, P);
    mpz_import(x1, 32, 1, 1, 0, 0, X1);
    mpz_import(y1, 32, 1, 1, 0, 0, Y1);
    mpz_import(x2, 32, 1, 1, 0, 0, X2);
    mpz_import(y2, 32, 1, 1, 0, 0, Y2);
    mpz_import(x3, 32, 1, 1, 0, 0, X3);
    mpz_import(y3, 32, 1, 1, 0, 0, Y3);
    mpz_sub(y3, _0, y3);

    mpz_t tx, ty;
    mpz_init(tx);
    mpz_init(ty);
    math_point_add(tx, ty, x1, y1, x2, y2, p);
    math_point_add(x, y, tx, ty, x3, y3, p);
    mpz_clear(tx);
    mpz_clear(ty);

    printf("x2 = %s\n", mpz_get_str(NULL, 16, x2));
    printf("y2 = %s\n", mpz_get_str(NULL, 16, y2));
    printf("x = %s\n", mpz_get_str(NULL, 16, x));
    printf("y = %s\n", mpz_get_str(NULL, 16, y));

    mpz_clear(x);
    mpz_clear(y);
    mpz_clear(p);
    mpz_clear(x1);
    mpz_clear(y1);
    mpz_clear(x2);
    mpz_clear(y2);
    mpz_clear(x3);
    mpz_clear(y3);
    mpz_clear(_0);
}

void pointMulTest() {
    mpz_t x, y, d, p, a, b, gx, gy, tx, ty;
    mpz_init(x);
    mpz_init(y);
    mpz_init(d);
    mpz_init(p);
    mpz_init(a);
    mpz_init(b);
    mpz_init(gx);
    mpz_init(gy);
    mpz_init(tx);
    mpz_init(ty);

    // uint8_t D[32] = {29, 253, 74, 47, 123, 64, 41, 123, 67, 247, 89, 16, 84, 115, 18, 248, 215, 159, 199, 36, 103, 60, 115, 133, 251, 218, 159, 127, 32, 235, 231, 2};
    
    uint8_t D[32] = {185, 236, 248, 61, 50, 94, 108, 146, 28, 45, 126, 24, 168, 89, 158, 54, 111, 81, 56, 157, 226, 38, 232, 15, 246, 8, 63, 221, 205, 171, 252, 126};

    uint8_t P[32] = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 252, 47};
    uint8_t N[32] = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 186, 174, 220, 230, 175, 72, 160, 59, 191, 210, 94, 140, 208, 54, 65, 65};
    uint8_t Gx[32] = {121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149, 206, 135, 11, 7, 2, 155, 252, 219, 45, 206, 40, 217, 89, 242, 129, 91, 22, 248, 23, 152};
    uint8_t Gy[32] = {72, 58, 218, 119, 38, 163, 196, 101, 93, 164, 251, 252, 14, 17, 8, 168, 253, 23, 180, 72, 166, 133, 84, 25, 156, 71, 208, 143, 251, 16, 212, 184};
    
    // uint8_t P[32] = {255, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255};
    // uint8_t A[32] = {255, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 252};
    // uint8_t B[32] = {40, 233, 250, 158, 157, 159, 94, 52, 77, 90, 158, 75, 207, 101, 9, 167, 243, 151, 137, 245, 21, 171, 143, 146, 221, 188, 189, 65, 77, 148, 14, 147};
    // uint8_t Gx[32] = {50, 196, 174, 44, 31, 25, 129, 25, 95, 153, 4, 70, 106, 57, 201, 148, 143, 227, 11, 191, 242, 102, 11, 225, 113, 90, 69, 137, 51, 76, 116, 199};
    // uint8_t Gy[32] = {188, 55, 54, 162, 244, 246, 119, 156, 89, 189, 206, 227, 107, 105, 33, 83, 208, 169, 135, 124, 198, 42, 71, 64, 2, 223, 50, 229, 33, 57, 240, 160};
      

    uint8_t Tx[32] = {36, 117, 169, 86, 235, 0, 78, 37, 128, 218, 255, 220, 182, 240, 60, 201, 210, 47, 227, 155, 95, 53, 113, 31, 0, 37, 210, 89, 186, 130, 10, 170};
    uint8_t Ty[32] = {44, 187, 129, 245, 237, 120, 173, 90, 46, 81, 15, 155, 240, 169, 150, 189, 223, 233, 18, 54, 189, 36, 99, 11, 59, 183, 160, 99, 158, 95, 141, 188};
    
    mpz_import(d, 32, 1, 1, 0, 0, D);
    mpz_import(p, 32, 1, 1, 0, 0, P);
    mpz_set_ui(a, 0);
    mpz_set_ui(b, 7);
    // mpz_import(a, 32, 1, 1, 0, 0, A);
    // mpz_import(b, 32, 1, 1, 0, 0, B);
    mpz_import(gx, 32, 1, 1, 0, 0, Gx);
    mpz_import(gy, 32, 1, 1, 0, 0, Gy);
    mpz_import(tx, 32, 1, 1, 0, 0, Tx);
    mpz_import(ty, 32, 1, 1, 0, 0, Ty);

    math_point_mul(x, y, d, p, a, b, gx, gy);

    printf("x = %s\n", mpz_get_str(NULL, 16, x));
    printf("y = %s\n", mpz_get_str(NULL, 16, y));

    mpz_clear(x);
    mpz_clear(y);
    mpz_clear(d);
    mpz_clear(p);
    mpz_clear(a);
    mpz_clear(b);
    mpz_clear(gx);
    mpz_clear(gy);
    mpz_clear(tx);
    mpz_clear(ty);

}

int main() {
  pointAddTest();

  return 1;
}

