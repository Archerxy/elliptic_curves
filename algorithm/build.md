# build windows MinGW
gcc -fPIC -shared *.c -static-libgcc -static-libstdc++ -std=c99 -O3 -o libalg.dll -lgmp -lpthread

# build linux GCC
gcc -fPIC -shared *.c -static-libgcc -static-libstdc++ -std=c99 -O3 -o libalg.so -lgmp -lpthread

# build windows static lib
gcc -fPIC -c ec_point.c  keccak256.c secp256k1.c sha256.c sm2.c sm3.c sm4.c -static-libgcc -static-libstdc++ -L../lib/ -lgmp -lpthread  -std=c99 -O3 -funroll-loops -finline-functions
ar -x libgmp.a libpthread.a
ar -rcs libalg.a *.o

# build windows dynamic lib
gcc -fPIC -shared ec_point.c  keccak256.c secp256k1.c sha256.c sm2.c sm3.c sm4.c -static-libgcc -static-libstdc++ -L../lib/ -lgmp -lpthread  -std=c99 -O3 -funroll-loops -finline-functions -o libalg-win64.dll

# build linux static lib
gcc -c ec_point.c  keccak256.c secp256k1.c sha256.c sm.c sm3.c sm4.c -static-libgcc -static-libstdc++ -lgmp -lpthread  -std=c99 -O3 -funroll-loops -finline-functions
ar -rcs libalg.a *.o