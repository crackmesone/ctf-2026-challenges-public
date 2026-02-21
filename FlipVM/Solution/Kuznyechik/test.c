#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#define BENCH_BUFSIZE 1024 * 1024 * 5
#define BENCH_ITER 5

#include "kuznyechik.h"


static const unsigned char key[32] = {
    0xde,0xc1,0x7c,0xfe,0xc3,0x0f,0x1a,0xdd,
    0x77,0x76,0x30,0x7f,0x4e,0xb2,0x06,0xc7,
    0x07,0x8e,0xc6,0x20,0xc8,0x1f,0xaf,0xca,
    0x43,0x72,0xb0,0xa8,0x50,0xa3,0x79,0xeb
};


#define REVERSE_ENDIAN_INPLACE(ptr, n) do {         \
    uint8_t* p = (uint8_t*)(ptr);                   \
    for (int i = 0; i < (n) / 2; ++i) {             \
        uint8_t tmp = p[i];                         \
        p[i] = p[(n) - 1 - i];                      \
        p[(n) - 1 - i] = tmp;                       \
    }                                               \
} while (0)


static const unsigned char ciphertext[16] = {
    0x7f, 0x67, 0x9d, 0x90, 0xbe, 0xbc, 0x24, 0x30,
    0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xed, 0xcd
};


static void print_block(const unsigned char *blk, const char *prefix, size_t len)
{
    unsigned int i;

    printf("%s ", prefix);
    for (i = 0; i < len; i++) {
        if(i % 8 == 0)
            printf(" 0x");
        printf("%02x", blk[i]);
    }
    putchar('\n');
}


int main(int argc, const char **argv) {
    unsigned char buffer[16];
    struct kuznyechik_subkeys subkeys;

    unsigned char plaintext1[16] = {
        0x7e,0x2a,0x2d,0x3c,0x7b,0x4f,0x4d,0x43,
        0x27,0x31,0x2e,0x2d,0x7e,0x2a,0x7e,0x2d
    };
    unsigned char plaintext2[16] = {
        0x7e,0x2d,0x2e,0x6e,0x49,0x2b,0x2b,0x6d,
        0x7d,0x3e,0x2d,0x2a,0x7e,0x2d,0x7e,0x2a
    };

    // Print and set the key
    kuznyechik_set_key(&subkeys, key);
    print_block(key, "K:", 32);
    printf("\n");

    // Print plaintext
    print_block(plaintext1, "P1:", 16);

    // Encrypt and print ciphertext
    kuznyechik_encrypt(&subkeys, buffer, plaintext1);
    print_block(buffer, "C1:", 16);

    printf("\n");

    // Print plaintext
    print_block(plaintext2, "P2:", 16);

    // Encrypt and print ciphertext
    kuznyechik_encrypt(&subkeys, buffer, plaintext2);
    print_block(buffer, "C2:", 16);

    kuznyechik_decrypt(&subkeys, buffer, buffer);
    print_block(buffer, "P2:", 16);
    printf("\n");

    return 0;
}
