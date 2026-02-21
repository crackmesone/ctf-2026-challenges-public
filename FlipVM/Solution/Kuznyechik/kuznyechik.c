/*
 * Kuznyechik / GOST R 34.12-2015
 * National Standard of the Russian Federation
 *
 * Copyright © 2017, 2019, 2025, Vlasta Vesely <vlastavesely@proton.me>
 *
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * This code is endian-independent.
 */
#include <stdio.h>
#include <stdbool.h>
#include "kuznyechik.h"


/* ────────────────────────────────────────────────────────────────────────── */



static unsigned char gf256_mul_slow(unsigned char a, unsigned char b)
{
    unsigned char c = 0;

    while (b) {
        if (b & 1) {
            c ^= a;
        }
        a = (a << 1) ^ (a & 0x80 ? GF_MUL_POLYNOMIAL : 0x00);
        b >>= 1;
    }
    return c;
}

/* ────────────────────────────────────────────────────────────────────────── */

/*
 * Linear mapping as defined in section 4.2.
 */
static void kuznyechik_linear(unsigned char *a)
{
    unsigned char l;
    int i, j;

    for (i = 0; i < 16; i++) {
        l = a[15];
        for (j = 14; j >= 0; j--) {
            a[j + 1] = a[j];
            l ^= gf256_mul_slow(a[j], kuznyechik_linear_vector[j]);
        }
        a[0] = l;
    }
}

/*
 * Inverse function to L() as defined in section 4.2.
 */
static void kuznyechik_linear_inv(unsigned char *a)
{
    unsigned char c;
    int i, j;

    for (i = 16; i; i--) {
        c = a[0];
        for (j = 0; j < 15; j++) {
            a[j] = a[j + 1];
            c ^= gf256_mul_slow(a[j], kuznyechik_linear_vector[j]);
        }
        a[15] = c;
    }
}

/* ────────────────────────────────────────────────────────────────────────── */

/*
 * The transformations of Kuznyechik can be optimised with lookup tables
 * containing precomputed values of the linear transformation performed
 * on zero vectors with a single byte set to a value x, where ∀x ∈ {0,…,255},
 * and transformed by the π′ function. In this way, encryption becomes
 * exclusively a series of XORs of values from the kuz_pil table and the round
 * subkeys. Decryption requires some additional transformation before XORing
 * the last round key.
 *
 * Let π′: ℤ₂⁸ → ℤ₂⁸ be the substitution function.
 * Let L: ℤ₂¹²⁸ → ℤ₂¹²⁸ be the linear transformation function.
 * Let eᵢ be a ℤ₂¹²⁸ with a single nonzero byte at position i.
 * Let π′⁻¹ be the inverse of π′.
 *
 * kuz_pil:
 *   Tᵢ​[x] = L(π′(x)·eᵢ​), ∀x ∈ {0,…,255}
 *
 * kuz_pil_inv:
 *   Tᵢ​[x] = L⁻¹(π′⁻¹(x)·eᵢ​), ∀x ∈ {0,…,255}
 *
 * kuz_l_inv:
 *   Tᵢ​[x] = L⁻¹(x·eᵢ​), ∀x ∈ {0,…,255}
 *
 * kuz_c:
 *   Tᵢ​[x] = L((x+1)·e₁₅), ∀x ∈ {0,…,31}
 */
static uint64_t kuz_pil[16][256][2];
static uint64_t kuz_pil_inv[16][256][2];
static uint64_t kuz_l_inv[16][256][2];

static int kuznyechik_initialised = false;

static void kuznyechik_initialise_tables()
{
    unsigned int i, j;
    unsigned char *ptr;

    if (kuznyechik_initialised == true) {
        return;
    }

    // gf256_init_tables();

    for (i = 0; i < 16; i++) {
        for (j = 0; j < 256; j++) {
            /*
             * Example for i = 1, j = 11:
             *   π′(j) = 0xda
             *   Tᵢ​[j] = L(0x00da0000000000000000000000000000)
             *   Tᵢ​[j] = 0x127cd4effe23c12e3d1b513972c8577c
             */
            ptr = (unsigned char *) kuz_pil[i][j];
            kuz_pil[i][j][0] = 0;
            kuz_pil[i][j][1] = 0;
            ptr[i] = kuznyechik_pi[j];
            kuznyechik_linear(ptr);

            /*
             * Example for i = 7, j = 56:
             *   π′⁻¹(j) = 0xaa
             *   Tᵢ​[j] = L⁻¹(0x00000000000000aa0000000000000000)
             *   Tᵢ​[j] = 0xaa1756ba36be19b344ee0a0d4d9d318e
             */
            ptr = (unsigned char *) kuz_pil_inv[i][j];
            kuz_pil_inv[i][j][0] = 0;
            kuz_pil_inv[i][j][1] = 0;
            ptr[i] = kuznyechik_pi_inv[j];
            kuznyechik_linear_inv(ptr);

            /*
             * Example for i = 2, j = 167:
             *   j = 0xa7
             *   Tᵢ​[j] = L⁻¹(0x0000a700000000000000000000000000)
             *   Tᵢ​[j] = 0x074d7f867f7f6339fb898dff3be5d739
             */
            ptr = (unsigned char *) kuz_l_inv[i][j];
            kuz_l_inv[i][j][0] = 0;
            kuz_l_inv[i][j][1] = 0;
            ptr[i] = j;
            kuznyechik_linear_inv(ptr);
        }
    }

    /*
     * Generate constants for key schedule, section 4.3.
     *
     *   Cᵢ = L(Vec₁₂₈(i)), i = 1, 2, …, 32
     */
    for (i = 0; i < 32; i++) {
        ptr = (unsigned char *) kuz_c[i];
        kuz_c[i][0] = 0;
        kuz_c[i][1] = 0;
        ptr[15] = (i + 1);
        kuznyechik_linear(ptr);
    }

    kuznyechik_initialised = true;
}

/* ────────────────────────────────────────────────────────────────────────── */

#define XOR_TABLE(lktab, a, b, i) (				\
lktab[ 0][(((unsigned char *) &a)[0]) & 0xff][i] ^	\
lktab[ 1][(((unsigned char *) &a)[1]) & 0xff][i] ^	\
lktab[ 2][(((unsigned char *) &a)[2]) & 0xff][i] ^	\
lktab[ 3][(((unsigned char *) &a)[3]) & 0xff][i] ^	\
lktab[ 4][(((unsigned char *) &a)[4]) & 0xff][i] ^	\
lktab[ 5][(((unsigned char *) &a)[5]) & 0xff][i] ^	\
lktab[ 6][(((unsigned char *) &a)[6]) & 0xff][i] ^	\
lktab[ 7][(((unsigned char *) &a)[7]) & 0xff][i] ^	\
lktab[ 8][(((unsigned char *) &b)[0]) & 0xff][i] ^	\
lktab[ 9][(((unsigned char *) &b)[1]) & 0xff][i] ^	\
lktab[10][(((unsigned char *) &b)[2]) & 0xff][i] ^	\
lktab[11][(((unsigned char *) &b)[3]) & 0xff][i] ^	\
lktab[12][(((unsigned char *) &b)[4]) & 0xff][i] ^	\
lktab[13][(((unsigned char *) &b)[5]) & 0xff][i] ^	\
lktab[14][(((unsigned char *) &b)[6]) & 0xff][i] ^	\
lktab[15][(((unsigned char *) &b)[7]) & 0xff][i]	\
)

#define KUZ_PI_INV (uint64_t) kuznyechik_pi_inv

#define INV_PI(a) (							\
KUZ_PI_INV[(a >> (0 * 8)) & 0xff] << (0 * 8) |			\
KUZ_PI_INV[(a >> (1 * 8)) & 0xff] << (1 * 8) |			\
KUZ_PI_INV[(a >> (2 * 8)) & 0xff] << (2 * 8) |			\
KUZ_PI_INV[(a >> (3 * 8)) & 0xff] << (3 * 8) |			\
KUZ_PI_INV[(a >> (4 * 8)) & 0xff] << (4 * 8) |			\
KUZ_PI_INV[(a >> (5 * 8)) & 0xff] << (5 * 8) |			\
KUZ_PI_INV[(a >> (6 * 8)) & 0xff] << (6 * 8) |			\
KUZ_PI_INV[(a >> (7 * 8)) & 0xff] << (7 * 8)			\
)

#define X(a, b, k1, k2)							\
a ^= k1;							\
b ^= k2;

#define SL(a, b, c, d)							\
c = XOR_TABLE(kuz_pil, a, b, 0);				\
d = XOR_TABLE(kuz_pil, a, b, 1);				\

#define IL(a, b, c, d)							\
c = XOR_TABLE(kuz_l_inv, a, b, 0);				\
d = XOR_TABLE(kuz_l_inv, a, b, 1);				\

#define ISL(a, b, c, d)							\
c = XOR_TABLE(kuz_pil_inv, a, b, 0);				\
d = XOR_TABLE(kuz_pil_inv, a, b, 1);				\

#define IS(a, b) {							\
a = INV_PI(a);							\
b = INV_PI(b);							\
}

#define FK(start, end) {						\
for (i = start; i <= end; i++) {				\
    c[0] = a[0] ^ kuz_c[i - 1][0];				\
    c[1] = a[1] ^ kuz_c[i - 1][1];				\
    d[0] = XOR_TABLE(kuz_pil, c[0], c[1], 0);		\
    d[1] = XOR_TABLE(kuz_pil, c[0], c[1], 1);		\
    \
    d[0] ^= b[0];						\
    d[1] ^= b[1];						\
    b[0] = a[0];						\
    b[1] = a[1];						\
    a[0] = d[0];						\
    a[1] = d[1];						\
}								\
}

/* ────────────────────────────────────────────────────────────────────────── */

int kuznyechik_set_key(struct kuznyechik_subkeys *subkeys,
                       const unsigned char *key)
{
    uint64_t a[2], b[2], c[2], d[2];
    uint64_t *ek = subkeys->ek;
    unsigned int i;

    if (kuznyechik_initialised == false) {
        printf("Initalizing!\n");
        kuznyechik_initialise_tables();
    }

    a[0] = ((uint64_t *) key)[0];
    a[1] = ((uint64_t *) key)[1];
    b[0] = ((uint64_t *) key)[2];
    b[1] = ((uint64_t *) key)[3];

    ek[0] = a[0];
    ek[1] = a[1];
    ek[2] = b[0];
    ek[3] = b[1];

    FK(1, 8);

    ek[4] = a[0];
    ek[5] = a[1];
    ek[6] = b[0];
    ek[7] = b[1];

    FK(9, 16);

    ek[8]  = a[0];
    ek[9]  = a[1];
    ek[10] = b[0];
    ek[11] = b[1];

    FK(17, 24);

    ek[12] = a[0];
    ek[13] = a[1];
    ek[14] = b[0];
    ek[15] = b[1];

    FK(25, 32);

    ek[16] = a[0];
    ek[17] = a[1];
    ek[18] = b[0];
    ek[19] = b[1];

    /*
     * Keys for decryption - with applied L⁻¹().
     */
    for (i = 0; i < 20; i += 2) {
        if (i == 0) {
            subkeys->dk[i + 0] = ek[i + 0];
            subkeys->dk[i + 1] = ek[i + 1];
            continue;
        }

        a[0] = ek[i + 0];
        a[1] = ek[i + 1];
        subkeys->dk[i + 0] = XOR_TABLE(kuz_l_inv, a[0], a[1], 0);
        subkeys->dk[i + 1] = XOR_TABLE(kuz_l_inv, a[0], a[1], 1);
    }

    return 0;
}

void kuznyechik_encrypt(struct kuznyechik_subkeys *subkeys, unsigned char *out,
                        const unsigned char *in)
{
    uint64_t a, b, c, d, *k = subkeys->ek;

    a = ((uint64_t *) in)[0];
    b = ((uint64_t *) in)[1];

    /* round 1 */
    X(a, b, k[0], k[1]);
    SL(a, b, c, d);

    /* round 2 */
    X(c, d, k[2], k[3]);
    SL(c, d, a, b);

    /* round 3 */
    X(a, b, k[4], k[5]);
    SL(a, b, c, d);

    /* round 4 */
    X(c, d, k[6], k[7]);
    SL(c, d, a, b);

    /* round 5 */
    X(a, b, k[8], k[9]);
    SL(a, b, c, d);

    /* round 6 */
    X(c, d, k[10], k[11]);
    SL(c, d, a, b);

    /* round 7 */
    X(a, b, k[12], k[13]);
    SL(a, b, c, d);

    /* round 8 */
    X(c, d, k[14], k[15]);
    SL(c, d, a, b);

    /* round 9 */
    X(a, b, k[16], k[17]);
    SL(a, b, c, d);

    /* round 10 */
    X(c, d, k[18], k[19]);
    SL(c, d, a, b);

    ((uint64_t *) out)[0] = c;
    ((uint64_t *) out)[1] = d;
}

void kuznyechik_decrypt(struct kuznyechik_subkeys *subkeys, unsigned char *out,
                        const unsigned char *in)
{
    uint64_t a, b, c, d, *k = subkeys->dk;

    a = ((uint64_t *) in)[0];
    b = ((uint64_t *) in)[1];

    /* round 1 */
    IL(a, b, c, d);
    X(c, d, k[18], k[19]);

    /* round 2 */
    ISL(c, d, a, b);
    X(a, b, k[16], k[17]);

    /* round 3 */
    ISL(a, b, c, d);
    X(c, d, k[14], k[15]);

    /* round 4 */
    ISL(c, d, a, b);
    X(a, b, k[12], k[13]);

    /* round 5 */
    ISL(a, b, c, d);
    X(c, d, k[10], k[11]);

    /* round 6 */
    ISL(c, d, a, b);
    X(a, b, k[8], k[9]);

    /* round 7 */
    ISL(a, b, c, d);
    X(c, d, k[6], k[7]);

    /* round 8 */
    ISL(c, d, a, b);
    X(a, b, k[4], k[5]);

    /* round 9 */
    ISL(a, b, c, d);
    X(c, d, k[2], k[3]);

    /* round 10 */
    IS(c, d);
    X(c, d, k[0], k[1]);

    ((uint64_t *) out)[0] = c;
    ((uint64_t *) out)[1] = d;
}

void kuznyechik_wipe_key(struct kuznyechik_subkeys *subkeys)
{
    unsigned int i;

    for (i = 0; i < 20; i++) {
        subkeys->ek[i] = 0;
        subkeys->dk[i] = 0;
    }
}
