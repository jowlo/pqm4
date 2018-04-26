#include "api.h"
#include "randombytes.h"
#include <string.h>
#include <stdio.h>

#define NTESTS 15
#define MLEN 32

static int test_sign(void)
{
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char sm[MLEN + CRYPTO_BYTES];
    unsigned char m[MLEN];

    unsigned long long mlen;
    unsigned long long smlen;

    int i;

    for (i = 0; i < NTESTS; i++) {
        crypto_sign_keypair(pk, sk);
        printf("crypto_sign_keypair DONE.\n");

        randombytes(m, MLEN);
        crypto_sign(sm, &smlen, m, MLEN, sk);
        printf("crypto_sign DONE.\n");

        // By relying on m == sm we prevent having to allocate CRYPTO_BYTES twice
        if (crypto_sign_open(sm, &mlen, sm, smlen, pk)) {
            printf("ERROR Signature did not verify correctly!\n");
        } else {
            printf("OK Signature did verify correctly!\n");
        }
        printf("crypto_sign_open DONE.\n");
    }

    return 0;
}

static int test_wrong_pk(void)
{
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char pk2[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char sm[MLEN + CRYPTO_BYTES];
    unsigned char m[MLEN];

    unsigned long long mlen;
    unsigned long long smlen;

    int i;

    for (i = 0; i < NTESTS; i++) {
        crypto_sign_keypair(pk2, sk);
        printf("crypto_sign_keypair DONE.\n");

        crypto_sign_keypair(pk, sk);
        printf("crypto_sign_keypair DONE.\n");


        randombytes(m, MLEN);
        crypto_sign(sm, &smlen, m, MLEN, sk);
        printf("crypto_sign DONE.\n");

        // By relying on m == sm we prevent having to allocate CRYPTO_BYTES twice
        if (crypto_sign_open(sm, &mlen, sm, smlen, pk2))
        {
            printf("OK Signature did not verify correctly under wrong public key!\n");
        }
        else
        {
            printf("ERROR Signature did verify correctly under wrong public key!\n");
        }
        printf("crypto_sign_open DONE.\n");
    }

    return 0;
}

int main(void)
{
    // marker for automated testing
    printf("==========================");
    test_sign();
    test_wrong_pk();
    printf("#");

    return 0;
}
