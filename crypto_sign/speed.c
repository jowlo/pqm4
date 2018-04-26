#include "api.h"
#include "xtimer"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define MLEN 59

static void printcycles(const char *s, xtimer_ticks32_t ticks)
{
  printf(s);
  printf("%d\n", ticks.ticks32);
}


int main(void)
{
  unsigned char sk[CRYPTO_SECRETKEYBYTES];
  unsigned char pk[CRYPTO_PUBLICKEYBYTES];
  unsigned char sm[MLEN+CRYPTO_BYTES];
  unsigned long long smlen;
  xtimer_ticks32_t t0, t1;

  printf("==========================");

  // Key-pair generation
  t0 = xtimer_now32();
  crypto_sign_keypair(pk, sk);
  t1 = xtimer_now32();
  printcycles("keypair cycles:", xtimer_diff(t0, t1));

  // Signing
  t0 = xtimer_now32();
  crypto_sign(sm, &smlen, sm, MLEN, sk);
  t1 = xtimer_now32();
  printcycles("sign cycles:", xtimer_diff(t0, t1));

  // Verification
  t0 = xtimer_now32();
  crypto_sign_open(sm, &smlen, sm, smlen, pk);
  t1 = xtimer_now32();
  printcycles("verify cycles:", xtimer_diff(t0, t1));

  printf("#");
  return 0;
}
