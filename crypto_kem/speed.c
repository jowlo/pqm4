#include "api.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <xtimer.h>

static void printcycles(const char *s, xtimer_ticks32_t ticks)
{
  printf(s);
  printf("%d\n", ticks.ticks32);
}


int main(void)
{
  unsigned char ss[CRYPTO_BYTES];
  unsigned char sk[CRYPTO_SECRETKEYBYTES];
  unsigned char pk[CRYPTO_PUBLICKEYBYTES];
  unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
  xtimer_ticks32_t t0, t1;

  printf("==========================");

  // Key-pair generation
  t0 = xtimer_now32();
  crypto_kem_keypair(pk, sk);
  t1 = xtimer_now32();
  printcycles("keypair cycles:", xtimer_diff32(t0, t1));

  // Encapsulation
  t0 = xtimer_now32();
  crypto_kem_enc(ct, ss, pk);
  t1 = xtimer_now32();
  printcycles("encaps cycles:", xtimer_diff32(t0, t1));

  // Decapsulation
  t0 = xtimer_now32();
  crypto_kem_dec(ss, ct, sk);
  t1 = xtimer_now32();
  printcycles("decaps cycles:", xtimer_diff32(t0, t1));

  printf("#");
  return 0;
}
