#include "api.h"
#include "randombytes.h"
#include <stdio.h>
#include <string.h>

#define MLEN 32
#define MAX_SIZE 0x16000

static void send_stack_usage(const char *s, unsigned int c) {
  printf(s);
  printf("%u\n", c);
}

unsigned int canary_size = MAX_SIZE;
volatile unsigned char *p;
unsigned int c;
uint8_t canary = 0x42;

unsigned char pk[CRYPTO_PUBLICKEYBYTES];
unsigned char sk[CRYPTO_SECRETKEYBYTES];
unsigned char sm[MLEN + CRYPTO_BYTES];
unsigned char m[MLEN];
unsigned char m_out[MLEN + CRYPTO_BYTES];

unsigned long long mlen;
unsigned long long smlen;
unsigned int rc;
unsigned int stack_key_gen, stack_sign, stack_verify;

#define FILL_STACK()                                                           \
  p = &a;                                                                      \
  while (p > &a - canary_size)                                                    \
    *(p--) = canary;
#define CHECK_STACK()                                                         \
  c = canary_size;                                                                \
  p = &a - canary_size + 1;                                                       \
  while (*p == canary && p < &a) {                                             \
    p++;                                                                       \
    c--;                                                                       \
  }                                                                            \

static int test_sign(void) {
  volatile unsigned char a;
  // Alice generates a public key
  FILL_STACK()
  crypto_sign_keypair(pk, sk);
  CHECK_STACK()
  if(c >= canary_size) return -1; 
  stack_key_gen = c;
  
  // Bob derives a secret key and creates a response
  randombytes(m, MLEN);
  FILL_STACK()
  crypto_sign(sm, &smlen, m, MLEN, sk);
  CHECK_STACK()
  if(c >= canary_size) return -1; 
  stack_sign = c;
    
  // Alice uses Bobs response to get her secret key
  FILL_STACK()
  rc = crypto_sign_open(m_out, &mlen, sm, smlen, pk);
  CHECK_STACK()
  if(c >= canary_size) return -1; 
  stack_verify = c;

  if (rc) {
    return -1;
  } else {
    send_stack_usage("crypto_sign_keypair stack usage", stack_key_gen);
    send_stack_usage("crypto_sign stack usage", stack_sign);
    send_stack_usage("crypto_sign_open stack usage", stack_verify);
    printf("Signature valid!\n");
    return 0;
  }
}

int main(void) {
 // marker for automated benchmarks
  printf("==========================");
  canary_size = MAX_SIZE;
  while(test_sign()){
    canary_size -= 0x1000;
    if(canary_size == 0) {
      printf("failed to measure stack usage.\n");
      break;
    } 
  }

  // marker for automated benchmarks
  printf("#");

  while(1);
  return 0;
}
