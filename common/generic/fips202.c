/* Based on the public domain implementation in
 * crypto_hash/keccakc512/simple/ from http://bench.cr.yp.to/supercop.html
 * by Ronny Van Keer
 * and the public domain "TweetFips202" implementation
 * from https://twitter.com/tweetfips202
 * by Gilles Van Assche, Daniel J. Bernstein, and Peter Schwabe */

#include <stdint.h>
#include "fips202.h"
#include "keccakf1600.h"
#include <string.h>


/*
================================================================
Technicalities
================================================================
*/

#define NROUNDS 24
#define ROL(a, offset) ((a << offset) ^ (a >> (64-offset)))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

typedef unsigned char UINT8;
typedef unsigned long long int UINT64;
typedef UINT64 tKeccakLane;

#ifndef LITTLE_ENDIAN
/** Function to load a 64-bit value using the little-endian (LE) convention.
  * On a LE platform, this could be greatly simplified using a cast.
  */
static UINT64 load64(const UINT8 *x)
{
  int i;
  UINT64 u=0;

  for(i=7; i>=0; --i) {
    u <<= 8;
    u |= x[i];
  }
  return u;
}

/** Function to store a 64-bit value using the little-endian (LE) convention.
  * On a LE platform, this could be greatly simplified using a cast.
  */
static void store64(UINT8 *x, UINT64 u)
{
  unsigned int i;

  for(i=0; i<8; ++i) {
    x[i] = u;
    u >>= 8;
  }
}

/** Function to XOR into a 64-bit value using the little-endian (LE) convention.
  * On a LE platform, this could be greatly simplified using a cast.
  */
//static void xor64(UINT8 *x, UINT64 u)
//{
//  unsigned int i;
//
//  for(i=0; i<8; ++i) {
//    x[i] ^= u;
//    u >>= 8;
//  }
//}
#endif

/*
================================================================
A readable and compact implementation of the Keccak-f[1600] permutation.
================================================================
*/

#define ROL64(a, offset) ((((UINT64)a) << offset) ^ (((UINT64)a) >> (64-offset)))
#define i(x, y) ((x)+5*(y))

#ifdef LITTLE_ENDIAN
    #define readLane(x, y)          (((tKeccakLane*)state)[i(x, y)])
    #define writeLane(x, y, lane)   (((tKeccakLane*)state)[i(x, y)]) = (lane)
    #define XORLane(x, y, lane)     (((tKeccakLane*)state)[i(x, y)]) ^= (lane)
#else
    #define readLane(x, y)          load64((UINT8*)state+sizeof(tKeccakLane)*i(x, y))
    #define writeLane(x, y, lane)   store64((UINT8*)state+sizeof(tKeccakLane)*i(x, y), lane)
    #define XORLane(x, y, lane)     xor64((UINT8*)state+sizeof(tKeccakLane)*i(x, y), lane)
#endif

/**
  * Function that computes the linear feedback shift register (LFSR) used to
  * define the round constants (see [Keccak Reference, Section 1.2]).
  */
int LFSR86540(UINT8 *LFSR)
{
  int result = ((*LFSR) & 0x01) != 0;
  if (((*LFSR) & 0x80) != 0)
    /* Primitive polynomial over GF(2): x^8+x^6+x^5+x^4+1 */
    (*LFSR) = ((*LFSR) << 1) ^ 0x71;
  else
    (*LFSR) <<= 1;
  return result;
}



/**
 * Function that computes the Keccak-f[1600] permutation on the given state.
 */
//void KeccakF1600_StatePermute(void *state)
//{
//  unsigned int round, x, y, j, t;
//  UINT8 LFSRstate = 0x01;
//
//  for(round=0; round<24; round++) {
//    {   /* === θ step (see [Keccak Reference, Section 2.3.2]) === */
//      tKeccakLane C[5], D;
//
//      /* Compute the parity of the columns */
//      for(x=0; x<5; x++)
//        C[x] = readLane(x, 0) ^ readLane(x, 1) ^ readLane(x, 2) ^ readLane(x, 3) ^ readLane(x, 4);
//      for(x=0; x<5; x++) {
//        /* Compute the θ effect for a given column */
//        D = C[(x+4)%5] ^ ROL64(C[(x+1)%5], 1);
//        /* Add the θ effect to the whole column */
//        for (y=0; y<5; y++)
//          XORLane(x, y, D);
//      }
//    }
//
//    {   /* === ρ and π steps (see [Keccak Reference, Sections 2.3.3 and 2.3.4]) === */
//      tKeccakLane current, temp;
//      /* Start at coordinates (1 0) */
//      x = 1; y = 0;
//      current = readLane(x, y);
//      /* Iterate over ((0 1)(2 3))^t * (1 0) for 0 ≤ t ≤ 23 */
//      for(t=0; t<24; t++) {
//        /* Compute the rotation constant r = (t+1)(t+2)/2 */
//        unsigned int r = ((t+1)*(t+2)/2)%64;
//        /* Compute ((0 1)(2 3)) * (x y) */
//        unsigned int Y = (2*x+3*y)%5; x = y; y = Y;
//        /* Swap current and state(x,y), and rotate */
//        temp = readLane(x, y);
//        writeLane(x, y, ROL64(current, r));
//        current = temp;
//      }
//    }
//
//    {   /* === χ step (see [Keccak Reference, Section 2.3.1]) === */
//      tKeccakLane temp[5];
//      for(y=0; y<5; y++) {
//        /* Take a copy of the plane */
//        for(x=0; x<5; x++)
//          temp[x] = readLane(x, y);
//        /* Compute χ on the plane */
//        for(x=0; x<5; x++)
//          writeLane(x, y, temp[x] ^((~temp[(x+1)%5]) & temp[(x+2)%5]));
//      }
//    }
//
//    {   /* === ι step (see [Keccak Reference, Section 2.3.5]) === */
//      for(j=0; j<7; j++) {
//        unsigned int bitPosition = (1<<j)-1; /* 2^j-1 */
//        if (LFSR86540(&LFSRstate))
//          XORLane(0, 0, (tKeccakLane)1<<bitPosition);
//      }
//    }
//  }
//}




/*************************************************
* Name:        keccak_absorb
*
* Description: Absorb step of Keccak;
*              non-incremental, starts by zeroeing the state.
*
* Arguments:   - uint64_t *s:             pointer to (uninitialized) output Keccak state
*              - unsigned int r:          rate in bytes (e.g., 168 for SHAKE128)
*              - const unsigned char *m:  pointer to input to be absorbed into s
*              - unsigned long long mlen: length of input in bytes
*              - unsigned char p:         domain-separation byte for different Keccak-derived functions
**************************************************/
static void keccak_absorb(uint64_t *s,
                          unsigned int r,
                          const unsigned char *m, unsigned long long int mlen,
                          unsigned char p)
{
  unsigned long long i;
  unsigned char t[200];

  // Zero state
  for (i = 0; i < 25; ++i)
    s[i] = 0;

  while (mlen >= r)
  {
    for (i = 0; i < r / 8; ++i)
      s[i] ^= load64(m + 8 * i);

    KeccakF1600_StatePermute(s);
    mlen -= r;
    m += r;
  }

  for (i = 0; i < r; ++i)
    t[i] = 0;
  for (i = 0; i < mlen; ++i)
    t[i] = m[i];
  t[i] = p;
  t[r - 1] |= 128;
  for (i = 0; i < r / 8; ++i)
    s[i] ^= load64(t + 8 * i);
}


/*************************************************
* Name:        keccak_squeezeblocks
*
* Description: Squeeze step of Keccak. Squeezes full blocks of r bytes each.
*              Modifies the state. Can be called multiple times to keep squeezing,
*              i.e., is incremental.
*
* Arguments:   - unsigned char *h:               pointer to output blocks
*              - unsigned long long int nblocks: number of blocks to be squeezed (written to h)
*              - uint64_t *s:                    pointer to in/output Keccak state
*              - unsigned int r:                 rate in bytes (e.g., 168 for SHAKE128)
**************************************************/
static void keccak_squeezeblocks(unsigned char *h, unsigned long long int nblocks,
                                 uint64_t *s,
                                 unsigned int r)
{
  unsigned int i;
  while(nblocks > 0)
  {
    KeccakF1600_StatePermute(s);
    for(i=0;i<(r>>3);i++)
    {
      store64(h+8*i, s[i]);
    }
    h += r;
    nblocks--;
  }
}

/********** cSHAKE128 ***********/

void cshake128_simple_absorb(uint64_t s[25], uint16_t cstm, const unsigned char *in, unsigned long long inlen)
{
  unsigned char *sep = (unsigned char*)s;
  unsigned int i;

  for (i = 0; i < 25; i++)
    s[i] = 0;

  /* Absorb customization (domain-separation) string */
  sep[0] = 0x01;
  sep[1] = 0xa8;
  sep[2] = 0x01;
  sep[3] = 0x00;
  sep[4] = 0x01;
  sep[5] = 16; // fixed bitlen of cstm
  sep[6] = cstm & 0xff;
  sep[7] = cstm >> 8;

  KeccakF1600_StatePermute(s);

  /* Absorb input */
  keccak_absorb(s, SHAKE128_RATE, in, inlen, 0x04);
}


void cshake128_simple_squeezeblocks(unsigned char *output, unsigned long long nblocks, uint64_t *s)
{
  keccak_squeezeblocks(output, nblocks, s, SHAKE128_RATE);
}


void cshake128_simple(unsigned char *output, unsigned long long outlen, uint16_t cstm, const unsigned char *in, unsigned long long inlen)
{
  uint64_t s[25];
  unsigned char t[SHAKE128_RATE];
  unsigned int i;

  cshake128_simple_absorb(s, cstm, in, inlen);

  /* Squeeze output */
  keccak_squeezeblocks(output, outlen/SHAKE128_RATE, s, SHAKE128_RATE);
  output += (outlen/SHAKE128_RATE)*SHAKE128_RATE;

  if (outlen%SHAKE128_RATE)
  {
    keccak_squeezeblocks(t, 1, s, SHAKE128_RATE);
    for (i = 0; i < outlen%SHAKE128_RATE; i++)
      output[i] = t[i];
  }
}



/*************************************************
* Name:        shake128_absorb
*
* Description: Absorb step of the SHAKE128 XOF.
*              non-incremental, starts by zeroeing the state.
*
* Arguments:   - uint64_t *s:                     pointer to (uninitialized) output Keccak state
*              - const unsigned char *input:      pointer to input to be absorbed into s
*              - unsigned long long inputByteLen: length of input in bytes
**************************************************/
void shake128_absorb(uint64_t *s, const unsigned char *input, unsigned int inputByteLen)
{
  keccak_absorb(s, SHAKE128_RATE, input, inputByteLen, 0x1F);
}

/*************************************************
* Name:        shake128_squeezeblocks
*
* Description: Squeeze step of SHAKE128 XOF. Squeezes full blocks of SHAKE128_RATE bytes each.
*              Modifies the state. Can be called multiple times to keep squeezing,
*              i.e., is incremental.
*
* Arguments:   - unsigned char *output:      pointer to output blocks
*              - unsigned long long nblocks: number of blocks to be squeezed (written to output)
*              - uint64_t *s:                pointer to in/output Keccak state
**************************************************/
void shake128_squeezeblocks(unsigned char *output, unsigned long long nblocks, uint64_t *s)
{
  keccak_squeezeblocks(output, nblocks, s, SHAKE128_RATE);
}

void shake128(unsigned char *output, unsigned long long outlen, const unsigned char *input,  unsigned long long inlen)
{
  uint64_t s[25] = {0};
  unsigned char t[SHAKE128_RATE];
  unsigned long long nblocks = outlen/SHAKE128_RATE;
  size_t i;

  /* Absorb input */
  keccak_absorb(s, SHAKE128_RATE, input, inlen, 0x1F);

  /* Squeeze output */
  keccak_squeezeblocks(output, nblocks, s, SHAKE128_RATE);

  output += nblocks*SHAKE128_RATE;
  outlen -= nblocks*SHAKE128_RATE;

  if (outlen)
  {
    keccak_squeezeblocks(t, 1, s, SHAKE128_RATE);
    for (i = 0; i < outlen; i++)
      output[i] = t[i];
  }
}


void shake256_absorb(uint64_t *s, const unsigned char *input, unsigned int inputByteLen)
{
	keccak_absorb(s, SHAKE256_RATE, input, inputByteLen, 0x1F);
}


void shake256_squeezeblocks(unsigned char *output, unsigned long long nblocks, uint64_t *s)
{
	keccak_squeezeblocks(output, nblocks, s, SHAKE256_RATE);
}

/*************************************************
* Name:        shake256
*
* Description: SHAKE256 XOF with non-incremental API
*
* Arguments:   - unsigned char *output:      pointer to output
*              - unsigned long long outlen:  requested output length in bytes
               - const unsigned char *input: pointer to input
               - unsigned long long inlen:   length of input in bytes
**************************************************/
void shake256(unsigned char *output, unsigned long long outlen,
              const unsigned char *input,  unsigned long long inlen)
{
  uint64_t s[25];
  unsigned char t[SHAKE256_RATE];
  unsigned long long nblocks = outlen/SHAKE256_RATE;
  size_t i;

  /* Absorb input */
  keccak_absorb(s, SHAKE256_RATE, input, inlen, 0x1F);

  /* Squeeze output */
  keccak_squeezeblocks(output, nblocks, s, SHAKE256_RATE);

  output+=nblocks*SHAKE256_RATE;
  outlen-=nblocks*SHAKE256_RATE;

  if(outlen)
  {
    keccak_squeezeblocks(t, 1, s, SHAKE256_RATE);
    for(i=0;i<outlen;i++)
      output[i] = t[i];
  }
}

/*************************************************
* Name:        sha3_256
*
* Description: SHA3-256 with non-incremental API
*
* Arguments:   - unsigned char *output:      pointer to output
*              - const unsigned char *input: pointer to input
*              - unsigned long long inlen:   length of input in bytes
**************************************************/
void sha3_256(unsigned char *output, const unsigned char *input,  unsigned long long inlen)
{
  uint64_t s[25];
  unsigned char t[SHA3_256_RATE];
  size_t i;

  /* Absorb input */
  keccak_absorb(s, SHA3_256_RATE, input, inlen, 0x06);

  /* Squeeze output */
  keccak_squeezeblocks(t, 1, s, SHA3_256_RATE);

  for(i=0;i<32;i++)
      output[i] = t[i];
}

/*************************************************
* Name:        sha3_512
*
* Description: SHA3-512 with non-incremental API
*
* Arguments:   - unsigned char *output:      pointer to output
*              - const unsigned char *input: pointer to input
*              - unsigned long long inlen:   length of input in bytes
**************************************************/
void sha3_512(unsigned char *output, const unsigned char *input,  unsigned long long inlen)
{
  uint64_t s[25];
  unsigned char t[SHA3_512_RATE];
  size_t i;

  /* Absorb input */
  keccak_absorb(s, SHA3_512_RATE, input, inlen, 0x06);

  /* Squeeze output */
  keccak_squeezeblocks(t, 1, s, SHA3_512_RATE);

  for(i=0;i<64;i++)
      output[i] = t[i];
}

/********** cSHAKE256 ***********/

void cshake256_simple_absorb(uint64_t s[25], uint16_t cstm, const unsigned char *in, unsigned long long inlen)
{
  unsigned char *sep = (unsigned char*)s;
  unsigned int i;

  for (i = 0; i < 25; i++)
    s[i] = 0;

  /* Absorb customization (domain-separation) string */
  sep[0] = 0x01;
  sep[1] = 0x88;
  sep[2] = 0x01;
  sep[3] = 0x00;
  sep[4] = 0x01;
  sep[5] = 16; // fixed bitlen of cstm
  sep[6] = cstm & 0xff;
  sep[7] = cstm >> 8;

  KeccakF1600_StatePermute(s);

  /* Absorb input */
  keccak_absorb(s, SHAKE256_RATE, in, inlen, 0x04);
}


void cshake256_simple_squeezeblocks(unsigned char *output, unsigned long long nblocks, uint64_t *s)
{
  keccak_squeezeblocks(output, nblocks, s, SHAKE256_RATE);
}


void cshake256_simple(unsigned char *output, unsigned long long outlen, uint16_t cstm, const unsigned char *in, unsigned long long inlen)
{
  uint64_t s[25];
  unsigned char t[SHAKE256_RATE];
  unsigned int i;

  cshake256_simple_absorb(s, cstm, in, inlen);

  /* Squeeze output */
  keccak_squeezeblocks(output, outlen/SHAKE256_RATE, s, SHAKE256_RATE);
  output += (outlen/SHAKE256_RATE)*SHAKE256_RATE;

  if(outlen%SHAKE256_RATE)
  {
    keccak_squeezeblocks(t, 1, s, SHAKE256_RATE);
    for (i = 0; i < outlen%SHAKE256_RATE; i++)
      output[i] = t[i];
  }
}


