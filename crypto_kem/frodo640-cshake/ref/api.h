/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: parameters and API for FrodoKEM-640
*********************************************************************************************/

#ifndef _API_FRODO640_H_
#define _API_FRODO640_H_

#include "pq_api.h"

#define CRYPTO_SECRETKEYBYTES  19872     // sizeof(s) + CRYPTO_PUBLICKEYBYTES + 2*PARAMS_N*PARAMS_NBAR
#define CRYPTO_PUBLICKEYBYTES   9616     // sizeof(seed_A) + (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8
#define CRYPTO_BYTES              16
#define CRYPTO_CIPHERTEXTBYTES  9736     // (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8 + (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8 + CRYPTO_BYTES

// Algorithm name
#define CRYPTO_ALGNAME "FrodoKEM-640"       


#endif

