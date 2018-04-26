//
//  api.h
//
//  Created by Bassham, Lawrence E (Fed) on 9/6/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//


//   This is a sample 'api.h' for use 'sign.c'
//

#ifndef SABER_api_h
#define SABER_api_h

#include "pq_api.h"

#define CRYPTO_ALGNAME "Saber"

#define CRYPTO_SECRETKEYBYTES 2304
#define CRYPTO_PUBLICKEYBYTES (3*320+32)
#define CRYPTO_BYTES 32
#define CRYPTO_CIPHERTEXTBYTES 1088

#endif /* api_h */
