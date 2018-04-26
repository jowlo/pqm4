/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: functions for FrodoKEM-640
*           Instantiates "frodo_macrify.c" with the necessary matrix arithmetic functions
*********************************************************************************************/

#include "api.h"
#include "frodo_macrify.h"



// CDF table
uint16_t CDF_TABLE[12] = {4727, 13584, 20864, 26113, 29434, 31278, 32176, 32560, 32704, 32751, 32764, 32767};
uint16_t CDF_TABLE_LEN = 12;

#include "kem.c"
#include "noise.c"
#include "frodo_macrify_reference.c"
