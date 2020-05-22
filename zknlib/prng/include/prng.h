/*
libzkn - definitions for PRNG 
Authors:
    Innokentii Sennovskii (i.sennovskiy@bi.zone)
*/
#include <stdint.h>
typedef struct __LEGENDRE_PRNG{
  uint64_t p;
  uint64_t K;
} LEGENDRE_PRNG, *PLEGENDRE_PRNG;

uint64_t generateRandomUpTo64Bits(PLEGENDRE_PRNG pLegendrePrng, uint8_t bBitLength);
PLEGENDRE_PRNG initializePRNG(uint64_t qwModulus);
void destroyPRNG(PLEGENDRE_PRNG pLegendrePrng);