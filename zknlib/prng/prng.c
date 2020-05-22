/*
libzkn - Legendre PRNG 
Legendre PRNG implementation.
Authors:
    Igor Motroni (i.motroni@bi.zone)
    Innokentii Sennovskii (isennovskiy@bi.zone)
*/
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include "prng.h"

/*
    uint64_t computeModularExponent(uint64_t x, uint64_t y, uint64_t p)
    description:
      Compute x to the power of y modulo p. Uses standard square and multiply
    arguments:
      x - base
      y - exponent
      p - modulus
    return value:
      x**y mod p
*/
uint64_t computeModularExponent(uint64_t x, uint64_t y, uint64_t p)
{
    uint64_t res = 1;
    x = x % p;

    while (y > 0)
    {
        if (y & 1)
            res = (uint64_t)(((__uint128_t) res*(__uint128_t)x) % (__uint128_t)p);

        y = y>>1;
        x = (uint64_t)(((__uint128_t)x*(__uint128_t)x) % (__uint128_t)p);
    }
    return res;
}

/*
    uint8_t computeLegendreSymbol(uint64_t a, uint64_t p)
    description:
      Compute Legendre symbol of a in p. Computes a to the power (p-1)/2 in GF(p).
    arguments:
      a - field element
      p - modulus
    return value:
      0 if Legendre Symbol is 0 or -1
      1 if legendre Symbol is 1
*/
uint8_t computeLegendreSymbol(uint64_t a, uint64_t p)
{
  if (a == 0)
  {
    return 0;
  }

  if (computeModularExponent(a, (p-1)/2, p) == 1)
  {
    return 1;
  }
  else 
  {
    return 0;
  }
}

/*
    uint64_t generateRandomUpTo64Bits(PLEGENDRE_PRNG pLegendrePRNG, uint8_t bBitLength)
    description:
      Generate bBitLength random bits, pack them in a single uint64_t and return. Maximum is 64 bits for obvious reasons
    arguments:
      pLegenderPRNG - pointer to structure holding PRNG state
      bBitLength - number of bits to produce
    return value:
      0 if bBitLength is 0, otherwise a value with first bBitLength bits pseudorandom
*/
uint64_t generateRandomUpTo64Bits(PLEGENDRE_PRNG pLegendrePRNG, uint8_t bBitLength)
{
  uint64_t result = 0;
  //Sanity check
  if (bBitLength==0){
    return 0;
  }
  //Generate bits one by one
  for (uint32_t i = 0; i < (uint32_t)bBitLength; i++)
  {
    //Shift ouput value
    result = result << 1;
    //Generate new bit
    result |= (uint64_t)computeLegendreSymbol((pLegendrePRNG->K ) % pLegendrePRNG->p, pLegendrePRNG->p);
    //Update internal state
    pLegendrePRNG->K = (pLegendrePRNG->K + 1) % pLegendrePRNG->p;
  }
  //Return result
  return result;
}

/*
    PLEGENDRE_PRNG initializePRNG(uint64_t qwModulus)
    description:
      Initialize Legendre PRNG.
    arguments:
      qwModulus - chosen modulus. Should be a prime number
    return value:
      SUCCESS - pointer to LEGENDRE_PRNG structure, containing PRNG state
      FAIL - NULL
*/
PLEGENDRE_PRNG initializePRNG(uint64_t qwModulus){

  // Initialize seed
  int randomData = open("/dev/urandom", O_RDONLY);
  if (randomData==-1) return NULL;
  union {
    char myRandomData[8];
    uint64_t l;
  } randomDataUnion;
  ssize_t accumulatedResult=0;
  ssize_t result=0;
  while ((accumulatedResult<sizeof(randomDataUnion)) && result !=-1){
    result=read(randomData, randomDataUnion.myRandomData, sizeof(randomDataUnion) - accumulatedResult);
    accumulatedResult+=result;
  }
  close(randomData);
  // Create and fill the PRNG struct
  PLEGENDRE_PRNG pLegendrePRNG = malloc(sizeof(LEGENDRE_PRNG));
  if (pLegendrePRNG==NULL){
    return NULL;
  }
  pLegendrePRNG->p = qwModulus;
  pLegendrePRNG->K = randomDataUnion.l%qwModulus;
  return pLegendrePRNG;
}

/*
    void destroyPRNG(PLEGENDRE_PRNG pLegendrePRNG)
    description:
      Destoy PRNG
    arguments:
      pLegendrePRNG - pointer to LEGENDRE_PRNG structure
    return value:
      N/A
*/
void destroyPRNG(PLEGENDRE_PRNG pLegendrePRNG){
  free(pLegendrePRNG);
}

/*int main(int argc, char *argv[])
{
    long p;
    sscanf (argv[1],"%ld",&p);
    long bit_length;
    sscanf (argv[2],"%ld",&bit_length);

    legender_PRNG_struct *legender_PRNG = initialize_PRNG(p);

    for (int i = 0; i < 10; i++)
    {
      printf ("%ld\n", gen_random(legender_PRNG, bit_length));
    }

    destroy_PRNG(legender_PRNG);
    return 0;
}*/
