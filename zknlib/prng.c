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

uint64_t modexp(uint64_t x, uint64_t y, uint64_t p)
{
    uint64_t res = 1;
    x = x % p;

    while (y > 0)
    {
        if (y & 1)
            res = (res*x) % p;

        y = y>>1;
        x = (x*x) % p;
    }
    return res;
}


uint8_t legendre_symbol(uint64_t a, uint64_t p)
{
  if (a == 0)
  {
    return 0;
  }

  if (modexp(a, (p-1)/2, p) == 1)
  {
    return 1;
  }
  else 
  {
    return 0;
  }
}

uint64_t gen_random(legender_PRNG_struct* legendre_PRNG, uint32_t bit_length)
{
  uint64_t result = 0;
  if (bit_length==0){
    return 0;
  }
  for (uint32_t i = 0; i < bit_length; i++)
  {
    result = result << 1;
    result |= (uint64_t)legendre_symbol((legendre_PRNG->K + i) % legendre_PRNG->p, legendre_PRNG->p);
    legendre_PRNG->K = (legendre_PRNG->K + 1) % legendre_PRNG->p;
  }
  return result;
}

legender_PRNG_struct *initialize_PRNG(long module){

  // Initialize seed
  int randomData = open("/dev/urandom", O_RDONLY);
  if (randomData==-1) return NULL;
  union {
    char myRandomData[8];
    long l;
  } randomDataUnion;
  ssize_t accumulatedResult=0;
  ssize_t result=0;
  while ((accumulatedResult<sizeof(randomDataUnion)) && result !=-1){
    result=read(randomData, randomDataUnion.myRandomData, sizeof(randomDataUnion) - accumulatedResult);
    accumulatedResult+=result;
  }

  // Create and fill the PRNG struct
  legender_PRNG_struct *legender_PRNG = malloc(sizeof(legender_PRNG_struct));
  if (legender_PRNG==NULL){
    return NULL;
  }
  legender_PRNG->p = module;
  legender_PRNG->K = randomDataUnion.l;

  return legender_PRNG;
}

void destroy_PRNG(legender_PRNG_struct* legender_PRNG){
  free(legender_PRNG);
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
