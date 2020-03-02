#include <stdint.h>
typedef struct {
  uint64_t p;
  uint64_t K;
} legender_PRNG_struct, *PLEGENDRE_PRNG;

uint64_t gen_random(legender_PRNG_struct* legender_PRNG, uint32_t bit_length);
legender_PRNG_struct *initialize_PRNG(long module);
void destroy_PRNG(legender_PRNG_struct* legender_PRNG);