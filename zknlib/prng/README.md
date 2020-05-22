# prng

## Initialize new instance of PRNG:
```legender_PRNG_struct *initialize_PRNG(long)```

## Generate *bit_length* (not more than SIZEOF(long)) pseudo-random bits:
```long gen_random(legender_PRNG_struct*, int)```

## Destroy instance:
```void destroy_PRNG(legender_PRNG_struct*)```
