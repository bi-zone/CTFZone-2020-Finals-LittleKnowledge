#ifndef zkn_h__
#define zkn_h__
#define DLL_PUBLIC __attribute__ ((visibility ("default")))
#include <stdint.h>
#include "prng.h"
#define P 863615239139 // Prime for Legendre PRF
typedef struct __ZKN_STATE{
  PLEGENDRE_PRNG  pprng_state; 
}ZKN_STATE,*PZKN_STATE;
DLL_PUBLIC extern PZKN_STATE initializeZKNThread(void);
DLL_PUBLIC extern void destroyZKNThread(PZKN_STATE);
#endif //