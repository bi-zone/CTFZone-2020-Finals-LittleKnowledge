#include "zkn.h"
#include <stdlib.h>
#include <stdio.h>

PZKN_STATE initializeZKNThread(void)
{
    PZKN_STATE pzkn_state;
    PLEGENDRE_PRNG plegendre_prng;
    pzkn_state=(PZKN_STATE)malloc(sizeof(ZKN_STATE));
    if (pzkn_state==NULL) return NULL;
    plegendre_prng=initialize_PRNG(P);
    printf("Heh\n");
    if (plegendre_prng==NULL){
        free(pzkn_state);
        return NULL;
    }
    pzkn_state->pprng_state=plegendre_prng;
    return pzkn_state;
}
void destroyZKNThread(PZKN_STATE pzkn_state)
{
    destroy_PRNG(pzkn_state->pprng_state);
    free(pzkn_state);
}