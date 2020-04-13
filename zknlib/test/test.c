#include "zkn.h"
#include <stdio.h>
int main(){
    PZKN_STATE pZKNState;
    pZKNState=initializeZKNThread(10);
    printf ("ZKNState %p\n",pZKNState);
    destroyZKNThread(pZKNState);
    return 0;
}