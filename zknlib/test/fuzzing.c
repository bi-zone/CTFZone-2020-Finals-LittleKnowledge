#include "../include/zkn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SMALL_VERTICE_COUNT 100
#define RSA_BYTES 2048/8
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size){
#ifdef PROOF_CONFIG_FUZZING
    if (Size<3){
        return 1;
    }
    PFULL_KNOWLEDGE pFullKnowledge;
    uint16_t wVerticeCount=*(uint16_t*)Data;
    Data=Data+2;
    pFullKnowledge=createFullKnowledgeForServer(wVerticeCount);
    if (pFullKnowledge==NULL) return 1;
    PPROOF_HELPER pProofHelper;
    uint8_t bErrorReason;
    pProofHelper=initializeProofHelper(pFullKnowledge,(PPROOF_CONFIGURATION_PACKET)Data,(uint32_t)Size-2,&bErrorReason);
    if (pProofHelper==NULL){
        freeFullKnowledge(pFullKnowledge);
        return 1;
    }
    freeProofHelper(pProofHelper);
    freeFullKnowledge(pFullKnowledge);
    return 0;
#endif
#ifdef UPDATE_ZKN_FUZZING
    PZKN_STATE pZKnState;
    uint16_t wVerticeCount;
    uint8_t bCheckCount;
    uint8_t bUsedAlgs;
    uint8_t bResult;
    unsigned char RANDOMR[16];
    memset(RANDOMR,0,16);
    if (Size<260){
        return 1;
        
    }
    wVerticeCount=((uint16_t)*Data)+1;
    bCheckCount=*(Data+1);
    bUsedAlgs=*(Data+2);
    pZKnState=initializeZKnState(wVerticeCount,bCheckCount,bUsedAlgs);
    if (pZKnState==NULL) return 1;
    Data=Data+3;
    bResult=updateZKnGraph(pZKnState,(PGRAPH_SET_PACKET)(Data+256),(uint32_t)(Size-259),Data,256,RANDOMR);
    destroyZKnState(pZKnState);
    return 0;
#endif
    PFULL_KNOWLEDGE pFullKnowledge;
    uint8_t* pNewBuffer;
    pNewBuffer=malloc(Size);
    memcpy(pNewBuffer,Data,Size);
    pFullKnowledge=unpackFullKnowledgeFromStorage(pNewBuffer,Size);
    freeFullKnowledge(pFullKnowledge);
    free(pNewBuffer);
    return 0;

};