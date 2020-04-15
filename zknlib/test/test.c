#include "zkn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SMALL_VERTICE_COUNT 100
#define RSA_BYTES 2048/8
void printArray(uint8_t* pbArray, uint32_t dwSize){
    uint8_t bLastRow=0;
    uint32_t dwFirstPart;
    uint32_t dwCounter;
    uint8_t bI;
    if ((dwSize%16)!=0) bLastRow=1;
    dwFirstPart=dwSize-(dwSize%16);
    if (dwFirstPart!=0){
        for (dwCounter=0;dwCounter<(dwFirstPart>>4);dwCounter=dwCounter+1){
            printf ("| ");
            for (bI=0;bI<16;bI=bI+1){
                printf("%02x ",pbArray[dwCounter*16+(uint32_t)bI]);
            }
            printf("|\n");
        }
    }
    if (bLastRow){
        printf("| ");
        for(;dwFirstPart<dwSize;dwFirstPart=dwFirstPart+1){
            printf("%02x ",pbArray[dwFirstPart]);
        }
        for (;(dwFirstPart%16)!=0;dwFirstPart=dwFirstPart+1){
            printf("   ");
        }
        printf("|\n");
    }
}
int main(){
    char FLAG[64]="FLAG";
    PZKN_STATE pZKnState;
    PFULL_KNOWLEDGE pFullKnowledge;
    PGRAPH_SET_PACKET pGraphSetPacket;
    uint8_t* pInitialSettingPacket;
    uint16_t wVerticeCount;
    uint32_t dwGraphSetPacketSize, dwResult;
    uint8_t* pbSignature;
    printf("Starting test of code functionaliy:\n");
    printf("#1 Test of full initialization cycle with small dimension\n");
    //Client side
    pZKnState=initializeZKnThread(MIN_MATRIX_DIMENSION);
    printf ("ZKNState %p\n",pZKnState);
    printf("PRNG: %p\nFLAG: %s\nGRAPH: %p\nVertice count: %d\n",pZKnState->pLegendrePrng,pZKnState->pbFLAG,pZKnState->pZKNGraph,pZKnState->wDefaultVerticeCount);
    pInitialSettingPacket=createInitialSettingPacket(pZKnState);
    printf("Initial setting packet at %p:\n",pInitialSettingPacket);
    printArray(pInitialSettingPacket,sizeof(INITIAL_SETTING_PACKET));
    //Server side
    wVerticeCount=getDesiredVerticeCountFromInitialSettingPacket(pInitialSettingPacket,sizeof(INITIAL_SETTING_PACKET));
    pFullKnowledge=createFullKnowledgeForServer(wVerticeCount);   
    pGraphSetPacket=createGraphSetPacket(pFullKnowledge,pInitialSettingPacket,FLAG,&dwGraphSetPacketSize);
    pbSignature=createPKCSSignature((uint8_t*)pGraphSetPacket,dwGraphSetPacketSize,RSA_BYTES);
    //Client side
    dwResult = updateZKnGraph(pZKnState,pGraphSetPacket,dwGraphSetPacketSize,pbSignature,RSA_BYTES,pInitialSettingPacket);
    free(pbSignature);
    free(pGraphSetPacket);
    printf("Update result: 0x%x\n",dwResult);
    free(pInitialSettingPacket);
    destroyZKnThread(pZKnState);

    //Server side
    freeFullKnowledgeForServer(pFullKnowledge);    
    return 0;
}