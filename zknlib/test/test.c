#include "../include/zkn.h"
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
    unsigned char hashTest[10]="AAAA";
    unsigned char aesKey[AES128_KEY_SIZE]={0};
    unsigned char aesIV[AES_IV_SIZE]={1};
    unsigned char *pbResultingBuffer, *pbResultingBuffer1;
    uint32_t dwOutputSize, dwOutputSize1;
    PZKN_STATE pZKnState;
    PFULL_KNOWLEDGE pFullKnowledge;
    PGRAPH_SET_PACKET pGraphSetPacket;
    uint8_t* pInitialSettingPacket;
    uint16_t wVerticeCount;
    uint32_t dwGraphSetPacketSize, dwResult;
    uint8_t* pbSignature;
    
    printf ("#1 Testing hashing/encryption\n");
    pbResultingBuffer= crc32(hashTest,4);
    if (memcmp(pbResultingBuffer,"\xf1\x08\x0d\x9b",CRC32_SIZE)!=0){
        free(pbResultingBuffer);
        printf("CRC32 check failed\n");
        return -1;
    }
    free(pbResultingBuffer);
    printf("crc32 correct\n");
    pbResultingBuffer= sha256(hashTest,4);
    if (memcmp(pbResultingBuffer,"\x63\xc1\xdd\x95\x1f\xfe\xdf\x6f\x7f\xd9\x68\xad\x4e\xfa\x39\xb8\xed\x58\x4f\x16\x2f\x46\xe7\x15\x11\x4e\xe1\x84\xf8\xde\x92\x01",SHA256_SIZE)!=0){
        free(pbResultingBuffer);
        printf("CRC32 check failed\n");
        return -1;
    }
    free(pbResultingBuffer);
    printf("sha256 correct\n");
    pbResultingBuffer=aes128cbc_encrypt(hashTest,4,aesKey,aesIV,&dwOutputSize);
    if (memcmp(pbResultingBuffer,"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x43\x0c\xb4\xd5\x46\xa4\xb3\x39\x2b\x5b\x3b\xc6\x25\x7d\xec\x83",AES_BLOCK_SIZE*2)!=0){
        free(pbResultingBuffer);
        printf("AES check failed\n");
        return -1;
    }
    //printArray(pbResultingBuffer,dwOutputSize);
    pbResultingBuffer1=aes128cbc_decrypt(pbResultingBuffer,dwOutputSize,aesKey,&dwOutputSize1);
    if (memcmp(pbResultingBuffer1,hashTest,4)!=0){
        free(pbResultingBuffer1);
        free(pbResultingBuffer);
        printf("AES check failed\n");
        return -1;
    }
    free(pbResultingBuffer);
    free(pbResultingBuffer1);
    printf ("AES correct\n");
    printf("Enc/hash test succeeded\n");
    printf("Starting test of code functionaliy:\n");
    printf("#2 Testing full initialization cycle with small dimension\n");
    //Client side
    pZKnState=initializeZKnThread(MIN_MATRIX_DIMENSION,32,0xff);
    printf ("ZKNState %p\n",pZKnState);
    printf("PRNG: %p\nFLAG: %s\nGRAPH: %p\nVertice count: %d\n",pZKnState->pLegendrePrng,pZKnState->pbFLAG,pZKnState->pZKnGraph,pZKnState->wDefaultVerticeCount);
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