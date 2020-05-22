/*
libzkn - testing functionality
Authors:
    Innokentii Sennovskii (i.sennovskiy@bi.zone)
*/
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
    PZKN_PROTOCOL_STATE pZKnProtocolState;
    PFULL_KNOWLEDGE pFullKnowledge;
    PGRAPH_SET_PACKET pGraphSetPacket;
    uint8_t* pInitialSettingPacket;
    uint16_t wVerticeCount;
    uint32_t dwGraphSetPacketSize, dwResult;
    uint8_t* pbSignature;
    uint8_t* pbProofSettingsPacket;
    uint32_t dwProofSettingsPacketSize;
    uint8_t* pbCommitment;
    uint32_t dwCommitmentSize;
    PCOMMITMENT_EXTRA_INFORMATION pCommitmentExtraInformation;
    uint8_t* pbChallenge;
    uint32_t dwChallengeSize;
    uint8_t* pbReveal;
    uint32_t dwRevealSize;
    PSINGLE_PROOF* pProofArray;
    PPROOF_HELPER pProofHelper;
    uint8_t bErrorReason;
    uint8_t bResult;
    uint8_t* pbFlagOutput;
#ifdef TEST_HASH_ENC
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
        printf("SHA256 check failed\n");
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
#endif

    //STARTING ZKN TESTS.
#ifdef TEST_MIN_DIM
    //TEST 2 SMALL DIMENSION / CORRECT PROOF
    printf("#2 Testing full proof cycle with small dimension\n");
    //Client side
    pZKnState=initializeZKnState(MIN_MATRIX_DIMENSION,32,0xff);
    printf ("ZKNState %p\n",pZKnState);
    printf("FLAG: %s\nGRAPH: %p\nVertice count: %d\n",pZKnState->pbFLAG,pZKnState->pZKnGraph,pZKnState->wDefaultVerticeCount);
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
    //Create proof settings packet
    pbProofSettingsPacket=(uint8_t *)createProofConfigurationPacket(pZKnState,&dwProofSettingsPacketSize);
    printf("Created Proof Configuration packet %p\n",pbProofSettingsPacket);
    //Server side
    //Create commitment
    pProofHelper=initializeProofHelper(pFullKnowledge,(PPROOF_CONFIGURATION_PACKET)pbProofSettingsPacket,dwProofSettingsPacketSize,&bErrorReason);
    free(pbProofSettingsPacket);
    printf("Created Proof Helper %p, error: %hhd\n",pProofHelper,bErrorReason);
    pProofArray=createProofsForOneRound(pProofHelper);
    printf("Created Proof Array %p\n",pProofArray);
    pbCommitment=(uint8_t*)createCommitmentPacket(pProofArray,pProofHelper,&dwCommitmentSize,&pCommitmentExtraInformation);
    printf("Created commitment packet %p of size %d bytes\n",pbCommitment,dwCommitmentSize);
    
    //Client side
    //Save commitment, create challenge
    pZKnProtocolState=initializeZKnProtocolState();
    printf("Initialized ZKnProtocolState %p\n",pZKnProtocolState);
    bResult=saveCommitment(pZKnState,pZKnProtocolState,pbCommitment,dwCommitmentSize);
    free(pbCommitment);
    printf("Saved commitment, result: %hhd\n",bResult);
    pbChallenge=(uint8_t*)createChallenge(pZKnState,pZKnProtocolState,&dwChallengeSize);
    printf("Created challenge: %p\n",pbChallenge);
    printArray(pbChallenge,dwChallengeSize);
    //Server side
    //Create
    pbReveal=(uint8_t*)createRevealPacket(pProofArray,pProofHelper,(PCHALLENGE_PACKET)pbChallenge,pCommitmentExtraInformation,&dwRevealSize);
    printf("Created Reveal packet %p of size %d bytes\n",pbReveal,dwRevealSize);
    free(pbChallenge);
    //Free everything related to proof on server side
    
    freeProofsForOneRound(pProofArray,pProofHelper);
    freeProofHelper(pProofHelper);

    //Client Side
    //Check proof
    bResult=checkProof(pZKnState,pZKnProtocolState,(PREVEAL_PACKET)pbReveal,dwRevealSize,&pbFlagOutput,&bErrorReason);
    printf("Proof check result: %hhd, reason: %hhd\n",bResult,bErrorReason);

    free(pbReveal);
    destroyZKnProtocolState(pZKnProtocolState);
    destroyZKnState(pZKnState);

    //Server side
    freeFullKnowledgeForServer(pFullKnowledge);    

    //TEST 2 COMPLETE.
#endif
#define TEST_CRC32_CORRECT_MAX
#ifdef TEST_CRC32_CORRECT_MAX
    //TEST 3 MAX DIMENSION / CORRECT PROOF
    printf("#3 Testing full proof cycle with MAX dimension\n");
    //Client side
    pZKnState=initializeZKnState(MAX_MATRIX_DIMENSION,63,0x7);
    printf ("ZKNState %p\n",pZKnState);
    printf("FLAG: %s\nGRAPH: %p\nVertice count: %d\n",pZKnState->pbFLAG,pZKnState->pZKnGraph,pZKnState->wDefaultVertexCount);
    pInitialSettingPacket=createInitialSettingPacket(pZKnState);
    printf("Initial setting packet at %p:\n",pInitialSettingPacket);
    printArray(pInitialSettingPacket,sizeof(INITIAL_SETTING_PACKET));
    //Server side
    wVerticeCount=getDesiredVerticeCountFromInitialSettingPacket(pInitialSettingPacket,sizeof(INITIAL_SETTING_PACKET));
    pFullKnowledge=createFullKnowledgeForServer(wVerticeCount);  
    printf("Created full knowldege %p\n",pFullKnowledge); 
    pGraphSetPacket=createGraphSetPacket(pFullKnowledge,pInitialSettingPacket,FLAG,&dwGraphSetPacketSize);
    printf("Created graph set packet %p\n",pGraphSetPacket);
    pbSignature=createPKCSSignature((uint8_t*)pGraphSetPacket,dwGraphSetPacketSize,RSA_BYTES);
    printf("Created psignature %p\n",pbSignature);
    //Client side
    dwResult = updateZKnGraph(pZKnState,pGraphSetPacket,dwGraphSetPacketSize,pbSignature,RSA_BYTES,pInitialSettingPacket);
    free(pbSignature);
    free(pGraphSetPacket);
    printf("Update result: 0x%x\n",dwResult);
    free(pInitialSettingPacket);
    //Create proof settings packet
    pbProofSettingsPacket=(uint8_t *)createProofConfigurationPacket(pZKnState,&dwProofSettingsPacketSize);
    printf("Created Proof Configuration packet %p\n",pbProofSettingsPacket);
    //Server side
    //Create commitment
    pProofHelper=initializeProofHelper(pFullKnowledge,(PPROOF_CONFIGURATION_PACKET)pbProofSettingsPacket,dwProofSettingsPacketSize,&bErrorReason);
    free(pbProofSettingsPacket);
    printf("Created Proof Helper %p, error: %hhd\n",pProofHelper,bErrorReason);
    pProofArray=createProofsForOneRound(pProofHelper);
    printf("Created Proof Array %p\n",pProofArray);
    pbCommitment=(uint8_t*)createCommitmentPacket(pProofArray,pProofHelper,&dwCommitmentSize,&pCommitmentExtraInformation);
    printf("Created commitment packet %p of size %d bytes\n",pbCommitment,dwCommitmentSize);
    
    //Client side
    //Save commitment, create challenge
    pZKnProtocolState=initializeZKnProtocolState();
    printf("Initialized ZKnProtocolState %p\n",pZKnProtocolState);
    bResult=saveCommitment(pZKnState,pZKnProtocolState,pbCommitment,dwCommitmentSize);
    freeDanglingPointer(pbCommitment);
    printf("Saved commitment, result: %hhd\n",bResult);
    pbChallenge=(uint8_t*)createChallenge(pZKnState,pZKnProtocolState,&dwChallengeSize);
    printf("Created challenge: %p\n",pbChallenge);
    printArray(pbChallenge,dwChallengeSize);
    //Server side
    //Create
    pbReveal=(uint8_t*)createRevealPacket(pProofArray,pProofHelper,(PCHALLENGE_PACKET)pbChallenge,pCommitmentExtraInformation,&dwRevealSize);
    printf("Created Reveal packet %p of size %d bytes\n",pbReveal,dwRevealSize);
    free(pbChallenge);
    //Free everything related to proof on server side
    
    freeProofsForOneRound(pProofArray,pProofHelper);
    freeProofHelper(pProofHelper);

    //Client Side
    //Check proof
    bResult=checkProof(pZKnState,pZKnProtocolState,(PREVEAL_PACKET)pbReveal,dwRevealSize,&pbFlagOutput,&bErrorReason);
    printf("Proof check result: %hhd, reason: %hhd\n",bResult,bErrorReason);

    free(pbReveal);
    destroyZKnProtocolState(pZKnProtocolState);
    destroyZKnState(pZKnState);

    //Server side
    freeFullKnowledgeForServer(pFullKnowledge);
#endif
#ifdef TEST_SHA256_MAX_DIMENSION_CORRECT

    //TEST 4 MAX DIMENSION / CORRECT PROOF / SHA256
    printf("#4 Testing full proof cycle with MAX dimension and SHA256 COMMITMENT\n");
    //Client side
    pZKnState=initializeZKnState(MAX_MATRIX_DIMENSION,32,2);
    printf ("ZKNState %p\n",pZKnState);
    printf("FLAG: %s\nGRAPH: %p\nVertice count: %d\n",pZKnState->pbFLAG,pZKnState->pZKnGraph,pZKnState->wDefaultVerticeCount);
    pInitialSettingPacket=createInitialSettingPacket(pZKnState);
    printf("Initial setting packet at %p:\n",pInitialSettingPacket);
    printArray(pInitialSettingPacket,sizeof(INITIAL_SETTING_PACKET));
    //Server side
    wVerticeCount=getDesiredVerticeCountFromInitialSettingPacket(pInitialSettingPacket,sizeof(INITIAL_SETTING_PACKET));
    pFullKnowledge=createFullKnowledgeForServer(wVerticeCount);  
    printf("Created full knowldege %p\n",pFullKnowledge); 
    pGraphSetPacket=createGraphSetPacket(pFullKnowledge,pInitialSettingPacket,FLAG,&dwGraphSetPacketSize);
    printf("Created graph set packet %p\n",pGraphSetPacket);
    pbSignature=createPKCSSignature((uint8_t*)pGraphSetPacket,dwGraphSetPacketSize,RSA_BYTES);
    printf("Created psignature %p\n",pbSignature);
    //Client side
    dwResult = updateZKnGraph(pZKnState,pGraphSetPacket,dwGraphSetPacketSize,pbSignature,RSA_BYTES,pInitialSettingPacket);
    free(pbSignature);
    free(pGraphSetPacket);
    printf("Update result: 0x%x\n",dwResult);
    free(pInitialSettingPacket);
    //Create proof settings packet
    pbProofSettingsPacket=(uint8_t *)createProofConfigurationPacket(pZKnState,&dwProofSettingsPacketSize);
    printf("Created Proof Configuration packet %p\n",pbProofSettingsPacket);
    //Server side
    //Create commitment
    pProofHelper=initializeProofHelper(pFullKnowledge,(PPROOF_CONFIGURATION_PACKET)pbProofSettingsPacket,dwProofSettingsPacketSize,&bErrorReason);
    free(pbProofSettingsPacket);
    printf("Created Proof Helper %p, error: %hhd\n",pProofHelper,bErrorReason);
    pProofArray=createProofsForOneRound(pProofHelper);
    printf("Created Proof Array %p\n",pProofArray);
    pbCommitment=(uint8_t*)createCommitmentPacket(pProofArray,pProofHelper,&dwCommitmentSize,&pCommitmentExtraInformation);
    printf("Created commitment packet %p of size %d bytes\n",pbCommitment,dwCommitmentSize);
    
    //Client side
    //Save commitment, create challenge
    pZKnProtocolState=initializeZKnProtocolState();
    printf("Initialized ZKnProtocolState %p\n",pZKnProtocolState);
    bResult=saveCommitment(pZKnState,pZKnProtocolState,pbCommitment,dwCommitmentSize);
    free(pbCommitment);
    printf("Saved commitment, result: %hhd\n",bResult);
    pbChallenge=(uint8_t*)createChallenge(pZKnState,pZKnProtocolState,&dwChallengeSize);
    printf("Created challenge: %p\n",pbChallenge);
    printArray(pbChallenge,dwChallengeSize);
    //Server side
    //Create
    pbReveal=(uint8_t*)createRevealPacket(pProofArray,pProofHelper,(PCHALLENGE_PACKET)pbChallenge,pCommitmentExtraInformation,&dwRevealSize);
    printf("Created Reveal packet %p of size %d bytes\n",pbReveal,dwRevealSize);
    free(pbChallenge);
    //Free everything related to proof on server side

    freeProofsForOneRound(pProofArray,pProofHelper);
    freeProofHelper(pProofHelper);

    //Client Side
    //Check proof
    bResult=checkProof(pZKnState,pZKnProtocolState,(PREVEAL_PACKET)pbReveal,dwRevealSize,&pbFlagOutput,&bErrorReason);
    printf("Proof check result: %hhd, reason: %hhd\n",bResult,bErrorReason);

    free(pbReveal);
    destroyZKnProtocolState(pZKnProtocolState);
    destroyZKnState(pZKnState);

    //Server side
    freeFullKnowledgeForServer(pFullKnowledge);
#endif
#ifdef TEST_AES_MAX_DIM_CORRECT
    //TEST 5 MAX DIMENSION / CORRECT PROOF / AES
    printf("#5 Testing full proof cycle with MAX dimension and AES COMMITMENT\n");
    //Client side
    pZKnState=initializeZKnState(MAX_MATRIX_DIMENSION,64,4);
    printf ("ZKNState %p\n",pZKnState);
    printf("FLAG: %s\nGRAPH: %p\nVertice count: %d\n",pZKnState->pbFLAG,pZKnState->pZKnGraph,pZKnState->wDefaultVerticeCount);
    pInitialSettingPacket=createInitialSettingPacket(pZKnState);
    printf("Initial setting packet at %p:\n",pInitialSettingPacket);
    printArray(pInitialSettingPacket,sizeof(INITIAL_SETTING_PACKET));
    //Server side
    wVerticeCount=getDesiredVerticeCountFromInitialSettingPacket(pInitialSettingPacket,sizeof(INITIAL_SETTING_PACKET));
    pFullKnowledge=createFullKnowledgeForServer(wVerticeCount);  
    printf("Created full knowldege %p\n",pFullKnowledge); 
    pGraphSetPacket=createGraphSetPacket(pFullKnowledge,pInitialSettingPacket,FLAG,&dwGraphSetPacketSize);
    printf("Created graph set packet %p\n",pGraphSetPacket);
    pbSignature=createPKCSSignature((uint8_t*)pGraphSetPacket,dwGraphSetPacketSize,RSA_BYTES);
    printf("Created psignature %p\n",pbSignature);
    //Client side
    dwResult = updateZKnGraph(pZKnState,pGraphSetPacket,dwGraphSetPacketSize,pbSignature,RSA_BYTES,pInitialSettingPacket);
    free(pbSignature);
    free(pGraphSetPacket);
    printf("Update result: 0x%x\n",dwResult);
    free(pInitialSettingPacket);
    //Create proof settings packet
    pbProofSettingsPacket=(uint8_t *)createProofConfigurationPacket(pZKnState,&dwProofSettingsPacketSize);
    printf("Created Proof Configuration packet %p\n",pbProofSettingsPacket);
    //Server side
    //Create commitment
    pProofHelper=initializeProofHelper(pFullKnowledge,(PPROOF_CONFIGURATION_PACKET)pbProofSettingsPacket,dwProofSettingsPacketSize,&bErrorReason);
    free(pbProofSettingsPacket);
    printf("Created Proof Helper %p, error: %hhd\n",pProofHelper,bErrorReason);
    pProofArray=createProofsForOneRound(pProofHelper);
    printf("Created Proof Array %p\n",pProofArray);
    pbCommitment=(uint8_t*)createCommitmentPacket(pProofArray,pProofHelper,&dwCommitmentSize,&pCommitmentExtraInformation);
    printf("Created commitment packet %p of size %d bytes\n",pbCommitment,dwCommitmentSize);
    
    //Client side
    //Save commitment, create challenge
    pZKnProtocolState=initializeZKnProtocolState();
    printf("Initialized ZKnProtocolState %p\n",pZKnProtocolState);
    bResult=saveCommitment(pZKnState,pZKnProtocolState,pbCommitment,dwCommitmentSize);
    free(pbCommitment);
    printf("Saved commitment, result: %hhd\n",bResult);
    pbChallenge=(uint8_t*)createChallenge(pZKnState,pZKnProtocolState,&dwChallengeSize);
    printf("Created challenge: %p\n",pbChallenge);
    printArray(pbChallenge,dwChallengeSize);
    //Server side
    //Create
    pbReveal=(uint8_t*)createRevealPacket(pProofArray,pProofHelper,(PCHALLENGE_PACKET)pbChallenge,pCommitmentExtraInformation,&dwRevealSize);
    printf("Created Reveal packet %p of size %d bytes\n",pbReveal,dwRevealSize);
    free(pbChallenge);
    //Free everything related to proof on server side
    
    freeCommitmentExtraInformation(pProofHelper, pCommitmentExtraInformation);
    freeProofsForOneRound(pProofArray,pProofHelper);
    freeProofHelper(pProofHelper);

    //Client Side
    //Check proof
    bResult=checkProof(pZKnState,pZKnProtocolState,(PREVEAL_PACKET)pbReveal,dwRevealSize,&pbFlagOutput,&bErrorReason);
    printf("Proof check result: %hhd, reason: %hhd\n",bResult,bErrorReason);

    free(pbReveal);
    destroyZKnProtocolState(pZKnProtocolState);
    destroyZKnState(pZKnState);

    //Server side
    freeFullKnowledgeForServer(pFullKnowledge);
#endif
#ifdef TEST_CRC32_INCORRECT_MAX
    //TEST 6 MAX DIMENSION / CORRECT PROOF
    printf("#6 Testing full proof cycle with MAX dimension\n");
    //Client side
    pZKnState=initializeZKnState(MAX_MATRIX_DIMENSION,32,0xff);
    printf ("ZKNState %p\n",pZKnState);
    printf("FLAG: %s\nGRAPH: %p\nVertice count: %d\n",pZKnState->pbFLAG,pZKnState->pZKnGraph,pZKnState->wDefaultVerticeCount);
    pInitialSettingPacket=createInitialSettingPacket(pZKnState);
    printf("Initial setting packet at %p:\n",pInitialSettingPacket);
    printArray(pInitialSettingPacket,sizeof(INITIAL_SETTING_PACKET));
    //Server side
    wVerticeCount=getDesiredVerticeCountFromInitialSettingPacket(pInitialSettingPacket,sizeof(INITIAL_SETTING_PACKET));
    pFullKnowledge=createFullKnowledgeForServer(wVerticeCount);  
    printf("Created full knowldege %p\n",pFullKnowledge); 
    pGraphSetPacket=createGraphSetPacket(pFullKnowledge,pInitialSettingPacket,FLAG,&dwGraphSetPacketSize);
    printf("Created graph set packet %p\n",pGraphSetPacket);
    pbSignature=createPKCSSignature((uint8_t*)pGraphSetPacket,dwGraphSetPacketSize,RSA_BYTES);
    printf("Created psignature %p\n",pbSignature);
    //Client side
    dwResult = updateZKnGraph(pZKnState,pGraphSetPacket,dwGraphSetPacketSize,pbSignature,RSA_BYTES,pInitialSettingPacket);
    free(pbSignature);
    free(pGraphSetPacket);
    printf("Update result: 0x%x\n",dwResult);
    free(pInitialSettingPacket);
    //Create proof settings packet
    pbProofSettingsPacket=(uint8_t *)createProofConfigurationPacket(pZKnState,&dwProofSettingsPacketSize);
    printf("Created Proof Configuration packet %p\n",pbProofSettingsPacket);
    //Server side
    //Create commitment
    pProofHelper=initializeProofHelper(pFullKnowledge,(PPROOF_CONFIGURATION_PACKET)pbProofSettingsPacket,dwProofSettingsPacketSize,&bErrorReason);
    free(pbProofSettingsPacket);
    printf("Created Proof Helper %p, error: %hhd\n",pProofHelper,bErrorReason);
    pProofArray=createProofsForOneRound(pProofHelper);
    printf("Created Proof Array %p\n",pProofArray);
    pbCommitment=(uint8_t*)createCommitmentPacket(pProofArray,pProofHelper,&dwCommitmentSize,&pCommitmentExtraInformation);
    pbCommitment[COMMITMENT_PACKET_HEADER_SIZE+CRC32_COMMITMENT_HEADER_SIZE]^=1;
    printf("Created commitment packet %p of size %d bytes\n",pbCommitment,dwCommitmentSize);
    
    //Client side
    //Save commitment, create challenge
    pZKnProtocolState=initializeZKnProtocolState();
    printf("Initialized ZKnProtocolState %p\n",pZKnProtocolState);
    bResult=saveCommitment(pZKnState,pZKnProtocolState,pbCommitment,dwCommitmentSize);
    free(pbCommitment);
    printf("Saved commitment, result: %hhd\n",bResult);
    pbChallenge=(uint8_t*)createChallenge(pZKnState,pZKnProtocolState,&dwChallengeSize);
    printf("Created challenge: %p\n",pbChallenge);
    printArray(pbChallenge,dwChallengeSize);
    //Server side
    //Create
    pbReveal=(uint8_t*)createRevealPacket(pProofArray,pProofHelper,(PCHALLENGE_PACKET)pbChallenge,pCommitmentExtraInformation,&dwRevealSize);
    printf("Created Reveal packet %p of size %d bytes\n",pbReveal,dwRevealSize);
    free(pbChallenge);
    //Free everything related to proof on server side
    
    freeProofsForOneRound(pProofArray,pProofHelper);
    freeProofHelper(pProofHelper);

    //Client Side
    //Check proof
    bResult=checkProof(pZKnState,pZKnProtocolState,(PREVEAL_PACKET)pbReveal,dwRevealSize,&pbFlagOutput,&bErrorReason);
    printf("Proof check result: %hhd, reason: %hhd\n",bResult,bErrorReason);

    free(pbReveal);
    destroyZKnProtocolState(pZKnProtocolState);
    destroyZKnState(pZKnState);

    //Server side
    freeFullKnowledgeForServer(pFullKnowledge);
#endif
    return 0;
}