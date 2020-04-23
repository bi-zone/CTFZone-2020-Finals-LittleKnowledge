#include "zkn.h"
#include "hash.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define MIN_PKCS_SIG_SIZE (SHA256_SIZE+4)
#define ERROR_SYSTEM 1
#define ERROR_BAD_VALUE 2
#define SUCCESS 0x0


#define ERROR_REASON_NONE 0
#define ERROR_REASON_SYSTEM 1
#define ERROR_REASON_WRONG_VALUE 2
#define ERROR_REASON_TOO_EARLY 3
#define ERROR_REASON_CHEATING 4
/*
    PZKN_STATE initializeZKnState(uint16_t wVerticeCount, uint8_t bCheckCount, uint8_t bSuppportedAlgorithms)
    description:
        Exported function, that initializes team server's zero knowledge state
    arguments:
        wVerticeCount - desired matrix dimension
    return value:
        SUCCESS - pointer to the state structure
        ERROR - NULL
*/
PZKN_STATE initializeZKnState(uint16_t wVerticeCount, uint8_t bCheckCount, uint8_t bSuppportedAlgorithms)
{
    PZKN_STATE pZKnState;
    if ((wVerticeCount>MAX_MATRIX_DIMENSION)|| (wVerticeCount<MIN_MATRIX_DIMENSION)) return NULL;
    if (bCheckCount<MINIMUM_CHECK_COUNT || bCheckCount>MAXIMUM_CHECK_COUNT) return NULL;
    if (bSuppportedAlgorithms<1 || bSuppportedAlgorithms>7) return NULL;
    pZKnState=(PZKN_STATE)malloc(sizeof(ZKN_STATE));
    if (pZKnState==NULL) return NULL;

    pZKnState->wDefaultVerticeCount=wVerticeCount;
    pZKnState->bCheckCount=bCheckCount;
    pZKnState->supportedAlgorithms.supportedAlgsCode=bSuppportedAlgorithms;
    pZKnState->pbFLAG=NULL;
    pZKnState->simulationDisabled=0;
    pZKnState->pZKnGraph=NULL;
    return pZKnState;
}
/*
    void destroyZKnState(PZKN_STATE pZKnState)
    description:
        Team Server's zero knowledge state destruction
    arguments:
        pZKNState - pointer to zero knowledge state structure
    return value:
        None
*/
void destroyZKnState(PZKN_STATE pZKnState)
{
    if (pZKnState==NULL) return;
    free(pZKnState->pbFLAG);
    if (pZKnState->pZKnGraph!=NULL) free(pZKnState->pZKnGraph->pbGraphData);
    free(pZKnState->pZKnGraph);
    free(pZKnState);
}

/*
    uint8_t * createInitialSettingPacket(PZKN_STATE pZKnState)
    description:
        Create inital packet containing RANDOM R and desired vertice count for checking server
    arguments:
        pZKnState - initialized zero knowledge state
    return value:
        SUCCESS - pointer to memory containing the packet
        FAIL - NULL
*/
uint8_t * createInitialSettingPacket(PZKN_STATE pZKnState){
    PINITIAL_SETTING_PACKET pInitialSettingPacket;
    int fd;
    ssize_t bytesRead, totalBytesRead;
    if (pZKnState==NULL) return NULL;
    pInitialSettingPacket=(PINITIAL_SETTING_PACKET)malloc(sizeof(INITIAL_SETTING_PACKET));
    if (pInitialSettingPacket==NULL) return NULL;
    fd=open("/dev/urandom",O_RDONLY);
    if (fd==-1){
        free(pInitialSettingPacket);
        return NULL;
    }
    totalBytesRead=0;
    while (totalBytesRead<RANDOM_R_SIZE){
        bytesRead=read(fd,pInitialSettingPacket->RANDOM_R+totalBytesRead,RANDOM_R_SIZE-totalBytesRead);
        if (bytesRead==-1){
            free(pInitialSettingPacket);
            close(fd);
            return NULL;
        }
        totalBytesRead+=bytesRead;
    }
    close(fd);
    pInitialSettingPacket->wVerticeCount=pZKnState->wDefaultVerticeCount;
    return (uint8_t *) pInitialSettingPacket;
}

/*
    void freeDanglingPointer(void* pPointer);
    description:
        Free a pointer
    arguments:
        pPointer - pointer
    return value:
        N/A
*/
void freeDanglingPointer(void* pPointer){

    free(pPointer);
}
/*
    uint8_t* badPKCSUnpadHash(uint8_t* pDecryptedSignature, uint32_t dsSize)
    description:
        Signature contents unparsing according to PKCS#1 v1.5, but with a bug that leads
        to Bleichenbacher's arrack on signatures with e=3
    arguments:
        pDecryptedSignature - pointer to array with signature bytes
        dsSize - size of the array
    return value:
        SUCCESS - pointer to offset in the signature array, where the hash bytes are located
        ERROR - NULL
*/
uint8_t* badPKCSUnpadHash(uint8_t* pDecryptedSignature, uint32_t dsSize){
    uint32_t i;
    if (dsSize<MIN_PKCS_SIG_SIZE) return NULL;
    if ((pDecryptedSignature[0]!=0)||(pDecryptedSignature[1]!=1))return NULL;
    i=2;
    while ((i<dsSize) && (pDecryptedSignature[i]==0xff)) i=i+1;
    if (i==2 || i>=dsSize) return NULL;
    if (pDecryptedSignature[i]!=0) return NULL;
    i=i+1;
    if ((i>=dsSize)||((dsSize-i)<SHA256_SIZE)) return NULL;
    return pDecryptedSignature+i;
}

/*
    uint32_t updateZKNGraph(PZKN_STATE pZKNState, PGRAPH_SET_PACKET pGraphSetPacket, uint32_t packetSize,
                            void* pDecryptedSignature, uint32_t dsSize, uint8_t* pRANDOMR)
    description:
        Update ZKN Graph and FLAG if all checks are passed
    arguments:
        pZKNState - pointer to zero knowledge state structure
        pGraphSetPacket - pointer to GRAPH_SET_PACKET structure
        packetSize - size of packet
        pDecryptedSignature - pointer to decrypted signature array
        dsSize - size of decrypted signature array
        pRANDOMR - pointer to RANDOM R (used for packet uniqueness) check
    return value:
        SUCCESS - SUCCESS 
        ERROR:
            ERROR_SYSTEM - something went wrong during parsing (not caller's fault)
            ERROR_BAD_VALUE - something was not right with the data (probably caller's fault)

*/
uint32_t updateZKnGraph(PZKN_STATE pZKNState,PGRAPH_SET_PACKET pGraphSetPacket, uint32_t dwPacketSize, uint8_t* pbDecryptedSignature, uint32_t dsSize, uint8_t* pRANDOMR)
{
    uint8_t* signHash;
    uint8_t* actualHash;
    uint8_t* plHolder;
    uint8_t* pbUnpackedMatrix;
    uint16_t wDimension;
    uint32_t dwUnpackedMatrixSize;
    PGRAPH pZKNGraph;
    if (pZKNState==NULL||pGraphSetPacket==NULL) return ERROR_SYSTEM;
    if (dwPacketSize<GRAPH_SET_PACKET_HEADER_SIZE) return ERROR_REASON_WRONG_VALUE;
    signHash=badPKCSUnpadHash(pbDecryptedSignature,dsSize);
    if (signHash==NULL) return ERROR_SYSTEM;
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    actualHash=sha256((unsigned char*) pGraphSetPacket,(ssize_t)dwPacketSize);
    if (actualHash==NULL) return ERROR_SYSTEM;
    if (memcmp(signHash,actualHash,SHA256_SIZE)!=0){
        free(actualHash);
        return ERROR_BAD_VALUE;
    }
    free(actualHash);
    if (memcmp(pRANDOMR,pGraphSetPacket->RANDOM_R,RANDOM_R_SIZE)!=0) return ERROR_BAD_VALUE;
#endif
    if (pGraphSetPacket->dwPackedMatrixSize!=(dwPacketSize-GRAPH_SET_PACKET_HEADER_SIZE)) return ERROR_BAD_VALUE;
    pbUnpackedMatrix=unpackMatrix(pGraphSetPacket->dwPackedMatrixSize,pGraphSetPacket->bPackedMatrixData,&wDimension);
    if (pbUnpackedMatrix==NULL) return ERROR_BAD_VALUE;

    if (wDimension!=pZKNState->wDefaultVerticeCount) {
        free(pbUnpackedMatrix);
        return ERROR_BAD_VALUE;
    }
    dwUnpackedMatrixSize=(((uint32_t) wDimension)*(uint32_t)wDimension);

    if (pZKNState->pbFLAG==NULL){
        plHolder=malloc(FLAG_ARRAY_SIZE);
        if (plHolder==NULL) 
        {
            free(pbUnpackedMatrix);
            return ERROR_SYSTEM;
        }
        pZKNState->pbFLAG=plHolder;
    }
    if (pZKNState->pZKnGraph!=NULL) free(pZKNState->pZKnGraph->pbGraphData);
    free(pZKNState->pZKnGraph);
    plHolder=malloc(sizeof(GRAPH));
    if (plHolder==NULL) {
        free(pbUnpackedMatrix);
        return ERROR_SYSTEM;
    }
    pZKNState->pZKnGraph=(PGRAPH)plHolder;
    memcpy(pZKNState->pbFLAG,pGraphSetPacket->FLAG,FLAG_ARRAY_SIZE);
    pZKNGraph=pZKNState->pZKnGraph;
    pZKNGraph->wVerticeCount=wDimension;
    pZKNGraph->dwMatrixSize=dwUnpackedMatrixSize;
    pZKNGraph->pbGraphData=pbUnpackedMatrix;
    return SUCCESS;
}


/*
    PFULL_KNOWLEDGE createFullKnowledgeForServer(int16_t wVerticeCount)
    description:
        create FULL_KNOWLEDGE (Graph with a hamiltonian cycle)
    arguments:
        wVerticeCount - desired number of vertices
    return value:
        SUCCESS - pointer to FULL_KNOWLEDGE structure
        ERROR - NULL

*/
PFULL_KNOWLEDGE createFullKnowledgeForServer(int16_t wVerticeCount){
    return generateGraphAndCycleMatrix(wVerticeCount);
};

/*    
    void freeFullKnowledgeForServer(PFULL_KNOWLEDGE pFullKnowledge){
    description:
        free FULL_KNOWLEDGE and all its members
    arguments:
        pfullKnowledge - pointer to FULL_KNOWLEDGE structure
    return value:
        N/A
*/
void freeFullKnowledgeForServer(PFULL_KNOWLEDGE pFullKnowledge){
    return freeFullKnowledge(pFullKnowledge);
}

/*
    uint8_t* packFullKnowledgeForStorage(PFULL_KNOWLEDGE pFullKnowledge, out int32_t* pdwDataSize)
    description:
        Pack FULL_KNOWLEDGE into one array of bytes for strorage
    arguments:
        pFullKnowledge - pointer to full knowledge structure
        pdwDataSize - pointer to int32_t where the final size of the output array is to be placed
    return value:
        SUCCESS - pointer to array containing packed FULL_KNOWLEDGE and its size in pdwDataSize
        FAIL - NULL
*/
uint8_t* packFullKnowledgeForStorage(PFULL_KNOWLEDGE pFullKnowledge, out uint32_t* pdwDataSize){
    uint32_t dwComputedDataSize;
    uint8_t *pbPackedMatr,*pbPackedCycle;
    PFULL_KNOWLEDGE_FOR_STORAGE pPackedFullKnowledge;
    uint32_t dwPackedMatrSize,dwPackedCycleSize;
    if (pFullKnowledge==NULL || pFullKnowledge->pbCycleMatrix==NULL || pFullKnowledge->pbGraphMatrix==NULL) return NULL;
    pbPackedMatr=packMatrix(pFullKnowledge->pbGraphMatrix,pFullKnowledge->wDimension,&dwPackedMatrSize);
    if (pbPackedMatr==NULL) return NULL;
    pbPackedCycle=packMatrix(pFullKnowledge->pbCycleMatrix,pFullKnowledge->wDimension,&dwPackedCycleSize);
    if (pbPackedCycle==NULL) {
        free(pbPackedMatr);
        return NULL;
    }
    if (dwPackedMatrSize!=dwPackedCycleSize){
        fprintf(stderr,"WTF happened here?\n");
        free(pbPackedCycle);
        free(pbPackedMatr);
        return NULL;
    }
    dwComputedDataSize=FULL_KNOWLEDGE_FOR_STORAGE_HEADER_SIZE+((uint32_t) dwPackedCycleSize)*2;
    pPackedFullKnowledge=malloc(dwComputedDataSize);
    if (pPackedFullKnowledge==NULL){
        free(pbPackedCycle);
        free(pbPackedMatr);
        return NULL;
    }
    pPackedFullKnowledge->dwSinglePackedMatrixSize=(uint32_t)dwPackedMatrSize;
    memcpy(pPackedFullKnowledge->bData,pbPackedMatr,pPackedFullKnowledge->dwSinglePackedMatrixSize);
    memcpy(pPackedFullKnowledge->bData+(pPackedFullKnowledge->dwSinglePackedMatrixSize),pbPackedCycle,pPackedFullKnowledge->dwSinglePackedMatrixSize);
    free(pbPackedCycle);
    free(pbPackedMatr);
    *(pdwDataSize)=dwComputedDataSize;
    return (uint8_t*)pPackedFullKnowledge;
}

/*
    PFULL_KNOWLEDGE unpackFullKnowledgeFromStorage(uint8_t* pbPackedFullKnowledge, uint32_t dwPackedFullKnowledgeSize)
    description:
        Unpack FULL_KNOWLEDGE from a version nice for storage
    arguments:
        pbPackedFullKnowledge - pointer to array containing packed full knowledge
        dwPackedFullKnowledgeSize - size of packed full knowledge array
    return value:
        SUCCESS - pointer to unpacked FULL_KNOWLEDGE structure
        FAIL - NULL
*/
PFULL_KNOWLEDGE unpackFullKnowledgeFromStorage(uint8_t* pbPackedFullKnowledge, uint32_t dwPackedFullKnowledgeSize){
    PFULL_KNOWLEDGE pFullKnowledge;
    PFULL_KNOWLEDGE_FOR_STORAGE pFknForStorage;
    uint8_t *pbUnpackedMatr;
    uint16_t wDimension;
    if (pbPackedFullKnowledge==NULL) return NULL;
    if (dwPackedFullKnowledgeSize<FULL_KNOWLEDGE_FOR_STORAGE_HEADER_SIZE) return NULL;
    pFknForStorage=(PFULL_KNOWLEDGE_FOR_STORAGE)pbPackedFullKnowledge;
    if ((pFknForStorage->dwSinglePackedMatrixSize*2)!=(dwPackedFullKnowledgeSize-FULL_KNOWLEDGE_FOR_STORAGE_HEADER_SIZE) || pFknForStorage->dwSinglePackedMatrixSize>MAX_MATR_BYTE_SIZE) return NULL;
    pFullKnowledge=(PFULL_KNOWLEDGE)malloc(sizeof(FULL_KNOWLEDGE));
    if (pFullKnowledge==NULL) return NULL;
    pbUnpackedMatr=unpackMatrix(pFknForStorage->dwSinglePackedMatrixSize,pFknForStorage->bData,&wDimension);
    if (pbUnpackedMatr==NULL){
        free(pFullKnowledge);
        return NULL;
    }
    pFullKnowledge->wDimension=wDimension;
    pFullKnowledge->dwMatrixArraySize=((uint32_t)wDimension)*(uint32_t)wDimension;

    pFullKnowledge->pbGraphMatrix=pbUnpackedMatr;
    pbUnpackedMatr=unpackMatrix((uint16_t)pFknForStorage->dwSinglePackedMatrixSize,pFknForStorage->bData+(pFknForStorage->dwSinglePackedMatrixSize),&wDimension);
    if (pbUnpackedMatr==NULL){
        free(pFullKnowledge->pbGraphMatrix);
        free(pFullKnowledge);
        return NULL;
    }
    pFullKnowledge->pbCycleMatrix=pbUnpackedMatr;
    return pFullKnowledge;
}

/*
    uint16_t getDesiredVerticeCountFromInitialSettingPacket(uint8_t* pbInitialSettingPacket, uint32_t dwPacketSize)
    description:
        Get vertice count from inital setting packet
    arguments:
        pbInitialSettingPacket - pointer to memory containing the initial setting packet
        dwPacketSize - size of the array
    return value:
        SUCCESS - desired vertice count
        ERROR - 0
*/
uint16_t getDesiredVerticeCountFromInitialSettingPacket(uint8_t* pbInitialSettingPacket, uint32_t dwPacketSize){
    PINITIAL_SETTING_PACKET pInitialSettingPacket;
    if (dwPacketSize<sizeof(INITIAL_SETTING_PACKET)||pbInitialSettingPacket==NULL) return 0;
    pInitialSettingPacket=(PINITIAL_SETTING_PACKET)pbInitialSettingPacket;
    return pInitialSettingPacket->wVerticeCount;
}
/*
    PGRAPH_SET_PACKET createGraphSetPacket(PFULL_KNOWLEDGE pFullKnowledge,uint8_t* pbRANDOM_R, char* psbFLAG, out uint32_t* pdwGraphSetPacketSize)
    description:
        Create a GraphSet packet
    arguments:
        pFullKnowledge - pointer to FULL KNOWLEDGE structure
        pbRANDOM_R - pointer to array containing random_r from clinet
        psbFLAG - pointer to FLAG array
        pdwGraphSetPacketSize - pointer to output resulting packet size
    return value:
        SUCCESS - GraphSet packet
        FAIL - NULL
*/
PGRAPH_SET_PACKET createGraphSetPacket(PFULL_KNOWLEDGE pFullKnowledge,uint8_t* pbRANDOM_R, char* psbFLAG, out uint32_t* pdwGraphSetPacketSize){
    PGRAPH_SET_PACKET pGraphSetPacket;
    uint32_t dwGraphSetPacketSize;
    uint8_t* pbPackedMatrix;
    uint32_t dwPackedMatrixSize;
    dwPackedMatrixSize=0;
    if (pFullKnowledge==NULL || pbRANDOM_R==NULL || psbFLAG==NULL || pdwGraphSetPacketSize==NULL) return NULL; 
    pbPackedMatrix=packMatrix(pFullKnowledge->pbGraphMatrix,pFullKnowledge->wDimension,&dwPackedMatrixSize);
    if (pbPackedMatrix==NULL) return NULL;
    dwGraphSetPacketSize=GRAPH_SET_PACKET_HEADER_SIZE + dwPackedMatrixSize;
    *(pdwGraphSetPacketSize)=dwGraphSetPacketSize;
    pGraphSetPacket=(PGRAPH_SET_PACKET)calloc(dwGraphSetPacketSize,1);
    if(pGraphSetPacket==NULL){
        free(pbPackedMatrix);
        return NULL;
    }
    pGraphSetPacket->dwPackedMatrixSize=dwPackedMatrixSize;
    
    memcpy(pGraphSetPacket->FLAG,psbFLAG,FLAG_ARRAY_SIZE);
    memcpy(pGraphSetPacket->RANDOM_R,pbRANDOM_R,RANDOM_R_SIZE);
    memcpy(pGraphSetPacket->bPackedMatrixData,pbPackedMatrix,dwPackedMatrixSize);
    free(pbPackedMatrix);
    return pGraphSetPacket;
}

/*
    uint8_t* createPKCSSignature(uint8_t* pbData,uint32_t dwDataSize,uint32_t dwDesiredSignatureSize)
    description:
        Create the PKCS#1 v1.5 signature,just without the actual sign operation
    arguments:
        pbData - pointer to array containing data to sign
        dwDataSize - size of array in bytes
        dwDesiredSignatureSize - the size of the signature array
    return value:
        SUCCESS - pointer to byte array containing the signature
        FAIL - NULL
*/
uint8_t* createPKCSSignature(uint8_t* pbData,uint32_t dwDataSize,uint32_t dwDesiredSignatureSize){
    uint8_t* pbHash;
    uint8_t* pbSign;
    if (dwDesiredSignatureSize<(SHA256_SIZE+4)) return NULL;
    pbHash=sha256(pbData,(ssize_t)dwDataSize);
    if (pbHash==NULL) return NULL;
    pbSign=calloc(dwDesiredSignatureSize,1);
    if (pbSign==NULL){
        free (pbHash);
        return NULL;
    }
    memcpy(pbSign+dwDesiredSignatureSize-SHA256_SIZE,pbHash,SHA256_SIZE);
    free(pbHash);
    *pbSign=0;
    *(pbSign+1)=1;
    *(pbSign+dwDesiredSignatureSize-SHA256_SIZE-1)=0;
    memset(pbSign+2,'\xff',dwDesiredSignatureSize-SHA256_SIZE-3);
    return pbSign;
}
/*
    PPROOF_CONFIGURATION_PACKET createProofConfigurationPacket(PZKN_STATE pZKnState, out uint32_t* pdwPacketSize)
    description:
        Create PROOF CONFIGURATION PACKET, which is used for informing Prover of Verifier's demands
    arguments:
        pZKnState - pointer to zero knowledge state used by the verifier to hold configuration
        pdwPacketSize - pointer to DWORD used to store output packet size
    return value:
        SUCCESS - a pointer to memory containing the resulting packet
        FAIL - NULL
*/
PPROOF_CONFIGURATION_PACKET createProofConfigurationPacket(PZKN_STATE pZKnState, out uint32_t* pdwPacketSize){
    uint8_t* pbPackedMatrix;
    uint32_t dwPackedMatrixSize;
    uint32_t dwPacketSize;
    PPROOF_CONFIGURATION_PACKET pProofConfigurationPacket;
    if (pZKnState==NULL ||pZKnState->pZKnGraph==NULL ||pZKnState->pZKnGraph->pbGraphData==NULL|| pdwPacketSize==NULL) return NULL;
    pbPackedMatrix=packMatrix(pZKnState->pZKnGraph->pbGraphData,pZKnState->pZKnGraph->wVerticeCount,&dwPackedMatrixSize);
    if (pbPackedMatrix==NULL) return NULL;
    dwPacketSize=PROOF_CONFIGURATON_PACKET_HEADER_SIZE + (uint32_t) dwPackedMatrixSize;
    pProofConfigurationPacket=(PPROOF_CONFIGURATION_PACKET) malloc(dwPacketSize);
    if (pProofConfigurationPacket==NULL){
        free (pbPackedMatrix);
        return NULL;
    }
    pProofConfigurationPacket->bCheckCount=pZKnState->bCheckCount;
    pProofConfigurationPacket->supportedAlgorithms=pZKnState->supportedAlgorithms;
    pProofConfigurationPacket->dwPackedMatrixSize=(uint32_t)dwPackedMatrixSize;
    memcpy(pProofConfigurationPacket->bPackedMatrixData,pbPackedMatrix,(ssize_t)dwPackedMatrixSize);
    free(pbPackedMatrix);
    *pdwPacketSize=dwPacketSize;
    return pProofConfigurationPacket;
}

/*
    PPROOF_HELPER initializeProofHelper(PFULL_KNOWLEDGE pFullKnowledge, PPROOF_CONFIGURATION_PACKET pProofConfigurationPacket, uint32_t dwPacketSize, out uint8_t* pbErrorReason);
    description:
        Initialize proof helper structure holding all the data needed to construct a proof
    arguments:
        pFullKnowledge - pointer to full knowledge structure, containing information for proof construction
        pProofConfigurationPacket - pointer to structure with protocol settings recieved from the client
        dwPacketSize - self-explanatory
        pbErrorReason - in case processing encounters an error, this pointer is used to inform the caller of the reason for the error: SYSTEM-related or INPUT-related
    return value:
        SUCCESS - pointer to PROOF_HELPER structure initialized with values needed for constructing proofs
        ERROR - NULL
    fuzz status:
        FUZZED
*/
PPROOF_HELPER initializeProofHelper(PFULL_KNOWLEDGE pFullKnowledge, PPROOF_CONFIGURATION_PACKET pProofConfigurationPacket, uint32_t dwPacketSize, out uint8_t* pbErrorReason){
    PPROOF_HELPER pProofHelper;
    uint8_t* pbUnpackedMatrix;
    uint16_t wDimension;
    *(pbErrorReason)=ERROR_REASON_NONE;
    if (pFullKnowledge==NULL || pProofConfigurationPacket==NULL) {
        *(pbErrorReason)=ERROR_REASON_SYSTEM;
        return NULL;
    }
    if  (dwPacketSize<PROOF_CONFIGURATON_PACKET_HEADER_SIZE){
        *(pbErrorReason)=ERROR_REASON_WRONG_VALUE;
        return NULL;
    }
    if (pProofConfigurationPacket->bCheckCount < MINIMUM_CHECK_COUNT || pProofConfigurationPacket->bCheckCount > MAXIMUM_CHECK_COUNT){
        *pbErrorReason=ERROR_REASON_WRONG_VALUE;
        return NULL;
    }
    if (pProofConfigurationPacket->supportedAlgorithms.supportedAlgsCode==0){
        *pbErrorReason=ERROR_REASON_WRONG_VALUE;
        return NULL;
    }
    if (pProofConfigurationPacket->dwPackedMatrixSize!=(dwPacketSize-PROOF_CONFIGURATON_PACKET_HEADER_SIZE) || pProofConfigurationPacket->dwPackedMatrixSize==0){
        *pbErrorReason=ERROR_REASON_CHEATING;
        return NULL;
    }
    pbUnpackedMatrix=unpackMatrix(pProofConfigurationPacket->dwPackedMatrixSize, pProofConfigurationPacket->bPackedMatrixData,&wDimension);
    if (pbUnpackedMatrix==NULL) 
    {
        *(pbErrorReason)=ERROR_REASON_SYSTEM;
        return NULL;
    }
    if (wDimension!=pFullKnowledge->wDimension) {
        *(pbErrorReason)=ERROR_REASON_WRONG_VALUE;
        free(pbUnpackedMatrix);
        return NULL;
    }
    if (memcmp(pFullKnowledge->pbGraphMatrix,pbUnpackedMatrix,pFullKnowledge->dwMatrixArraySize)!=0){
        *(pbErrorReason)=ERROR_REASON_WRONG_VALUE;
        free(pbUnpackedMatrix);
        return NULL;
    }
    pProofHelper=(PPROOF_HELPER) malloc(sizeof(PROOF_HELPER));
    if (pProofHelper==NULL) {
        *(pbErrorReason)=ERROR_REASON_SYSTEM;
        free(pbUnpackedMatrix);
        return NULL;
    }
    pProofHelper->pFullKnowledge=pFullKnowledge;
    pProofHelper->supportedAlgorithms=pProofConfigurationPacket->supportedAlgorithms;
    pProofHelper->bCheckCount=pProofConfigurationPacket->bCheckCount;
    free(pbUnpackedMatrix);
    return pProofHelper;
}
/*
    void freeProofHelper(PPROOF_HELPER pProofHelper)
    description:
        Free Proof Helper
    arguments:
        pProofHelper - pointer to proof helper
    return value:
        N/A
*/
void freeProofHelper(PPROOF_HELPER pProofHelper){
    free(pProofHelper);
}
/*
    PSINGLE_PROOF createSingleProof(PPROOF_HELPER pProofHelper);
    description:
        Create everything needed for a single proof (Permutation, Permuted Graph Matrix, Permuted Cycle Matrix)
    arguments:
        pProofHelper - pointer to structure with everything needed to create a single proof
    return value:
        SUCCESS - pointer to SINGLE_PROOF with everything needed for a proof
        FAIL - NULL
*/
PSINGLE_PROOF createSingleProof(PPROOF_HELPER pProofHelper){
    PSINGLE_PROOF pSingleProof;
    uint8_t* pbPermutationMatrix;
    uint8_t* pbPermutedGraphMatrix;
    uint8_t* pbPermutedCycleMatrix;
    uint8_t* pbPackedMatrix;
    uint32_t dwPackedMatrixSize;
    if (pProofHelper==NULL) return NULL;
    pSingleProof=(PSINGLE_PROOF) malloc(sizeof(SINGLE_PROOF));
    if (pSingleProof==NULL) return NULL;
    pbPermutationMatrix=generatePermutationMatrix(pProofHelper->pFullKnowledge->wDimension);
    if (pbPermutationMatrix==NULL){
        free(pSingleProof);
        return NULL;
    }
#ifdef ENABLE_FOR_TEST
    printf("Started permutation\n");
#endif
    pbPermutedGraphMatrix=permuteMatrix(pbPermutationMatrix,pProofHelper->pFullKnowledge->pbGraphMatrix,pProofHelper->pFullKnowledge->wDimension);
    if (pbPermutedGraphMatrix==NULL){
        free(pSingleProof);
        free(pbPermutationMatrix);
        return NULL;
    } 
    pbPermutedCycleMatrix=permuteMatrix(pbPermutationMatrix,pProofHelper->pFullKnowledge->pbCycleMatrix,pProofHelper->pFullKnowledge->wDimension);
    if (pbPermutedCycleMatrix==NULL){
        free(pSingleProof);
        free(pbPermutationMatrix);
        free(pbPermutedGraphMatrix);
        return NULL;
    }
    
#ifdef ENABLE_FOR_TEST
    printf("Ended permutation\n");
#endif
    pbPackedMatrix=packMatrix(pbPermutationMatrix,pProofHelper->pFullKnowledge->wDimension,&dwPackedMatrixSize);
    if (pbPackedMatrix==NULL){
        free(pSingleProof);
        free(pbPermutationMatrix);
        free(pbPermutedCycleMatrix);
        free(pbPermutedGraphMatrix);
        return NULL;
    }
    pSingleProof->dwPackedMatrixSize=dwPackedMatrixSize;
    pSingleProof->pbPackedPermutationMatrix=pbPackedMatrix;
    free(pbPermutationMatrix);
    
    pbPackedMatrix=packMatrix(pbPermutedGraphMatrix,pProofHelper->pFullKnowledge->wDimension,&dwPackedMatrixSize);
    if (pbPackedMatrix==NULL||dwPackedMatrixSize!=pSingleProof->dwPackedMatrixSize){
        free(pSingleProof->pbPackedPermutationMatrix);
        free(pSingleProof);
        free(pbPermutedCycleMatrix);
        free(pbPermutedGraphMatrix);
        return NULL;
    }
    pSingleProof->pbPackedPermutedGraphMatrix=pbPackedMatrix;
    free(pbPermutedGraphMatrix);
    
    pbPackedMatrix=packMatrix(pbPermutedCycleMatrix,pProofHelper->pFullKnowledge->wDimension,&dwPackedMatrixSize);
    if (pbPackedMatrix==NULL||dwPackedMatrixSize!=pSingleProof->dwPackedMatrixSize){
        free(pSingleProof->pbPackedPermutationMatrix);
        free(pSingleProof->pbPackedPermutedGraphMatrix);
        free(pSingleProof);
        free(pbPermutedCycleMatrix);
        return NULL;
    }
    pSingleProof->pbPackedPermutedCycleMatrix=pbPackedMatrix;
    free(pbPermutedCycleMatrix);

    return pSingleProof;
}

/*
    void freeSingleProof(PSINGLE_PROOF pSingleProof)
    description:
        Destroy single proof and free all its members
    arguments:
        pSingleProof - pointer to SINGLE_PROOF
    return value:
        N/A
*/
void freeSingleProof(PSINGLE_PROOF pSingleProof){
    if (pSingleProof==NULL) return;
    free(pSingleProof->pbPackedPermutationMatrix);
    free(pSingleProof->pbPackedPermutedCycleMatrix);
    free(pSingleProof->pbPackedPermutedGraphMatrix);
    free(pSingleProof);
}

/*
    PSINGLE_PROOF* createProofsForOneRound(PPROOF_HELPER pProofHelper)
    definition:
        Create an array of single proofs enough for one round
    arguments:
        pProofHelper - pointer to structure containing enough information to create proofs
    return value:
        SUCCESS - pointer to array of PSINGLE_PROOF(s) enough for one round
        FAIL - NULL
*/
PSINGLE_PROOF* createProofsForOneRound(PPROOF_HELPER pProofHelper){
    PSINGLE_PROOF* pProofArray;
    PSINGLE_PROOF pSingleProof;
    uint8_t bIndex,bJndex;
    if (pProofHelper==NULL) return NULL;
    pProofArray=(PSINGLE_PROOF*)malloc(sizeof(SINGLE_PROOF)*(uint32_t)(pProofHelper->bCheckCount));
    if (pProofArray==NULL) return NULL;
    for (bIndex=0;bIndex<pProofHelper->bCheckCount;bIndex=bIndex+1){
#ifdef ENABLE_FOR_TEST
        printf("Currently creating proof %hhd\n",bIndex);
#endif
        pSingleProof=createSingleProof(pProofHelper);
        if (pSingleProof==NULL) break;
        pProofArray[bIndex]=pSingleProof;
    }
    if (bIndex!=pProofHelper->bCheckCount){
        for (bJndex=0;bJndex<bIndex;bJndex=bJndex+1){
            freeSingleProof(pProofArray[bJndex]);
        }
        free(pProofArray);
        return NULL;
    }
    return pProofArray;
}


/*
    void freeProofsForOneRound(PSINGLE_PROOF* pProofArray,PPROOF_HELPER pProofHelper)
    description:
        Free all previously created proofs
    arguments:
        pProofArray - pointer to array of PSINGLE_PROOF, which we want to free along with proofs
        pProofHelper - pointer to proof helper structure (needed to get the number of PSINGLE_PROOF)
    return value:
        N\A
*/
void freeProofsForOneRound(PSINGLE_PROOF* pProofArray,PPROOF_HELPER pProofHelper){
    uint8_t bIndex;
    if (pProofArray==NULL || pProofHelper==NULL) return;
    for (bIndex=0;bIndex<pProofHelper->bCheckCount;bIndex=bIndex+1){
        freeSingleProof(pProofArray[bIndex]);
    }
    free(pProofArray);
}

/*
    uint8_t* createSingleCRC32Commitment(PSINGLE_PROOF pSingleProof,  out uint32_t* pdwSingleCommitmentSize)
    description:
        Create a single commitment with CRC32 hash
    arguments:
        pSingleProof - pointer to structure containing permutation, permuted graph and permuted cycle
        pdwSingleCommitmentSize - for informing the caller of resulting size
    return value:
        SUCCESS - pointer to commiment data
        FAIL - NULL
*/
uint8_t* createSingleCRC32Commitment(PSINGLE_PROOF pSingleProof,  out uint32_t* pdwSingleCommitmentSize){
    uint32_t dwSingleCommitmentSize;
    PCRC32_COMMITMENT pCRC32Commitment;
    uint8_t* pCRC32;
    dwSingleCommitmentSize=sizeof(CRC32_COMMITMENT);
    pCRC32Commitment=(PCRC32_COMMITMENT)malloc(dwSingleCommitmentSize);
    if (pCRC32Commitment==NULL) return NULL;
    pCRC32=crc32(pSingleProof->pbPackedPermutationMatrix,pSingleProof->dwPackedMatrixSize);
    if (pCRC32==NULL){
        free(pCRC32Commitment);
        return NULL;
    }
    memcpy(pCRC32Commitment->permutationCRC32,pCRC32,CRC32_SIZE);
    free(pCRC32);
    pCRC32=crc32(pSingleProof->pbPackedPermutedGraphMatrix,pSingleProof->dwPackedMatrixSize);
    if (pCRC32==NULL){
        free(pCRC32Commitment);
        return NULL;
    }
    memcpy(pCRC32Commitment->permutedGraphCRC32,pCRC32,CRC32_SIZE);
    free(pCRC32);
    pCRC32=crc32(pSingleProof->pbPackedPermutedCycleMatrix,pSingleProof->dwPackedMatrixSize);
    if (pCRC32==NULL){
        free(pCRC32Commitment);
        return NULL;
    }
    memcpy(pCRC32Commitment->permutedCycleCRC32,pCRC32,CRC32_SIZE);
    free(pCRC32);
    *pdwSingleCommitmentSize=dwSingleCommitmentSize;
    return (uint8_t*)pCRC32Commitment;
}

/*
    uint8_t* createCRC32CommitmentRound(PSINGLE_PROOF* pProofArray, PPROOF_HELPER pProofHelper, out uint32_t* pdwCommitmentDataSize)
    description:
        Create multiple CRC32 commitments from proof array and put them into one blob
    arguments:
        pProofArray - array of single prrofs
        pProofHelper - additional information for proods
        pdwCommitmentDataSize - for telling the caller output array size
    return value:
        SUCCESS - pointer to blob containing commitments
        FAIL - NULL
*/
uint8_t* createCRC32CommitmentRound(PSINGLE_PROOF* pProofArray, PPROOF_HELPER pProofHelper, out uint32_t* pdwCommitmentDataSize){
    uint8_t* pCommitmentArray=NULL;
    uint32_t dwCommitmentRoundDataSize=0;
    uint32_t dwSingleCommitmentSize;
    uint8_t* pSingleCommitment;
    uint8_t bIndex;
    for (bIndex=0;bIndex<pProofHelper->bCheckCount;bIndex=bIndex+1){
#ifdef ENABLE_FOR_TEST
        printf("Currently creating commitment %hhd\n",bIndex);
#endif
        pSingleCommitment=createSingleCRC32Commitment(pProofArray[bIndex], &dwSingleCommitmentSize);
        if (pSingleCommitment==NULL){
            free(pCommitmentArray);
            return NULL;
        }
        pCommitmentArray=realloc(pCommitmentArray,dwSingleCommitmentSize+dwCommitmentRoundDataSize);
        memcpy(pCommitmentArray+dwCommitmentRoundDataSize,pSingleCommitment,dwSingleCommitmentSize);
        dwCommitmentRoundDataSize=dwCommitmentRoundDataSize+dwSingleCommitmentSize;
        free(pSingleCommitment);
    }
    *pdwCommitmentDataSize=dwCommitmentRoundDataSize;
    return pCommitmentArray;
}

/*
    uint8_t* createSingleSHA256Commitment(PSINGLE_PROOF pSingleProof,  out uint32_t* pdwSingleCommitmentSize)
    description:
        Create a single commitment with SHA256 hash
    arguments:
        pSingleProof - pointer to structure containing permutation, permuted graph and permuted cycle
        pdwSingleCommitmentSize - for informing the caller of resulting size
    return value:
        SUCCESS - pointer to commiment data
        FAIL - NULL
*/
 uint8_t* createSingleSHA256Commitment(PSINGLE_PROOF pSingleProof,  out uint32_t* pdwSingleCommitmentSize){
    uint32_t dwSingleCommitmentSize;
    PSHA256_COMMITMENT pSHA256Commitment;
    uint8_t* pSHA256;
    dwSingleCommitmentSize=sizeof(SHA256_COMMITMENT);
    pSHA256Commitment=(PSHA256_COMMITMENT)malloc(dwSingleCommitmentSize);
    if (pSHA256Commitment==NULL) return NULL;
    pSHA256=sha256(pSingleProof->pbPackedPermutationMatrix,pSingleProof->dwPackedMatrixSize);
    if (pSHA256==NULL){
        free(pSHA256Commitment);
        return NULL;
    }
    memcpy(pSHA256Commitment->permutationSHA256,pSHA256,SHA256_SIZE);
    free(pSHA256);
    pSHA256=sha256(pSingleProof->pbPackedPermutedGraphMatrix,pSingleProof->dwPackedMatrixSize);
    if (pSHA256==NULL){
        free(pSHA256Commitment);
        return NULL;
    }
    memcpy(pSHA256Commitment->permutedGraphSHA256,pSHA256,SHA256_SIZE);
    free(pSHA256);
    pSHA256=sha256(pSingleProof->pbPackedPermutedCycleMatrix,pSingleProof->dwPackedMatrixSize);
    if (pSHA256==NULL){
        free(pSHA256Commitment);
        return NULL;
    }
    memcpy(pSHA256Commitment->permutedCycleSHA256,pSHA256,SHA256_SIZE);
    free(pSHA256);
    *pdwSingleCommitmentSize=dwSingleCommitmentSize;
    return (uint8_t*)pSHA256Commitment;
}

/*
    uint8_t* createSHA256CommitmentRound(PSINGLE_PROOF* pProofArray, PPROOF_HELPER pProofHelper, out uint32_t* pdwCommitmentDataSize)
    description:
        Create multiple SHA256 commitments from proof array and put them into one blob
    arguments:
        pProofArray - array of single prrofs
        pProofHelper - additional information for proods
        pdwCommitmentDataSize - for telling the caller output array size
    return value:
        SUCCESS - pointer to blob containing commitments
        FAIL - NULL
*/
uint8_t* createSHA256CommitmentRound(PSINGLE_PROOF* pProofArray, PPROOF_HELPER pProofHelper, out uint32_t* pdwCommitmentDataSize){
    uint8_t* pCommitmentArray=NULL;
    uint32_t dwCommitmentRoundDataSize=0;
    uint32_t dwSingleCommitmentSize;
    uint8_t* pSingleCommitment;
    uint8_t bIndex;
    for (bIndex=0;bIndex<pProofHelper->bCheckCount;bIndex=bIndex+1){
        pSingleCommitment=createSingleSHA256Commitment(pProofArray[bIndex], &dwSingleCommitmentSize);
        if (pSingleCommitment==NULL){
            free(pCommitmentArray);
            return NULL;
        }
        pCommitmentArray=realloc(pCommitmentArray,dwSingleCommitmentSize+dwCommitmentRoundDataSize);
        memcpy(pCommitmentArray+dwCommitmentRoundDataSize,pSingleCommitment,dwSingleCommitmentSize);
        dwCommitmentRoundDataSize=dwCommitmentRoundDataSize+dwSingleCommitmentSize;
        free(pSingleCommitment);
    }
    *pdwCommitmentDataSize=dwCommitmentRoundDataSize;
    return pCommitmentArray;
}

/*
    PAES_COMMITMENT createSingleAESCommitment(PSINGLE_PROOF pSingleProof, out uint32_t* pdwCommitmentSize, \
        out PSINGLE_AES_COMMITMENT_EXTRA_INFORMATION* ppSingleAesCommitmentExtraInformation)
    description:
        Create a single AES commitment
    arguments:
        pSingleProof - pointer to permutation / permuted graph / permuted cycle data
        pdwCommitmentSize - for outputing size of output data
        ppSingleAesCommitmentExtraInformation - pointer for outputing extra information for unpacking commitment (keys)
    return value:
        SUCCESS - pointer to comitment data
        FAIL - NULL
*/
PAES_COMMITMENT createSingleAESCommitment(PSINGLE_PROOF pSingleProof, out uint32_t* pdwCommitmentSize, \
out PSINGLE_AES_COMMITMENT_EXTRA_INFORMATION* ppSingleAesCommitmentExtraInformation){
    PSINGLE_AES_COMMITMENT_EXTRA_INFORMATION pExtraInformation;
    PAES_COMMITMENT pAESCommitment;
    uint8_t* pbEncryptedPermutationData;
    uint8_t* pbEncryptedCycleData;
    uint32_t dwEncryptedPermutationDataSize;
    uint32_t dwEncryptedCycleDataSize;
    uint32_t dwSingleCommitmentSize;
    unsigned char IV1[AES_IV_SIZE];
    unsigned char IV2[AES_IV_SIZE];
    if (pSingleProof==NULL || ppSingleAesCommitmentExtraInformation==NULL) return NULL;
    pExtraInformation=(PSINGLE_AES_COMMITMENT_EXTRA_INFORMATION)malloc(sizeof(SINGLE_AES_COMMITMENT_EXTRA_INFORMATION));
    if (pExtraInformation==NULL) return NULL;
    getRandomBytes(IV1,AES_IV_SIZE);
    getRandomBytes(IV2,AES_IV_SIZE);
    getRandomBytes(pExtraInformation->permutationKey,AES128_KEY_SIZE);
    getRandomBytes(pExtraInformation->permutedCycleKey,AES128_KEY_SIZE);
    pbEncryptedPermutationData=aes128cbc_encrypt(pSingleProof->pbPackedPermutationMatrix,pSingleProof->dwPackedMatrixSize, \
        pExtraInformation->permutationKey,IV1,&dwEncryptedPermutationDataSize);
    if (pbEncryptedPermutationData==NULL){
        free(pExtraInformation);
        return NULL;
    }
    pbEncryptedCycleData=aes128cbc_encrypt(pSingleProof->pbPackedPermutedCycleMatrix,pSingleProof->dwPackedMatrixSize, \
        pExtraInformation->permutedCycleKey,IV2,&dwEncryptedCycleDataSize);
    if (pbEncryptedPermutationData==NULL || dwEncryptedCycleDataSize!=dwEncryptedPermutationDataSize){
        free(pbEncryptedCycleData);
        free(pbEncryptedPermutationData);
        free(pExtraInformation);
        return NULL;
    }
    dwSingleCommitmentSize=AES_COMMITMENT_HEADER_SIZE+2*dwEncryptedPermutationDataSize+pSingleProof->dwPackedMatrixSize;
    pAESCommitment=(PAES_COMMITMENT)malloc(dwSingleCommitmentSize);
    if (pAESCommitment==NULL){
        free(pbEncryptedCycleData);
        free(pbEncryptedPermutationData);
        free(pExtraInformation);
        return NULL;
    }
    pAESCommitment->dwPackedPermutedMatrixSize=pSingleProof->dwPackedMatrixSize;
    pAESCommitment->dwSingleCiphertextPlusIVSize=dwEncryptedCycleDataSize;
    memcpy(pAESCommitment->commitmentData,pbEncryptedPermutationData,dwEncryptedPermutationDataSize);
    memcpy(pAESCommitment->commitmentData+dwEncryptedPermutationDataSize,pbEncryptedCycleData,dwEncryptedCycleDataSize);
    memcpy(pAESCommitment->commitmentData+dwEncryptedPermutationDataSize+dwEncryptedCycleDataSize,pSingleProof->pbPackedPermutedGraphMatrix,pSingleProof->dwPackedMatrixSize);
    *pdwCommitmentSize=dwSingleCommitmentSize;
    *ppSingleAesCommitmentExtraInformation=pExtraInformation;
    free(pbEncryptedCycleData);
    free(pbEncryptedPermutationData);
    return pAESCommitment; 
}

/*
    uint8_t* createAESCommitmentRound(PSINGLE_PROOF* pProofArray, PPROOF_HELPER pProofHelper, out uint32_t* pdwCommitmentDataSize, \
        out PCOMMITMENT_EXTRA_INFORMATION* ppCommitmentExtraInformation)
    description:
        Create a full round worth of AES commitments
    arguments:
        pProofArray - array with proofs for each commitment
        pProofHelper - additional information for proofs
        pdwCommitmentDataSize - returns output array size to the caller
        ppCommitmentExtraInformation - key information ouput for unpacking commitment
    return value:
        SUCCESS - pointer to AES commitment data
        FAIL - NULL
*/
uint8_t* createAESCommitmentRound(PSINGLE_PROOF* pProofArray, PPROOF_HELPER pProofHelper, out uint32_t* pdwCommitmentDataSize, \
out PCOMMITMENT_EXTRA_INFORMATION* ppCommitmentExtraInformation){
    PSINGLE_AES_COMMITMENT_EXTRA_INFORMATION* pAESExtraInformationArray;
    PCOMMITMENT_EXTRA_INFORMATION pCommitmentExtraInformation;
    uint32_t dwTotalCommitmentDataSize=0;
    uint32_t dwCurrentCommitmentSize;
    uint8_t* pbCommitmentRoundData=NULL;
    uint8_t* pbCurrentCommitment;
    uint8_t bIndex,bJndex;
    pAESExtraInformationArray=(PSINGLE_AES_COMMITMENT_EXTRA_INFORMATION*)malloc(sizeof(PSINGLE_AES_COMMITMENT_EXTRA_INFORMATION)*(uint32_t)pProofHelper->bCheckCount);
    if (pAESExtraInformationArray==NULL) return NULL;
    pCommitmentExtraInformation=(PCOMMITMENT_EXTRA_INFORMATION)malloc(sizeof(COMMITMENT_EXTRA_INFORMATION));
    
    *ppCommitmentExtraInformation=pCommitmentExtraInformation;
    if (pCommitmentExtraInformation==NULL){
        free(pAESExtraInformationArray);
        return NULL;
    }
    pCommitmentExtraInformation->dwDataSize=sizeof(PSINGLE_AES_COMMITMENT_EXTRA_INFORMATION)*(uint32_t)pProofHelper->bCheckCount;
    pCommitmentExtraInformation->pbData=(uint8_t*)pAESExtraInformationArray;
    for(bIndex=0;bIndex<pProofHelper->bCheckCount;bIndex=bIndex+1){
        pbCurrentCommitment=(uint8_t*)createSingleAESCommitment(pProofArray[bIndex],&dwCurrentCommitmentSize,&pAESExtraInformationArray[bIndex]);
        if (pbCurrentCommitment==NULL){
            for (bJndex=0;bJndex<bIndex;bJndex=bJndex+1){
                free(pAESExtraInformationArray[bJndex]);
            }
            free(pAESExtraInformationArray);
            free(pbCommitmentRoundData);
            return NULL;
        }
       pbCommitmentRoundData=realloc(pbCommitmentRoundData,dwTotalCommitmentDataSize+dwCurrentCommitmentSize);
       if (pbCommitmentRoundData==NULL){
            for (bJndex=0;bJndex<bIndex;bJndex=bJndex+1){
                free(pAESExtraInformationArray[bJndex]);
            }
            free(pAESExtraInformationArray);
            return NULL;
       } 
       memcpy(pbCommitmentRoundData+dwTotalCommitmentDataSize,pbCurrentCommitment,dwCurrentCommitmentSize);
       free(pbCurrentCommitment);
       dwTotalCommitmentDataSize=dwTotalCommitmentDataSize+dwCurrentCommitmentSize;
    }
   *pdwCommitmentDataSize=dwTotalCommitmentDataSize;
   return pbCommitmentRoundData; 
}


/*
    void freeCommitmentExtraInformation(PPROOF_HELPER pProofHelper, PCOMMITMENT_EXTRA_INFORMATION pCommitmentExtraInformation)
    description:
        Free commitment extra information structure and its members
    arguments:
        pCommitmentExtraInformation - pointer to COMMITMENT_EXTRA_INFORMATION to free
    return value:
        N/A
*/
void freeCommitmentExtraInformation(PPROOF_HELPER pProofHelper,PCOMMITMENT_EXTRA_INFORMATION pCommitmentExtraInformation){
    if (pCommitmentExtraInformation==NULL) return;
    uint8_t bIndex;
    PSINGLE_AES_COMMITMENT_EXTRA_INFORMATION* pArray;
    pArray=(PSINGLE_AES_COMMITMENT_EXTRA_INFORMATION*)pCommitmentExtraInformation->pbData;
    for (bIndex=0;bIndex<pProofHelper->bCheckCount;bIndex=bIndex+1){
       free(pArray[bIndex]); 
    }
    free(pCommitmentExtraInformation->pbData);
    free(pCommitmentExtraInformation);
}

/*
    PCOMMITMENT_PACKET createCommitmentPacket(PSINGLE_PROOF* pProofArray,PPROOF_HELPER pProofHelper,out uint32_t* pdwCommitmentPacketSize, \
        out PCOMMITMENT_EXTRA_INFORMATION* ppCommitmentExtraInformation)
    description:
        Create Full Round commitment packet
    arguments:
        pProofArray - array of pointers to single proofs
        pProofHelper - all additional information
        pdwCommitmentPacketSize - output packet size
        ppCommitmentExtraInformation - output additional data for unpacking commitment (needed for aes commitment)
    return value
        SUCCESS - commitment packet
        FAIL - NULL
*/
PCOMMITMENT_PACKET createCommitmentPacket(PSINGLE_PROOF* pProofArray,PPROOF_HELPER pProofHelper,out uint32_t* pdwCommitmentPacketSize, \
out PCOMMITMENT_EXTRA_INFORMATION* ppCommitmentExtraInformation){
    //PCOMMITMENT_PACKET pCommitmentPacket;
    COMMITMENT_ALGORITHMS commitmentAlgs;
    PCOMMITMENT_PACKET pCommitmentPacket;
    uint32_t dwCommitmentDataSize;
    uint32_t dwResultingPacketSize;
    uint8_t* pbCommitmentData;
    if (pProofArray==NULL || pProofHelper==NULL || ppCommitmentExtraInformation==NULL) return NULL;
    *ppCommitmentExtraInformation=NULL;
    commitmentAlgs=pProofHelper->supportedAlgorithms;
    if(commitmentAlgs.isCRC32Supported){
        pbCommitmentData=createCRC32CommitmentRound(pProofArray,pProofHelper,&dwCommitmentDataSize);
        if (pbCommitmentData==NULL) return NULL;
        dwResultingPacketSize=dwCommitmentDataSize+COMMITMENT_PACKET_HEADER_SIZE;
        pCommitmentPacket=(PCOMMITMENT_PACKET)malloc(dwResultingPacketSize);
        if (pCommitmentPacket==NULL){
            free(pbCommitmentData);
            return NULL;
        }
        pCommitmentPacket->bCommitmentCount=pProofHelper->bCheckCount;
        commitmentAlgs.supportedAlgsCode=0;
        commitmentAlgs.isCRC32Supported=1;
        pCommitmentPacket->commitmentType=commitmentAlgs;
        pCommitmentPacket->dwDataSize=dwCommitmentDataSize;
        memcpy(pCommitmentPacket->commitmentData,pbCommitmentData,dwCommitmentDataSize);
        free(pbCommitmentData);
        *pdwCommitmentPacketSize=dwResultingPacketSize;
        return pCommitmentPacket;
    }else{
        if (commitmentAlgs.isSHA256Supported){
            pbCommitmentData=createSHA256CommitmentRound(pProofArray,pProofHelper,&dwCommitmentDataSize);
            if (pbCommitmentData==NULL) return NULL;
            dwResultingPacketSize=dwCommitmentDataSize+COMMITMENT_PACKET_HEADER_SIZE;
            pCommitmentPacket=(PCOMMITMENT_PACKET)malloc(dwResultingPacketSize);
            if (pCommitmentPacket==NULL){
                free(pbCommitmentData);
                return NULL;
            }
            pCommitmentPacket->bCommitmentCount=pProofHelper->bCheckCount;
            commitmentAlgs.supportedAlgsCode=0;
            commitmentAlgs.isSHA256Supported=1;
            pCommitmentPacket->commitmentType=commitmentAlgs;
            pCommitmentPacket->dwDataSize=dwCommitmentDataSize;
            memcpy(pCommitmentPacket->commitmentData,pbCommitmentData,dwCommitmentDataSize);
            free(pbCommitmentData);
            *pdwCommitmentPacketSize=dwResultingPacketSize;
            return pCommitmentPacket;    
        }
        else{
            if (commitmentAlgs.isAESSupported){
                pbCommitmentData=createAESCommitmentRound(pProofArray,pProofHelper,&dwCommitmentDataSize,ppCommitmentExtraInformation);
                if (pbCommitmentData==NULL) return NULL;
                dwResultingPacketSize=dwCommitmentDataSize+COMMITMENT_PACKET_HEADER_SIZE;
                pCommitmentPacket=(PCOMMITMENT_PACKET)malloc(dwResultingPacketSize);
                if (pCommitmentPacket==NULL){
                    free(pbCommitmentData);
                    free(*ppCommitmentExtraInformation);
                    *ppCommitmentExtraInformation=NULL;
                    return NULL;
                }
                pCommitmentPacket->bCommitmentCount=pProofHelper->bCheckCount;
                commitmentAlgs.supportedAlgsCode=0;
                commitmentAlgs.isAESSupported=1;
                pCommitmentPacket->commitmentType=commitmentAlgs;
                pCommitmentPacket->dwDataSize=dwCommitmentDataSize;
                memcpy(pCommitmentPacket->commitmentData,pbCommitmentData,dwCommitmentDataSize);
                free(pbCommitmentData);
                *pdwCommitmentPacketSize=dwResultingPacketSize;
                return pCommitmentPacket;
            }else{
                return NULL;
            }
        }
    }

}
/*
    uint8_t saveCommitment(PZKN_STATE pZKnState,PZKN_PROTOCOL_STATE pZKnProtocolState,uint8_t* pbCommitmentData, uint32_t dwCommitmentDataSize)
    description:
        Save commitment for the proof (copy data)
    arguments:
        pZKnState - pointer to structure holding general configuration
        pZKnProtocolState - pointer to protocol state structure
        pbCommitmentData - pointer to commitment data
        dwCommitmentDataSize - size of commitment data
    return value
        SUCCESS - SUCCESS
        FAIL - ERROR_SYSTEM if something on a system level went wrong
                ERROR_BAD_VALUE if simulation is disabled and commitment has already been saved        
*/
uint8_t saveCommitment(PZKN_STATE pZKnState,PZKN_PROTOCOL_STATE pZKnProtocolState,uint8_t* pbCommitmentData, uint32_t dwCommitmentDataSize){
    if (pZKnState==NULL || pZKnProtocolState==NULL || pbCommitmentData==NULL) return ERROR_SYSTEM;
    if (dwCommitmentDataSize<COMMITMENT_PACKET_HEADER_SIZE) return ERROR_BAD_VALUE;
    if (pZKnProtocolState->protocolProgress.isCommitmentStageComplete ){
        if ((pZKnState->simulationDisabled)!=0){
            return ERROR_BAD_VALUE;
        }
        free(pZKnProtocolState->pbCommitmentData);
    }
    pZKnProtocolState->pbCommitmentData=(uint8_t*)malloc(dwCommitmentDataSize);
    if (pZKnProtocolState->pbCommitmentData==NULL) return ERROR_SYSTEM;
    memcpy(pZKnProtocolState->pbCommitmentData,pbCommitmentData,dwCommitmentDataSize);
    pZKnProtocolState->dwCommitmentDataSize=dwCommitmentDataSize;
    pZKnProtocolState->protocolProgress.isCommitmentStageComplete=1;
    return SUCCESS;
}

/*
    PCHALLENGE_PACKET createChallenge(PZKN_STATE pZKnState, PZKN_PROTOCOL_STATE pZKnProtocolState, out uint32_t* pdwPacketSize)
    description:
        Generate challenge (random bits) to send to the prover
    arguments:
        pZKnState - pointer to structure holding general configuration
        pZKnProtocolState - pointer to protocol state structure
        pdwPacketSize - for output; packet size
    return value:
        SUCCESS - pointer to challenge packet
        FAIL - NULL
*/
PCHALLENGE_PACKET createChallenge(PZKN_STATE pZKnState, PZKN_PROTOCOL_STATE pZKnProtocolState, out uint32_t* pdwPacketSize){
    uint64_t dwRandom;
    uint8_t bBitLength;
    PCHALLENGE_PACKET pChallengePacket;
    if (pZKnState==NULL || pZKnProtocolState==NULL) return NULL;
    if (pZKnProtocolState->protocolProgress.isCommitmentStageComplete!=1) return NULL;
    pChallengePacket=(PCHALLENGE_PACKET)calloc(1,sizeof(CHALLENGE_PACKET));
    if (pChallengePacket==NULL) return NULL;
    dwRandom=generateRandomUpTo64Bits(pZKnProtocolState->pLegendrePRNG,pZKnState->bCheckCount);
    bBitLength=pZKnState->bCheckCount;
    pZKnProtocolState->qwRandom=dwRandom;
    pChallengePacket->qwRandom=dwRandom;
    pChallengePacket->bBitCount=bBitLength;
    *pdwPacketSize=sizeof(CHALLENGE_PACKET);
    pZKnProtocolState->protocolProgress.isRandomnessStageComplete=1;
    return pChallengePacket;
}

/*
    PCRC32_REVEAL createSingleCRC32Reveal(PSINGLE_PROOF pSingleProof,uint8_t bBit, out uint32_t* pdwRevealSize)
    description:
        Create single reveal for CRC32
    arguments:
        pSingleProof - pointer to proof information
        bBut - chosen bit
        pdwRevealSize - for saving output size
    return value:
        SUCCESS - pointer to commitment data
        FAIL - NULL
*/
PCRC32_REVEAL createSingleCRC32Reveal(PSINGLE_PROOF pSingleProof,uint8_t bBit, out uint32_t* pdwRevealSize){
    PCRC32_REVEAL pCRC32Reveal;
    if (pSingleProof==NULL || pdwRevealSize==NULL) return NULL;
    pCRC32Reveal=(PCRC32_REVEAL)malloc(pSingleProof->dwPackedMatrixSize*2+CRC32_REVEAL_HEADER_SIZE);
    if (pCRC32Reveal==NULL) return NULL;
    memcpy(pCRC32Reveal->packedPermutedGraphAndPermutationOrCycle,pSingleProof->pbPackedPermutedGraphMatrix,pSingleProof->dwPackedMatrixSize);
    if (bBit==0){
        memcpy(pCRC32Reveal->packedPermutedGraphAndPermutationOrCycle+pSingleProof->dwPackedMatrixSize,pSingleProof->pbPackedPermutationMatrix,pSingleProof->dwPackedMatrixSize);
    }else{
        memcpy(pCRC32Reveal->packedPermutedGraphAndPermutationOrCycle+pSingleProof->dwPackedMatrixSize,pSingleProof->pbPackedPermutedCycleMatrix,pSingleProof->dwPackedMatrixSize);
    }
    pCRC32Reveal->dwPackedMatrixSize=pSingleProof->dwPackedMatrixSize;
    *pdwRevealSize=pSingleProof->dwPackedMatrixSize*2+CRC32_REVEAL_HEADER_SIZE;
    return pCRC32Reveal;
}

/*
    uint8_t* createCRC32RevealRound(PSINGLE_PROOF* pProofArray, PCHALLENGE_PACKET pChallengePacket, out uint32_t* pdwRevealSize)
    description:
        Create full round worth of crc32 reveal
    arguments:
        pProofArray - pointer to array of single proofs
        pChallengePacket - pointert to challenge packet
        pdwRevealSize - pointer for outputing size for ouput data
    return value:
        SUCCESS - pointer to full reveal round
        FAIL - NULL
*/
uint8_t* createCRC32RevealRound(PSINGLE_PROOF* pProofArray, PCHALLENGE_PACKET pChallengePacket, out uint32_t* pdwRevealSize){
    uint8_t* pbRevealRound=NULL;
    uint32_t dwTotalRevealSize=0;
    uint32_t dwCurrentRevealSize;
    uint8_t bIndex;
    uint64_t qwCurrentBit;
    PCRC32_REVEAL pSingleReveal;
    if (pProofArray==NULL || pChallengePacket==NULL || pdwRevealSize==NULL ) return NULL;
    qwCurrentBit=pChallengePacket->qwRandom;
    for (bIndex=0;bIndex<pChallengePacket->bBitCount; bIndex=bIndex+1){
        pSingleReveal=createSingleCRC32Reveal(pProofArray[bIndex],(uint8_t)(qwCurrentBit&1),&dwCurrentRevealSize);
        qwCurrentBit=qwCurrentBit>>1;
        if (pSingleReveal==NULL){
            free(pbRevealRound);
            return NULL;
        }
        pbRevealRound=(uint8_t*)realloc(pbRevealRound,dwTotalRevealSize+dwCurrentRevealSize);
        if (pbRevealRound==NULL) {
            free(pSingleReveal);
            return NULL;
        }
        memcpy(pbRevealRound+dwTotalRevealSize,(uint8_t*)pSingleReveal,dwCurrentRevealSize);
        free(pSingleReveal);
        dwTotalRevealSize=dwTotalRevealSize+dwCurrentRevealSize;
    }
    *pdwRevealSize=dwTotalRevealSize;
    return pbRevealRound;
}

/*
    PCRC32_UNPACK_COMMITMENT createSingleSHA256Reveal(PSINGLE_PROOF pSingleProof,uint8_t bBit, out uint32_t* pdwRevealSize)
    description:
        Create single reveal for SHA256
    arguments:
        pSingleProof - pointer to proof information
        bBut - chosen bit
        pdwRevealSize - for saving output size
    return value:
        SUCCESS - pointer to commitment data
        FAIL - NULL
*/
PSHA256_REVEAL createSingleSHA256Reveal(PSINGLE_PROOF pSingleProof,uint8_t bBit, out uint32_t* pdwRevealSize){
    PSHA256_REVEAL pSHA256Reveal;
    if (pSingleProof==NULL || pdwRevealSize==NULL) return NULL;
    pSHA256Reveal=(PSHA256_REVEAL)malloc(pSingleProof->dwPackedMatrixSize*2+SHA256_REVEAL_HEADER_SIZE);
    if (pSHA256Reveal==NULL) return NULL;
    memcpy(pSHA256Reveal->packedPermutedGraphAndPermutationOrCycle,pSingleProof->pbPackedPermutedGraphMatrix,pSingleProof->dwPackedMatrixSize);
    if (bBit==0){
        memcpy(pSHA256Reveal->packedPermutedGraphAndPermutationOrCycle+pSingleProof->dwPackedMatrixSize,pSingleProof->pbPackedPermutationMatrix,pSingleProof->dwPackedMatrixSize);
    }else{
        memcpy(pSHA256Reveal->packedPermutedGraphAndPermutationOrCycle+pSingleProof->dwPackedMatrixSize,pSingleProof->pbPackedPermutedCycleMatrix,pSingleProof->dwPackedMatrixSize);
    }
    pSHA256Reveal->dwPackedMatrixSize=pSingleProof->dwPackedMatrixSize;
    *pdwRevealSize=pSingleProof->dwPackedMatrixSize*2+SHA256_REVEAL_HEADER_SIZE;
    return pSHA256Reveal;
}

/*
    uint8_t* createSHA256RevealRound(PSINGLE_PROOF* pProofArray, PCHALLENGE_PACKET pChallengePacket, out uint32_t* pdwRevealSize)
    description:
        Create full round worth of sha256 reveal
    arguments:
        pProofArray - pointer to array of single proofs
        pChallengePacket - pointert to challenge packet
        pdwRevealSize - pointer for outputing size for ouput data
    return value:
        SUCCESS - pointer to full reveal round
        FAIL - NULL
*/
uint8_t* createSHA256RevealRound(PSINGLE_PROOF* pProofArray, PCHALLENGE_PACKET pChallengePacket, out uint32_t* pdwRevealSize){
    uint8_t* pbRevealRound=NULL;
    uint32_t dwTotalRevealSize=0;
    uint32_t dwCurrentRevealSize;
    uint8_t bIndex;
    uint64_t qwCurrentBit;
    PSHA256_REVEAL pSingleReveal;
    if (pProofArray==NULL || pChallengePacket==NULL || pdwRevealSize==NULL ) return NULL;
    qwCurrentBit=pChallengePacket->qwRandom;
    for (bIndex=0;bIndex<pChallengePacket->bBitCount; bIndex=bIndex+1){
        pSingleReveal=createSingleSHA256Reveal(pProofArray[bIndex],(uint8_t)(qwCurrentBit&1),&dwCurrentRevealSize);
        qwCurrentBit=qwCurrentBit>>1;
        if (pSingleReveal==NULL){
            free(pbRevealRound);
            return NULL;
        }
        pbRevealRound=(uint8_t*)realloc(pbRevealRound,dwTotalRevealSize+dwCurrentRevealSize);
        if (pbRevealRound==NULL) {
            free(pSingleReveal);
            return NULL;
        }
        memcpy(pbRevealRound+dwTotalRevealSize,(uint8_t*)pSingleReveal,dwCurrentRevealSize);
        free(pSingleReveal);
        dwTotalRevealSize=dwTotalRevealSize+dwCurrentRevealSize;
    }
    *pdwRevealSize=dwTotalRevealSize;
    return pbRevealRound;
}

/*
    PAES_REVEAL createSingleAESReveal(uint8_t bBit, PSINGLE_AES_COMMITMENT_EXTRA_INFORMATION pSingleAESCommitmentExtraInformation, \
        out uint32_t* pdwRevealSize)
    description:
        Create a single commitment unpacker with AES
    arguments:
        bBit - challenge bit
        pSingleAESCommitmentExtraInformation - AES keys
        pdwRevealSize - pointer for outputing result size
    return value:
        SUCCESS - pointer to aes reveal data
        FAIL - NULL 
*/
PAES_REVEAL createSingleAESReveal(uint8_t bBit, PSINGLE_AES_COMMITMENT_EXTRA_INFORMATION pSingleAESCommitmentExtraInformation, \
out uint32_t* pdwRevealSize){
    PAES_REVEAL pAESReveal;
    if (pSingleAESCommitmentExtraInformation==NULL || pdwRevealSize==NULL) return NULL;
    pAESReveal=(PAES_REVEAL)malloc(sizeof(AES_REVEAL));
    if (pAESReveal==NULL) return NULL;
    if (bBit==0){
        memcpy(pAESReveal->revealingKey,pSingleAESCommitmentExtraInformation->permutationKey,AES128_KEY_SIZE);
    }else{
        memcpy(pAESReveal->revealingKey,pSingleAESCommitmentExtraInformation->permutedCycleKey,AES128_KEY_SIZE);
    }
    *pdwRevealSize=sizeof(AES_REVEAL);
    return pAESReveal;
}

/*
    uint8_t* createAESRevealRound(PPROOF_HELPER pProofHelper,PCHALLENGE_PACKET pChallengePacket, \
        PCOMMITMENT_EXTRA_INFORMATION pCommitmentExtraInformation, out uint32_t* pdwCommitmentSize)
    description:
        Create full round worth of AES commitment reveal information
    arguments:
        pProofHelper - parameters fo rproofs
        pChallengePacket - challenge packet
        pCommitmentExtraInformation - previously used AES keys
        pdwCommitmentSize - pointer for outputing return data size
    return value:
        SUCCESS - pointer to bytes containint reveal information
        FAIL - NULL
*/
uint8_t* createAESRevealRound(PPROOF_HELPER pProofHelper,PCHALLENGE_PACKET pChallengePacket, \
PCOMMITMENT_EXTRA_INFORMATION pCommitmentExtraInformation, out uint32_t* pdwCommitmentSize){
    PAES_REVEAL pCurrentReveal;
    uint8_t* pbReveals=NULL;
    uint32_t dwTotalSize=0;
    uint32_t dwCurrentUnpackSize;
    uint8_t bIndex;
    uint64_t qwChallengeRandom;
    uint32_t dwDataOffset=0;
    qwChallengeRandom=pChallengePacket->qwRandom;
    if (pProofHelper==NULL || pCommitmentExtraInformation==NULL || pdwCommitmentSize==NULL) return NULL;
    for (bIndex=0; bIndex<pProofHelper->bCheckCount;bIndex=bIndex+1){
        pCurrentReveal=createSingleAESReveal((uint8_t)(qwChallengeRandom&1),((PSINGLE_AES_COMMITMENT_EXTRA_INFORMATION*)(pCommitmentExtraInformation->pbData))[bIndex],&dwCurrentUnpackSize);
        qwChallengeRandom=qwChallengeRandom>>1;
        dwDataOffset=dwDataOffset+sizeof(SINGLE_AES_COMMITMENT_EXTRA_INFORMATION);
        if (pCurrentReveal==NULL){
            free(pbReveals);
            return NULL;
        }
        pbReveals=realloc(pbReveals,dwTotalSize+dwCurrentUnpackSize);
        if (pbReveals==NULL){
            free(pCurrentReveal);
            return NULL;
        }
        memcpy(pbReveals+dwTotalSize,pCurrentReveal,dwCurrentUnpackSize);
        dwTotalSize=dwTotalSize+dwCurrentUnpackSize;
        free(pCurrentReveal);
    }
    *pdwCommitmentSize=dwTotalSize;
    return pbReveals;
}

/*
    PREVEAL_PACKET createRevealPacket(PSINGLE_PROOF* pProofArray,PPROOF_HELPER pProofHelper, PCHALLENGE_PACKET pChallengePacket, \
        PCOMMITMENT_EXTRA_INFORMATION pCommitmentExtraInformation, out uint32_t* pdwRevealPacketSize)
    description:
        Create a packet for revealing commitments
    arguments:
        pProofArray - array of proofs
        pProofHelper - additional information for proofs
        pChallengePacket - challenge packet
        pCommitmentExtraInformation - extra information (needed for AES, otherwise NULL)
        pdwRevealPacketSize - for outputing size of return data
    return value:
        SUCCESS - packet with information for revealing commitments
        FAIL - NULL
*/
PREVEAL_PACKET createRevealPacket(PSINGLE_PROOF* pProofArray,PPROOF_HELPER pProofHelper, PCHALLENGE_PACKET pChallengePacket, \
PCOMMITMENT_EXTRA_INFORMATION pCommitmentExtraInformation, out uint32_t* pdwRevealPacketSize){
    PREVEAL_PACKET pRevealPacket;
    uint8_t* pbRevealData;
    uint32_t dwRevealDataSize;
    uint32_t dwPacketSize;
    if(pProofArray==NULL || pProofHelper==NULL || pChallengePacket==NULL || pdwRevealPacketSize==NULL) return NULL;
    if (pChallengePacket->bBitCount!=pProofHelper->bCheckCount) return NULL;
    if (pProofHelper->supportedAlgorithms.isCRC32Supported||pProofHelper->supportedAlgorithms.isSHA256Supported){
        if(pProofHelper->supportedAlgorithms.isCRC32Supported){
            pbRevealData=createCRC32RevealRound(pProofArray,pChallengePacket,&dwRevealDataSize);
        }else{
            pbRevealData=createSHA256RevealRound(pProofArray,pChallengePacket,&dwRevealDataSize);
        }
        if (pbRevealData==NULL) return NULL;
        dwPacketSize=REVEAL_PACKET_HEADER_SIZE+dwRevealDataSize;
        pRevealPacket=(PREVEAL_PACKET)malloc(dwPacketSize);
        if (pRevealPacket==NULL){
            free(pbRevealData);
            return NULL;
        } 
        pRevealPacket->bCommitmentCount=pProofHelper->bCheckCount;
        pRevealPacket->commitmentType.supportedAlgsCode=0;
        if(pProofHelper->supportedAlgorithms.isCRC32Supported){
            pRevealPacket->commitmentType.isCRC32Supported=1;
        }else{
            pRevealPacket->commitmentType.isSHA256Supported=1;
        }
        pRevealPacket->dwDataSize=dwRevealDataSize;
        memcpy(pRevealPacket->revealData,pbRevealData,dwRevealDataSize);
        free(pbRevealData);
        *pdwRevealPacketSize=dwPacketSize;
        return pRevealPacket;
    }else{
        if(pProofHelper->supportedAlgorithms.isAESSupported){
            pbRevealData=createAESRevealRound(pProofHelper,pChallengePacket,pCommitmentExtraInformation,&dwRevealDataSize);
            if (pbRevealData==NULL) return NULL;
            dwPacketSize=REVEAL_PACKET_HEADER_SIZE+dwRevealDataSize;
            pRevealPacket=(PREVEAL_PACKET)malloc(dwPacketSize);
            if (pRevealPacket==NULL){
                free(pbRevealData);
                return NULL;
            } 
            pRevealPacket->bCommitmentCount=pProofHelper->bCheckCount;
            pRevealPacket->commitmentType.supportedAlgsCode=0;
            pRevealPacket->commitmentType.isAESSupported=1;
            pRevealPacket->dwDataSize=dwRevealDataSize;
            memcpy(pRevealPacket->revealData,pbRevealData,dwRevealDataSize);
            free(pbRevealData);
            *pdwRevealPacketSize=dwPacketSize;
            return pRevealPacket;
        }else{
            return NULL;
        }
    }
}

/*
    uint8_t checkCRC32Proof(PZKN_STATE pZKnState,uint64_t qwChallengeRandom, uint8_t* pbCommitmentData, uint32_t dwCommitmentDataSize, \
        uint8_t* pbRevealData, uint32_t dwRevealDataSize, uint8_t* pbErrorReason)
    description:
        Check CRC32 Proof
    arguments:
        pZKnState - zero knowledge state
        qwChallengeRandom - challenge bits
        pbCommitmentData - commitments
        dwCommitmentDataSize - commitment data size
        pbRevealData - commitment revealing data
        dwRevealDataSize - reveal data size
        pbErrorReason - pointer for outputing error reasons
    return value:
        SUCCESS - SUCCESS
        FAIL - ERROR_SYSTEM or ERROR_BAD_VALUE

*/
uint8_t checkCRC32Proof(PZKN_STATE pZKnState,uint64_t qwChallengeRandom, uint8_t* pbCommitmentData, uint32_t dwCommitmentDataSize, \
uint8_t* pbRevealData, uint32_t dwRevealDataSize, uint8_t* pbErrorReason){
    PCRC32_COMMITMENT pCRC32Commitment;
    PCRC32_REVEAL pCRC32Reveal;
    uint8_t* pbBuffer;
    uint32_t dwCommitmentDataLeft;
    uint32_t dwRevealDataLeft;
    uint8_t bIndex;
    uint64_t qwChallengeBit;
    uint8_t* pbCRC32;
    uint8_t* pbCRC32PermutedMatrix;
    uint8_t* pbUnpackedMatrix;
    uint8_t* pbUnpackedPermutedGraphMatrix;
    uint16_t wCheckDimension, wPermutedGraphDimension;
    dwCommitmentDataLeft=dwCommitmentDataSize;
    dwRevealDataLeft=dwRevealDataSize;
    qwChallengeBit=qwChallengeRandom;
    pCRC32Commitment=(PCRC32_COMMITMENT)pbCommitmentData;
    pCRC32Reveal=(PCRC32_REVEAL)pbRevealData;
    for (bIndex=0; bIndex<pZKnState->bCheckCount;bIndex=bIndex+1){
        //Checking under/overflows in reveal record
        if (dwRevealDataLeft < CRC32_REVEAL_HEADER_SIZE || (pCRC32Reveal->dwPackedMatrixSize*2+CRC32_REVEAL_HEADER_SIZE)>dwRevealDataLeft || pCRC32Reveal->dwPackedMatrixSize>dwRevealDataLeft){
            *pbErrorReason=ERROR_REASON_WRONG_VALUE;
            return ERROR_BAD_VALUE;
        }
        //Computing CRC32 of permutedGraphMatrix 
        pbCRC32PermutedMatrix=crc32(pCRC32Reveal->packedPermutedGraphAndPermutationOrCycle,pCRC32Reveal->dwPackedMatrixSize);
        if (pbCRC32PermutedMatrix==NULL){
            *pbErrorReason=ERROR_REASON_SYSTEM;
            return ERROR_SYSTEM;
        }
        //Computing CRC32 of cycle/permutation
        pbCRC32=crc32(pCRC32Reveal->packedPermutedGraphAndPermutationOrCycle+pCRC32Reveal->dwPackedMatrixSize,pCRC32Reveal->dwPackedMatrixSize);
        if (pbCRC32==NULL){
            free(pbCRC32PermutedMatrix);
            *pbErrorReason=ERROR_REASON_SYSTEM;
            return ERROR_SYSTEM;
        }
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        //Checking CRC32
        if (memcmp(pCRC32Commitment->permutedGraphCRC32,pbCRC32PermutedMatrix,CRC32_SIZE)!=0){
            free(pbCRC32);
            free(pbCRC32PermutedMatrix);
            *pbErrorReason=ERROR_REASON_CHEATING;
            return ERROR_BAD_VALUE;
        }
#endif
        free(pbCRC32PermutedMatrix);

        //Checking CRC32 of cycle/permutation
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        if((qwChallengeBit&1)==0){
            if (memcmp(pCRC32Commitment->permutationCRC32,pbCRC32,CRC32_SIZE)!=0){
                free(pbCRC32);
                *pbErrorReason=ERROR_REASON_CHEATING;
                return ERROR_BAD_VALUE;
            }
        }else{
            if (memcmp(pCRC32Commitment->permutedCycleCRC32,pbCRC32,CRC32_SIZE)!=0){
                free(pbCRC32);
                *pbErrorReason=ERROR_REASON_CHEATING;
                return ERROR_BAD_VALUE;
            }
        }
#endif
        free(pbCRC32);
        //Unpacking reveal matrix
        pbUnpackedMatrix=unpackMatrix(pCRC32Reveal->dwPackedMatrixSize,pCRC32Reveal->packedPermutedGraphAndPermutationOrCycle+pCRC32Reveal->dwPackedMatrixSize,&wCheckDimension);
        if (pbUnpackedMatrix==NULL){
            *pbErrorReason=ERROR_REASON_SYSTEM;
            return ERROR_SYSTEM;
        }
        //Unpacking permuted graph matrix
        pbUnpackedPermutedGraphMatrix=unpackMatrix(pCRC32Reveal->dwPackedMatrixSize,pCRC32Reveal->packedPermutedGraphAndPermutationOrCycle,&wPermutedGraphDimension);
        if (pbUnpackedPermutedGraphMatrix==NULL){
            free(pbUnpackedMatrix);
            *pbErrorReason=ERROR_REASON_SYSTEM;
            return ERROR_SYSTEM;
        }
        //Checking dimensions are the same everywhere
        if (wCheckDimension!=pZKnState->pZKnGraph->wVerticeCount || wCheckDimension!=wPermutedGraphDimension){
            free(pbUnpackedMatrix);
            free(pbUnpackedPermutedGraphMatrix);
            *pbErrorReason=ERROR_REASON_CHEATING;
            return ERROR_SYSTEM;
        }
        if((qwChallengeBit&1)==0){
            //if given permutation matrix, we need to check permutation is correct
            pbBuffer=permuteMatrix(pbUnpackedMatrix,pZKnState->pZKnGraph->pbGraphData,wCheckDimension);
            if (pbBuffer==NULL){
                free(pbUnpackedMatrix);
                free(pbUnpackedPermutedGraphMatrix);
                *pbErrorReason=ERROR_REASON_SYSTEM;
                return ERROR_SYSTEM;
            }
            if (memcmp(pbBuffer,pbUnpackedPermutedGraphMatrix,pZKnState->pZKnGraph->dwMatrixSize)!=0){
                free(pbUnpackedMatrix);
                free(pbUnpackedPermutedGraphMatrix);
                free(pbBuffer);
                *pbErrorReason=ERROR_REASON_CHEATING;
                return ERROR_BAD_VALUE;
            }
            free(pbBuffer);
        }else{
            //if it's the cycle check, we need to check it's hamiltonian
            if (checkHamiltonianCycle(pbUnpackedPermutedGraphMatrix,pbUnpackedMatrix,wCheckDimension)==1){
                free(pbUnpackedMatrix);
                free(pbUnpackedPermutedGraphMatrix);
                *pbErrorReason=ERROR_REASON_CHEATING;
                return ERROR_BAD_VALUE;
            }
        }
        //We passed this challenge
        free(pbUnpackedMatrix);
        free(pbUnpackedPermutedGraphMatrix);
        //Next challenge bit
        qwChallengeBit=qwChallengeBit>>1;
        //Update data left   
        dwCommitmentDataLeft=dwCommitmentDataLeft-sizeof(CRC32_COMMITMENT);
        dwRevealDataLeft=dwRevealDataLeft-(pCRC32Reveal->dwPackedMatrixSize*2+CRC32_REVEAL_HEADER_SIZE);
        //Go to next entries
        pCRC32Commitment=(PCRC32_COMMITMENT)(((uint8_t*)pCRC32Commitment)+sizeof(CRC32_COMMITMENT));
        pCRC32Reveal=(PCRC32_REVEAL)(((uint8_t*)pCRC32Reveal)+pCRC32Reveal->dwPackedMatrixSize*2+CRC32_REVEAL_HEADER_SIZE);
    }
    //Proof worked
    *pbErrorReason=ERROR_REASON_NONE;
    return SUCCESS;
}

/*
    uint8_t checkSHA256Proof(PZKN_STATE pZKnState,uint64_t qwChallengeRandom, uint8_t* pbCommitmentData, uint32_t dwCommitmentDataSize, \
        uint8_t* pbRevealData, uint32_t dwRevealDataSize, uint8_t* pbErrorReason)
    description:
        Check SHA256 Proof
    arguments:
        pZKnState - zero knowledge state
        qwChallengeRandom - challenge bits
        pbCommitmentData - commitments
        dwCommitmentDataSize - commitment data size
        pbRevealData - commitment revealing data
        dwRevealDataSize - reveal data size
        pbErrorReason - pointer for outputing error reasons
    return value:
        SUCCESS - SUCCESS
        FAIL - ERROR_SYSTEM or ERROR_BAD_VALUE

*/
uint8_t checkSHA256Proof(PZKN_STATE pZKnState,uint64_t qwChallengeRandom, uint8_t* pbCommitmentData, uint32_t dwCommitmentDataSize, \
uint8_t* pbRevealData, uint32_t dwRevealDataSize, uint8_t* pbErrorReason){
    PSHA256_COMMITMENT pSHA256Commitment;
    PSHA256_REVEAL pSHA256Reveal;
    uint8_t* pbBuffer;
    uint32_t dwCommitmentDataLeft;
    uint32_t dwRevealDataLeft;
    uint8_t bIndex;
    uint64_t qwChallengeBit;
    uint8_t* pbSHA256;
    uint8_t* pbSHA256PermutedGraph;
    uint8_t* pbUnpackedMatrix;
    uint8_t* pbUnpackedPermutedGraphMatrix;
    uint16_t wCheckDimension, wPermutedGraphDimension;
    dwCommitmentDataLeft=dwCommitmentDataSize;
    dwRevealDataLeft=dwRevealDataSize;
    qwChallengeBit=qwChallengeRandom;
    pSHA256Commitment=(PSHA256_COMMITMENT)pbCommitmentData;
    pSHA256Reveal=(PSHA256_REVEAL)pbRevealData;
    for (bIndex=0; bIndex<pZKnState->bCheckCount;bIndex=bIndex+1){
        //Checking under/overflows in reveal record
        if (((pSHA256Reveal->dwPackedMatrixSize*2+SHA256_REVEAL_HEADER_SIZE)>dwRevealDataLeft)|| pSHA256Reveal->dwPackedMatrixSize>dwRevealDataLeft){
            *pbErrorReason=ERROR_REASON_WRONG_VALUE;
            return ERROR_BAD_VALUE;
        }
        if (dwCommitmentDataLeft<sizeof(SHA256_COMMITMENT)){
            *pbErrorReason=ERROR_REASON_WRONG_VALUE;
            return ERROR_BAD_VALUE;
        }
        //Computing SHA256
        pbSHA256PermutedGraph=sha256(pSHA256Reveal->packedPermutedGraphAndPermutationOrCycle,pSHA256Reveal->dwPackedMatrixSize);
        if (pbSHA256PermutedGraph==NULL){
            *pbErrorReason=ERROR_REASON_SYSTEM;
            return ERROR_SYSTEM;
        }
        //Computing SHA256
        pbSHA256=sha256(pSHA256Reveal->packedPermutedGraphAndPermutationOrCycle+pSHA256Reveal->dwPackedMatrixSize,pSHA256Reveal->dwPackedMatrixSize);
        if (pbSHA256==NULL){
            free(pbSHA256PermutedGraph);
            *pbErrorReason=ERROR_REASON_SYSTEM;
            return ERROR_SYSTEM;
        }
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        if (memcmp(pSHA256Commitment->permutedGraphSHA256,pbSHA256PermutedGraph,SHA256_SIZE)!=0){
            free(pbSHA256);
            free(pbSHA256PermutedGraph);
            *pbErrorReason=ERROR_REASON_CHEATING;
            return ERROR_SYSTEM;
        }
#endif
        free(pbSHA256PermutedGraph);
        //Checking SHA256
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        if((qwChallengeBit&1)==0){
            if (memcmp(pSHA256Commitment->permutationSHA256,pbSHA256,SHA256_SIZE)!=0){
                free(pbSHA256);
                *pbErrorReason=ERROR_REASON_CHEATING;
                return ERROR_BAD_VALUE;
            }
        }else{
            if (memcmp(pSHA256Commitment->permutedCycleSHA256,pbSHA256,SHA256_SIZE)!=0){
                free(pbSHA256);
                *pbErrorReason=ERROR_REASON_CHEATING;
                return ERROR_BAD_VALUE;
            }
        }
#endif
        free(pbSHA256);
        //Unpacking reveal matrix
        pbUnpackedMatrix=unpackMatrix(pSHA256Reveal->dwPackedMatrixSize,pSHA256Reveal->packedPermutedGraphAndPermutationOrCycle+pSHA256Reveal->dwPackedMatrixSize,&wCheckDimension);
        if (pbUnpackedMatrix==NULL){
            *pbErrorReason=ERROR_REASON_SYSTEM;
            return ERROR_SYSTEM;
        }
        //Unpacking permuted graph matrix
        pbUnpackedPermutedGraphMatrix=unpackMatrix(pSHA256Reveal->dwPackedMatrixSize,pSHA256Reveal->packedPermutedGraphAndPermutationOrCycle,&wPermutedGraphDimension);
        if (pbUnpackedPermutedGraphMatrix==NULL){
            free(pbUnpackedMatrix);
            *pbErrorReason=ERROR_REASON_SYSTEM;
            return ERROR_SYSTEM;
        }
        //Checking dimensions are the same everywhere
        if (wCheckDimension!=pZKnState->pZKnGraph->wVerticeCount || wCheckDimension!=wPermutedGraphDimension){
            free(pbUnpackedMatrix);
            free(pbUnpackedPermutedGraphMatrix);
            *pbErrorReason=ERROR_REASON_CHEATING;
            return ERROR_SYSTEM;
        }
        if((qwChallengeBit&1)==0){
            //if given permutation matrix, we need to check permutation is correct
            pbBuffer=permuteMatrix(pbUnpackedMatrix,pZKnState->pZKnGraph->pbGraphData,wCheckDimension);
            if (pbBuffer==NULL){
                free(pbUnpackedMatrix);
                free(pbUnpackedPermutedGraphMatrix);
                *pbErrorReason=ERROR_REASON_SYSTEM;
                return ERROR_SYSTEM;
            }
            if (memcmp(pbBuffer,pbUnpackedPermutedGraphMatrix,pZKnState->pZKnGraph->dwMatrixSize)!=0){
                free(pbUnpackedMatrix);
                free(pbUnpackedPermutedGraphMatrix);
                free(pbBuffer);
                *pbErrorReason=ERROR_REASON_CHEATING;
                return ERROR_BAD_VALUE;
            }
            free(pbBuffer);
        }else{
            //if it's the cycle check, we need to check it's hamiltonian
            if (checkHamiltonianCycle(pbUnpackedPermutedGraphMatrix,pbUnpackedMatrix,wCheckDimension)==1){
                free(pbUnpackedMatrix);
                free(pbUnpackedPermutedGraphMatrix);
                *pbErrorReason=ERROR_REASON_CHEATING;
                return ERROR_BAD_VALUE;
            }
        }
        //We passed this challenge
        free(pbUnpackedMatrix);
        free(pbUnpackedPermutedGraphMatrix);
        //Next challenge bit
        qwChallengeBit=qwChallengeBit>>1;
        //Update data left   
        dwCommitmentDataLeft=dwCommitmentDataLeft-sizeof(SHA256_COMMITMENT);
        dwRevealDataLeft=dwRevealDataLeft-(pSHA256Reveal->dwPackedMatrixSize*2+SHA256_REVEAL_HEADER_SIZE);
        //Go to next entries
        pSHA256Commitment=(PSHA256_COMMITMENT)(((uint8_t*)pSHA256Commitment)+sizeof(SHA256_COMMITMENT));
        pSHA256Reveal=(PSHA256_REVEAL)(((uint8_t*)pSHA256Reveal)+pSHA256Reveal->dwPackedMatrixSize*2+SHA256_REVEAL_HEADER_SIZE);
    }
    //Proof worked
    *pbErrorReason=ERROR_REASON_NONE;
    return SUCCESS;
}

/*
    uint8_t checkAESProof(PZKN_STATE pZKnState,uint64_t qwChallengeRandom, uint8_t* pbCommitmentData, uint32_t dwCommitmentDataSize, \
        uint8_t* pbRevealData, uint32_t dwRevealDataSize, uint8_t* pbErrorReason)
    description:
        Check AES Proof
    arguments:
        pZKnState - zero knowledge state
        qwChallengeRandom - challenge bits
        pbCommitmentData - commitments
        dwCommitmentDataSize - commitment data size
        pbRevealData - commitment revealing data
        dwRevealDataSize - reveal data size
        pbErrorReason - pointer for outputing error reasons
    return value:
        SUCCESS - SUCCESS
        FAIL - ERROR_SYSTEM or ERROR_BAD_VALUE

*/
uint8_t checkAESProof(PZKN_STATE pZKnState,uint64_t qwChallengeRandom, uint8_t* pbCommitmentData, uint32_t dwCommitmentDataSize, \
uint8_t* pbRevealData, uint32_t dwRevealDataSize, uint8_t* pbErrorReason){
    PAES_COMMITMENT pAESCommitment;
    PAES_REVEAL pAESReveal;
    uint8_t* pbDecryptedData;
    uint32_t dwCommitmentDataLeft;
    uint32_t dwRevealDataLeft;
    uint8_t bIndex;
    uint64_t qwChallengeBit;
    uint8_t* pbBuffer;
    uint8_t* pbUnpackedMatrix;
    uint8_t* pbUnpackedPermutedGraphMatrix;
    uint16_t wCheckDimension, wPermutedGraphDimension;
    uint32_t dwDecryptedDataSize;
    dwCommitmentDataLeft=dwCommitmentDataSize;
    dwRevealDataLeft=dwRevealDataSize;
    qwChallengeBit=qwChallengeRandom;
    pAESCommitment=(PAES_COMMITMENT)pbCommitmentData;
    pAESReveal=(PAES_REVEAL)pbRevealData;
    for (bIndex=0; bIndex<pZKnState->bCheckCount;bIndex=bIndex+1){
        //Checking under/overflows in commitment record
        if ((pAESCommitment->dwSingleCiphertextPlusIVSize*2+pAESCommitment->dwPackedPermutedMatrixSize +AES_COMMITMENT_HEADER_SIZE) > dwCommitmentDataLeft || \
        pAESCommitment->dwSingleCiphertextPlusIVSize >dwCommitmentDataLeft ||
        pAESCommitment->dwPackedPermutedMatrixSize>dwCommitmentDataLeft){
            *pbErrorReason=ERROR_REASON_WRONG_VALUE;
            return ERROR_BAD_VALUE;
        }
        //Checking under/overflows in reveal record
        if (sizeof(AES_REVEAL)>dwRevealDataLeft){
            *pbErrorReason=ERROR_REASON_WRONG_VALUE;
            return ERROR_BAD_VALUE;
        }
        //Decrypting Commitment
        if((qwChallengeBit&1)==0){
            pbDecryptedData=aes128cbc_decrypt(pAESCommitment->commitmentData,pAESCommitment->dwSingleCiphertextPlusIVSize,pAESReveal->revealingKey,&dwDecryptedDataSize);
        }else{
            pbDecryptedData=aes128cbc_decrypt(pAESCommitment->commitmentData+pAESCommitment->dwSingleCiphertextPlusIVSize,pAESCommitment->dwSingleCiphertextPlusIVSize,pAESReveal->revealingKey,&dwDecryptedDataSize);
        }
        if (pbDecryptedData==NULL){
            *pbErrorReason=ERROR_REASON_SYSTEM;
            return ERROR_SYSTEM;
        }
        //Unpacking revealed matrix
        pbUnpackedMatrix=unpackMatrix(dwDecryptedDataSize,pbDecryptedData,&wCheckDimension);
        if (pbUnpackedMatrix==NULL){
            free(pbDecryptedData);
            *pbErrorReason=ERROR_REASON_SYSTEM;
            return ERROR_SYSTEM;
        }
        free(pbDecryptedData);
        //Unpacking permuted graph matrix
        pbUnpackedPermutedGraphMatrix=unpackMatrix(pAESCommitment->dwPackedPermutedMatrixSize,pAESCommitment->commitmentData + pAESCommitment->dwSingleCiphertextPlusIVSize*2,&wPermutedGraphDimension);
        if (pbUnpackedPermutedGraphMatrix==NULL){
            free(pbUnpackedMatrix);
            *pbErrorReason=ERROR_REASON_SYSTEM;
            return ERROR_SYSTEM;
        }
        //Checking dimensions are the same everywhere
        if (wCheckDimension!=pZKnState->pZKnGraph->wVerticeCount || wCheckDimension!=wPermutedGraphDimension){
            free(pbUnpackedMatrix);
            free(pbUnpackedPermutedGraphMatrix);
            *pbErrorReason=ERROR_REASON_CHEATING;
            return ERROR_SYSTEM;
        }
        if((qwChallengeBit&1)==0){
            //if given permutation matrix, we need to check permutation is correct
            pbBuffer=permuteMatrix(pbUnpackedMatrix,pZKnState->pZKnGraph->pbGraphData,wCheckDimension);
            if (pbBuffer==NULL){
                free(pbUnpackedMatrix);
                free(pbUnpackedPermutedGraphMatrix);
                *pbErrorReason=ERROR_REASON_SYSTEM;
                return ERROR_SYSTEM;
            }
            if (memcmp(pbBuffer,pbUnpackedPermutedGraphMatrix,pZKnState->pZKnGraph->dwMatrixSize)!=0){
                free(pbUnpackedMatrix);
                free(pbUnpackedPermutedGraphMatrix);
                free(pbBuffer);
                *pbErrorReason=ERROR_REASON_CHEATING;
                return ERROR_BAD_VALUE;
            }
            free(pbBuffer);
        }else{
            //if it's the cycle check, we need to check it's hamiltonian
            if (checkHamiltonianCycle(pbUnpackedPermutedGraphMatrix,pbUnpackedMatrix,wCheckDimension)==1){
                free(pbUnpackedMatrix);
                free(pbUnpackedPermutedGraphMatrix);
                *pbErrorReason=ERROR_REASON_CHEATING;
                return ERROR_BAD_VALUE;
            }
        }
        //We passed this challenge
        free(pbUnpackedMatrix);
        free(pbUnpackedPermutedGraphMatrix);
        //Next challenge bit
        qwChallengeBit=qwChallengeBit>>1;
        //Update data left   
        dwCommitmentDataLeft=dwCommitmentDataLeft-AES_COMMITMENT_HEADER_SIZE-((pAESCommitment->dwSingleCiphertextPlusIVSize)*2)- pAESCommitment->dwPackedPermutedMatrixSize;
        dwRevealDataLeft=dwRevealDataLeft-sizeof(AES_REVEAL);
        //Go to next entries
        pAESCommitment=(PAES_COMMITMENT)(((uint8_t*)pAESCommitment)+pAESCommitment->dwPackedPermutedMatrixSize+AES_COMMITMENT_HEADER_SIZE +(pAESCommitment->dwSingleCiphertextPlusIVSize*2));
        pAESReveal=(PAES_REVEAL)(((uint8_t*)pAESReveal)+sizeof(AES_REVEAL));
    }
    //Proof worked
    *pbErrorReason=ERROR_REASON_NONE;
    return SUCCESS;
}

/*
    uint8_t checkProof(PZKN_STATE pZKnState, PZKN_PROTOCOL_STATE pZKnProtocolState, PREVEAL_PACKET pRevealPacket, \
    uint32_t dwRevealPacketSize, uint8_t** ppbFlag, uint8_t* pbErrorReason)
    description:
        Check given proof, reset protocol if something goes wrong
    arguments:
        pZKnState - zero knowledge state (main graph, etc..)
        pZknProtocolState - protocol state
        pRevealPacket - revealing packet
        dwRevealPacketSize - reveal packet size
        ppbFlag - poiter for outputing flag
        pbErrorReason - pointer for outputing error reason
    return value:
        SUCCESS - SUCCESS
        FAIL - ERROR_SYSTEM or ERROR_BAD_VALUE (depending on error reason this means attempts to subvert logic or pwn)
*/
uint8_t checkProof(PZKN_STATE pZKnState, PZKN_PROTOCOL_STATE pZKnProtocolState, PREVEAL_PACKET pRevealPacket, \
uint32_t dwRevealPacketSize, uint8_t** ppbFlag,uint8_t* pbErrorReason){
    PCOMMITMENT_PACKET pCommitmentPacket;
    uint8_t bResult;
    //Checking sanity
    if (pZKnState==NULL || pZKnProtocolState==NULL || pRevealPacket==NULL || ppbFlag==NULL) 
    {
        *pbErrorReason=ERROR_REASON_SYSTEM;
        bResult= ERROR_SYSTEM;
        goto protocol_reset;
    }
    if (dwRevealPacketSize<REVEAL_PACKET_HEADER_SIZE){
        *pbErrorReason=ERROR_REASON_WRONG_VALUE;
        bResult=ERROR_BAD_VALUE;
        goto protocol_reset;
    }
    //Checking that the protocol is at the right stage
    if (pZKnProtocolState->protocolProgress.isCommitmentStageComplete==0 || pZKnProtocolState->protocolProgress.isRandomnessStageComplete==0){
        *pbErrorReason=ERROR_REASON_TOO_EARLY;
        bResult= ERROR_BAD_VALUE;
        goto protocol_reset;
    }
    pCommitmentPacket=(PCOMMITMENT_PACKET)pZKnProtocolState->pbCommitmentData;
    
    //Checking commitment data is not under/overflowing
    if (pCommitmentPacket->dwDataSize!=(pZKnProtocolState->dwCommitmentDataSize-COMMITMENT_PACKET_HEADER_SIZE)){
        *pbErrorReason=ERROR_REASON_WRONG_VALUE;
        bResult= ERROR_BAD_VALUE;
        goto protocol_reset;
    }
    //Checking reveal data is not under/overflowing
    if (pRevealPacket->dwDataSize!=(dwRevealPacketSize-REVEAL_PACKET_HEADER_SIZE)){
        *pbErrorReason=ERROR_REASON_WRONG_VALUE;
        bResult= ERROR_BAD_VALUE;
        goto protocol_reset;
    }
    //Check that prover honored verifier's settings
    if (pCommitmentPacket->bCommitmentCount!=pZKnState->bCheckCount || pRevealPacket->bCommitmentCount!=pZKnState->bCheckCount){
        *pbErrorReason=ERROR_REASON_CHEATING;
        bResult= ERROR_BAD_VALUE;
        goto protocol_reset;
    }
    if ((pCommitmentPacket->commitmentType.supportedAlgsCode & pZKnState->supportedAlgorithms.supportedAlgsCode & pRevealPacket->commitmentType.supportedAlgsCode)==0){
        *pbErrorReason=ERROR_REASON_CHEATING;
        bResult= ERROR_BAD_VALUE;
        goto protocol_reset;
    }
    //Check only a single one was used
    if ((pCommitmentPacket->commitmentType.isCRC32Supported & pCommitmentPacket->commitmentType.isSHA256Supported) || \
    (pCommitmentPacket->commitmentType.isCRC32Supported & pCommitmentPacket->commitmentType.isAESSupported) || \
    (pCommitmentPacket->commitmentType.isSHA256Supported & pCommitmentPacket->commitmentType.isAESSupported)){
        *pbErrorReason=ERROR_REASON_CHEATING;
        bResult= ERROR_BAD_VALUE;
        goto protocol_reset;
    }
    if ((pRevealPacket->commitmentType.isCRC32Supported & pRevealPacket->commitmentType.isSHA256Supported) || \
    (pRevealPacket->commitmentType.isCRC32Supported & pRevealPacket->commitmentType.isAESSupported) || \
    (pRevealPacket->commitmentType.isSHA256Supported & pRevealPacket->commitmentType.isAESSupported)){
        *pbErrorReason=ERROR_REASON_CHEATING;
        bResult= ERROR_BAD_VALUE;
        goto protocol_reset;
    }
    if (pRevealPacket->commitmentType.isCRC32Supported){
        bResult= checkCRC32Proof(pZKnState,pZKnProtocolState->qwRandom,pCommitmentPacket->commitmentData,pCommitmentPacket->dwDataSize,\
        pRevealPacket->revealData,pRevealPacket->dwDataSize,pbErrorReason);
    }else{
        if (pRevealPacket->commitmentType.isSHA256Supported){
            bResult= checkSHA256Proof(pZKnState,pZKnProtocolState->qwRandom,pCommitmentPacket->commitmentData,pCommitmentPacket->dwDataSize,\
            pRevealPacket->revealData,pRevealPacket->dwDataSize,pbErrorReason);
        }else{
            bResult= checkAESProof(pZKnState,pZKnProtocolState->qwRandom,pCommitmentPacket->commitmentData,pCommitmentPacket->dwDataSize,\
            pRevealPacket->revealData,pRevealPacket->dwDataSize,pbErrorReason);
           
        }
    }
    if (bResult==SUCCESS){
        *ppbFlag=pZKnState->pbFLAG;
    }
    else{
        *ppbFlag=NULL;
    }
protocol_reset:
    //Reset protocol in any case
    pZKnProtocolState->protocolProgress.status=0;
    pZKnProtocolState->dwCommitmentDataSize=0;
    free(pZKnProtocolState->pbCommitmentData);
    pZKnProtocolState->pbCommitmentData=NULL;
    return bResult;

}
/*
    PZKN_PROTOCOL_STATE initializeZKnProtocolState()
    description:
        Initialize ZKN protocol state (when we actual want to prove the knowledge)
    arguments:
        None
    return value:
        SUCCESS - pointer to ZKN_PROTOCOL_STATE
        FAIL - NULL
*/
PZKN_PROTOCOL_STATE initializeZKnProtocolState(){
    PZKN_PROTOCOL_STATE pZKnProtocolState;
    pZKnProtocolState=(PZKN_PROTOCOL_STATE) calloc(1,sizeof(ZKN_PROTOCOL_STATE));
    if (pZKnProtocolState==NULL) return NULL;
    pZKnProtocolState->pLegendrePRNG=initializePRNG(P);
    if (pZKnProtocolState->pLegendrePRNG==NULL){
        free(pZKnProtocolState);
        return NULL;
    }
    pZKnProtocolState->protocolProgress.status=0;
    return pZKnProtocolState;
}

/*
    void destroyZKnProtocolState(PZKN_PROTOCOL_STATE pZKnProtocolState)
    description:
        Destroy ZKN Protocol State
    arguments:
        pZKnProtocolState - pointer to the structure to destroy
    return value:
        N/A
*/
void destroyZKnProtocolState(PZKN_PROTOCOL_STATE pZKnProtocolState){
    free(pZKnProtocolState->pLegendrePRNG);
    free(pZKnProtocolState->pbCommitmentData);
    free(pZKnProtocolState);
}

/*
    uint8_t* packMatrixForEmbedding(uint8_t* pbMatrix, uint16_t wDimension, out uint32_t* pdwDataSize)
    description:
        Pack matrix for transmission
    arguments:
        pbMatrix - matrix
        wDimension - matrix dimension (number of elements in a row) 
        pdwDataSize - size of output byte array if successful
    return value:
        SUCCESS - pointer to byte array containing packed matrix
        FAIL - NULL
*/
uint8_t* packMatrixForEmbedding(uint8_t* pbMatrix, uint16_t wDimension, out uint32_t* pdwDataSize){
    uint8_t * pbPacked;
    if (pbMatrix== NULL || pdwDataSize==NULL) return NULL;
    pbPacked=packMatrix(pbMatrix,wDimension,pdwDataSize);
    return pbPacked;
}

/*
    uint8_t* unpackPackedMatrix(uint8_t* pbPackedMatrix, uint32_t dwSize, out uint16_t pwOutputDimension)
    description:
        Unpack packed matrix
    arguments:
        pbPackedMatrix - packed matrix
        dwSize - its size
        pwOutputDimension - for outputing resulting dimension 
*/
uint8_t* unpackPackedMatrix(uint8_t* pbPackedMatrix, uint32_t dwSize, out uint16_t* pwOutputDimension){
    uint8_t* pbUnpacked;
    if (pbPackedMatrix==NULL|| pwOutputDimension==NULL) return NULL;
    pbUnpacked=unpackMatrix(dwSize,pbPackedMatrix,pwOutputDimension);
    return pbUnpacked;
}