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
/*
    PZKN_STATE initializeZKNThread(void)
    description:
        Exported function, that initializes team server's zero knowledge thread
    arguments:
        wVerticeCount - desired matrix dimension
    return value:
        SUCCESS - pointer to the state structure
        ERROR - NULL
*/
PZKN_STATE initializeZKnThread(uint16_t wVerticeCount, uint8_t bCheckCount, uint8_t bSuppportedAlgorithms)
{
    PZKN_STATE pZKNState;
    PLEGENDRE_PRNG plegendre_prng;
    pZKNState=(PZKN_STATE)malloc(sizeof(ZKN_STATE));
    if (pZKNState==NULL) return NULL;
    pZKNState->wDefaultVerticeCount=wVerticeCount;
    pZKNState->bCheckCount=bCheckCount;
    pZKNState->supportedAlgorithms.supportedAlgsCode=bSuppportedAlgorithms;
    plegendre_prng=initialize_PRNG(P);
    if (plegendre_prng==NULL){
        free(pZKNState);
        return NULL;
    }
    pZKNState->pLegendrePrng=plegendre_prng;
    pZKNState->pbFLAG=NULL;
    pZKNState->pZKnGraph=NULL;
    return pZKNState;
}
/*
    void destroyZKNThread(PZKN_STATE pZKNState)
    description:
        Team Server's zero knowledge thread state destructure
    arguments:
        pZKNState - pointer to zero knowledge state structure
    return value:
        None
*/
void destroyZKnThread(PZKN_STATE pZKNState)
{
    destroy_PRNG(pZKNState->pLegendrePrng);
    free(pZKNState->pbFLAG);
    if (pZKNState->pZKnGraph!=NULL) free(pZKNState->pZKnGraph->pbGraphData);
    free(pZKNState->pZKnGraph);
    free(pZKNState);
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
    if (i==2) return NULL;
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
    if (pZKNState==NULL) return ERROR_SYSTEM;
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

    if (wDimension!=pZKNState->wDefaultVerticeCount) return ERROR_BAD_VALUE;
    dwUnpackedMatrixSize=(((uint32_t) wDimension)*(uint32_t)wDimension);
    if (dwUnpackedMatrixSize>MAX_MATR_BYTE_SIZE) return ERROR_BAD_VALUE;

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
    if (plHolder==NULL) return ERROR_SYSTEM;
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
uint8_t* packFullKnowledgeForStorage(PFULL_KNOWLEDGE pFullKnowledge, out int32_t* pdwDataSize){
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
    pFknForStorage=(PFULL_KNOWLEDGE_FOR_STORAGE)pbPackedFullKnowledge;
    pFullKnowledge=(PFULL_KNOWLEDGE)malloc(sizeof(FULL_KNOWLEDGE));
    if (pFullKnowledge==NULL) return NULL;
    pbUnpackedMatr=unpackMatrix((uint16_t)pFknForStorage->dwSinglePackedMatrixSize,pFknForStorage->bData,&wDimension);
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
    if (dwPacketSize<sizeof(INITIAL_SETTING_PACKET)) return 0;
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
*/
PPROOF_HELPER initializeProofHelper(PFULL_KNOWLEDGE pFullKnowledge, PPROOF_CONFIGURATION_PACKET pProofConfigurationPacket, uint32_t dwPacketSize, out uint8_t* pbErrorReason){
    //IMPORTANT!!!
    //TODO:
    //Add check count and algorithm selection checks
    PPROOF_HELPER pProofHelper;
    uint8_t* pbUnpackedMatrix;
    uint16_t wDimension;
    *(pbErrorReason)=ERROR_REASON_NONE;
    if (pFullKnowledge==NULL || pProofConfigurationPacket==NULL) {
        *(pbErrorReason)=ERROR_REASON_SYSTEM;
        return NULL;
    }
    pbUnpackedMatrix=unpackMatrix((uint16_t)pProofConfigurationPacket->dwPackedMatrixSize, pProofConfigurationPacket->bPackedMatrixData,&wDimension);
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

uint8_t* createSingleCRC32Commitment(PSINGLE_PROOF pSingleProof,  out uint32_t* pdwSingleCommitmentSize){
    uint32_t dwSingleCommitmentSize;
    PCRC32_COMMITMENT pCRC32Commitment;
    uint8_t* pCRC32;
    dwSingleCommitmentSize=CRC32_COMMITMENT_HEADER_SIZE+pSingleProof->dwPackedMatrixSize;
    pCRC32Commitment=(PCRC32_COMMITMENT)malloc(dwSingleCommitmentSize);
    if (pCRC32Commitment==NULL) return NULL;
    pCRC32=crc32(pSingleProof->pbPackedPermutationMatrix,pSingleProof->dwPackedMatrixSize);
    if (pCRC32==NULL){
        free(pCRC32Commitment);
        return NULL;
    }
    memcpy(pCRC32Commitment->permutationCRC32,pCRC32,CRC32_SIZE);
    free(pCRC32);
    pCRC32=crc32(pSingleProof->pbPackedPermutedCycleMatrix,pSingleProof->dwPackedMatrixSize);
    if (pCRC32==NULL){
        free(pCRC32Commitment);
        return NULL;
    }
    memcpy(pCRC32Commitment->permutedCycleCRC32,pCRC32,CRC32_SIZE);
    free(pCRC32);
    pCRC32Commitment->dwPackedPermutedMatrixSize=pSingleProof->dwPackedMatrixSize;
    memcpy(pCRC32Commitment->packedPermutedGraphMatrix,pSingleProof->pbPackedPermutedGraphMatrix,pSingleProof->dwPackedMatrixSize);
    *pdwSingleCommitmentSize=dwSingleCommitmentSize;
    return (uint8_t*)pCRC32Commitment;
}

uint8_t* createCRC32CommitmentRound(PSINGLE_PROOF* pProofArray, PPROOF_HELPER pProofHelper, out uint32_t* pdwCommitmentDataSize){
    uint8_t* pCommitmentArray=NULL;
    uint32_t dwCommitmentRoundDataSize=0;
    uint32_t dwSingleCommitmentSize;
    uint8_t* pSingleCommitment;
    uint8_t bIndex;
    for (bIndex=0;bIndex<pProofHelper->bCheckCount;bIndex=bIndex+1){
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
uint8_t* createSHA256CommitmentRound(PSINGLE_PROOF* pProofArray,PPROOF_HELPER pProofHelper,out uint32_t* pdwCommitmentDataSize){
    return NULL;
}
 

/*
*/
PCOMMITMENT_PACKET createCommitmentPacket(PSINGLE_PROOF* pProofArray,PPROOF_HELPER pProofHelper,out uint32_t* pdwCommitmentPacketSize, \
                                            out PCOMMITMENT_EXTRA_INFORMATION pCommitmentExtraInformation){
    //PCOMMITMENT_PACKET pCommitmentPacket;
    COMMITMENT_ALGORITHMS commitmentAlgs;
    PCOMMITMENT_PACKET pCommitmentPacket;
    uint32_t dwCommitmentDataSize;
    uint32_t dwResultingPacketSize;
    uint8_t* pbCommitmentData;
    if (pProofArray==NULL || pProofHelper==NULL) return NULL;
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
            return NULL;
        }
        else{
            if (commitmentAlgs.isAESSupported){
                return NULL;
            }else{
                return NULL;
            }
        }
    }

}

/*
    uint8_t* packMatrixForTransmission(PMATRIX_HOLDER pMatrixHolder, out uint32_t* pdwDataSize)
    description:
        Pack matrix for transmission
    arguments:
        pMatrixHolder - structure holding matrix information
        pdwDataSize - size of output byte array if successful
    return value:
        SUCCESS - pointer to byte array containing packed matrix
        FAIL - NULL
*/
uint8_t* packMatrixForTransmission(PMATRIX_HOLDER pMatrixHolder, out uint32_t* pdwDataSize){
    PPACKED_MATRIX pPackedMatrix;
    uint8_t * pbPacked;
    uint32_t dwResultingSize;
    uint32_t dwResSize;
    if (pMatrixHolder==NULL || pMatrixHolder->pbData) return NULL;
    pbPacked=packMatrix(pMatrixHolder->pbData,pMatrixHolder->wDimension,&dwResSize);
    if (pbPacked==NULL) return NULL;
    dwResultingSize=(uint32_t)dwResSize+PACKED_MATRIX_HEADER_SIZE;
    pPackedMatrix=(PPACKED_MATRIX)malloc(dwResultingSize);
    if (pPackedMatrix==NULL){
        free(pbPacked);
        return NULL;
    }
    pPackedMatrix->wDimension=pMatrixHolder->wDimension;
    memcpy(pPackedMatrix->bData,pbPacked,(uint32_t)dwResSize);
    free(pbPacked);
    *pdwDataSize=dwResultingSize;
    return (uint8_t*)pPackedMatrix;
}

/*
    void freePackedMatrixForTransmission(uint8_t* pbPackedMatrix);
    description:
        free packed matrix array
    arguments:
        pbPackedMatrix - pointer to packed matrix array
    return value:
        N/A
*/
void freePackedMatrixForTransmission(uint8_t* pbPackedMatrix){
    free(pbPackedMatrix);
}