#include "zkn.h"
#include "hash.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#define MIN_PKCS_SIG_SIZE (HASH_SIZE+4)
#define ERROR_SYSTEM 1
#define ERROR_BAD_VALUE 2
#define SUCCESS 0x0

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
PZKN_STATE initializeZKNThread(uint16_t wVerticeCount)
{
    PZKN_STATE pZKNState;
    PLEGENDRE_PRNG plegendre_prng;
    pZKNState=(PZKN_STATE)malloc(sizeof(ZKN_STATE));
    if (pZKNState==NULL) return NULL;
    pZKNState->wDefaultVerticeCount=wVerticeCount;
    plegendre_prng=initialize_PRNG(P);
    if (plegendre_prng==NULL){
        free(pZKNState);
        return NULL;
    }
    pZKNState->pLedendrePrng=plegendre_prng;
    pZKNState->pbFLAG=NULL;
    pZKNState->pZKNGraph=NULL;
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
void destroyZKNThread(PZKN_STATE pZKNState)
{
    destroy_PRNG(pZKNState->pLedendrePrng);
    free(pZKNState->pbFLAG);
    free(pZKNState->pZKNGraph);
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
        bytesRead=read(fd,pInitialSettingPacket->RANDOM_R+bytesRead,RANDOM_R_SIZE-totalBytesRead);
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
    if ((i>=dsSize)||((dsSize-i)<HASH_SIZE)) return NULL;
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
uint32_t updateZKNGraph(PZKN_STATE pZKNState,PGRAPH_SET_PACKET pGraphSetPacket, uint32_t dwPacketSize, uint8_t* pbDecryptedSignature, uint32_t dsSize, uint8_t* pRANDOMR)
{
    uint8_t* signHash;
    uint8_t* actualHash;
    uint8_t* plHolder;
    uint8_t* pbUnpackedMatrix;
    int16_t swDimension;
    uint32_t dwUnpackedMatrixSize;
    PGRAPH pZKNGraph;
    if (pZKNState==NULL) return ERROR_SYSTEM;
    signHash=badPKCSUnpadHash(pbDecryptedSignature,dsSize);
    if (signHash==NULL) return ERROR_SYSTEM;
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    actualHash=hashsum((unsigned char*) pGraphSetPacket,(ssize_t)dwPacketSize);
    if (actualHash==NULL) return ERROR_SYSTEM;
    if (memcmp(signHash,actualHash,HASH_SIZE)!=0){
        free(actualHash);
        return ERROR_BAD_VALUE;
    }
    free(actualHash);
    if (memcmp(pRANDOMR,pGraphSetPacket->RANDOM_R,RANDOM_R_SIZE)!=0) return ERROR_BAD_VALUE;
#endif
    if (pGraphSetPacket->dwPackedMatrixSize!=(dwPacketSize-GRAPH_SET_PACKET_HEADER_SIZE)) return ERROR_BAD_VALUE;
    pbUnpackedMatrix=unpack_matr(pGraphSetPacket->dwPackedMatrixSize,pGraphSetPacket->bPackedMatrixData,&swDimension);
    if (pbUnpackedMatrix==NULL) return NULL;

    if (swDimension!=pZKNState->wDefaultVerticeCount) return ERROR_BAD_VALUE;
    dwUnpackedMatrixSize=(((uint32_t) swDimension)*(uint32_t)swDimension);
    if (dwUnpackedMatrixSize>MAX_MATR_BYTE_SIZE) return ERROR_BAD_VALUE;

    if (pZKNState->pbFLAG==NULL){
        plHolder=calloc(0,FLAG_ARRAY_SIZE);
        if (plHolder==NULL) return ERROR_SYSTEM;
        pZKNState->pbFLAG=plHolder;
    }
    free(pZKNState->pZKNGraph);
    plHolder=malloc(GRAPH_HEADER_SIZE+dwUnpackedMatrixSize);
    if (plHolder==NULL) return ERROR_SYSTEM;
    pZKNState->pZKNGraph=(PGRAPH)plHolder;
    memcpy(pZKNState->pbFLAG,pGraphSetPacket->FLAG,FLAG_ARRAY_SIZE);
    pZKNState->pbFLAG[FLAG_ARRAY_SIZE-1]=0;
    pZKNGraph=pZKNState->pZKNGraph;
    pZKNGraph->wVerticeCount=swDimension;
    pZKNGraph->dwMatrixSize=dwUnpackedMatrixSize;
    memcpy(pZKNGraph->graphData,pbUnpackedMatrix,dwUnpackedMatrixSize);
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
    return generate_graph_and_cycle_matrix(wVerticeCount);
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
    return free_full_knowledge(pFullKnowledge);
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
    int16_t wPackedMatrSize, wPackedCycleSize;
    if (pFullKnowledge==NULL || pFullKnowledge->pbCycleMatrix==NULL || pFullKnowledge->pbGraphMatrix==NULL) return NULL;
    pbPackedMatr=pack_matr(pFullKnowledge->pbGraphMatrix,pFullKnowledge->swDimension,&wPackedMatrSize);
    if (pbPackedMatr==NULL) return NULL;
    pbPackedCycle=pack_matr(pFullKnowledge->pbCycleMatrix,pFullKnowledge->swDimension,&wPackedCycleSize);
    if (pbPackedCycle==NULL) {
        free(pbPackedMatr);
        return NULL;
    }
    if (wPackedMatrSize!=wPackedCycleSize){
        fprintf(stderr,"WTF happened here?\n");
        free(pbPackedCycle);
        free(pbPackedMatr);
        return NULL;
    }
    dwComputedDataSize=FULL_KNOWLEDGE_FOR_STORAGE_HEADER_SIZE+((uint32_t) wPackedCycleSize)*2;
    pPackedFullKnowledge=calloc(0,dwComputedDataSize);
    if (pPackedFullKnowledge==NULL){
        free(pbPackedCycle);
        free(pbPackedMatr);
        return NULL;
    }
    pPackedFullKnowledge->dwSinglePackedMatrixSize=(uint32_t)wPackedMatrSize;
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
    int16_t swDimension;
    if (pbPackedFullKnowledge==NULL) return NULL;
    pFknForStorage=(PFULL_KNOWLEDGE_FOR_STORAGE)pbPackedFullKnowledge;
    pFullKnowledge=(PFULL_KNOWLEDGE)malloc(sizeof(FULL_KNOWLEDGE));
    if (pFullKnowledge==NULL) return NULL;
    pbUnpackedMatr=unpack_matr((uint16_t)pFknForStorage->dwSinglePackedMatrixSize,pFknForStorage->bData,&swDimension);
    if (pbUnpackedMatr==NULL){
        free(pFullKnowledge);
        return NULL;
    }
    pFullKnowledge->swDimension=swDimension;
    pFullKnowledge->dwMatrixArraySize=((uint32_t)swDimension)*(uint32_t)swDimension;

    pFullKnowledge->pbGraphMatrix=pbUnpackedMatr;
    pbUnpackedMatr=unpack_matr((uint16_t)pFknForStorage->dwSinglePackedMatrixSize,pFknForStorage->bData+(pFknForStorage->dwSinglePackedMatrixSize),&swDimension);
    if (pbUnpackedMatr==NULL){
        free(pFullKnowledge->pbGraphMatrix);
        free(pFullKnowledge);
        return NULL;
    }
    pFullKnowledge->pbCycleMatrix=pbUnpackedMatr;
    return pFullKnowledge;
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
    
    pbPackedMatrix=pack_matr(pFullKnowledge->pbGraphMatrix,pFullKnowledge->swDimension,(uint16_t*)&dwPackedMatrixSize);
    if (pbPackedMatrix==NULL) return NULL;
    dwGraphSetPacketSize=GRAPH_SET_PACKET_HEADER_SIZE + dwPackedMatrixSize;
    pGraphSetPacket=(PGRAPH_SET_PACKET)malloc(dwGraphSetPacketSize);
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
    if (dwDesiredSignatureSize<(HASH_SIZE+4)) return NULL;
    pbHash=hashsum(pbData,(ssize_t)dwDataSize);
    if (pbHash==NULL) return NULL;
    pbSign=malloc(dwDesiredSignatureSize);
    if (pbSign==NULL){
        free (pbHash);
        return NULL;
    }
    memcpy(pbSign+dwDesiredSignatureSize-HASH_SIZE,pbHash,HASH_SIZE);
    *pbSign=0;
    *(pbSign+1)=1;
    *(pbSign+dwDesiredSignatureSize-HASH_SIZE-1)=0;
    memset(pbSign+2,'\xff',dwDesiredSignatureSize-HASH_SIZE-3);
    return pbSign;
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
    int16_t wResSize;
    if (pMatrixHolder==NULL || pMatrixHolder->pbData) return NULL;
    pbPacked=pack_matr(pMatrixHolder->pbData,pMatrixHolder->wDimension,&wResSize);
    if (pbPacked==NULL) return NULL;
    dwResultingSize=(uint32_t)wResSize+PACKED_MATRIX_HEADER_SIZE;
    pPackedMatrix=(PPACKED_MATRIX)malloc(dwResultingSize);
    if (pPackedMatrix==NULL){
        free(pbPacked);
        return NULL;
    }
    pPackedMatrix->wDimension=pMatrixHolder->wDimension;
    memcpy(pPackedMatrix->bData,pbPacked,(uint32_t)wResSize);
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