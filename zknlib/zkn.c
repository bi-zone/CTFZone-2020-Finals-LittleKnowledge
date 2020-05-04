/*
zkn.c - Main code file containing Zero-Knowledge functionality and exported functions

The macro SAFE_VERSION is never used and represents the changes you would need to make, to fix the intended bugs
Authors:
    Innokentii Sennovskii (i.sennovskiy@bi.zone)
*/

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
        This function intializes permanent Zero-Knowledge information (mostly configuration) for storage by the Verifier.
        The information stored includes:
            The number of vertices in the graph used for Zero-Knowledge (or the dimension of square graph adjacency matrix)
            The number of checks during each parallel interaction
            Supported commitment algorithms
    arguments:
        wVerticeCount - desired adjacency matrix dimension (Graph vertice count)
        bCheckCount - the number of checks done in parallel
        bSupportedAlgorithms - the choice of commitment algorithms
    return value:
        SUCCESS - pointer to the state structure
        ERROR - NULL
*/
PZKN_STATE initializeZKnState(uint16_t wVerticeCount, uint8_t bCheckCount, uint8_t bSuppportedAlgorithms)
{
    PZKN_STATE pZKnState;
    //First we check that wVerticeCount and bCheckCount fit the chosen scope 
    if ((wVerticeCount>MAX_MATRIX_DIMENSION)|| (wVerticeCount<MIN_MATRIX_DIMENSION)) return NULL;
    if (bCheckCount<MINIMUM_CHECK_COUNT || bCheckCount>MAXIMUM_CHECK_COUNT) return NULL;
    //bSupportedAlgorithms is bit-mask of three bits and at least one of them needs to be set.
    if (bSuppportedAlgorithms<1 || bSuppportedAlgorithms>7) return NULL;

    pZKnState=(PZKN_STATE)malloc(sizeof(ZKN_STATE));
    if (pZKnState==NULL) return NULL;
    //Saving initial settings
    pZKnState->wDefaultVerticeCount=wVerticeCount;
    pZKnState->bCheckCount=bCheckCount;
    pZKnState->supportedAlgorithms.supportedAlgsCode=bSuppportedAlgorithms;
    //The flag and graph are to be initialized later by the checker
    pZKnState->pbFLAG=NULL;
    pZKnState->pZKnGraph=NULL;
    //Simulation mode is enabled by default. This is one of the intended bugs.
    //It allows an attacker invert the commitment/challenge part of the protocol
    // and commit to a proof, when he already knows the challenge
#ifdef SAFE_VERSION
    pZKnState->simulationDisabled=1;
#else
    pZKnState->simulationDisabled=0;
#endif
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
        This function is used at the beginning of Checker - Verifier interaction,
        when the checker wants to set the Zero-Knowledge graph. Since the Prover chooses vertice count,
        we need to creat a packet, that transmits the desired vertice count. We also include a random 16-byte
        value in the packet to protect against reuse attacks.
    arguments:
        pZKnState - initialized Zero-Knowledge state
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
    //Read 16 bytes from /dev/urandom to the packet
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
    //Add desired vertice count
    pInitialSettingPacket->wVerticeCount=pZKnState->wDefaultVerticeCount;
    return (uint8_t *) pInitialSettingPacket;
}

/*
    void freeDanglingPointer(void* pPointer);
    description:
        Free a pointer (we need this to call "free" from python)
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
        to Bleichenbacher's arrack on signatures with e=3. We don't account for the size of the signature,
        just take the first SHA256_SIZE bytes after 00 01 FF .. FF 00.

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
#ifdef SAFE_VERSION
    //Check that there are no bytes left, apart from hash itself
    //(We presume that the caller did not truncate the signature after exponentiation
    // and the dsSize is the equal to modulus size in bytes
    if ((dsSize-i)!=SHA256_SIZE) return NULL;
#endif
    return pDecryptedSignature+i;
}

/*
    uint32_t updateZKNGraph(PZKN_STATE pZKNState, PGRAPH_SET_PACKET pGraphSetPacket, uint32_t packetSize,
                            void* pDecryptedSignature, uint32_t dsSize, uint8_t* pRANDOMR)
    description:
        Update the graph and flag in Zero-Knowledge state. First we check the correctness and authenticity
         of the data, then we update everything. 
    arguments:
        pZKNState - pointer to zero knowledge state structure
        pGraphSetPacket - pointer to GRAPH_SET_PACKET structure
        packetSize - size of packet
        pDecryptedSignature - pointer to decrypted signature array
        dsSize - size of decrypted signature array
        pRANDOMR - pointer to RANDOM R (used for packet uniqueness check)
    return value:
        SUCCESS - SUCCESS 
        ERROR:
            ERROR_SYSTEM - something went wrong during parsing (not caller's fault)
            ERROR_BAD_VALUE - something was not right with the data (probably caller's fault)

*/
uint32_t updateZKnGraph(PZKN_STATE pZKNState,PGRAPH_SET_PACKET pGraphSetPacket, uint32_t dwPacketSize, uint8_t* pbDecryptedSignature, uint32_t dsSize, uint8_t* pRANDOMR)
{
    uint8_t* pbHashFromPKCS;
    uint8_t* pbComputedHash;
    uint8_t* pbPlaceHolder;
    uint8_t* pbUnpackedMatrix;
    uint16_t wMatrixDimension;
    uint32_t dwUnpackedMatrixSize;
    PGRAPH pZKNGraph;
    //First let's check that everything important is initialized
    if (pZKNState==NULL||pGraphSetPacket==NULL || pbDecryptedSignature==NULL || pRANDOMR==NULL) return ERROR_SYSTEM;
    //Check that packet size is at least big enough for the header (so that we don't try access uninitialized memory)
    if (dwPacketSize<GRAPH_SET_PACKET_HEADER_SIZE) return ERROR_REASON_WRONG_VALUE;
    //Get hash from the signature
    pbHashFromPKCS=badPKCSUnpadHash(pbDecryptedSignature,dsSize);
    //Signature contents may be incorrect
    if (pbHashFromPKCS==NULL) return ERROR_BAD_VALUE;
//We would like to check our code for unintended bugs before we ship it
// so we want to fuzz it. Certain checks will make it impossible  to reach
// critical functionality that can contain bugs, so we use preprocessor definitions
// to disable such checks. Here sha256 and RANDOMR checks are disabled
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    //Computing the actual hash of the packets
    pbComputedHash=sha256((unsigned char*) pGraphSetPacket,(ssize_t)dwPacketSize);
    if (pbComputedHash==NULL) return ERROR_SYSTEM;
    //Comparing the hashes
    if (memcmp(pbHashFromPKCS,pbComputedHash,SHA256_SIZE)!=0){
        free(pbComputedHash);
        return ERROR_BAD_VALUE;
    }
    free(pbComputedHash);
    //Comparing RANDOMR to prevent reuse attacks
    if (memcmp(pRANDOMR,pGraphSetPacket->RANDOM_R,RANDOM_R_SIZE)!=0) return ERROR_BAD_VALUE;
#endif
    //Check that packed matrix size is correct
    if (pGraphSetPacket->dwPackedMatrixSize!=(dwPacketSize-GRAPH_SET_PACKET_HEADER_SIZE)) return ERROR_BAD_VALUE;
    //Unpack the matrix, since we'll mostly need it in unpacked form from now on
    pbUnpackedMatrix=unpackMatrix(pGraphSetPacket->dwPackedMatrixSize,pGraphSetPacket->bPackedMatrixData,&wMatrixDimension);
    if (pbUnpackedMatrix==NULL) return ERROR_BAD_VALUE;
    //Make sure the dimension of the matrix is the same as we requested in initial settings packet
    if (wMatrixDimension!=pZKNState->wDefaultVerticeCount) {
        free(pbUnpackedMatrix);
        return ERROR_BAD_VALUE;
    }
    //Compute unpacked matrix size
    dwUnpackedMatrixSize=(((uint32_t) wMatrixDimension)*(uint32_t)wMatrixDimension);
    //Allocate memory for holding the flag if it's the first time we receive an update
    if (pZKNState->pbFLAG==NULL){
        pbPlaceHolder=malloc(FLAG_ARRAY_SIZE);
        if (pbPlaceHolder==NULL) 
        {
            free(pbUnpackedMatrix);
            return ERROR_SYSTEM;
        }
        pZKNState->pbFLAG=pbPlaceHolder;
    }
    //Free previous graph if it exists
    if (pZKNState->pZKnGraph!=NULL) free(pZKNState->pZKnGraph->pbGraphData);
    free(pZKNState->pZKnGraph);
    //Allocate memory for a new one
    pbPlaceHolder=malloc(sizeof(GRAPH));
    if (pbPlaceHolder==NULL) {
        free(pbUnpackedMatrix);
        return ERROR_SYSTEM;
    }
    //Save graph matrix, dimension, size, 
    pZKNState->pZKnGraph=(PGRAPH)pbPlaceHolder;
    memcpy(pZKNState->pbFLAG,pGraphSetPacket->FLAG,FLAG_ARRAY_SIZE);
    pZKNGraph=pZKNState->pZKnGraph;
    pZKNGraph->wVerticeCount=wMatrixDimension;
    pZKNGraph->dwMatrixSize=dwUnpackedMatrixSize;
    pZKNGraph->pbGraphData=pbUnpackedMatrix;
    return SUCCESS;
}


/*
    PFULL_KNOWLEDGE createFullKnowledgeForServer(uint16_t wVerticeCount)
    description:
        Create a graph with a hamiltonian cycle and the cycle given the number of vertices,
         save them both to a FULL_KNOWLEDGE structure and return the pointer
    arguments:
        wVerticeCount - number of vertices in graph
    return value:
        SUCCESS - pointer to FULL_KNOWLEDGE structure
        ERROR - NULL

*/
PFULL_KNOWLEDGE createFullKnowledgeForServer(uint16_t wVerticeCount){
    //We just proxy it to matrices/matr.c, which holds all the matrix logic
    return generateGraphAndCycleMatrix(wVerticeCount);
};

/*    
    void freeFullKnowledgeForServer(PFULL_KNOWLEDGE pFullKnowledge){
    description:
        Free all members of structure and the structure itself
    arguments:
        pfullKnowledge - pointer to FULL_KNOWLEDGE structure
    return value:
        N/A
*/
void freeFullKnowledgeForServer(PFULL_KNOWLEDGE pFullKnowledge){
    //Proxy to matrices/matr.c
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
    //Sanity check
    if (pFullKnowledge==NULL || pFullKnowledge->pbCycleMatrix==NULL || pFullKnowledge->pbGraphMatrix==NULL) return NULL;
    //Pack graph matrix
    pbPackedMatr=packMatrix(pFullKnowledge->pbGraphMatrix,pFullKnowledge->wDimension,&dwPackedMatrSize);
    if (pbPackedMatr==NULL) return NULL;
    //Pack cycle matrix
    pbPackedCycle=packMatrix(pFullKnowledge->pbCycleMatrix,pFullKnowledge->wDimension,&dwPackedCycleSize);
    if (pbPackedCycle==NULL) {
        free(pbPackedMatr);
        return NULL;
    }
    //Make sure that packed matrices have the same size (should always be true)
    if (dwPackedMatrSize!=dwPackedCycleSize){
        fprintf(stderr,"WTF happened here?\n");
        free(pbPackedCycle);
        free(pbPackedMatr);
        return NULL;
    }
    //Compute resulting Packed Full Knowledge size and allocate resulting memory
    dwComputedDataSize=FULL_KNOWLEDGE_FOR_STORAGE_HEADER_SIZE+((uint32_t) dwPackedCycleSize)*2;
    pPackedFullKnowledge=malloc(dwComputedDataSize);
    if (pPackedFullKnowledge==NULL){
        free(pbPackedCycle);
        free(pbPackedMatr);
        return NULL;
    }
    //Save single matrix size, and copy packed graph matrix and cycle matrix consecutively to packed knowledge
    pPackedFullKnowledge->dwSinglePackedMatrixSize=dwPackedMatrSize;
    memcpy(pPackedFullKnowledge->bData,pbPackedMatr,pPackedFullKnowledge->dwSinglePackedMatrixSize);
    memcpy(pPackedFullKnowledge->bData+(pPackedFullKnowledge->dwSinglePackedMatrixSize),pbPackedCycle,pPackedFullKnowledge->dwSinglePackedMatrixSize);
    free(pbPackedCycle);
    free(pbPackedMatr);
    //Output resulting packed full knowledge size
    *(pdwDataSize)=dwComputedDataSize;
    //return pointer to memory containing packed full knowledge
    return (uint8_t*)pPackedFullKnowledge;
}

/*
    PFULL_KNOWLEDGE unpackFullKnowledgeFromStorage(uint8_t* pbPackedFullKnowledge, uint32_t dwPackedFullKnowledgeSize)
    description:
        Unpack FULL_KNOWLEDGE from a version for storage and save to a regular FULL_KNOWLEDGE structure
    arguments:
        pbPackedFullKnowledge - pointer to array containing packed Full Knowledge
        dwPackedFullKnowledgeSize - size of packed Full Knowledge array
    return value:
        SUCCESS - pointer to unpacked FULL_KNOWLEDGE structure
        FAIL - NULL
*/
PFULL_KNOWLEDGE unpackFullKnowledgeFromStorage(uint8_t* pbPackedFullKnowledge, uint32_t dwPackedFullKnowledgeSize){
    PFULL_KNOWLEDGE pFullKnowledge;
    PFULL_KNOWLEDGE_FOR_STORAGE pFknForStorage;
    uint8_t *pbUnpackedMatr;
    uint16_t wDimension;
    //Sanity check
    if (pbPackedFullKnowledge==NULL) return NULL;
    //Check that there is enough data to access header fields
    if (dwPackedFullKnowledgeSize<FULL_KNOWLEDGE_FOR_STORAGE_HEADER_SIZE) return NULL;
    pFknForStorage=(PFULL_KNOWLEDGE_FOR_STORAGE)pbPackedFullKnowledge;
    //Check that sizes don't overflow anything and are in designated scope
    if ((pFknForStorage->dwSinglePackedMatrixSize*2)!=(dwPackedFullKnowledgeSize-FULL_KNOWLEDGE_FOR_STORAGE_HEADER_SIZE) || pFknForStorage->dwSinglePackedMatrixSize>MAX_MATR_BYTE_SIZE) return NULL;

    pFullKnowledge=(PFULL_KNOWLEDGE)malloc(sizeof(FULL_KNOWLEDGE));
    if (pFullKnowledge==NULL) return NULL;
    //Unpack Graph matrix
    pbUnpackedMatr=unpackMatrix(pFknForStorage->dwSinglePackedMatrixSize,pFknForStorage->bData,&wDimension);
    if (pbUnpackedMatr==NULL){
        free(pFullKnowledge);
        return NULL;
    }
    //Save matrix dimension and size in memory to FULL_KNOWLEDGE
    pFullKnowledge->wDimension=wDimension;
    pFullKnowledge->dwMatrixArraySize=((uint32_t)wDimension)*(uint32_t)wDimension;

    //Save matrix unpacked graph matrix to full knowledge structure
    pFullKnowledge->pbGraphMatrix=pbUnpackedMatr;
    //Unpack Cycle matrix
    pbUnpackedMatr=unpackMatrix(pFknForStorage->dwSinglePackedMatrixSize,pFknForStorage->bData+(pFknForStorage->dwSinglePackedMatrixSize),&wDimension);
    if (pbUnpackedMatr==NULL){
        free(pFullKnowledge->pbGraphMatrix);
        free(pFullKnowledge);
        return NULL;
    }
    //Save unpacked cycle matrix to Full Knowledge structure
    pFullKnowledge->pbCycleMatrix=pbUnpackedMatr;
    //return pointer to FULL_KNOWLEDGE
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
        SUCCESS - vertice count
        ERROR - 0
*/
uint16_t getDesiredVerticeCountFromInitialSettingPacket(uint8_t* pbInitialSettingPacket, uint32_t dwPacketSize){
    PINITIAL_SETTING_PACKET pInitialSettingPacket;
    //Check that packet is big enough
    if (dwPacketSize<sizeof(INITIAL_SETTING_PACKET)||pbInitialSettingPacket==NULL) return 0;
    pInitialSettingPacket=(PINITIAL_SETTING_PACKET)pbInitialSettingPacket;
    //Return vertice count
    return pInitialSettingPacket->wVerticeCount;
}
/*
    PGRAPH_SET_PACKET createGraphSetPacket(PFULL_KNOWLEDGE pFullKnowledge,uint8_t* pbRANDOM_R, char* psbFLAG, out uint32_t* pdwGraphSetPacketSize)
    description:
        Create a packet for setting graph matrix and flag on the verifier
    arguments:
        pFullKnowledge - pointer to FULL KNOWLEDGE structure
        pbRANDOM_R - pointer to array containing random_r from clinet
        psbFLAG - pointer to FLAG array
        pdwGraphSetPacketSize - pointer to output resulting packet size
    return value:
        SUCCESS - pointer to the packet
        FAIL - NULL
*/
PGRAPH_SET_PACKET createGraphSetPacket(PFULL_KNOWLEDGE pFullKnowledge,uint8_t* pbRANDOM_R, char* psbFLAG, out uint32_t* pdwGraphSetPacketSize){
    PGRAPH_SET_PACKET pGraphSetPacket;
    uint32_t dwGraphSetPacketSize;
    uint8_t* pbPackedMatrix;
    uint32_t dwPackedMatrixSize;
    dwPackedMatrixSize=0;
    //Sanity check
    if (pFullKnowledge==NULL || pbRANDOM_R==NULL || psbFLAG==NULL || pdwGraphSetPacketSize==NULL) return NULL; 
    //Pack Graph matrix
    pbPackedMatrix=packMatrix(pFullKnowledge->pbGraphMatrix,pFullKnowledge->wDimension,&dwPackedMatrixSize);
    if (pbPackedMatrix==NULL) return NULL;
    //Compute and send packet size to the caller
    dwGraphSetPacketSize=GRAPH_SET_PACKET_HEADER_SIZE + dwPackedMatrixSize;
    *(pdwGraphSetPacketSize)=dwGraphSetPacketSize;
    //Allocate memory for the packet
    pGraphSetPacket=(PGRAPH_SET_PACKET)calloc(dwGraphSetPacketSize,1);
    if(pGraphSetPacket==NULL){
        free(pbPackedMatrix);
        return NULL;
    }
    //Fill the packet with packed matrix size, flag, RANDOM_R and packed matrix
    pGraphSetPacket->dwPackedMatrixSize=dwPackedMatrixSize;
    memcpy(pGraphSetPacket->FLAG,psbFLAG,FLAG_ARRAY_SIZE);
    memcpy(pGraphSetPacket->RANDOM_R,pbRANDOM_R,RANDOM_R_SIZE);
    memcpy(pGraphSetPacket->bPackedMatrixData,pbPackedMatrix,dwPackedMatrixSize);
    free(pbPackedMatrix);
    //Return pointer to the packet
    return pGraphSetPacket;
}

/*
    uint8_t* createPKCSSignature(uint8_t* pbData,uint32_t dwDataSize,uint32_t dwDesiredSignatureSize)
    description:
        Create the PKCS#1 v1.5 signature array without cryptography (signing is handled by the caller)
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
    //Check that desired signature size will fit at least 00 01 FF 00 HASH
    if (dwDesiredSignatureSize<(SHA256_SIZE+4)) return NULL;
    //Compute sha256
    pbHash=sha256(pbData,(ssize_t)dwDataSize);
    if (pbHash==NULL) return NULL;
    //Allocate memory for signature
    pbSign=calloc(dwDesiredSignatureSize,1);
    if (pbSign==NULL){
        free (pbHash);
        return NULL;
    }
    //Copy sha256 to signature
    memcpy(pbSign+dwDesiredSignatureSize-SHA256_SIZE,pbHash,SHA256_SIZE);
    free(pbHash);
    //Set 00 01 in the beginning
    *pbSign=0;
    *(pbSign+1)=1;
    //Set 00 before the hash
    *(pbSign+dwDesiredSignatureSize-SHA256_SIZE-1)=0;
    //Fill remaining space with FF
    memset(pbSign+2,'\xff',dwDesiredSignatureSize-SHA256_SIZE-3);
    //Return the signature
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
    //Sanity check
    if (pZKnState==NULL ||pZKnState->pZKnGraph==NULL ||pZKnState->pZKnGraph->pbGraphData==NULL|| pdwPacketSize==NULL) return NULL;
    //Pack graph matrix
    pbPackedMatrix=packMatrix(pZKnState->pZKnGraph->pbGraphData,pZKnState->pZKnGraph->wVerticeCount,&dwPackedMatrixSize);
    if (pbPackedMatrix==NULL) return NULL;
    //Compute packet size
    dwPacketSize=PROOF_CONFIGURATON_PACKET_HEADER_SIZE + (uint32_t) dwPackedMatrixSize;
    //Allocate memory for packet
    pProofConfigurationPacket=(PPROOF_CONFIGURATION_PACKET) malloc(dwPacketSize);
    if (pProofConfigurationPacket==NULL){
        free (pbPackedMatrix);
        return NULL;
    }
    //Fill the check count, supported algorithms, packed matrix size and packed matrix in the packet
    pProofConfigurationPacket->bCheckCount=pZKnState->bCheckCount;
    pProofConfigurationPacket->supportedAlgorithms=pZKnState->supportedAlgorithms;
    pProofConfigurationPacket->dwPackedMatrixSize=(uint32_t)dwPackedMatrixSize;
    memcpy(pProofConfigurationPacket->bPackedMatrixData,pbPackedMatrix,(ssize_t)dwPackedMatrixSize);
    free(pbPackedMatrix);
    //Send the size of the packet to the caller
    *pdwPacketSize=dwPacketSize;
    //Return the packet
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
    //Set default error reason
    *(pbErrorReason)=ERROR_REASON_NONE;
    //Sanity check
    if (pFullKnowledge==NULL || pProofConfigurationPacket==NULL) {
        *(pbErrorReason)=ERROR_REASON_SYSTEM;
        return NULL;
    }
    //Checking packet size (this is untrusted data, we need to be careful)
    if  (dwPacketSize<PROOF_CONFIGURATON_PACKET_HEADER_SIZE){
        *(pbErrorReason)=ERROR_REASON_WRONG_VALUE;
        return NULL;
    }
    //Verify check count is within limits
    if (pProofConfigurationPacket->bCheckCount < MINIMUM_CHECK_COUNT || pProofConfigurationPacket->bCheckCount > MAXIMUM_CHECK_COUNT){
        *pbErrorReason=ERROR_REASON_WRONG_VALUE;
        return NULL;
    }
    //Verify at least one of commitment algorithms is supported
    if (pProofConfigurationPacket->supportedAlgorithms.supportedAlgsCode==0){
        *pbErrorReason=ERROR_REASON_WRONG_VALUE;
        return NULL;
    }
    //Check that packed matrix size is the same as packet size without the header
    if (pProofConfigurationPacket->dwPackedMatrixSize!=(dwPacketSize-PROOF_CONFIGURATON_PACKET_HEADER_SIZE) || pProofConfigurationPacket->dwPackedMatrixSize==0){
        *pbErrorReason=ERROR_REASON_CHEATING;
        return NULL;
    }
    //Unpack matrix
    pbUnpackedMatrix=unpackMatrix(pProofConfigurationPacket->dwPackedMatrixSize, pProofConfigurationPacket->bPackedMatrixData,&wDimension);
    if (pbUnpackedMatrix==NULL) 
    {
        *(pbErrorReason)=ERROR_REASON_SYSTEM;
        return NULL;
    }
    //Check that dimensions of the received matrix and the matrix that the prover created are the same
    if (wDimension!=pFullKnowledge->wDimension) {
        *(pbErrorReason)=ERROR_REASON_WRONG_VALUE;
        free(pbUnpackedMatrix);
        return NULL;
    }
    //Check that Prover's graph matrix and Verifier's graph matrix are the same
    if (memcmp(pFullKnowledge->pbGraphMatrix,pbUnpackedMatrix,pFullKnowledge->dwMatrixArraySize)!=0){
        *(pbErrorReason)=ERROR_REASON_WRONG_VALUE;
        free(pbUnpackedMatrix);
        return NULL;
    }
    //Allocate memory for PROOF_HELPER
    pProofHelper=(PPROOF_HELPER) malloc(sizeof(PROOF_HELPER));
    if (pProofHelper==NULL) {
        *(pbErrorReason)=ERROR_REASON_SYSTEM;
        free(pbUnpackedMatrix);
        return NULL;
    }
    //Fill PROOF_HELPER with pointer to FULL_KNOWLEDGE, supported algorithms and check count
    pProofHelper->pFullKnowledge=pFullKnowledge;
    pProofHelper->supportedAlgorithms=pProofConfigurationPacket->supportedAlgorithms;
    pProofHelper->bCheckCount=pProofConfigurationPacket->bCheckCount;
    free(pbUnpackedMatrix);
    //Return pointer to proof helper
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
    //Sanity check
    if (pProofHelper==NULL) return NULL;
    //Allocate SINGLE_PROOF structure
    pSingleProof=(PSINGLE_PROOF) malloc(sizeof(SINGLE_PROOF));
    if (pSingleProof==NULL) return NULL;
    //Generate permutation matrix
    pbPermutationMatrix=generatePermutationMatrix(pProofHelper->pFullKnowledge->wDimension);
    if (pbPermutationMatrix==NULL){
        free(pSingleProof);
        return NULL;
    }
    //Compute permuted graph matrix
    pbPermutedGraphMatrix=permuteMatrix(pbPermutationMatrix,pProofHelper->pFullKnowledge->pbGraphMatrix,pProofHelper->pFullKnowledge->wDimension);
    if (pbPermutedGraphMatrix==NULL){
        free(pSingleProof);
        free(pbPermutationMatrix);
        return NULL;
    } 
    //Compute permuted cycle matrix
    pbPermutedCycleMatrix=permuteMatrix(pbPermutationMatrix,pProofHelper->pFullKnowledge->pbCycleMatrix,pProofHelper->pFullKnowledge->wDimension);
    if (pbPermutedCycleMatrix==NULL){
        free(pSingleProof);
        free(pbPermutationMatrix);
        free(pbPermutedGraphMatrix);
        return NULL;
    }
    //Pack permutation matrix 
    pbPackedMatrix=packMatrix(pbPermutationMatrix,pProofHelper->pFullKnowledge->wDimension,&dwPackedMatrixSize);
    if (pbPackedMatrix==NULL){
        free(pSingleProof);
        free(pbPermutationMatrix);
        free(pbPermutedCycleMatrix);
        free(pbPermutedGraphMatrix);
        return NULL;
    }
    //Save packed matrix size and packed permutation matrix
    pSingleProof->dwPackedMatrixSize=dwPackedMatrixSize;
    pSingleProof->pbPackedPermutationMatrix=pbPackedMatrix;
    free(pbPermutationMatrix);
    //Pack permuted graph matrix
    pbPackedMatrix=packMatrix(pbPermutedGraphMatrix,pProofHelper->pFullKnowledge->wDimension,&dwPackedMatrixSize);
    //The sizes of all packed matrixes should be the same
    if (pbPackedMatrix==NULL||dwPackedMatrixSize!=pSingleProof->dwPackedMatrixSize){
        free(pSingleProof->pbPackedPermutationMatrix);
        free(pSingleProof);
        free(pbPermutedCycleMatrix);
        free(pbPermutedGraphMatrix);
        return NULL;
    }
    //Save packed permuted graph matrix
    pSingleProof->pbPackedPermutedGraphMatrix=pbPackedMatrix;
    free(pbPermutedGraphMatrix);
    //Pack permuted cycle matrix
    pbPackedMatrix=packMatrix(pbPermutedCycleMatrix,pProofHelper->pFullKnowledge->wDimension,&dwPackedMatrixSize);
    if (pbPackedMatrix==NULL||dwPackedMatrixSize!=pSingleProof->dwPackedMatrixSize){
        free(pSingleProof->pbPackedPermutationMatrix);
        free(pSingleProof->pbPackedPermutedGraphMatrix);
        free(pSingleProof);
        free(pbPermutedCycleMatrix);
        return NULL;
    }
    //Save packed permuted cycle matrix
    pSingleProof->pbPackedPermutedCycleMatrix=pbPackedMatrix;
    free(pbPermutedCycleMatrix);
    //Return pointer to SINGLE_PROOF
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
    //Sanity check
    if (pSingleProof==NULL) return;
    free(pSingleProof->pbPackedPermutationMatrix);
    free(pSingleProof->pbPackedPermutedCycleMatrix);
    free(pSingleProof->pbPackedPermutedGraphMatrix);
    free(pSingleProof);
}

/*
    PSINGLE_PROOF* createProofsForOneRound(PPROOF_HELPER pProofHelper)
    definition:
        Create an array of single proofs enough for one round. Repeatedly calls createSingleProof and adds them to an array
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
    //Sanity check
    if (pProofHelper==NULL) return NULL;
    //Allocate array of pointers to proofs
    pProofArray=(PSINGLE_PROOF*)malloc(sizeof(SINGLE_PROOF)*(uint32_t)(pProofHelper->bCheckCount));
    if (pProofArray==NULL) return NULL;
    //Create proofs one by one
    for (bIndex=0;bIndex<pProofHelper->bCheckCount;bIndex=bIndex+1){
        pSingleProof=createSingleProof(pProofHelper);
        if (pSingleProof==NULL) break;
        pProofArray[bIndex]=pSingleProof;
    }
    //If for some reason we couldn't create enough proofs, free the ones we did create
    if (bIndex!=pProofHelper->bCheckCount){
        for (bJndex=0;bJndex<bIndex;bJndex=bJndex+1){
            freeSingleProof(pProofArray[bJndex]);
        }
        free(pProofArray);
        return NULL;
    }
    //Return array of proofs
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
    //Sanity check
    if (pProofArray==NULL || pProofHelper==NULL) return;
    //Free all SINGLE_PROOF structures one by one
    for (bIndex=0;bIndex<pProofHelper->bCheckCount;bIndex=bIndex+1){
        freeSingleProof(pProofArray[bIndex]);
    }
    //Free the proof array
    free(pProofArray);
}

/*
    uint8_t* createSingleCRC32Commitment(PSINGLE_PROOF pSingleProof,  out uint32_t* pdwSingleCommitmentSize)
    description:
        Create a single commitment with CRC32 hash (obviously not supposed to be computationally binding)
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
    //Sanity check
    if (pSingleProof==NULL || pdwSingleCommitmentSize==NULL) return NULL;
    dwSingleCommitmentSize=sizeof(CRC32_COMMITMENT);
    //Allocate CRC32_COMMITMENT structure
    pCRC32Commitment=(PCRC32_COMMITMENT)malloc(dwSingleCommitmentSize);
    if (pCRC32Commitment==NULL) return NULL;
    //Computed crc32 of packed permutation matrix
    pCRC32=crc32(pSingleProof->pbPackedPermutationMatrix,pSingleProof->dwPackedMatrixSize);
    if (pCRC32==NULL){
        free(pCRC32Commitment);
        return NULL;
    }
    //Copy to the structure
    memcpy(pCRC32Commitment->permutationCRC32,pCRC32,CRC32_SIZE);
    free(pCRC32);
    //Compute crc32 of packed permuted graph matrix
    pCRC32=crc32(pSingleProof->pbPackedPermutedGraphMatrix,pSingleProof->dwPackedMatrixSize);
    if (pCRC32==NULL){
        free(pCRC32Commitment);
        return NULL;
    }
    //Copy to the structure
    memcpy(pCRC32Commitment->permutedGraphCRC32,pCRC32,CRC32_SIZE);
    free(pCRC32);
    //Compute crc32 of packed permuted cycle matrix
    pCRC32=crc32(pSingleProof->pbPackedPermutedCycleMatrix,pSingleProof->dwPackedMatrixSize);
    if (pCRC32==NULL){
        free(pCRC32Commitment);
        return NULL;
    }
    //Copy to the structure
    memcpy(pCRC32Commitment->permutedCycleCRC32,pCRC32,CRC32_SIZE);
    free(pCRC32);
    //Send commitment size to the caller
    *pdwSingleCommitmentSize=dwSingleCommitmentSize;
    //Return commitment
    return (uint8_t*)pCRC32Commitment;
}

/*
    uint8_t* createCRC32CommitmentRound(PSINGLE_PROOF* pProofArray, PPROOF_HELPER pProofHelper, out uint32_t* pdwCommitmentDataSize)
    description:
        Create multiple CRC32 commitments from proof array and put them in one blob
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
    //No sanity check, it was done by the caller
    //Create CRC32 commitments one by one for every SINGLE_PROOF in pProofArray
    for (bIndex=0;bIndex<pProofHelper->bCheckCount;bIndex=bIndex+1){
        pSingleCommitment=createSingleCRC32Commitment(pProofArray[bIndex], &dwSingleCommitmentSize);
        if (pSingleCommitment==NULL){
            free(pCommitmentArray);
            return NULL;
        }
        //Could be made faster, but this method is more generic and works for all types of commitments
        //Reallocating the array holding commitments
        pCommitmentArray=realloc(pCommitmentArray,dwSingleCommitmentSize+dwCommitmentRoundDataSize);
        //Copy commitment to the blob
        memcpy(pCommitmentArray+dwCommitmentRoundDataSize,pSingleCommitment,dwSingleCommitmentSize);
        //Increase blob size
        dwCommitmentRoundDataSize=dwCommitmentRoundDataSize+dwSingleCommitmentSize;
        free(pSingleCommitment);
    }
    //Send resulting data size to the caller
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
    //Sanity check
    if (pSingleProof==NULL || pdwSingleCommitmentSize==NULL) return NULL;
    dwSingleCommitmentSize=sizeof(SHA256_COMMITMENT);
    //Allocate structure
    pSHA256Commitment=(PSHA256_COMMITMENT)malloc(dwSingleCommitmentSize);
    if (pSHA256Commitment==NULL) return NULL;
    //Compute packed permutation matrix sha256
    pSHA256=sha256(pSingleProof->pbPackedPermutationMatrix,pSingleProof->dwPackedMatrixSize);
    if (pSHA256==NULL){
        free(pSHA256Commitment);
        return NULL;
    }
    //Copy to structure
    memcpy(pSHA256Commitment->permutationSHA256,pSHA256,SHA256_SIZE);
    free(pSHA256);
    //Compute packed graph matrix sha256
    pSHA256=sha256(pSingleProof->pbPackedPermutedGraphMatrix,pSingleProof->dwPackedMatrixSize);
    if (pSHA256==NULL){
        free(pSHA256Commitment);
        return NULL;
    }
    //Copy to structure
    memcpy(pSHA256Commitment->permutedGraphSHA256,pSHA256,SHA256_SIZE);
    free(pSHA256);
    //Compute packed cycle matrix sha256
    pSHA256=sha256(pSingleProof->pbPackedPermutedCycleMatrix,pSingleProof->dwPackedMatrixSize);
    if (pSHA256==NULL){
        free(pSHA256Commitment);
        return NULL;
    }
    //Copy to structure
    memcpy(pSHA256Commitment->permutedCycleSHA256,pSHA256,SHA256_SIZE);
    free(pSHA256);
    //Send commitment size to the caller
    *pdwSingleCommitmentSize=dwSingleCommitmentSize;
    //Return commitment
    return (uint8_t*)pSHA256Commitment;
}

/*
    uint8_t* createSHA256CommitmentRound(PSINGLE_PROOF* pProofArray, PPROOF_HELPER pProofHelper, out uint32_t* pdwCommitmentDataSize)
    description:
        Create multiple SHA256 commitments from proof array and put them into one blob.
         (Calls createSingleSHA256Commitment repeatedly and puts results into one blob)
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
    //Sanity check were performed by the caller
    //Create single commitments one by one and append to the blob
    for (bIndex=0;bIndex<pProofHelper->bCheckCount;bIndex=bIndex+1){
        pSingleCommitment=createSingleSHA256Commitment(pProofArray[bIndex], &dwSingleCommitmentSize);
        if (pSingleCommitment==NULL){
            free(pCommitmentArray);
            return NULL;
        }
        //Reallocate blob to fit in one more commitment
        pCommitmentArray=realloc(pCommitmentArray,dwSingleCommitmentSize+dwCommitmentRoundDataSize);
        //Copy a single commitment to the blob
        memcpy(pCommitmentArray+dwCommitmentRoundDataSize,pSingleCommitment,dwSingleCommitmentSize);
        //Update blob size
        dwCommitmentRoundDataSize=dwCommitmentRoundDataSize+dwSingleCommitmentSize;
        free(pSingleCommitment);
    }
    //Return blob size and blob
    *pdwCommitmentDataSize=dwCommitmentRoundDataSize;
    return pCommitmentArray;
}

/*
    PAES_COMMITMENT createSingleAESCommitment(PSINGLE_PROOF pSingleProof, out uint32_t* pdwCommitmentSize, \
        out PSINGLE_AES_COMMITMENT_EXTRA_INFORMATION* ppSingleAesCommitmentExtraInformation)
    description:
        Create a single AES commitment. Packed permuted graph matrix is sent in plaintext, while packed permutation
         and cycle matrices are packed and encrypted with different keys.
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
    //sanity check
    if (pSingleProof==NULL || ppSingleAesCommitmentExtraInformation==NULL) return NULL;
    //Allocating structure
    pExtraInformation=(PSINGLE_AES_COMMITMENT_EXTRA_INFORMATION)malloc(sizeof(SINGLE_AES_COMMITMENT_EXTRA_INFORMATION));
    if (pExtraInformation==NULL) return NULL;
    //Generate initialization vectors and keys for permutation and permuted cycle encryption
    getRandomBytes(IV1,AES_IV_SIZE);
    getRandomBytes(IV2,AES_IV_SIZE);
    getRandomBytes(pExtraInformation->permutationKey,AES128_KEY_SIZE);
    getRandomBytes(pExtraInformation->permutedCycleKey,AES128_KEY_SIZE);
    //Encrypt packed permutation matrix with AES in CBC Mode
    pbEncryptedPermutationData=aes128cbc_encrypt(pSingleProof->pbPackedPermutationMatrix,pSingleProof->dwPackedMatrixSize, \
        pExtraInformation->permutationKey,IV1,&dwEncryptedPermutationDataSize);
    if (pbEncryptedPermutationData==NULL){
        free(pExtraInformation);
        return NULL;
    }
    //Encrypt packed permuted cycle matrix with AES in CBC Mode
    pbEncryptedCycleData=aes128cbc_encrypt(pSingleProof->pbPackedPermutedCycleMatrix,pSingleProof->dwPackedMatrixSize, \
        pExtraInformation->permutedCycleKey,IV2,&dwEncryptedCycleDataSize);
    if (pbEncryptedPermutationData==NULL || dwEncryptedCycleDataSize!=dwEncryptedPermutationDataSize){
        free(pbEncryptedCycleData);
        free(pbEncryptedPermutationData);
        free(pExtraInformation);
        return NULL;
    }
    //Compute commitment size
    dwSingleCommitmentSize=AES_COMMITMENT_HEADER_SIZE+2*dwEncryptedPermutationDataSize+pSingleProof->dwPackedMatrixSize;
    //Allocate structure
    pAESCommitment=(PAES_COMMITMENT)malloc(dwSingleCommitmentSize);
    if (pAESCommitment==NULL){
        free(pbEncryptedCycleData);
        free(pbEncryptedPermutationData);
        free(pExtraInformation);
        return NULL;
    }
    //Save packed matrix size and packed and encrypted matrix size to the structure
    pAESCommitment->dwPackedPermutedMatrixSize=pSingleProof->dwPackedMatrixSize;
    pAESCommitment->dwSingleCiphertextPlusIVSize=dwEncryptedCycleDataSize;
    //The data is located in this way: ( Packed and Encrypted Permutation Matrix | Packed and Encrypted Cycle Matrix | Packed Permuted Graph Matrix )
    //Copy the encrypted/packed matrices to the structure 
    memcpy(pAESCommitment->commitmentData,pbEncryptedPermutationData,dwEncryptedPermutationDataSize);
    memcpy(pAESCommitment->commitmentData+dwEncryptedPermutationDataSize,pbEncryptedCycleData,dwEncryptedCycleDataSize);
    memcpy(pAESCommitment->commitmentData+dwEncryptedPermutationDataSize+dwEncryptedCycleDataSize,pSingleProof->pbPackedPermutedGraphMatrix,pSingleProof->dwPackedMatrixSize);
    //Free everything we don't need any more
    free(pbEncryptedCycleData);
    free(pbEncryptedPermutationData);
    //Return commitment size, aes keys and commitment itself 
    *pdwCommitmentSize=dwSingleCommitmentSize;
    *ppSingleAesCommitmentExtraInformation=pExtraInformation;
    return pAESCommitment; 
}

/*
    uint8_t* createAESCommitmentRound(PSINGLE_PROOF* pProofArray, PPROOF_HELPER pProofHelper, out uint32_t* pdwCommitmentDataSize, \
        out PCOMMITMENT_EXTRA_INFORMATION* ppCommitmentExtraInformation)
    description:
        Create a full round worth of AES commitments. (Create single AES commitments and put them into one blob)
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
    //Sanity checks performed by the called
    //Allocate array of pointers to SINGLE_AES_COMMITMENT_EXTRA_INFORMATION (for AES keys)
    pAESExtraInformationArray=(PSINGLE_AES_COMMITMENT_EXTRA_INFORMATION*)malloc(sizeof(PSINGLE_AES_COMMITMENT_EXTRA_INFORMATION)*(uint32_t)pProofHelper->bCheckCount);
    if (pAESExtraInformationArray==NULL) return NULL;
    //Allocate COMMITMENT_EXTRA_INFORMATION structure (for saving AES keys)
    pCommitmentExtraInformation=(PCOMMITMENT_EXTRA_INFORMATION)malloc(sizeof(COMMITMENT_EXTRA_INFORMATION));
    //Return pointer to COMMITMENT_EXTRA_INFORMATION to the callser
    *ppCommitmentExtraInformation=pCommitmentExtraInformation;
    if (pCommitmentExtraInformation==NULL){
        free(pAESExtraInformationArray);
        return NULL;
    }
    //Fill the fields of COMMITMENT_EXTRA_INFORMATION with array pointer and array size
    pCommitmentExtraInformation->dwDataSize=sizeof(PSINGLE_AES_COMMITMENT_EXTRA_INFORMATION)*(uint32_t)pProofHelper->bCheckCount;
    pCommitmentExtraInformation->pbData=(uint8_t*)pAESExtraInformationArray;
    //Create single commitments one by one
    for(bIndex=0;bIndex<pProofHelper->bCheckCount;bIndex=bIndex+1){
        //Create SINGLE_AES_COMMITMENT, pointer to AES keys is automatically written to the array
        pbCurrentCommitment=(uint8_t*)createSingleAESCommitment(pProofArray[bIndex],&dwCurrentCommitmentSize,&pAESExtraInformationArray[bIndex]);
        if (pbCurrentCommitment==NULL){
            //If something goes wrong we need to free all allocated buffers
            for (bJndex=0;bJndex<bIndex;bJndex=bJndex+1){
                free(pAESExtraInformationArray[bJndex]);
            }
            free(pAESExtraInformationArray);
            free(pbCommitmentRoundData);
            return NULL;
        }
        //Reallocate the commitment array to append the commitment
        pbCommitmentRoundData=realloc(pbCommitmentRoundData,dwTotalCommitmentDataSize+dwCurrentCommitmentSize);
        //Something goes wrong - free everything
        if (pbCommitmentRoundData==NULL){
            for (bJndex=0;bJndex<bIndex;bJndex=bJndex+1){
                free(pAESExtraInformationArray[bJndex]);
            }
            free(pAESExtraInformationArray);
            return NULL;
       } 
       //Copy commitment to blob
       memcpy(pbCommitmentRoundData+dwTotalCommitmentDataSize,pbCurrentCommitment,dwCurrentCommitmentSize);
       //Free commitment buffer
       free(pbCurrentCommitment);
       //Update total blob size
       dwTotalCommitmentDataSize=dwTotalCommitmentDataSize+dwCurrentCommitmentSize;
    }
    //Return blob size and pointer to blob
   *pdwCommitmentDataSize=dwTotalCommitmentDataSize;
   return pbCommitmentRoundData; 
}


/*
    void freeCommitmentExtraInformation(PPROOF_HELPER pProofHelper, PCOMMITMENT_EXTRA_INFORMATION pCommitmentExtraInformation)
    description:
        Free commitment extra information structure and its members
    arguments:
        pProofHelper - pointer to PROOF_HELPER, we only actually need check count
        pCommitmentExtraInformation - pointer to COMMITMENT_EXTRA_INFORMATION to free
    return value:
        N/A
*/
void freeCommitmentExtraInformation(PPROOF_HELPER pProofHelper,PCOMMITMENT_EXTRA_INFORMATION pCommitmentExtraInformation){
    if (pProofHelper==NULL || pCommitmentExtraInformation==NULL) return;
    uint8_t bIndex;
    PSINGLE_AES_COMMITMENT_EXTRA_INFORMATION* pArray;
    pArray=(PSINGLE_AES_COMMITMENT_EXTRA_INFORMATION*)pCommitmentExtraInformation->pbData;
    //Free all SINGLE_AES_COMMITMENT_EXTRA_INFORMATION pointers one by one
    for (bIndex=0;bIndex<pProofHelper->bCheckCount;bIndex=bIndex+1){
       free(pArray[bIndex]); 
    }
    //Free array and holding structure
    free(pCommitmentExtraInformation->pbData);
    free(pCommitmentExtraInformation);
}

/*
    PCOMMITMENT_PACKET createCommitmentPacket(PSINGLE_PROOF* pProofArray,PPROOF_HELPER pProofHelper,out uint32_t* pdwCommitmentPacketSize, \
        out PCOMMITMENT_EXTRA_INFORMATION* ppCommitmentExtraInformation)
    description:
        Create a FULL Round commitment packet that will hold CRC32, SHA256 or AES commitments
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
    COMMITMENT_ALGORITHMS commitmentAlgs;
    PCOMMITMENT_PACKET pCommitmentPacket;
    uint32_t dwCommitmentDataSize;
    uint32_t dwResultingPacketSize;
    uint8_t* pbCommitmentData;
    //Sanity check
    if (pProofArray==NULL || pProofHelper==NULL || pdwCommitmentPacketSize==NULL || ppCommitmentExtraInformation==NULL) return NULL;
    //In 2 out of 3 cases we don't need extra information, so we immediately set it to NULL just in case
    *ppCommitmentExtraInformation=NULL;
    commitmentAlgs=pProofHelper->supportedAlgorithms;
    //First check if CRC32 commitment is supported (we use the worst possible scenario)
    if(commitmentAlgs.isCRC32Supported){
        //If CRC32 commitment is supported, create CRC32 commitment
        pbCommitmentData=createCRC32CommitmentRound(pProofArray,pProofHelper,&dwCommitmentDataSize);
        if (pbCommitmentData==NULL) return NULL;
        //Compute resulting packet size and allocate the structure
        dwResultingPacketSize=dwCommitmentDataSize+COMMITMENT_PACKET_HEADER_SIZE;
        pCommitmentPacket=(PCOMMITMENT_PACKET)malloc(dwResultingPacketSize);
        if (pCommitmentPacket==NULL){
            free(pbCommitmentData);
            return NULL;
        }
        //Fill the fields of commitment packet with chosen commitment algorithm, number of checks,
        // commitment data size and actual commitment data
        pCommitmentPacket->bCommitmentCount=pProofHelper->bCheckCount;
        commitmentAlgs.supportedAlgsCode=0;
        commitmentAlgs.isCRC32Supported=1;
        pCommitmentPacket->commitmentType=commitmentAlgs;
        pCommitmentPacket->dwDataSize=dwCommitmentDataSize;
        memcpy(pCommitmentPacket->commitmentData,pbCommitmentData,dwCommitmentDataSize);
        free(pbCommitmentData);
        //Return packet size and pointer to packet
        *pdwCommitmentPacketSize=dwResultingPacketSize;
        return pCommitmentPacket;
    }else{
        //If not CRC32, check if SHA256 is supported
        if (commitmentAlgs.isSHA256Supported){
            //Create SHA256 commitment
            pbCommitmentData=createSHA256CommitmentRound(pProofArray,pProofHelper,&dwCommitmentDataSize);
            if (pbCommitmentData==NULL) return NULL;
            //Calculate resulting packet size and allocate structure
            dwResultingPacketSize=dwCommitmentDataSize+COMMITMENT_PACKET_HEADER_SIZE;
            pCommitmentPacket=(PCOMMITMENT_PACKET)malloc(dwResultingPacketSize);
            if (pCommitmentPacket==NULL){
                free(pbCommitmentData);
                return NULL;
            }
            //Fill the fields of commitment packet with chosen commitment algorithm, number of checks,
            // commitment data size and actual commitment data
            pCommitmentPacket->bCommitmentCount=pProofHelper->bCheckCount;
            commitmentAlgs.supportedAlgsCode=0;
            commitmentAlgs.isSHA256Supported=1;
            pCommitmentPacket->commitmentType=commitmentAlgs;
            pCommitmentPacket->dwDataSize=dwCommitmentDataSize;
            memcpy(pCommitmentPacket->commitmentData,pbCommitmentData,dwCommitmentDataSize);
            free(pbCommitmentData);
            //Return packet size and data
            *pdwCommitmentPacketSize=dwResultingPacketSize;
            return pCommitmentPacket;    
        }
        else{
            //If not SHA256 either, then check if AES
            if (commitmentAlgs.isAESSupported){
                //Create AES commitment
                pbCommitmentData=createAESCommitmentRound(pProofArray,pProofHelper,&dwCommitmentDataSize,ppCommitmentExtraInformation);
                if (pbCommitmentData==NULL) return NULL;
                //Calculate resulting packet size and allocate structure
                dwResultingPacketSize=dwCommitmentDataSize+COMMITMENT_PACKET_HEADER_SIZE;
                pCommitmentPacket=(PCOMMITMENT_PACKET)malloc(dwResultingPacketSize);
                if (pCommitmentPacket==NULL){
                    free(pbCommitmentData);
                    free(*ppCommitmentExtraInformation);
                    *ppCommitmentExtraInformation=NULL;
                    return NULL;
                }
                //Fill the fields of commitment packet with chosen commitment algorithm, number of checks,
                // commitment data size and actual commitment data
                pCommitmentPacket->bCommitmentCount=pProofHelper->bCheckCount;
                commitmentAlgs.supportedAlgsCode=0;
                commitmentAlgs.isAESSupported=1;
                pCommitmentPacket->commitmentType=commitmentAlgs;
                pCommitmentPacket->dwDataSize=dwCommitmentDataSize;
                memcpy(pCommitmentPacket->commitmentData,pbCommitmentData,dwCommitmentDataSize);
                free(pbCommitmentData);
                //Return packet size and pointer to packet
                *pdwCommitmentPacketSize=dwResultingPacketSize;
                return pCommitmentPacket;
            }else{
                //No other commitment algorithms, so return NULL
                return NULL;
            }
        }
    }

}
/*
    uint8_t saveCommitment(PZKN_STATE pZKnState,PZKN_PROTOCOL_STATE pZKnProtocolState,uint8_t* pbCommitmentData, uint32_t dwCommitmentDataSize)
    description:
        Save commitment for the proof (copy data). We are only checking the size of the commitment packet at this stage.
        Nothing more. 
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
    //Sanity check
    if (pZKnState==NULL || pZKnProtocolState==NULL || pbCommitmentData==NULL) return ERROR_SYSTEM;
    //Check that commitment data is at least as big as its header size
    if (dwCommitmentDataSize<COMMITMENT_PACKET_HEADER_SIZE) return ERROR_BAD_VALUE;
    //If simulation mode is disabled and we try to apply commitment several times during one iteration of the protocol,
    // then don't save commitment data. If simulation mode is enabled, then commitment is updated
    if (pZKnProtocolState->protocolProgress.isCommitmentStageComplete ){
        if ((pZKnState->simulationDisabled)!=0){
            return ERROR_BAD_VALUE;
        }
        //If we already have commitment data, free it
        free(pZKnProtocolState->pbCommitmentData);
    }
    //Allocate buffer for commitment data
    pZKnProtocolState->pbCommitmentData=(uint8_t*)malloc(dwCommitmentDataSize);
    if (pZKnProtocolState->pbCommitmentData==NULL) return ERROR_SYSTEM;
    //Copy commitment data, fill out data size in protocol state and mark commitment stage as complete
    memcpy(pZKnProtocolState->pbCommitmentData,pbCommitmentData,dwCommitmentDataSize);
    pZKnProtocolState->dwCommitmentDataSize=dwCommitmentDataSize;
    pZKnProtocolState->protocolProgress.isCommitmentStageComplete=1;
    //Return success
    return SUCCESS;
}

/*
    PCHALLENGE_PACKET createChallenge(PZKN_STATE pZKnState, PZKN_PROTOCOL_STATE pZKnProtocolState, out uint32_t* pdwPacketSize)
    description:
        Generate challenge (random bits) to send to the Prover
    arguments:
        pZKnState - pointer to structure holding general configuration
        pZKnProtocolState - pointer to protocol state structure
        pdwPacketSize - for output; packet size
    return value:
        SUCCESS - pointer to challenge packet
        FAIL - NULL
*/
PCHALLENGE_PACKET createChallenge(PZKN_STATE pZKnState, PZKN_PROTOCOL_STATE pZKnProtocolState, out uint32_t* pdwPacketSize){
    uint64_t qwRandom;
    uint8_t bBitLength;
    PCHALLENGE_PACKET pChallengePacket;
    //Sanity check
    if (pZKnState==NULL || pZKnProtocolState==NULL || pdwPacketSize==NULL) return NULL;
    //If commitment stage is not yet complete, there is no point in creating a challenge
    if (pZKnProtocolState->protocolProgress.isCommitmentStageComplete!=1) return NULL;
    //Allocate structure
    pChallengePacket=(PCHALLENGE_PACKET)calloc(1,sizeof(CHALLENGE_PACKET));
    if (pChallengePacket==NULL) return NULL;
    //Generate pZKnState->bCheckCount random bits on our insecure PRNG
    qwRandom=generateRandomUpTo64Bits(pZKnProtocolState->pLegendrePRNG,pZKnState->bCheckCount);
    //Fill the bit length and random fields in the packet 
    bBitLength=pZKnState->bCheckCount;
    pZKnProtocolState->qwRandom=qwRandom;
    pChallengePacket->qwRandom=qwRandom;
    pChallengePacket->bBitCount=bBitLength;
    //Mark challenge creation stage as complete
    pZKnProtocolState->protocolProgress.isChallengeCreationStageComplete=1;
    //Return packet size and pointer to the packet
    *pdwPacketSize=sizeof(CHALLENGE_PACKET);
    return pChallengePacket;
}

/*
    PCRC32_REVEAL createSingleCRC32Reveal(PSINGLE_PROOF pSingleProof,uint8_t bBit, out uint32_t* pdwRevealSize)
    description:
        Create single reveal for CRC32 (in this case we send (permuted graph | permutation) if bit is 0 and (permuted graph | permuted cycle) if bit is 1) 
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
    //Sanity check
    if (pSingleProof==NULL || pdwRevealSize==NULL) return NULL;
    //Allocate structure
    pCRC32Reveal=(PCRC32_REVEAL)malloc(pSingleProof->dwPackedMatrixSize*2+CRC32_REVEAL_HEADER_SIZE);
    if (pCRC32Reveal==NULL) return NULL;
    //Copy permuted graph packed matrix to the structure first
    memcpy(pCRC32Reveal->packedPermutedGraphAndPermutationOrCycle,pSingleProof->pbPackedPermutedGraphMatrix,pSingleProof->dwPackedMatrixSize);
    if (bBit==0){
        //If chosen bit is 0, copy packed permutation matrix to the structure
        memcpy(pCRC32Reveal->packedPermutedGraphAndPermutationOrCycle+pSingleProof->dwPackedMatrixSize,pSingleProof->pbPackedPermutationMatrix,pSingleProof->dwPackedMatrixSize);
    }else{
        //If chosen bit is 0, copy packed permuted cycle matrix to the structure
        memcpy(pCRC32Reveal->packedPermutedGraphAndPermutationOrCycle+pSingleProof->dwPackedMatrixSize,pSingleProof->pbPackedPermutedCycleMatrix,pSingleProof->dwPackedMatrixSize);
    }
    //Save size of single packed matrix to the structure
    pCRC32Reveal->dwPackedMatrixSize=pSingleProof->dwPackedMatrixSize;
    //Return structure size and pointer to structure
    *pdwRevealSize=pSingleProof->dwPackedMatrixSize*2+CRC32_REVEAL_HEADER_SIZE;
    return pCRC32Reveal;
}

/*
    uint8_t* createCRC32RevealRound(PSINGLE_PROOF* pProofArray, PCHALLENGE_PACKET pChallengePacket, out uint32_t* pdwRevealSize)
    description:
        Create full round worth of crc32 "reveal"s. Create single reveals and pack them together.
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
    //Sannity check
    if (pProofArray==NULL || pChallengePacket==NULL || pdwRevealSize==NULL ) return NULL;
    //Initialize variable that will hold updated challenge value
    qwCurrentBit=pChallengePacket->qwRandom;
    //Create single reveals one by one
    for (bIndex=0;bIndex<pChallengePacket->bBitCount; bIndex=bIndex+1){
        //Create single reveal
        pSingleReveal=createSingleCRC32Reveal(pProofArray[bIndex],(uint8_t)(qwCurrentBit&1),&dwCurrentRevealSize);
        //Shift QWORD that holds the challenge
        qwCurrentBit=qwCurrentBit>>1;
        if (pSingleReveal==NULL){
            free(pbRevealRound);
            return NULL;
        }
        //Reallocate reveal blob
        pbRevealRound=(uint8_t*)realloc(pbRevealRound,dwTotalRevealSize+dwCurrentRevealSize);
        if (pbRevealRound==NULL) {
            free(pSingleReveal);
            return NULL;
        }
        //Copy current reveal to the blob
        memcpy(pbRevealRound+dwTotalRevealSize,(uint8_t*)pSingleReveal,dwCurrentRevealSize);
        free(pSingleReveal);
        //Update total blob size
        dwTotalRevealSize=dwTotalRevealSize+dwCurrentRevealSize;
    }
    //Return blob size and pointer to blob
    *pdwRevealSize=dwTotalRevealSize;
    return pbRevealRound;
}

/*
    PCRC32_UNPACK_COMMITMENT createSingleSHA256Reveal(PSINGLE_PROOF pSingleProof,uint8_t bBit, out uint32_t* pdwRevealSize)
    description:
        Create single reveal for SHA256. This method is identical to createSingleCRC32Reveal.
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
    //Sanity check
    if (pSingleProof==NULL || pdwRevealSize==NULL) return NULL;
    //Allocate structure
    pSHA256Reveal=(PSHA256_REVEAL)malloc(pSingleProof->dwPackedMatrixSize*2+SHA256_REVEAL_HEADER_SIZE);
    if (pSHA256Reveal==NULL) return NULL;
    //Copy packed permuted graph matrix to the structure
    memcpy(pSHA256Reveal->packedPermutedGraphAndPermutationOrCycle,pSingleProof->pbPackedPermutedGraphMatrix,pSingleProof->dwPackedMatrixSize);
    if (bBit==0){
        //If challenge bit is 0, copy packed permutation matrix to the structure
        memcpy(pSHA256Reveal->packedPermutedGraphAndPermutationOrCycle+pSingleProof->dwPackedMatrixSize,pSingleProof->pbPackedPermutationMatrix,pSingleProof->dwPackedMatrixSize);
    }else{
        //If challenge bit is 1, copy packed permuted cycle matrix to the structure
        memcpy(pSHA256Reveal->packedPermutedGraphAndPermutationOrCycle+pSingleProof->dwPackedMatrixSize,pSingleProof->pbPackedPermutedCycleMatrix,pSingleProof->dwPackedMatrixSize);
    }
    //Save single packed matrix size to the structure
    pSHA256Reveal->dwPackedMatrixSize=pSingleProof->dwPackedMatrixSize;
    //Return reveal size and pointer to reveal
    *pdwRevealSize=pSingleProof->dwPackedMatrixSize*2+SHA256_REVEAL_HEADER_SIZE;
    return pSHA256Reveal;
}

/*
    uint8_t* createSHA256RevealRound(PSINGLE_PROOF* pProofArray, PCHALLENGE_PACKET pChallengePacket, out uint32_t* pdwRevealSize)
    description:
        Create full round worth of sha256 reveal. Identical to createCRC32RevealRound.
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
    //Sanity check
    if (pProofArray==NULL || pChallengePacket==NULL || pdwRevealSize==NULL ) return NULL;
    //Save challenge bit to new variable
    qwCurrentBit=pChallengePacket->qwRandom;
    //Get single reveals one by one and append them to the same blob
    for (bIndex=0;bIndex<pChallengePacket->bBitCount; bIndex=bIndex+1){
        //Create single reveal
        pSingleReveal=createSingleSHA256Reveal(pProofArray[bIndex],(uint8_t)(qwCurrentBit&1),&dwCurrentRevealSize);
        //Shift challenge to get next bit
        qwCurrentBit=qwCurrentBit>>1;
        if (pSingleReveal==NULL){
            free(pbRevealRound);
            return NULL;
        }
        //Reallocate the blob to fit in new reveal
        pbRevealRound=(uint8_t*)realloc(pbRevealRound,dwTotalRevealSize+dwCurrentRevealSize);
        if (pbRevealRound==NULL) {
            free(pSingleReveal);
            return NULL;
        }
        //Copy reveal to the blob
        memcpy(pbRevealRound+dwTotalRevealSize,(uint8_t*)pSingleReveal,dwCurrentRevealSize);
        free(pSingleReveal);
        //Update total blob size
        dwTotalRevealSize=dwTotalRevealSize+dwCurrentRevealSize;
    }
    //Return blob size and pointer to the blob
    *pdwRevealSize=dwTotalRevealSize;
    return pbRevealRound;
}

/*
    PAES_REVEAL createSingleAESReveal(uint8_t bBit, PSINGLE_AES_COMMITMENT_EXTRA_INFORMATION pSingleAESCommitmentExtraInformation, \
        out uint32_t* pdwRevealSize)
    description:
        Create a single AES reveal. This is easier than in cases of CRC32 and SHA256.
         Everything has already been sent in commitment. We just need to send the key.
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
    //Sanity check
    if (pSingleAESCommitmentExtraInformation==NULL || pdwRevealSize==NULL) return NULL;
    //Allocate structure
    pAESReveal=(PAES_REVEAL)malloc(sizeof(AES_REVEAL));
    if (pAESReveal==NULL) return NULL;
    if (bBit==0){
        //If challenge bit is 0, send permutation key
        memcpy(pAESReveal->revealingKey,pSingleAESCommitmentExtraInformation->permutationKey,AES128_KEY_SIZE);
    }else{
        //If challenge bit is 1, send permuted cycle key
        memcpy(pAESReveal->revealingKey,pSingleAESCommitmentExtraInformation->permutedCycleKey,AES128_KEY_SIZE);
    }
    //Return size and pointer to reveal
    *pdwRevealSize=sizeof(AES_REVEAL);
    return pAESReveal;
}

/*
    uint8_t* createAESRevealRound(PPROOF_HELPER pProofHelper,PCHALLENGE_PACKET pChallengePacket, \
        PCOMMITMENT_EXTRA_INFORMATION pCommitmentExtraInformation, out uint32_t* pdwCommitmentSize)
    description:
        Create full round worth of AES commitment reveal information. Just put all single reveals in one blob.
    arguments:
        pProofHelper - parameters fo rproofs
        pChallengePacket - challenge packet
        pCommitmentExtraInformation - previously used AES keys
        pdwCommitmentSize - pointer for outputing return data size
    return value:
        SUCCESS - pointer to bytes containing reveal information
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
    //Sanity check
    if (pProofHelper==NULL || pChallengePacket==NULL || pCommitmentExtraInformation==NULL || pdwCommitmentSize==NULL) return NULL;
    //Save challenge bits into new variable
    qwChallengeRandom=pChallengePacket->qwRandom;
    //Create single reveals one by one and append them to a blob
    for (bIndex=0; bIndex<pProofHelper->bCheckCount;bIndex=bIndex+1){
        //Create single reveal
        pCurrentReveal=createSingleAESReveal((uint8_t)(qwChallengeRandom&1),((PSINGLE_AES_COMMITMENT_EXTRA_INFORMATION*)(pCommitmentExtraInformation->pbData))[bIndex],&dwCurrentUnpackSize);
        //Update challenge bit
        qwChallengeRandom=qwChallengeRandom>>1;
        //Compute new data offset
        dwDataOffset=dwDataOffset+sizeof(SINGLE_AES_COMMITMENT_EXTRA_INFORMATION);
        if (pCurrentReveal==NULL){
            free(pbReveals);
            return NULL;
        }
        //Reallocate blob with reveals
        pbReveals=realloc(pbReveals,dwTotalSize+dwCurrentUnpackSize);
        if (pbReveals==NULL){
            free(pCurrentReveal);
            return NULL;
        }
        //Copy reveal to the blob
        memcpy(pbReveals+dwTotalSize,pCurrentReveal,dwCurrentUnpackSize);
        //Update blob size
        dwTotalSize=dwTotalSize+dwCurrentUnpackSize;
        free(pCurrentReveal);
    }
    //Return blob size and pointer to blob
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
    //Sanity check (we don't chacke pCommitmentExtraInformation, because it can be NULL for CRC32 and SHA256 commitments) 
    if(pProofArray==NULL || pProofHelper==NULL || pChallengePacket==NULL || pdwRevealPacketSize==NULL) return NULL;
    //Check that the check count is the same as in the commitment phase
    if (pChallengePacket->bBitCount!=pProofHelper->bCheckCount) return NULL;
    //Cases with CRC32 and SHA256 are almost the same
    if (pProofHelper->supportedAlgorithms.isCRC32Supported||pProofHelper->supportedAlgorithms.isSHA256Supported){
        if(pProofHelper->supportedAlgorithms.isCRC32Supported){
            //If CRC32 is the chosen algorithm,  then create reveal round for that
            pbRevealData=createCRC32RevealRound(pProofArray,pChallengePacket,&dwRevealDataSize);
        }else{
            //If SHA256 - create a SHA256 reveal round
            pbRevealData=createSHA256RevealRound(pProofArray,pChallengePacket,&dwRevealDataSize);
        }
        if (pbRevealData==NULL) return NULL;
        //Compute packet size and allocate packet
        dwPacketSize=REVEAL_PACKET_HEADER_SIZE+dwRevealDataSize;
        pRevealPacket=(PREVEAL_PACKET)malloc(dwPacketSize);
        if (pRevealPacket==NULL){
            free(pbRevealData);
            return NULL;
        } 
        //Fill in the check count, used commitment algorithm, reveal data size and copy reveal blob inside
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
        //Return packet size an dpointer to  the packet
        *pdwRevealPacketSize=dwPacketSize;
        return pRevealPacket;
    }else{
        if(pProofHelper->supportedAlgorithms.isAESSupported){
            //If Verifier chose AES, create AES reveal round
            pbRevealData=createAESRevealRound(pProofHelper,pChallengePacket,pCommitmentExtraInformation,&dwRevealDataSize);
            if (pbRevealData==NULL) return NULL;
            //Compute packet size and allocate packet
            dwPacketSize=REVEAL_PACKET_HEADER_SIZE+dwRevealDataSize;
            pRevealPacket=(PREVEAL_PACKET)malloc(dwPacketSize);
            if (pRevealPacket==NULL){
                free(pbRevealData);
                return NULL;
            } 
            //Fill in check count, chosen algorithm, reveal data size and copy reveal blob inside
            pRevealPacket->bCommitmentCount=pProofHelper->bCheckCount;
            pRevealPacket->commitmentType.supportedAlgsCode=0;
            pRevealPacket->commitmentType.isAESSupported=1;
            pRevealPacket->dwDataSize=dwRevealDataSize;
            memcpy(pRevealPacket->revealData,pbRevealData,dwRevealDataSize);
            free(pbRevealData);
            //Return packet size and pointer to the packet
            *pdwRevealPacketSize=dwPacketSize;
            return pRevealPacket;
        }else{
            //This shouldn't happen, but just in case return NULL
            return NULL;
        }
    }
}

/*
    uint8_t checkCRC32Proof(PZKN_STATE pZKnState,uint64_t qwChallengeRandom, uint8_t* pbCommitmentData, uint32_t dwCommitmentDataSize, \
        uint8_t* pbRevealData, uint32_t dwRevealDataSize, uint8_t* pbErrorReason)
    description:
        Check CRC32 Proof. Check CRC32s and check that either permutation is correct or permuted cycle is a cycle on permuted graph.
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
    //No sanity checks, since everything is check by caller
    //Initialize variables to keep track of our blobs. We don't want to read or write to uninitialized memory
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
//It would be hard for fuzzing to create valid CRC32s so we pass the check by default
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        //Checking CRC32 of packed permuted graph matrix
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
            //If challenge bit is equal to 0, check permutation's CRC32
            if (memcmp(pCRC32Commitment->permutationCRC32,pbCRC32,CRC32_SIZE)!=0){
                free(pbCRC32);
                *pbErrorReason=ERROR_REASON_CHEATING;
                return ERROR_BAD_VALUE;
            }
        }else{
            //If challenge bit is equal to 1, check permuted cycle's CRC32
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
            //Check that matrix permuted with this permutation is equal to Prover's permuted matrix
            if (memcmp(pbBuffer,pbUnpackedPermutedGraphMatrix,pZKnState->pZKnGraph->dwMatrixSize)!=0){
                free(pbUnpackedMatrix);
                free(pbUnpackedPermutedGraphMatrix);
                free(pbBuffer);
                *pbErrorReason=ERROR_REASON_CHEATING;
                return ERROR_BAD_VALUE;
            }
            free(pbBuffer);
        }else{
            //If it's the cycle check, we need to check it's hamiltonian
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
        Check SHA256 Proof (almost the same as CRC32, but we check SHA256)
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
        if (dwRevealDataLeft<SHA256_REVEAL_HEADER_SIZE || ((pSHA256Reveal->dwPackedMatrixSize*2+SHA256_REVEAL_HEADER_SIZE)>dwRevealDataLeft)|| pSHA256Reveal->dwPackedMatrixSize>dwRevealDataLeft){
            *pbErrorReason=ERROR_REASON_WRONG_VALUE;
            return ERROR_BAD_VALUE;
        }
        //Check that commitment data left is at least as big a single SHA256 commitment
        if (dwCommitmentDataLeft<sizeof(SHA256_COMMITMENT)){
            *pbErrorReason=ERROR_REASON_WRONG_VALUE;
            return ERROR_BAD_VALUE;
        }
        //Computing SHA256 of packed permuted graph matrix
        pbSHA256PermutedGraph=sha256(pSHA256Reveal->packedPermutedGraphAndPermutationOrCycle,pSHA256Reveal->dwPackedMatrixSize);
        if (pbSHA256PermutedGraph==NULL){
            *pbErrorReason=ERROR_REASON_SYSTEM;
            return ERROR_SYSTEM;
        }
        //Computing SHA256 of either packed permutation matrix or packed permuted cycle
        pbSHA256=sha256(pSHA256Reveal->packedPermutedGraphAndPermutationOrCycle+pSHA256Reveal->dwPackedMatrixSize,pSHA256Reveal->dwPackedMatrixSize);
        if (pbSHA256==NULL){
            free(pbSHA256PermutedGraph);
            *pbErrorReason=ERROR_REASON_SYSTEM;
            return ERROR_SYSTEM;
        }
//Disable SHA256 checks for fuzzing
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        //Check permuted graph sha256
        if (memcmp(pSHA256Commitment->permutedGraphSHA256,pbSHA256PermutedGraph,SHA256_SIZE)!=0){
            free(pbSHA256);
            free(pbSHA256PermutedGraph);
            *pbErrorReason=ERROR_REASON_CHEATING;
            return ERROR_SYSTEM;
        }
#endif
        free(pbSHA256PermutedGraph);
        //Checking permutation or permuted cycle sha256
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        if((qwChallengeBit&1)==0){
            //Check permutation sha256
            if (memcmp(pSHA256Commitment->permutationSHA256,pbSHA256,SHA256_SIZE)!=0){
                free(pbSHA256);
                *pbErrorReason=ERROR_REASON_CHEATING;
                return ERROR_BAD_VALUE;
            }
        }else{
            //Check permuted cycle sha256
            if (memcmp(pSHA256Commitment->permutedCycleSHA256,pbSHA256,SHA256_SIZE)!=0){
                free(pbSHA256);
                *pbErrorReason=ERROR_REASON_CHEATING;
                return ERROR_BAD_VALUE;
            }
        }
#endif
        free(pbSHA256);
        //Unpacking permutation or cycle matrix
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
            //If given permutation matrix, we need to check permutation is correct
            pbBuffer=permuteMatrix(pbUnpackedMatrix,pZKnState->pZKnGraph->pbGraphData,wCheckDimension);
            if (pbBuffer==NULL){
                free(pbUnpackedMatrix);
                free(pbUnpackedPermutedGraphMatrix);
                *pbErrorReason=ERROR_REASON_SYSTEM;
                return ERROR_SYSTEM;
            }
            //Check that permutation applied to our initial graph matrix results in the same permuted matrix as Prover's
            if (memcmp(pbBuffer,pbUnpackedPermutedGraphMatrix,pZKnState->pZKnGraph->dwMatrixSize)!=0){
                free(pbUnpackedMatrix);
                free(pbUnpackedPermutedGraphMatrix);
                free(pbBuffer);
                *pbErrorReason=ERROR_REASON_CHEATING;
                return ERROR_BAD_VALUE;
            }
            free(pbBuffer);
        }else{
            //If it's the cycle check, we need to check it's hamiltonian
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
    //Sanity checks were performed by the caller
    dwCommitmentDataLeft=dwCommitmentDataSize;
    dwRevealDataLeft=dwRevealDataSize;
    qwChallengeBit=qwChallengeRandom;
    pAESCommitment=(PAES_COMMITMENT)pbCommitmentData;
    pAESReveal=(PAES_REVEAL)pbRevealData;
    //Perform single proof checks one by one
    for (bIndex=0; bIndex<pZKnState->bCheckCount;bIndex=bIndex+1){
        //Checking under/overflows in commitment record
        if (dwCommitmentDataLeft<AES_COMMITMENT_HEADER_SIZE || \
        (pAESCommitment->dwSingleCiphertextPlusIVSize*2+pAESCommitment->dwPackedPermutedMatrixSize +AES_COMMITMENT_HEADER_SIZE) > dwCommitmentDataLeft || \
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
            //If challenge bit is 0, decrypt permutation
            pbDecryptedData=aes128cbc_decrypt(pAESCommitment->commitmentData,pAESCommitment->dwSingleCiphertextPlusIVSize,pAESReveal->revealingKey,&dwDecryptedDataSize);
        }else{
            //If challenge bit is 1, decrypt permuted cycle
            pbDecryptedData=aes128cbc_decrypt(pAESCommitment->commitmentData+pAESCommitment->dwSingleCiphertextPlusIVSize,pAESCommitment->dwSingleCiphertextPlusIVSize,pAESReveal->revealingKey,&dwDecryptedDataSize);
        }
        if (pbDecryptedData==NULL){
            *pbErrorReason=ERROR_REASON_SYSTEM;
            return ERROR_SYSTEM;
        }
        //Unpacking permutation or permuted cycle matrix
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
            //Check that permutation applied to our initial matrix results in the same permuted matrix
            if (memcmp(pbBuffer,pbUnpackedPermutedGraphMatrix,pZKnState->pZKnGraph->dwMatrixSize)!=0){
                free(pbUnpackedMatrix);
                free(pbUnpackedPermutedGraphMatrix);
                free(pbBuffer);
                *pbErrorReason=ERROR_REASON_CHEATING;
                return ERROR_BAD_VALUE;
            }
            free(pbBuffer);
        }else{
            //If it's the cycle check, we need to check it's hamiltonian
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
    if (pZKnState==NULL || pZKnProtocolState==NULL || pRevealPacket==NULL || ppbFlag==NULL || pbErrorReason==NULL) 
    {
        *pbErrorReason=ERROR_REASON_SYSTEM;
        bResult= ERROR_SYSTEM;
        goto protocol_reset;
    }
    //Check that reveal packet is at least the size of packet head
    if (dwRevealPacketSize<REVEAL_PACKET_HEADER_SIZE){
        *pbErrorReason=ERROR_REASON_WRONG_VALUE;
        bResult=ERROR_BAD_VALUE;
        goto protocol_reset;
    }
    //Checking that the protocol is at the right stage
    if (pZKnProtocolState->protocolProgress.isCommitmentStageComplete==0 || pZKnProtocolState->protocolProgress.isChallengeCreationStageComplete==0){
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
    //Check only a single commitment algorithm was set
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
    //Use the corresponding check
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
    //Return result
    return bResult;

}
/*
    PZKN_PROTOCOL_STATE initializeZKnProtocolState()
    description:
        Initialize ZKN protocol state (when we actually want to prove the knowledge)
    arguments:
        None
    return value:
        SUCCESS - pointer to ZKN_PROTOCOL_STATE
        FAIL - NULL
*/
PZKN_PROTOCOL_STATE initializeZKnProtocolState(){
    PZKN_PROTOCOL_STATE pZKnProtocolState;
    //Allocate structure
    pZKnProtocolState=(PZKN_PROTOCOL_STATE) calloc(1,sizeof(ZKN_PROTOCOL_STATE));
    if (pZKnProtocolState==NULL) return NULL;
    //Initialize prng and save it to the structure 
    //(we initialize it here so that each team would get an independent prng)
    pZKnProtocolState->pLegendrePRNG=initializePRNG(P);
    if (pZKnProtocolState->pLegendrePRNG==NULL){
        free(pZKnProtocolState);
        return NULL;
    }
    //Set protocol progress to 0
    pZKnProtocolState->protocolProgress.status=0;
    //Return pointer
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
    //Sanity check
    if (pZKnProtocolState==NULL) return;
    //Free everything
    free(pZKnProtocolState->pLegendrePRNG);
    free(pZKnProtocolState->pbCommitmentData);
    free(pZKnProtocolState);
}

/*
    uint8_t* packMatrixForEmbedding(uint8_t* pbMatrix, uint16_t wDimension, out uint32_t* pdwDataSize)
    description:
        Pack matrix for transmission. This is for the use by contestants. We don't actually need this.
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
    //Sanity check
    if (pbMatrix== NULL || pdwDataSize==NULL) return NULL;
    //Pack matrix
    pbPacked=packMatrix(pbMatrix,wDimension,pdwDataSize);
    //Return packed matrix
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
    //Sanity check
    if (pbPackedMatrix==NULL|| pwOutputDimension==NULL) return NULL;
    //Unpack matrix
    pbUnpacked=unpackMatrix(dwSize,pbPackedMatrix,pwOutputDimension);
    //Return unpacked matrix
    return pbUnpacked;
}