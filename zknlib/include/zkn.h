#ifndef zkn_h__
#define zkn_h__
#define DLL_PUBLIC __attribute__ ((visibility ("default")))
#include <stdint.h>
#include <stddef.h>
#include "hash.h"
#include "../prng/include/prng.h"
#include "../matrices/include/matr.h"
#define P 863615239139 // Prime for Legendre PRF
#define RANDOM_R_SIZE 16
#define FLAG_ARRAY_SIZE 64


typedef struct __GRAPH{
  uint32_t dwMatrixSize;
  uint16_t wVerticeCount;
  uint8_t* pbGraphData;
}GRAPH, *PGRAPH;

typedef union{
  struct{
    uint8_t isCRC32Supported:1;
    uint8_t isSHA256Supported:1;
    uint8_t isAESSupported:1;
  };
  uint8_t supportedAlgsCode:3;
}COMMITMENT_ALGORITHMS, *PCOMMITMENT_ALGORITHMS;

typedef struct __ZKN_STATE{
  PLEGENDRE_PRNG  pLegendrePrng;
  PGRAPH pZKnGraph;
  uint8_t* pbFLAG;
  uint16_t wDefaultVerticeCount;
  uint8_t bCheckCount;
  COMMITMENT_ALGORITHMS supportedAlgorithms;
}ZKN_STATE,*PZKN_STATE;

typedef struct __GRAPH_SET_PACKET{
  uint8_t RANDOM_R[RANDOM_R_SIZE];
  char FLAG[FLAG_ARRAY_SIZE];
  uint32_t dwPackedMatrixSize;
  uint8_t bPackedMatrixData[1];
}GRAPH_SET_PACKET, *PGRAPH_SET_PACKET;

#define GRAPH_SET_PACKET_HEADER_SIZE offsetof(GRAPH_SET_PACKET,bPackedMatrixData)

typedef struct __PROOF_CONFIGURATION_PACKET{
  uint32_t dwPackedMatrixSize;
  uint8_t bCheckCount;
  COMMITMENT_ALGORITHMS supportedAlgorithms;
  uint8_t bPackedMatrixData[1];
}PROOF_CONFIGURATION_PACKET, *PPROOF_CONFIGURATION_PACKET;

#define PROOF_CONFIGURATON_PACKET_HEADER_SIZE offsetof(PROOF_CONFIGURATION_PACKET,bPackedMatrixData)

typedef struct __COMMITMENT_PACKET{
  uint32_t dwDataSize;
  uint8_t bCommitmentCount;
  COMMITMENT_ALGORITHMS commitmentType;
  uint8_t commitmentData[1];
}COMMITMENT_PACKET, *PCOMMITMENT_PACKET;

#define COMMITMENT_PACKET_HEADER_SIZE offsetof(COMMITMENT_PACKET, commitmentData)

typedef struct __CRC32_COMMITMENT{
  uint8_t permutationCRC32[CRC32_SIZE];
  uint8_t permutedCycleCRC32[CRC32_SIZE];
  uint32_t dwPackedPermutedMatrixSize;
  uint8_t packedPermutedGraphMatrix[1];
}CRC32_COMMITMENT, *PCRC32_COMMITMENT;

#define CRC32_COMMITMENT_HEADER_SIZE offsetof(CRC32_COMMITMENT,packedPermutedGraphMatrix)

typedef struct __SHA256_COMMITMENT{
  uint8_t permutationSHA256[SHA256_SIZE];
  uint8_t permutedCycleSHA256[SHA256_SIZE];
  uint32_t dwPackedPermutedMatrixSize;
  uint8_t packedPermutedMatrix[1];
}SHA256_COMMITMENT, *PSHA256_COMMITMENT;

#define SHA256_COMMITMENT_HEADER_SIZE offsetof(SHA256_COMMITMENT,packedPermutedMatrix)

typedef struct __AES_COMMITMENT{
  uint32_t dwSingleCiphertextPlusIVSize;
  uint32_t dwPackedPermutationMatrixSize;
  uint8_t commitmentData[1];//permutation commitment | cycle commitment | permuted matrix
}AES_COMMITMENT, *PAES_COMMITMENT;

#define AES_COMMITMENT_HEADER_SIZE offsetof(AES_COMMITMENT, commitmentData)

//We need to save AES keys somewhere, when commiting. Two other schemes don't require extra informtion,
//since they rely on initial graphs.
typedef struct __COMMTIMENT_EXTRA_INFORMATION{
  uint32_t dwDataSize;
  uint8_t data[1];
}COMMITMENT_EXTRA_INFORMATION, *PCOMMITMENT_EXTRA_INFORMATION;

#define COMMITMENT_EXTRA_INFORMATION_HEADER_SIZE offsetof(COMMITMENT_EXTRA_INFORMATION,data)

typedef struct __UNPACK_COMMITMENT_PACKET{
  uint32_t dwDataSize;
  uint8_t bCommitmentCount;
  COMMITMENT_ALGORITHMS commitmentType;
  uint8_t unpackCommitmentData[1];
}UNPACK_COMMITMENT_PACKET, *PUNPACK_COMMITMENT_PACKET;


typedef struct __CRC32_UNPACK_COMMITMENT{
  uint32_t dwPackedPermutationOrCycleSize;
  uint8_t packedPermutationOrCycle[1];
}CRC32_UNPACK_COMMITMENT, *PCRC32_UNPACK_COMMITMENT;

#define CRC32_UNPACK_COMMITMENT_HEADER_SIZE offsetof(CRC32_UNPACK_COMMITMENT,packedPermutationOrCycle)

typedef struct __SHA256_UNPACK_COMMITMENT{
  uint32_t dwPackedPermutationOrCycleSize;
  uint8_t packedPermutationOrCycle[1];
}SHA256_UNPACK_COMMITMENT, *PSHA256_UNPACK_COMMITMENT;

#define SHA256_UNPACK_COMMITMENT_HEADER_SIZE offsetof(SHA256_UNPACK_COMMITMENT,packedPermutationOrCycle)

typedef struct __AES_UNPACK_COMMITMENT{
  uint8_t unpackingKey[16];
}AES_UNPACK_COMMITMENT, *PAES_UNPACK_COMMITMENT;

#define AES_COMMITMENT_HEADER_SIZE offsetof(AES_COMMITMENT, commitmentData)

typedef struct __PROOF_HELPER{
  PFULL_KNOWLEDGE pFullKnowledge;
  uint8_t bCheckCount;
  COMMITMENT_ALGORITHMS supportedAlgorithms;
}PROOF_HELPER, *PPROOF_HELPER;


typedef struct __SINGLE_PROOF{
  uint8_t* pbPackedPermutationMatrix;
  uint8_t* pbPackedPermutedGraphMatrix;
  uint8_t* pbPackedPermutedCycleMatrix;
  uint32_t dwPackedMatrixSize;
}SINGLE_PROOF, *PSINGLE_PROOF;

typedef struct __INITIAL_SETTING_PACKET{
  uint8_t RANDOM_R[RANDOM_R_SIZE];
  uint16_t wVerticeCount;
}INITIAL_SETTING_PACKET, *PINITIAL_SETTING_PACKET;

typedef struct __FULL_KNOWLEDGE_FOR_STORAGE
{
  uint32_t dwSinglePackedMatrixSize;
  uint8_t bData[1];  
}FULL_KNOWLEDGE_FOR_STORAGE, *PFULL_KNOWLEDGE_FOR_STORAGE;

#define FULL_KNOWLEDGE_FOR_STORAGE_HEADER_SIZE offsetof(FULL_KNOWLEDGE_FOR_STORAGE,bData)


DLL_PUBLIC extern PZKN_STATE initializeZKnThread(uint16_t verticeNumber, uint8_t bCheckCount, uint8_t bSuppportedAlgorithms);
DLL_PUBLIC uint8_t * createInitialSettingPacket(PZKN_STATE pZKnState);
DLL_PUBLIC uint16_t getDesiredVerticeCountFromInitialSettingPacket(uint8_t* pbInitialSettingPacket, uint32_t dwPacketSize);
DLL_PUBLIC PGRAPH_SET_PACKET createGraphSetPacket(PFULL_KNOWLEDGE pFullKnowledge,uint8_t* pbRANDOM_R, char* psbFLAG, out uint32_t* pdwGraphSetPacketSize);
DLL_PUBLIC uint8_t* createPKCSSignature(uint8_t* pbData,uint32_t dwDataSize,uint32_t dwDesiredSignatureSize);
DLL_PUBLIC uint32_t updateZKnGraph(PZKN_STATE pZKNState,PGRAPH_SET_PACKET pGraphSetPacket, uint32_t dwPacketSize, uint8_t* pbDecryptedSignature, uint32_t dsSize, uint8_t* pRANDOMR);
DLL_PUBLIC PFULL_KNOWLEDGE createFullKnowledgeForServer(int16_t wVerticeCount);
DLL_PUBLIC void freeFullKnowledgeForServer(PFULL_KNOWLEDGE pFullKnowledge);

DLL_PUBLIC extern void destroyZKnThread(PZKN_STATE);

#endif //