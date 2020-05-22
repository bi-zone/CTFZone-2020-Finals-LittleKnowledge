/*
libzkn - main structures, definitions and exports 
Authors:
    Innokentii Sennovskii (i.sennovskiy@bi.zone)
*/
#ifndef zkn_h__
#define zkn_h__
#define DLL_PUBLIC __attribute__ ((visibility ("default")))
#include <stdint.h>
#include <stddef.h>
#include "hash.h"
#include "../prng/include/prng.h"
#include "../matrices/include/matr.h"
#define P 3581731379 // Prime for Legendre PRF
#define RANDOM_R_SIZE 16
#define FLAG_ARRAY_SIZE 2048

#define MINIMUM_CHECK_COUNT 4
#define MAXIMUM_CHECK_COUNT 64

typedef struct __GRAPH{
  uint32_t dwMatrixSize;
  uint16_t wVertexCount;
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
  PGRAPH pZKnGraph;
  uint8_t* pbFLAG;
  uint16_t wDefaultVertexCount;
  uint8_t bCheckCount;
  COMMITMENT_ALGORITHMS supportedAlgorithms;
  uint8_t simulationDisabled:1;
}ZKN_STATE,*PZKN_STATE;

typedef union{
  struct{
    uint8_t isCommitmentStageComplete:1;
    uint8_t isChallengeCreationStageComplete:1;
    uint8_t isProofStageComplete:1;
  };
  uint8_t status;
}PROTOCOL_PROGRESS,*PPROTOCOL_PROGRESS;

typedef struct __ZKN_PROTOCOL_STATE{
  PLEGENDRE_PRNG pLegendrePRNG;
  uint64_t qwRandom;
  uint8_t* pbCommitmentData;
  uint32_t dwCommitmentDataSize;
  PROTOCOL_PROGRESS protocolProgress;
}ZKN_PROTOCOL_STATE, *PZKN_PROTOCOL_STATE;

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
  uint8_t permutedGraphCRC32[CRC32_SIZE];
  uint8_t permutedCycleCRC32[CRC32_SIZE];
}CRC32_COMMITMENT, *PCRC32_COMMITMENT;


typedef struct __SHA256_COMMITMENT{
  uint8_t permutationSHA256[SHA256_SIZE];
  uint8_t permutedGraphSHA256[SHA256_SIZE];
  uint8_t permutedCycleSHA256[SHA256_SIZE];
}SHA256_COMMITMENT, *PSHA256_COMMITMENT;


typedef struct __AES_COMMITMENT{
  uint32_t dwSingleCiphertextPlusIVSize;
  uint32_t dwPackedPermutedMatrixSize;
  uint8_t commitmentData[1];//permutation commitment | cycle commitment | permuted matrix
}AES_COMMITMENT, *PAES_COMMITMENT;

#define AES_COMMITMENT_HEADER_SIZE offsetof(AES_COMMITMENT, commitmentData)

typedef struct __SINGLE_AES_COMMITMENT_EXTRA_INFORMATION{
  uint8_t permutationKey[AES128_KEY_SIZE];
  uint8_t permutedCycleKey[AES128_KEY_SIZE];
}SINGLE_AES_COMMITMENT_EXTRA_INFORMATION, *PSINGLE_AES_COMMITMENT_EXTRA_INFORMATION;

//We need to save AES keys somewhere, when commiting. Two other schemes don't require extra informtion,
//since they rely on initial graphs.
typedef struct __COMMTIMENT_EXTRA_INFORMATION{
  uint32_t dwDataSize;
  uint8_t* pbData;
}COMMITMENT_EXTRA_INFORMATION, *PCOMMITMENT_EXTRA_INFORMATION;

#define COMMITMENT_EXTRA_INFORMATION_HEADER_SIZE offsetof(COMMITMENT_EXTRA_INFORMATION,data)

typedef struct __CHALLENGE_PACKET{
  uint64_t qwRandom;
  uint32_t bBitCount;
}CHALLENGE_PACKET, *PCHALLENGE_PACKET;

typedef struct __REVEAL_PACKET{
  uint32_t dwDataSize;
  uint8_t bCommitmentCount;
  COMMITMENT_ALGORITHMS commitmentType;
  uint8_t revealData[1];
}REVEAL_PACKET, *PREVEAL_PACKET;

#define REVEAL_PACKET_HEADER_SIZE offsetof(REVEAL_PACKET,revealData)

typedef struct __CRC32_REVEAL{
  uint32_t dwPackedMatrixSize;
  uint8_t packedPermutedGraphAndPermutationOrCycle[1]; //permuted graph matrix | permutation or permuted cycle matrix
}CRC32_REVEAL, *PCRC32_REVEAL;

#define CRC32_REVEAL_HEADER_SIZE offsetof(CRC32_REVEAL,packedPermutedGraphAndPermutationOrCycle)

typedef struct __SHA256_REVEAL{
  uint32_t dwPackedMatrixSize;
  uint8_t packedPermutedGraphAndPermutationOrCycle[1]; //permuted graph matrix | permutation or permuted cycle matrix
}SHA256_REVEAL, *PSHA256_REVEAL;

#define SHA256_REVEAL_HEADER_SIZE offsetof(SHA256_REVEAL,packedPermutedGraphAndPermutationOrCycle)

typedef struct __AES_REVEAL{
  uint8_t revealingKey[16];
}AES_REVEAL, *PAES_REVEAL;

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
  uint16_t wVertexCount;
}INITIAL_SETTING_PACKET, *PINITIAL_SETTING_PACKET;

typedef struct __FULL_KNOWLEDGE_FOR_STORAGE
{
  uint32_t dwSinglePackedMatrixSize;
  uint8_t bData[1];  
}FULL_KNOWLEDGE_FOR_STORAGE, *PFULL_KNOWLEDGE_FOR_STORAGE;

#define FULL_KNOWLEDGE_FOR_STORAGE_HEADER_SIZE offsetof(FULL_KNOWLEDGE_FOR_STORAGE,bData)


DLL_PUBLIC extern PZKN_STATE initializeZKnState(uint16_t verticeNumber, uint8_t bCheckCount, uint8_t bSuppportedAlgorithms);
DLL_PUBLIC PZKN_PROTOCOL_STATE initializeZKnProtocolState();
DLL_PUBLIC uint8_t * createInitialSettingPacket(PZKN_STATE pZKnState);
DLL_PUBLIC void freeDanglingPointer(void* pPointer);
DLL_PUBLIC uint16_t getDesiredVerticeCountFromInitialSettingPacket(uint8_t* pbInitialSettingPacket, uint32_t dwPacketSize);
DLL_PUBLIC PGRAPH_SET_PACKET createGraphSetPacket(PFULL_KNOWLEDGE pFullKnowledge,uint8_t* pbRANDOM_R, char* psbFLAG, out uint32_t* pdwGraphSetPacketSize);
DLL_PUBLIC uint8_t* createPKCSSignature(uint8_t* pbData,uint32_t dwDataSize,uint32_t dwDesiredSignatureSize);
DLL_PUBLIC uint32_t updateZKnGraph(PZKN_STATE pZKNState,PGRAPH_SET_PACKET pGraphSetPacket, uint32_t dwPacketSize, uint8_t* pbDecryptedSignature, uint32_t dsSize, uint8_t* pRANDOMR);
DLL_PUBLIC PFULL_KNOWLEDGE createFullKnowledgeForServer(uint16_t wVertexCount);
DLL_PUBLIC void freeFullKnowledgeForServer(PFULL_KNOWLEDGE pFullKnowledge);
DLL_PUBLIC uint8_t* packFullKnowledgeForStorage(PFULL_KNOWLEDGE pFullKnowledge, out uint32_t* pdwDataSize);
DLL_PUBLIC PFULL_KNOWLEDGE unpackFullKnowledgeFromStorage(uint8_t* pbPackedFullKnowledge, uint32_t dwPackedFullKnowledgeSize);
DLL_PUBLIC PPROOF_CONFIGURATION_PACKET createProofConfigurationPacket(PZKN_STATE pZKnState, out uint32_t* pdwPacketSize);
DLL_PUBLIC PPROOF_HELPER initializeProofHelper(PFULL_KNOWLEDGE pFullKnowledge, PPROOF_CONFIGURATION_PACKET pProofConfigurationPacket, uint32_t dwPacketSize, out uint8_t* pbErrorReason);
DLL_PUBLIC void freeProofHelper(PPROOF_HELPER pProofHelper);
DLL_PUBLIC PSINGLE_PROOF* createProofsForOneRound(PPROOF_HELPER pProofHelper);
DLL_PUBLIC void freeProofsForOneRound(PSINGLE_PROOF* pProofArray,PPROOF_HELPER pProofHelper);
DLL_PUBLIC PCOMMITMENT_PACKET createCommitmentPacket(PSINGLE_PROOF* pProofArray,PPROOF_HELPER pProofHelper,out uint32_t* pdwCommitmentPacketSize, \
out PCOMMITMENT_EXTRA_INFORMATION* ppCommitmentExtraInformation);
DLL_PUBLIC uint8_t saveCommitment(PZKN_STATE pZKnState,PZKN_PROTOCOL_STATE pZKnProtocolState,uint8_t* pbCommitmentData, uint32_t dwCommitmentDataSize);
DLL_PUBLIC PCHALLENGE_PACKET createChallenge(PZKN_STATE pZKnState, PZKN_PROTOCOL_STATE pZKnProtocolState, out uint32_t* pdwPacketSize);
DLL_PUBLIC PREVEAL_PACKET createRevealPacket(PSINGLE_PROOF* pProofArray,PPROOF_HELPER pProofHelper, PCHALLENGE_PACKET pChallengePacket, \
PCOMMITMENT_EXTRA_INFORMATION pCommitmentExtraInformation, out uint32_t* pdwRevealPacketSize);
DLL_PUBLIC void freeCommitmentExtraInformation(PPROOF_HELPER pProofHelper,PCOMMITMENT_EXTRA_INFORMATION pCommitmentExtraInformation);
DLL_PUBLIC uint8_t checkProof(PZKN_STATE pZKnState, PZKN_PROTOCOL_STATE pZKnProtocolState, PREVEAL_PACKET pRevealPacket, \
uint32_t dwRevealPacketSize, uint8_t** ppbFlag,uint8_t* pbErrorReason);
DLL_PUBLIC uint8_t* packMatrixForEmbedding(uint8_t* pbMatrix, uint16_t wDimension, out uint32_t* pdwDataSize);
DLL_PUBLIC uint8_t* unpackPackedMatrix(uint8_t* pbPackedMatrix, uint32_t dwSize, out uint16_t* pwOutputDimension);

DLL_PUBLIC void destroyZKnProtocolState(PZKN_PROTOCOL_STATE pZKnProtocolState);
DLL_PUBLIC extern void destroyZKnState(PZKN_STATE);

#endif //