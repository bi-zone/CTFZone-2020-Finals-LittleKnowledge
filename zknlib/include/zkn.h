#ifndef zkn_h__
#define zkn_h__
#define DLL_PUBLIC __attribute__ ((visibility ("default")))
#include <stdint.h>
#include <stddef.h>
#include "../prng/include/prng.h"
#include "../matrices/include/matr.h"
#define P 863615239139 // Prime for Legendre PRF
#define RANDOM_R_SIZE 16
#define FLAG_ARRAY_SIZE 64

typedef struct __GRAPH{
  uint32_t dwMatrixSize;
  uint16_t wVerticeCount;
  uint8_t graphData[1];
}GRAPH, *PGRAPH;



#define GRAPH_HEADER_SIZE offsetof(GRAPH,graphData)

typedef struct __ZKN_STATE{
  PLEGENDRE_PRNG  pLedendrePrng;
  PGRAPH pZKNGraph;
  uint8_t* pbFLAG;
  uint16_t wDefaultVerticeCount;
}ZKN_STATE,*PZKN_STATE;

typedef struct __GRAPH_SET_PACKET{
  uint8_t RANDOM_R[RANDOM_R_SIZE];
  char FLAG[FLAG_ARRAY_SIZE];
  uint32_t dwPackedMatrixSize;
  uint8_t bPackedMatrixData[1];
}GRAPH_SET_PACKET, *PGRAPH_SET_PACKET;

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

#define GRAPH_SET_PACKET_HEADER_SIZE offsetof(GRAPH_SET_PACKET,bPackedMatrixData)
DLL_PUBLIC extern PZKN_STATE initializeZKNThread(uint16_t verticeNumber);
DLL_PUBLIC extern void destroyZKNThread(PZKN_STATE);
#endif //