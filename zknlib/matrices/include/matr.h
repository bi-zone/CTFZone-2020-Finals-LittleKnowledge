/*
libzkn - definitions for matrices
Authors:
    Innokentii Sennovskii (i.sennovskiy@bi.zone)
*/
#include <stdint.h>


#ifndef out
#define out
#endif

#define MAX_MATRIX_DIMENSION 256
#define MIN_MATRIX_DIMENSION 3

#define MAX_MATR_BYTE_SIZE MAX_MATRIX_DIMENSION*MAX_MATRIX_DIMENSION
typedef struct __MATRIX_HOLDER{
    uint8_t* pbData;
    uint32_t dwDataSize;
    uint16_t wDimension;   
}MATRIX_HOLDER, *PMATRIX_HOLDER;


#define PACKED_MATRIX_HEADER_SIZE offsetof(PACKED_MATRIX,bData)

typedef struct __FULL_KNOWLEDGE{
    uint8_t* pbGraphMatrix;
    uint8_t* pbCycleMatrix;
    uint32_t dwMatrixArraySize;
    uint16_t wDimension;
}FULL_KNOWLEDGE, *PFULL_KNOWLEDGE;

PFULL_KNOWLEDGE generateGraphAndCycleMatrix(uint16_t wVerticeCount);
void freeFullKnowledge(PFULL_KNOWLEDGE pFullKnowledge);
uint8_t *generatePermutationMatrix(uint16_t wDimension);
uint8_t *permuteMatrix(uint8_t *pbPermutationMatrix, uint8_t *pwInitialMatrix, uint16_t wDimension) ;
uint8_t *packMatrix(uint8_t *pbMatrix, uint16_t wDimension, uint32_t *pdwPackedSize); 
uint8_t *unpackMatrix(uint32_t wPackedMatrixSize, uint8_t *pbPackedMatrix, uint16_t* pwDimension);
uint8_t checkHamiltonianCycle(uint8_t* pbGraphMatrix, uint8_t* pbCycleMatrix, uint16_t wDimension);
