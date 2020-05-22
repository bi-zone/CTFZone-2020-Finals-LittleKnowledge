/*
libzkn - matrix operations
Authors:
    Alina Garbuz (a.garbuz@bi.zone)
    Innokentii Sennovskii (isennovskiy@bi.zone)
*/
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <math.h>
#include <string.h>
#include "matr.h"
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
//Random state from which we take bits when needed
#define ENTROPY_COLLECTOR_SIZE 64
uint8_t bRandomInitalized=0;
uint8_t bCurrentBit=0;
uint16_t bCurrentByte=0;
uint8_t randomBytes[ENTROPY_COLLECTOR_SIZE];

/*
    void initializeRandom()
    description:
        Initialize or reinitialize randomBytes array to random data
    arguments:
        None
    return value:
        N/A
*/
void initializeRandom(){
    uint16_t wCounter;
    //We need determinism when fuzzing, so during fuzzing PRNG used is rand with srand(0)
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    srand(0);
    for (wCounter=0;wCounter<ENTROPY_COLLECTOR_SIZE;wCounter=wCounter+1){
        randomBytes[wCounter]=rand()&0xff;
    }
#else
    //In prod, we get bytes from /dev/urandom
    int fd;
    ssize_t bytesRead, totalBytesRead;
    totalBytesRead=0;
    fd=open("/dev/urandom",O_RDONLY);
    if (fd==-1){
        //default to rand with constant reinitialization
unsafe_default:
        srand(time(NULL));
        for (wCounter=0;wCounter<ENTROPY_COLLECTOR_SIZE;wCounter=wCounter+1){
            randomBytes[wCounter]=rand()&0xff;
        }
    } 
    else{
        while (totalBytesRead<ENTROPY_COLLECTOR_SIZE){
            bytesRead=read(fd,randomBytes+totalBytesRead,ENTROPY_COLLECTOR_SIZE-totalBytesRead);
            if (bytesRead==-1){
                //Weird
                close(fd);
                goto unsafe_default;
            }
            totalBytesRead+=bytesRead;
        }
        close(fd);
    }
#endif
    bCurrentBit=0;
    bCurrentByte=0;
    bRandomInitalized=1;
}

/*
    int getRandomBit()
    description:
        Return one pseudorandom bit
    arguments:
        None
    return value:
        0 or 1
*/
int getRandomBit(){
    uint8_t wBit;
    //Check if random is initialized. If not, do it
    if ((bRandomInitalized==0) || (bCurrentByte==ENTROPY_COLLECTOR_SIZE)) initializeRandom();
    //Get one bit
    wBit=(randomBytes[bCurrentByte]>>bCurrentBit)&1;
    //Update indexes
    bCurrentBit=bCurrentBit+1;
    bCurrentByte=bCurrentByte+(uint16_t)(bCurrentBit>>3);
    bCurrentBit&=7;
    //Return bit
    return wBit;
}

/*
    uint16_t getRandom()
    description:
        return random uint16_t
    arguments:
        None
    return value:
        random uint16_t
*/
uint16_t getRandom(){
    uint16_t wResult=0;
    uint8_t bCounter;
    //Just get bits one by one and insert into uint16_t
    for (bCounter=0;bCounter<16;bCounter=bCounter+1){
        wResult=(wResult<<1)|getRandomBit();
    }
    //Return result
    return wResult;
}
/* 
    uint8_t freeMemory(void *pArray);
    description:
        Deallocates the memory 
    argument: 
            void *pArray - the pointer to a memory block
    return value:
            SUCCESS: 0
            ERROR: 1 
*/

uint8_t freeMemory(void *pArray) {
    if (!pArray) {
        return 1;
    }
    else {
        free(pArray);
        return 0;
    }    
}

/*
    uint8_t *createMatrix(uint16_t dwDimension, uint8_t bValue);
    description:
        creation the matrix filled with 0 or 1
    arguments:
        dwDimension - matrix dimension
        bValue - default value for matrix elements (0 or 1)
    return value:
        SUCCESS: uint8_t *matrix
        ERROR: NULL        
*/

uint8_t *createMatrix(uint16_t dwDimension, uint8_t bValue) { 
    uint8_t *matrix = NULL;
    uint32_t index = 0, num = 0;
    //Check sanity and limits
    if (dwDimension > MAX_MATRIX_DIMENSION || dwDimension < MIN_MATRIX_DIMENSION || (bValue != 1 && bValue != 0)) { 
        return NULL;
    }
    //Allocate buffer
    matrix = (uint8_t *)malloc((uint32_t)dwDimension * (uint32_t)dwDimension * sizeof(uint8_t));
    if (!matrix) {
        return NULL;
    }
    //Compute size
    num = (uint32_t)dwDimension * (uint32_t)dwDimension;
    //Set all elements to 0 or 1
    for (index = 0; index < num; index++) {
        *(matrix + index) = bValue;
    }
    //Return pointer
    return matrix;
}
/*
    uint8_t *createMatrixFast(uint16_t dwDimension);
    description:
        create the matrix
    arguments:
        dwDimension - matrix dimension
    return value:
        SUCCESS: uint8_t *matrix
        ERROR: NULL        
*/

uint8_t *createMatrixFast(uint16_t dwDimension) { 
    uint8_t *matrix = NULL;
    //Check limits
    if (dwDimension > MAX_MATRIX_DIMENSION || dwDimension < MIN_MATRIX_DIMENSION ) { 
        return NULL;
    }
    //Allocate buffer
    matrix = (uint8_t *)malloc((uint32_t)dwDimension * (uint32_t)dwDimension * sizeof(uint8_t));
    if (!matrix) {
        return NULL;
    }
    //Return buffer
    return matrix;
}
/*
    createGraphMatrix(uint16_t dwDimension);
    description:
        create the matrix filled with the 1 arbitrarily and symmetrical
    arguments:
        uint16_t dwDimension - matrix dimension
    return value:
        SUCCESS: uint8_t *pbMatrix - graph matrix (symmentric matrix)
        ERROR: NULL
*/

uint8_t *createGraphMatrix(uint16_t dwDimension) {
    uint8_t *pbMatrix = NULL;
    uint8_t bTemp;
    uint16_t wColumn = 0, wRow = 0;
    //Check dimension limits
    if (dwDimension > MAX_MATRIX_DIMENSION || dwDimension < MIN_MATRIX_DIMENSION) {
        return NULL;
    }
    //Create matrix filled with 0s
    pbMatrix = createMatrix(dwDimension, 0);
    if (!pbMatrix) {
        return NULL;
    }
    //Fill with 1s randomly, but with diagonal symmetry 
    for (wColumn = 0; wColumn < dwDimension; wColumn++) {
        for (wRow = wColumn; wRow < dwDimension; wRow++) {
            bTemp=getRandomBit();
            *(pbMatrix + wRow * dwDimension + wColumn) = bTemp;
            *(pbMatrix + wColumn * dwDimension + wRow) = bTemp;
        }
    }
    //Return matrix
    return pbMatrix;
}

/*
    uint8_t permuteArrayRandomly(uint16_t *pwArray, uint16_t wSize);
    description:
        Random array permutation
    arguments: 
        uint16_t *pwArray - array for permutation (passed by reference)
        uint16_t wSize - size of the array
    return value:
        SUCCESS: 0
        ERROR: 1
*/

uint8_t permuteArrayRandomly(uint16_t* pwArray, uint16_t wSize) {
    int32_t sdwIndex = 0;
    uint16_t wCounter = 0, wRandomNumber = 0, wTemp = 0;
    //Check sanity and limits
    if (!pwArray || wSize > MAX_MATRIX_DIMENSION || wSize < MIN_MATRIX_DIMENSION) {
        return 1;
    }
    //Loop through the indexes four times 
    while (wCounter < wSize * 4) {
        for (sdwIndex =(int32_t) wSize - 2; sdwIndex >= 0; sdwIndex--) {
            //Loop through each index and exchange current element with an element at random index
            wRandomNumber = getRandom() % (sdwIndex + 2);
            wTemp = pwArray[sdwIndex + 1];
            pwArray[sdwIndex + 1] = pwArray[wRandomNumber];
            pwArray[wRandomNumber] = wTemp; 
        }
        wCounter++;
    }
    return 0;
}

/*
    uint16_t *createCycle(uint16_t wCycleLength);
    description:
        create the cycle
    arguments:
        uint16_t wCycleLength - cycle length
    return value:
        SUCCESS: uint16_t *pwCycle - array filled with numbers from 0 to size arbitrarily
        ERROR: NULL
*/

uint16_t *createCycle(uint16_t wCycleLength) {
    uint16_t *pwCycle = NULL, wIndex = 0;
    //Check cycle dimension limit
    if (wCycleLength > MAX_MATRIX_DIMENSION || wCycleLength < MIN_MATRIX_DIMENSION) {
        return NULL;
    }
    //Allocate buffer
    pwCycle = (uint16_t *)malloc(wCycleLength * sizeof(uint16_t));
    if (!pwCycle) {
        return NULL;
    }
    //Set each element in buffer to its index
    for (wIndex = 0; wIndex < wCycleLength; wIndex ++) {
        pwCycle[wIndex] = wIndex;
    }
    //Shuffle elements
    if (permuteArrayRandomly(pwCycle, wCycleLength) == 0) {
        return pwCycle;
    }
    else {
        return NULL;
    }
}

/*
    uint8_t *createGraphMatrixWithHamiltonianCycle(uint16_t wDimension, uint16_t *pwCycle);
    description:
        creation the graph matrix with Hamiltonian cycle
    arguments:
        uint16_t wDimension - matrix dimension
        uint16_t *pwCycle - cycle (has the same dimension as the matrix)
    return value:
        SUCCESS: uint8_t *pbMatrix graph matrix with Hamiltonian cycle
        ERROR: NULL
*/

uint8_t *createGraphMatrixWithHamiltonianCycle(uint16_t wDimension, uint16_t *pwCycle) {
    uint8_t *pbMatrix = NULL;
    uint16_t wIndex = 0; 
    //Check sanity and limits
    if (wDimension > MAX_MATRIX_DIMENSION || wDimension < MIN_MATRIX_DIMENSION || !pwCycle) {
        return NULL;
    }
    //Create graph matrix
    pbMatrix = createGraphMatrix(wDimension);
    if (!pbMatrix) {
        return NULL;
    } 
    //Add cycle to the matrix
    for(wIndex = 0; wIndex < wDimension - 1; wIndex++) {
        *(pbMatrix + pwCycle[wIndex] * wDimension + pwCycle[wIndex + 1]) = 1;
        *(pbMatrix + pwCycle[wIndex + 1] * wDimension + pwCycle[wIndex]) = 1;
    }
    *(pbMatrix + pwCycle[0] * wDimension + pwCycle[wDimension - 1]) = 1;
    *(pbMatrix + pwCycle[wDimension - 1] * wDimension + pwCycle[0]) = 1;
    //Return matrix with cycle
    return pbMatrix;
}

/*
    uint8_t *createCycleMatrix(uint16_t *pwCycle, uint16_t wDimension);
    description:
        Create the matrix of the Hamiltonian cycle
    arguments:
        uint16_t *pwCycle - cycle
        uint16_t wDimension - cycle size (it's the size of the matrix)
    return value:
        SUCCESS: uint8_t *pbCycleMatrix - cycle matrix
        ERROR: NULL
*/

uint8_t *createCycleMatrix(uint16_t *pwCycle, uint16_t wDimension) {
    uint8_t *pbCycleMatrix = NULL;
    uint16_t wIndex = 0;
    //Check sanity and limits 
    if (!pwCycle || wDimension > MAX_MATRIX_DIMENSION || wDimension < MIN_MATRIX_DIMENSION) {
        return NULL;
    }
    //Create matrix filled with zeros
    pbCycleMatrix = createMatrix(wDimension, 0);
    if (!pbCycleMatrix) {
        return NULL;
    }
    //Fill in cycle edges
    for(wIndex = 0; wIndex < wDimension - 1; wIndex++) {
        *(pbCycleMatrix + pwCycle[wIndex + 1] * wDimension + pwCycle[wIndex]) = 1;
    }
    *(pbCycleMatrix + pwCycle[0] * wDimension + pwCycle[wDimension - 1]) = 1;
    //Return cycle matrix
    return pbCycleMatrix;
}

/*
    uint8_t *muliplyMatrixesJustForPermutations(uint8_t *pbMatrixA, uint8_t *pbMatrixB, uint16_t wDimension);
    description:
        matrix multiplication
    arguments:
        uint8_t *pbMatrixA - first matrix
        uint8_t *pbMatrixB - second matrix
        uint16_t wDimension - dimension of the matrices
    return value:
        SUCCESS: uint8_t *pbResultingMatrix - result of multiplication
        ERROR: NULL
*/

uint8_t *muliplyMatrixesJustForPermutations(uint8_t *pbMatrixA, uint8_t *pbMatrixB, uint16_t wDimension) {
   uint8_t *pbResultingMatrix = NULL;
   uint16_t i = 0, j = 0, k = 0;
   uint8_t t;
   //Check sanity and limits
    if (!pbMatrixA || !pbMatrixB || wDimension > MAX_MATRIX_DIMENSION || wDimension < MIN_MATRIX_DIMENSION) {
        return NULL;
    }
    //Allocate matrix buffer
    pbResultingMatrix = createMatrixFast(wDimension);
    if (!pbResultingMatrix) {
        return NULL;
    }
    //Standard row by column multiplication, only we are using AND instead of multiplication and XOR instead of addition 
    for (i = 0; i < wDimension; i++) {
        for (j = 0; j < wDimension; j++) {
            t=0;
            for(k = 0; t==0 && k < wDimension; k++) {
                t^=*(pbMatrixA + i * wDimension + k) & *(pbMatrixB + k * wDimension + j);
            }
            *(pbResultingMatrix + i * wDimension + j) =t; 
        }
    }
    return pbResultingMatrix;
}

/*
    uint8_t *multiplyMatrixByPermutation(uint8_t *pbMatrixA, uint8_t *pbMatrixB, uint16_t wDimension);
    description:
        matrix multiplication
    arguments:
        uint8_t *pbMatrixA - first matrix
        uint8_t *pbMatrixB - second matrix
        uint16_t wDimension - dimension of the matrices
    return value:
        SUCCESS: uint8_t *pbResultingMatrix - result of multiplication
        ERROR: NULL
*/

uint8_t *multiplyMatrixByPermutation(uint8_t *pbMatrixA, uint8_t *pbMatrixB, uint16_t wDimension) {
   uint8_t *pbResultingMatrix = NULL, *pbResultingOffsets;
   uint16_t i = 0, j = 0, k = 0;
   //Sanity check
    if (!pbMatrixA || !pbMatrixB || wDimension > MAX_MATRIX_DIMENSION || wDimension < MIN_MATRIX_DIMENSION) {
        return NULL;
    }
    //Allocate matrix buffer
    pbResultingMatrix = createMatrixFast(wDimension);
    pbResultingOffsets=pbResultingMatrix;
    if (!pbResultingMatrix) {
        return NULL;
    }
    pbResultingOffsets=pbResultingOffsets-1;
    //This is a spead up version, that works only for permutations.
    //For each column i of permutation matrix B find cell (j,i) not equal to zero.
    //Then copy column j of inital matrix S to position i in resulting matrix
    for (i=0; i< wDimension;i++){
        pbResultingOffsets=pbResultingOffsets+1;
        for (j=0;j<wDimension;j++){
            if (*(pbMatrixB + j*wDimension +i)!=0){
                break;
            }
        }
        if (j==wDimension) continue;
        for (k=0;k<wDimension;k++){
            pbResultingOffsets[k*wDimension]=pbMatrixA[k*wDimension+j];
        }
    }
    //Return matrix
    return pbResultingMatrix;
}

/*
    uint8_t *multiplyPermutationByMatrix(uint8_t *pbMatrixA, uint8_t *pbMatrixB, uint16_t wDimension);
    description:
        matrix multiplication
    arguments:
        uint8_t *pbMatrixA - first matrix
        uint8_t *pbMatrixB - second matrix
        uint16_t wDimension - dimension of the matrices
    return value:
        SUCCESS: uint8_t *pbResultingMatrix - result of multiplication
        ERROR: NULL
*/

uint8_t *multiplyPermutationByMatrix(uint8_t *pbMatrixA, uint8_t *pbMatrixB, uint16_t wDimension) {
   uint8_t *pbResultingMatrix = NULL ;
   uint16_t i = 0, j = 0;
   //Check sanity and limits
    if (!pbMatrixA || !pbMatrixB || wDimension > MAX_MATRIX_DIMENSION || wDimension < MIN_MATRIX_DIMENSION) {
        return NULL;
    }
    //Allocate matrix
    pbResultingMatrix = createMatrixFast(wDimension);
    if (!pbResultingMatrix) {
        return NULL;
    }
    //For each row i of permutation matrix A find cell (i,j) not equal to zero
    //Copy row j of matrix B to row i of resulting matrix
    //Memcpy relies on SIMD, so we significantly speed up multiplication
    for (i=0; i< wDimension;i++){
        for (j=0;j<wDimension;j++){
            if (*(pbMatrixA + j +i*wDimension)!=0){
                break;
            }
        }
        if (j==wDimension) continue;
        memcpy(pbResultingMatrix+(i*wDimension),pbMatrixB+(j*wDimension),wDimension);
    }
    //Return resulting matrix
    return pbResultingMatrix;
}
/*
    uint8_t *transposeMatrix(uint8_t *pbMatrix, uint16_t wDimension);
    description:
        matrix transpose
    arguments:
        uint8_t *pbMatrix - initial matrix
        uint16_t wDimension - matrix dimension
    return value:
        SUCCESS: uint8_t *pbTransposedMatrix - transposed matrix
        ERROR: NULL
*/

uint8_t *transposeMatrix(uint8_t *pbMatrix, uint16_t wDimension) {
    uint8_t *pbTransposedMatrix = NULL;
    uint16_t i = 0, j = 0;
    //Check sanity and limits
    if (!pbMatrix || wDimension > MAX_MATRIX_DIMENSION || wDimension < MIN_MATRIX_DIMENSION) {
        return NULL;
    }
    //Allocate matrix buffer
    pbTransposedMatrix = createMatrixFast(wDimension);
    if (!pbTransposedMatrix) {
        return NULL;
    }
    //Transpose 
    for (i = 0; i < wDimension; i++) {
        for(j = 0; j < wDimension; j++) {
            *(pbTransposedMatrix + j * wDimension + i) = *(pbMatrix + i * wDimension + j);
        }
    }
    //Return transposed matrix
    return pbTransposedMatrix;
}

/*
    uint8_t *generatePermutationMatrix(uint16_t wDimension);
    description:
        creatуe the matrix permutation
    arguments:
        uint16_t wDimension - matrix dimension
    return value:
        SUCCESS: uint8_t *pbPermutationMatrix - matrix of the pi
        ERROR: NULL
*/

uint8_t *generatePermutationMatrix(uint16_t wDimension) {
    uint8_t *pbPermutationMatrix = NULL;
    uint16_t *pwPermutationCycle = NULL, i = 0;
    //Check limits
    if (wDimension > MAX_MATRIX_DIMENSION || wDimension < MIN_MATRIX_DIMENSION) {
        return NULL;
    }
    //Create matrix field with 0s
    pbPermutationMatrix = createMatrix(wDimension, 0);
    if (!pbPermutationMatrix) {
        return NULL;
    }
    //Create cycle
    pwPermutationCycle = createCycle(wDimension);
    if (!pwPermutationCycle) {
        freeMemory(pbPermutationMatrix);
        return NULL;
    }
    //Create edge between vertex i and cycle[i]
    for (i = 0; i < wDimension; i++) {
        *(pbPermutationMatrix + pwPermutationCycle[i] * wDimension + i) = 1;
    }
    //Cleanup
    freeMemory(pwPermutationCycle);
    //Return permutation matrix
    return pbPermutationMatrix;
}

/*
    uint8_t *permuteMatrix(uint8_t *pbPermutationMatrix, uint8_t *pbInitialMatrix, uint16_t wDimension);
    description:
        permute the initial matrix using the permutation matrix
    arguments:
        uint8_t *pbPermutationMatrix - permutation matrix
        uint8_t *pbInitialMatrix - initial matrix
        uint16_t wDimension - matrix dimension
    return value:
        SUCCESS: uint8_t *pbResultingMatrix - permute of the initial matrix
        ERROR: NULL
*/

uint8_t *permuteMatrix(uint8_t *pbPermutationMatrix, uint8_t *pbInitialMatrix, uint16_t wDimension) {
    uint8_t *pbTemporaryBuffer = NULL, *pbTemporaryBuffer2 = NULL, *pbResultingMatrix = NULL;
    //Check sanity an limits
    if (!pbPermutationMatrix || wDimension > MAX_MATRIX_DIMENSION || wDimension < MIN_MATRIX_DIMENSION) {
        return NULL;
    }
    //Compute initial matrix transposition
    pbTemporaryBuffer2 = transposeMatrix(pbInitialMatrix, wDimension);
    if (!pbTemporaryBuffer2) {
        return NULL;
    }
    //Multiply permutation by transposed initial matrix: P*M'
    pbTemporaryBuffer = multiplyPermutationByMatrix(pbPermutationMatrix, pbTemporaryBuffer2, wDimension);
    if (!pbTemporaryBuffer) {
        freeMemory(pbTemporaryBuffer2);
        return NULL;
    }
    freeMemory(pbTemporaryBuffer2);
    //Compute transposition of previous multiplication: (P*M')'=M*P'
    pbTemporaryBuffer2=transposeMatrix(pbTemporaryBuffer,wDimension);
    free(pbTemporaryBuffer);
    //Multiply permutation matrix by previous result: P*M*P'
    pbResultingMatrix = multiplyPermutationByMatrix(pbPermutationMatrix, pbTemporaryBuffer2, wDimension);
    freeMemory(pbTemporaryBuffer2);
    if (pbResultingMatrix==NULL) return NULL;
    //Return resulting matrix
    return pbResultingMatrix;
}

/*
    uint8_t printMatrix(uint8_t *pbMatrix, uint16_t wDimension);
    description:
        print matrix
    arguments:
        uint8_t *pbMatrix - matrix
        uint16_t wDimension - matrix dimension
    return value:
        SUCCESS: 0
        ERROR: 1
*/

uint8_t printMatrix(uint8_t *pbMatrix, uint16_t wDimension) {
    uint16_t i = 0, j = 0;
    //Check sanity and limits
    if (!pbMatrix || wDimension > MAX_MATRIX_DIMENSION || wDimension < MIN_MATRIX_DIMENSION) {
        return 1;
    }
    for (i = 0; i < wDimension; i++) {
        for (j = 0; j < wDimension; j++) {
            printf("%d ", *(pbMatrix + i * wDimension + j));
        }
        printf("\n");
    }
    printf("\n\n");
    return 0;
}

/*
    uint32_t computePackedMatrixSize(uint16_t wUnpackedSize);
    description:
        searching for the number of bytes necessary for storing packed matrix
    arguments:
        uint16_t wUnpackedSize - matrix dimension
    return value:
        uint32_t dwPackedSize - the number of bytes
*/

uint32_t computePackedMatrixSize(uint16_t wUnpackedSize) {
    uint32_t dwPackedSize = 0;
    if ((uint32_t) wUnpackedSize * (uint32_t)wUnpackedSize % 8 != 0) {
        dwPackedSize = (uint32_t)wUnpackedSize * (uint32_t)wUnpackedSize / 8 + sizeof(uint16_t) + 1;
    }
    else {
        dwPackedSize = (uint32_t)wUnpackedSize * (uint32_t)wUnpackedSize / 8 + sizeof(uint16_t);
    }
    return dwPackedSize;
}

/*
    uint8_t *packMatrix(uint8_t *pbMatrix, uint16_t wDimension, uint32_t *pdwPackedSize);
    description:
        packing the matrix for further transmission 
        if we have 4-dimension matrix [1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0]
        packed matrix looks like [0x00, 0x04, 0xFF, 0x00]
    arguments:
        uint8_t *pbMatrix - matrix for packing
        uint16_t wDimension - matrix dimension
        uint16_t *pdwPackedSize - size of the packed matrix (passed by reference)
    return value:
        SUCCESS: uint8_t *pbPackedMatrix - packe matrix
        ERROR: NULL
*/

uint8_t *packMatrix(uint8_t *pbMatrix, uint16_t wDimension, uint32_t *pdwPackedSize) {
    uint8_t *pbPackedMatrix = NULL, bAccumulator = 0;
    uint32_t dwMatrixIndex = 0, dwPackedMatrixIndex = 2, dwMatrixSize = 0, dwOffset = 0;
    int16_t swPowerOf2 = 0;
    //Check sanity and limits
    if (!pbMatrix || wDimension > MAX_MATRIX_DIMENSION || wDimension < MIN_MATRIX_DIMENSION) {
        return NULL;
    }
    //Compute packed matrix size and allocate buffer
    *pdwPackedSize = computePackedMatrixSize(wDimension);
    pbPackedMatrix = (uint8_t *)malloc(*pdwPackedSize * sizeof(uint8_t));
    if (!pbPackedMatrix) {
        return NULL;
    }
    //Set everything to zero to stop leaks
    memset(pbPackedMatrix, 0, *pdwPackedSize);
    //Save wDimension in big-endian format
    pbPackedMatrix[0] = wDimension / 256;
    pbPackedMatrix[1] = wDimension % 256;
    dwMatrixSize = (uint32_t)wDimension * (uint32_t)wDimension;
    //Pack each tuple of 8 elements into one byte
    for (dwMatrixIndex = 0; dwMatrixIndex < dwMatrixSize; dwMatrixIndex += 8) {
        if (dwMatrixSize - dwMatrixIndex >= 8) {
            dwOffset = 7;
        }
        else {
            dwOffset = dwMatrixSize - dwMatrixIndex - 1;
        }
        for (swPowerOf2 = dwOffset; swPowerOf2 >= 0; swPowerOf2--) {
            bAccumulator |= pbMatrix[dwMatrixIndex + dwOffset - swPowerOf2] << swPowerOf2;
        }  
        pbPackedMatrix[dwPackedMatrixIndex] = bAccumulator;
        bAccumulator = 0;
        dwPackedMatrixIndex++;
    }
    //Return packed matrix
    return pbPackedMatrix;
}

/*
    uint8_t *unpackMatrix(uint32_t wPackedMatrixSize, uint8_t *pbPackedMatrix, uint16_t* pwDimension);
    description:
        unpacking the received matrix
    arguments:
        uint32_t wPackedMatrixSize - size of the packed matrix
        uint8_t *pbPackedMatrix - packed matrix
        uint16_t* pwDimension - size of the unpacked matrix
    return value:
        SUCCESS: uint8_t *pbUnpackedMatrix - unpacked matrix
        ERROR: NULL
*/

uint8_t *unpackMatrix(uint32_t dwPackedMatrixSize, uint8_t *pbPackedMatrix, uint16_t *pwDimension) {
    uint32_t dwIndex = 0, dwIndexInUnpackedMatrix = 0, dwOffset = 0, dwMatrixSize = 0;
    uint16_t wUnpackedMatrixSize = 0;
    uint8_t *pbUnpackedMatrix = NULL, bTemp = 0;  
    uint32_t dwComputedSize;
    //Sanity checks
    if (!pbPackedMatrix || dwPackedMatrixSize < 2) {
        return NULL;
    }
    //Dimension reconstruction
    wUnpackedMatrixSize = pbPackedMatrix[0] * 256 + pbPackedMatrix[1];
    *pwDimension=wUnpackedMatrixSize;
    //Check limits and compare matrix size with computed size to prevent overflows.
    //We allow underflows for CRC32 collision bug
    if ((computePackedMatrixSize(wUnpackedMatrixSize) - 2 > dwPackedMatrixSize - 2) || wUnpackedMatrixSize > MAX_MATRIX_DIMENSION || wUnpackedMatrixSize < MIN_MATRIX_DIMENSION) {
        return NULL;
    }
    //Compute packed size
    dwComputedSize=computePackedMatrixSize(wUnpackedMatrixSize);
    //Allocate matrix
    pbUnpackedMatrix = (uint8_t *)createMatrix(wUnpackedMatrixSize, 0);
    if (!pbUnpackedMatrix) {
        return NULL;
    }
    dwMatrixSize = (uint32_t)wUnpackedMatrixSize * (uint32_t)wUnpackedMatrixSize;
    //Unpack elements into matrix
    for (dwIndex = 2; dwIndex < dwComputedSize; dwIndex++) {
        bTemp = pbPackedMatrix[dwIndex];
        if (dwMatrixSize - dwIndexInUnpackedMatrix >= 8) {
            dwOffset = 7;
        } 
        else {
            dwOffset = dwMatrixSize - dwIndexInUnpackedMatrix - 1;
        }
        if (bTemp != 0) {
            while (bTemp > 0) {
                pbUnpackedMatrix[dwIndexInUnpackedMatrix + dwOffset] = bTemp & 1 ;
                dwOffset--;
                bTemp = bTemp>>1;
            } 
        }
        dwIndexInUnpackedMatrix += 8;
    }
    //Return matrix
    return pbUnpackedMatrix;
}

/*
    PFULL_KNOWLEDGE generateGraphAndCycleMatrix(uint16_t wVertexCount
    description:
        This function is supposed to generate a graph of <wVertexCount> vertices with a Hamiltonian cycle
        and return the adjacency matrix along with the cycle matrix
    arguments:
        wVerticeCount - the number of vertices in a graph
    return value:
        SUCCESS - pointer to FULL_KNOWLEDGE structure, containing the graphs and additional parameters
        ERROR - NULL

*/
PFULL_KNOWLEDGE generateGraphAndCycleMatrix(uint16_t wVertexCount)
{
    PFULL_KNOWLEDGE pFKnowledge;
    uint8_t* pMatrix;
    uint16_t* pCycle;
    //Check limits
    if ((wVertexCount>MAX_MATRIX_DIMENSION)||(wVertexCount<MIN_MATRIX_DIMENSION)) return NULL;
    //Allocate structure
    pFKnowledge=malloc(sizeof(FULL_KNOWLEDGE));
    if (pFKnowledge==NULL) return NULL;
    //Create cycle
    pCycle=createCycle(wVertexCount);
    if (pCycle==NULL){
        free(pFKnowledge);
        return NULL;
    }
    //Create cycle matrix
    pMatrix=createCycleMatrix(pCycle,wVertexCount);
    if (pMatrix==NULL){
        free(pFKnowledge);
        free(pCycle);
        return NULL;
    }
    //Fill vertex count, matrix size and cycle matrix in structure
    pFKnowledge->wDimension=wVertexCount;
    pFKnowledge->dwMatrixArraySize=((uint32_t)wVertexCount)*(uint32_t)wVertexCount;
    pFKnowledge->pbCycleMatrix=pMatrix; 
    //Create graph matrix
    pMatrix=createGraphMatrixWithHamiltonianCycle(wVertexCount,pCycle);
    free(pCycle);
    if (pMatrix==NULL){
        free(pFKnowledge->pbCycleMatrix);
        free(pFKnowledge);
        return NULL;
    }
    //Fill graph matrix
    pFKnowledge->pbGraphMatrix=pMatrix;
    //Return pointer to structure
    return pFKnowledge;
}

/*
    void freeFullKnowledge(PFULL_KNOWLEDGE pFullKnowledge)
    description:
        free full knowledge structure and all members
    arguments:
        pFullKnowledge - pointer to full knowledge structure
    return value:
        None

*/
void freeFullKnowledge(PFULL_KNOWLEDGE pFullKnowledge){
    //Check sanity
    if (pFullKnowledge==NULL) return;
    if (pFullKnowledge->pbCycleMatrix==NULL) return;
    if (pFullKnowledge->pbGraphMatrix==NULL) return;
    //Free members
    free(pFullKnowledge->pbGraphMatrix);
    free(pFullKnowledge->pbCycleMatrix);
    free(pFullKnowledge);
}

/*
    uint8_t checkHamiltonianCycle(uint8_t* pbGraphMatrix, uint8_t* pbCycleMatrix, uint16_t wDimension)
    description:
        Check if this is a hamiltonian cycle
    arguments:
        pbGraphMatrix - graph matrix
        pbCycleMatrix - cycle matrix
        wDimension - their dimension
    return value:
        hamiltionian cycle - 0
        not hamiltonian cycle - 1
*/
uint8_t checkHamiltonianCycle(uint8_t *pbGraphMatrix, uint8_t *pbCycleMatrix, uint16_t wDimension){
    uint32_t dwDimension;
    dwDimension=(uint32_t)wDimension;
    uint32_t dwIndex, dwJndex,dwKndex, dwRowCount,dwJumpCount;
    uint32_t * pdwVisitedNodes;
    //First let's check that all 1s in pbCycleMatrix are in pbGraphMatrix's
    for (dwIndex=0;dwIndex<dwDimension;dwIndex=dwIndex+1){
        dwRowCount=0;
        for (dwJndex=0;dwJndex<dwDimension;dwJndex=dwJndex+1){
            if (pbCycleMatrix[dwIndex*dwDimension+dwJndex]==1){
                dwRowCount=dwRowCount+1;
                if (dwIndex==dwJndex || pbGraphMatrix[dwIndex*dwDimension+dwJndex]!=1){
                    return 1;
                }
            }
        }
        //And that each vertice has only one outward edge
        if (dwRowCount!=1){
            return 1;
        }
    }
    //Allocate buffer for saving visits
    pdwVisitedNodes=(uint32_t*)malloc(dwDimension*sizeof(uint32_t));
    if (pdwVisitedNodes==NULL) return 1;
    //Fill everything with 0xffffffff by default
    memset(pdwVisitedNodes,0xff,dwDimension*sizeof(uint32_t));
    dwJumpCount=0;
    dwIndex=0;
    //Visit nodes one by one. If we visit a node twice and it's not the last one, then return error
    while (1){
        for(dwJndex=0;dwJndex<dwDimension;dwJndex=dwJndex+1){
            if (pbCycleMatrix[dwIndex*dwDimension+dwJndex]==1){
                if (dwJumpCount==(dwDimension-1)){
                    free(pdwVisitedNodes);
                    return 0;
                }
                for (dwKndex=0;dwKndex<dwJumpCount;dwKndex=dwKndex+1){
                    if (pdwVisitedNodes[dwKndex]==dwJndex){
                        free(pdwVisitedNodes);
                        return 1;
                    }
                    if (pdwVisitedNodes[dwKndex]==0xffffffff) break;
                }
                pdwVisitedNodes[dwKndex]=dwJndex;
                dwJumpCount=dwJumpCount+1;
                dwIndex=dwJndex;
                break;
            }

        }
        //This shouldn't happen, but just in case:
        //free(pdwVisitedNodes);
        //return 1;
    }
}
