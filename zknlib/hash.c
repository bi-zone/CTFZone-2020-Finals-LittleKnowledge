/*
libzkn - cryptography functions (named hash.c, since at the beginning there were only hashes)
We use linux kernel usermode cryptoapi
Authors:
    Innokentii Sennovskii (i.sennovskiy@bi.zone)
*/
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"
#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif



/*
    unsigned char * sha256(unsigned char* pData,ssize_t dSize){
    description:
        Compute a sha256 digest of data and return pointer to a
        newly allocated buffer with the digest.
    arguments:
        pData - pointer to array of bytes
        dSize - size of the array
    return value:
        SUCCESS - pointer to array with hash
        ERROR - NULL
*/
unsigned char * sha256(unsigned char* pData,size_t dSize){
    unsigned char hash[SHA256_SIZE];
    unsigned char* pHash;
    int sock_fd;
    int bfd;
    int opfd;
    ssize_t ret;
    //Socket addr for sha256
    struct sockaddr_alg sa = {
        .salg_family=AF_ALG,
        .salg_type="hash",
        .salg_name=SHA256_NAME
    };
    //Create socket descriptor for AF_ALG
    sock_fd=socket(AF_ALG,SOCK_SEQPACKET,0);
    if (sock_fd==-1) return NULL;
    //Bind to it
    bfd=bind(sock_fd,(struct sockaddr*)&sa,sizeof(sa));
    if (bfd==-1) {
        close(sock_fd);
        return NULL;
    }
    //Connect to it
    opfd=accept(sock_fd,NULL,0);
    if (opfd==-1) {
        close(sock_fd);
        return NULL;
    }
    //Send data to it
    ret=send(opfd,pData,dSize,0);
    if (ret!=dSize) 
    {
        close(opfd);
        close(sock_fd);
        return NULL;
    }
    //Receive hash
    ret=recv(opfd,hash,SHA256_SIZE,0);
    if (ret!=SHA256_SIZE) {
        close(sock_fd);
        close(opfd);
        return NULL;
    }
    //Allocate buffer
    pHash=malloc(SHA256_SIZE);
    if (pHash==NULL) {
        close(sock_fd);
        close(opfd);
        return NULL;
    }
    //Copy digest to buffer
    memcpy(pHash,hash,SHA256_SIZE);
    //Close decsriptors
    close(sock_fd);
    close(opfd);
    //Return digest
    return pHash;
}


/*
    unsigned char * crc32(unsigned char* pData,ssize_t dSize){
    description:
        Compute crc32 on data and return in a newly 
        allocated buffer 
    arguments:
        pData - pointer to array of bytes
        dSize - size of the array
    return value:
        SUCCESS - pointer to array with hash
        ERROR - NULL
*/
unsigned char * crc32(unsigned char* pData,size_t dSize){
    unsigned char hash[CRC32_SIZE]={0xff,0xff,0xff,0xff};
    unsigned char* pHash;
    int sock_fd;
    int bfd;
    int opfd;
    ssize_t ret;
    //Create socket addres
    struct sockaddr_alg sa = {
        .salg_family=AF_ALG,
        .salg_type="hash",
        .salg_name=CRC32_NAME
    };
    //Open AF_ALF socket
    sock_fd=socket(AF_ALG,SOCK_SEQPACKET,0);
    if (sock_fd==-1) return NULL;
    //Bind to it
    bfd=bind(sock_fd,(struct sockaddr*)&sa,sizeof(sa));
    if (bfd==-1)
    {
        close(sock_fd);
        return NULL;
    }
    //Set initial crc32 state to 0xffffffff
    if(setsockopt(sock_fd,SOL_ALG,ALG_SET_KEY,hash,CRC32_SIZE)==-1){
        close(sock_fd);
        return NULL;
    }
    //Connect
    opfd=accept(sock_fd,NULL,0);
    if (opfd==-1) 
    {
        close(sock_fd);
        return NULL;
    }
    //Send data to kernel 
    ret=send(opfd,pData,dSize,MSG_DONTWAIT);
    if (ret!=dSize) {
        close(opfd);
        close(sock_fd);
        return NULL;
    }
    //Receive crc32 state
    ret=recv(opfd,hash,CRC32_SIZE,0);
    if (ret!=CRC32_SIZE) {
        close(opfd);
        close(sock_fd);
        return NULL;
    }
    //Allocate buffer for returning digest
    pHash=malloc(CRC32_SIZE);
    if (pHash==NULL) {
        close(opfd);
        close(sock_fd);
        return NULL;
    }
    //Negate state to complete calculation
    *(uint32_t*)pHash=0xffffffff&(~(*(uint32_t*)hash));
    //Clean up
    close(opfd);
    close(sock_fd);
    //Return hash
    return pHash;
}
/*
    int getRandomBytes(unsigned char* pData, size_t dataSize);
    description:
        Write random bytes to the given location (from urandom)
    arguments:
        pData - pointer to area to write bytes to
        dataSize - requested data size
    return value:
        SUCCESS - 0
        FAIL - -1
*/
int getRandomBytes(unsigned char* pData, size_t dataSize){
    int fd;
    size_t bytesRead, totalBytesRead;
    totalBytesRead=0;
    //Open urandom
    fd=open("/dev/urandom",O_RDONLY);
    if (fd==-1){
        return -1;
    } 
    else{
        //Read until we have enough bytes
        while (totalBytesRead<dataSize){
            bytesRead=read(fd,pData+totalBytesRead,AES_IV_SIZE-totalBytesRead);
            if (bytesRead==-1){
                //Weird
                close(fd);
                return -1;
            }
            totalBytesRead+=bytesRead;
        }
        close(fd);
    }
    return 0;
}

/*
    unsigned char* aes128cbc_encrypt(unsigned char* pData, size_t dSize, unsigned char* pbKey, unsigned char* pbIV, out uint32_t* pdwCiphertextSize)
    description:
        Pack and encrypt data with 128-bit aes in CBC. (Packing is not PKCS, IV is generated automatically and prepended to the CT)
        The result is a buffer wit the following structure:
            IV|AES-CBC(uint32_t(plaintext_size)|plaintext|padding zeros)
    arguments:
        pData - pointer to plaintext data
        dSize - size of data to encrypt
        pbKey - pointer to key data (16 bytes needed)
        pdwCiphertextSize - pointer for saving resulting ciphertext size
    return value:
        SUCCESS - pointer to IV|CT
        FAIL - NULL
*/
unsigned char* aes128cbc_encrypt(unsigned char* pData, size_t dSize, unsigned char* pbKey, unsigned char*pbIV, out uint32_t* pdwCiphertextSize){
    unsigned char* pbPtBuf;
    unsigned char* pbCtBuf;
    size_t totalSize;
    int opfd;
    int tfmfd;
    int res;
//When we fuzz, encryption makes it impossible to reach deeper branches
//So we just do IV|uint32_t(pt_size)|pt|padding zeros. Without aes
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    if (pData==NULL || pdwCiphertextSize==NULL ||dSize==0) return NULL;
    totalSize=dSize+sizeof(uint32_t);
    if ((totalSize%16)!=0){
        totalSize=totalSize+16-totalSize%16;
    }
    pbPtBuf=calloc(totalSize,1);
    if (pbPtBuf==NULL) return NULL;
    pbCtBuf=calloc(totalSize+AES_IV_SIZE,1);
    if (pbCtBuf==NULL){
        free(pbPtBuf);
        return NULL;
    }
    *((uint32_t*)pbPtBuf)=(uint32_t)dSize;
    memcpy(pbPtBuf+sizeof(uint32_t),pData,dSize);

    memcpy(pbCtBuf,pbIV,AES_IV_SIZE);
    memcpy(pbCtBuf+AES_IV_SIZE,pbPtBuf,totalSize);
    free(pbPtBuf);
    *(pdwCiphertextSize)=totalSize+AES_IV_SIZE;
    return pbCtBuf;
#else
    //Creat sock address
    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type = "skcipher",
        .salg_name = AES_CBC_MODE
    };
    struct msghdr msg = {};
    struct cmsghdr *cmsg;
    char cbuf[CMSG_SPACE(4) + CMSG_SPACE(20)] = {0};
    struct af_alg_iv *iv;
    struct iovec iov;
    //Sanity check
    if (pData==NULL || pdwCiphertextSize==NULL) return NULL;
    //Compute size of plaintext with prepended size
    totalSize=dSize+sizeof(uint32_t);
    //Fit to 16-byte border
    if ((totalSize%16)!=0){
        totalSize=totalSize+16-totalSize%16;
    }
    //Allocate plaintext buffer
    pbPtBuf=calloc(totalSize,1);
    if (pbPtBuf==NULL) return NULL;
    //Allocate ciphertext buffer
    pbCtBuf=calloc(totalSize+AES_IV_SIZE,1);
    if (pbCtBuf==NULL){
        free(pbPtBuf);
        return NULL;
    }
    //Copy size to plaintext buffer
    *((uint32_t*)pbPtBuf)=(uint32_t)dSize;
    //Copy plaintext to plaintext buffer
    memcpy(pbPtBuf+sizeof(uint32_t),pData,dSize);
    //Copy IV to ciphertext buffer
    memcpy(pbCtBuf,pbIV,AES_IV_SIZE);
    //Create AF_ALG socket
    tfmfd=socket(AF_ALG,SOCK_SEQPACKET,0);
    if (tfmfd==-1){
        free(pbCtBuf);
        free(pbPtBuf);
        return NULL;
    }
    //Bind
    res=bind(tfmfd,(struct sockaddr*)&sa,sizeof(sa));
    if (res==-1){
        close(tfmfd);
        free(pbCtBuf);
        free(pbPtBuf);
        return NULL;
    }
    //Set key 
    if (setsockopt(tfmfd,SOL_ALG,ALG_SET_KEY,pbKey,AES128_KEY_SIZE)==-1){
        close(tfmfd);
        free(pbCtBuf);
        free(pbPtBuf);
        return NULL;
    }
    //Connect
    opfd=accept(tfmfd,NULL,0);
    if (opfd==-1){
        close(tfmfd);
        free(pbCtBuf);
        free(pbPtBuf);
        return NULL;
    }
    //Fill values in control message
    msg.msg_control=cbuf;
    msg.msg_controllen=sizeof(cbuf);
    cmsg=CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level=SOL_ALG;
    cmsg->cmsg_type=ALG_SET_OP;
    cmsg->cmsg_len=CMSG_LEN(4);
    //Set operation to encrypt
    *(uint32_t *)CMSG_DATA(cmsg)=ALG_OP_ENCRYPT;
    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(20);
    //Set IV
    iv = (void *)CMSG_DATA(cmsg);
    iv->ivlen = AES_IV_SIZE;
    memcpy(iv->iv, pbIV, AES_IV_SIZE);

    iov.iov_base=pbPtBuf;
    iov.iov_len=totalSize;

    msg.msg_iov=&iov;
    msg.msg_iovlen=1;
    //Send message to the socket
    if(sendmsg(opfd,&msg,0)==-1){
        close(tfmfd);
        free(pbCtBuf);
        free(pbPtBuf);
        return NULL;
    }
    //Read encrypted data
    if (read(opfd,pbCtBuf+AES_IV_SIZE,totalSize)!=totalSize){
        close(tfmfd);
        free(pbCtBuf);
        free(pbPtBuf);
        return NULL;
    }
    //Cleanup
    close(opfd);
    close(tfmfd);
    //Return resulting size and pointer to ciphertext buffer
    *(pdwCiphertextSize)=(uint32_t)(totalSize+AES_BLOCK_SIZE);
    free(pbPtBuf);
    return pbCtBuf;
#endif
}


/*
    unsigned char* aes128cbc_decrypt(unsigned char* pData, size_t dSize, unsigned char* pbKey, out uint32_t* pdwPlaintextSize)
    description:
        Decrypt with AES128 in CBC mode. The first BLOCK of input is IV. The first 4 bytes of PT are size of actual plaintext
    arguments:
        pData - pointer to IV|CT
        dSize - size of IV|CT
        pbKey - key (16 bytes)
        pdwPlaintextSize - for plaintext size output
    return value:
        SUCCESS - pointer to plaintext bytes
        ERROR - NULL
*/
unsigned char* aes128cbc_decrypt(unsigned char* pData, size_t dSize, unsigned char* pbKey, out uint32_t* pdwPlaintextSize){
    unsigned char* pbPtBuf;
    unsigned char* pbFinalPtBuf;
    uint32_t dwPlaintextSize;
    int opfd;
    int tfmfd;
    int res;
//If fuzzing, just unpack, no decryption
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    if (pData==NULL ||pdwPlaintextSize==NULL || dSize<(AES_IV_SIZE+AES_BLOCK_SIZE)) return NULL;
    pbPtBuf=malloc(dSize-AES_IV_SIZE);

    if (pbPtBuf==NULL) return NULL;
    memcpy(pbPtBuf,pData+AES_IV_SIZE,dSize-AES_IV_SIZE);
    dwPlaintextSize=*(uint32_t*)pbPtBuf;
    if (dwPlaintextSize>(dSize-AES_IV_SIZE)) {
        free(pbPtBuf);
        return NULL;
    }
    pbFinalPtBuf=malloc(dwPlaintextSize);
    if (pbFinalPtBuf==NULL){
        free(pbPtBuf);
        return NULL;
    }
    memcpy(pbFinalPtBuf,pbPtBuf+sizeof(uint32_t),(size_t)dwPlaintextSize);
    *pdwPlaintextSize=dwPlaintextSize;

    
    free(pbPtBuf);
    return pbFinalPtBuf;

#else
    //Create socket address
    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type = "skcipher",
        .salg_name = AES_CBC_MODE
    };
    struct msghdr msg = {};
    struct cmsghdr *cmsg;
    char cbuf[CMSG_SPACE(4) + CMSG_SPACE(20)] = {0};
    struct af_alg_iv *iv;
    struct iovec iov;
    //Sanity check
    if (pData==NULL || pdwPlaintextSize==NULL || dSize<(AES_IV_SIZE+AES_BLOCK_SIZE)) return NULL;
    //Allocate buffer
    pbPtBuf=calloc(dSize-AES_IV_SIZE,1);
    if (pbPtBuf==NULL) return NULL;

    //Create socket
    tfmfd=socket(AF_ALG,SOCK_SEQPACKET,0);
    if (tfmfd==-1){
        free(pbPtBuf);
        return NULL;
    }
    //Bind socket
    res=bind(tfmfd,(struct sockaddr*)&sa,sizeof(sa));
    if (res==-1){
        close(tfmfd);
        free(pbPtBuf);
        return NULL;
    }
    //Set key
    if (setsockopt(tfmfd,SOL_ALG,ALG_SET_KEY,pbKey,AES128_KEY_SIZE)==-1){
        close(tfmfd);
        free(pbPtBuf);
        return NULL;
    }
    //Connect
    opfd=accept(tfmfd,NULL,0);
    if (opfd==-1){
        close(tfmfd);
        free(pbPtBuf);
        return NULL;
    }
    //Set decryption mode and input buffer
    msg.msg_control=cbuf;
    msg.msg_controllen=sizeof(cbuf);

    cmsg=CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level=SOL_ALG;
    cmsg->cmsg_type=ALG_SET_OP;
    cmsg->cmsg_len=CMSG_LEN(4);
    *(uint32_t *)CMSG_DATA(cmsg)=ALG_OP_DECRYPT;

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(20);
    iv = (void *)CMSG_DATA(cmsg);
    iv->ivlen = AES_IV_SIZE;
    memcpy(iv->iv, pData, AES_IV_SIZE);

    iov.iov_base=pData+AES_IV_SIZE;
    iov.iov_len=dSize-AES_IV_SIZE;

    msg.msg_iov=&iov;
    msg.msg_iovlen=1;
    //Send message to API
    if(sendmsg(opfd,&msg,0)==-1){
        close(tfmfd);
        free(pbPtBuf);
        return NULL;
    }
    //Read plaintext
    if (read(opfd,pbPtBuf,dSize-AES_IV_SIZE)!=(dSize-AES_IV_SIZE)){
        close(tfmfd);
        free(pbPtBuf);
        return NULL;
    }
    //Cleanup
    close(opfd);
    close(tfmfd);
    //Retrieve plaintext size
    dwPlaintextSize=*(uint32_t*)pbPtBuf;
    //Check that is fits inside encrypted container
    if (dwPlaintextSize>(dSize-AES_IV_SIZE)) {
        free(pbPtBuf);
        return NULL;
    }
    //Allocate buffer for plaintext
    pbFinalPtBuf=malloc(dwPlaintextSize);
    if (pbFinalPtBuf==NULL){
        free(pbPtBuf);
        return NULL;
    }
    //Copy plaintext to buffer
    memcpy(pbFinalPtBuf,pbPtBuf+sizeof(uint32_t),(size_t)dwPlaintextSize);
    //Return plaintext size
    *pdwPlaintextSize=dwPlaintextSize;
    free(pbPtBuf);
    //Return plaintext
    return pbFinalPtBuf;
#endif
}