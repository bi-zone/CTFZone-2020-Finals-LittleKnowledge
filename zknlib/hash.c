#include <sys/socket.h>
#include <linux/if_alg.h>
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
    unsigned char * hashsum(unsigned char* pData,ssize_t dSize){
    description:
        Hash data
    arguments:
        pData - pointer to array of bytes
        dSize - size of the array
    return value:
        SUCCESS - pointer to array with hash
        ERROR - NULL
*/
unsigned char * hashsum(unsigned char* pData,ssize_t dSize){
    unsigned char hash[HASH_SIZE];
    unsigned char* pHash;
    int sock_fd;
    int bfd;
    int opfd;
    ssize_t ret;
    struct sockaddr_alg sa = {
        .salg_family=AF_ALG,
        .salg_type="hash",
        .salg_name=HASH_NAME
    };
    sock_fd=socket(AF_ALG,SOCK_SEQPACKET,0);
    if (sock_fd==-1) return NULL;
    bfd=bind(sock_fd,(struct sockaddr*)&sa,sizeof(sa));
    if (bfd==-1) return NULL;
    opfd=accept(sock_fd,NULL,0);
    if (opfd==-1) return NULL;

    ret=send(opfd,pData,dSize,0);
    if (ret!=dSize) return NULL;
    ret=recv(opfd,hash,HASH_SIZE,0);
    if (ret!=HASH_SIZE) return NULL;
    pHash=malloc(HASH_SIZE);
    if (pHash==NULL) return NULL;
    memcpy(pHash,hash,HASH_SIZE);
    return pHash;
}