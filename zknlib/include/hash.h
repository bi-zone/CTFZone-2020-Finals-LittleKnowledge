#include <sys/types.h>
#define SHA256_NAME "sha256"
#define SHA256_SIZE 32
unsigned char * sha256(unsigned char* pData,size_t dSize);
#define CRC32_NAME "crc32"
#define CRC32_SIZE 4
unsigned char * crc32(unsigned char* pData,size_t dSize);


#define AES_BLOCK_SIZE 16
#define AES_IV_SIZE 16
#define AES128_KEY_SIZE 16
#define AES_CBC_MODE "cbc(aes)"

#define out


int get16RandomBytes(unsigned char* pData);

unsigned char* aes128cbc_encrypt(unsigned char* pData, size_t dSize, unsigned char* pbKey, unsigned char* pbIV, out uint32_t* pdwCiphertextSize);
unsigned char* aes128cbc_decrypt(unsigned char* pData, size_t dSize, unsigned char* pbKey, out uint32_t* pdwPlaintextSize);
