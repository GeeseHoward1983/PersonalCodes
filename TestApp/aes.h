#ifndef AES_H
#define AES_H
#include <stdint.h>

// 工作模式枚举
typedef enum {
    AES_MODE_ECB,
    AES_MODE_CBC,
    AES_MODE_CTR,
} CipherMode;

typedef enum {
    AES_MODE_NOPADDING,
    AES_MODE_PKCS5,
    AES_MODE_PKCS7,
    AES_MODE_ZEROPADDING,
    AES_MODE_X923PADDING,
    AES_MODE_ISO7816_4PADDING,
    AES_MODE_ISO10126PADDING,
} PaddingMode;


int AES_Encrypt(uint8_t* plaintext, int plaintext_len, uint8_t* key, int key_size,
    uint8_t* iv, CipherMode mode, PaddingMode paddingmode, uint8_t** ciphertext);

int AES_Decrypt(uint8_t* ciphertext, int ciphertext_len, uint8_t* key, int key_size,
    uint8_t* iv, CipherMode mode, PaddingMode paddingmode, uint8_t** plaintext);


#endif
