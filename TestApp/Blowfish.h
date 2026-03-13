// blowfish.h
#ifndef BLOWFISH_H
#define BLOWFISH_H

#include <stdint.h>
#include <stddef.h>

// Blowfish块大小
#define BLOWFISH_BLOCK_SIZE 8

// 加密模式
#define BLOWFISH_MODE_ECB 0
#define BLOWFISH_MODE_CBC 1
#define BLOWFISH_MODE_CFB 2
#define BLOWFISH_MODE_OFB 3

// 错误码
#define BLOWFISH_SUCCESS 0
#define BLOWFISH_INVALID_KEY_LENGTH -1
#define BLOWFISH_INVALID_MODE -2
#define BLOWFISH_INVALID_INPUT_LENGTH -3

typedef struct {
    uint32_t P[18];
    uint32_t S[4][256];
    uint8_t iv[BLOWFISH_BLOCK_SIZE];
    int mode;
} blowfish_context;

// 函数声明
int blowfish_init(blowfish_context* ctx, const uint8_t* key, size_t key_len, int mode, const uint8_t* iv);
void blowfish_encrypt_block(blowfish_context* ctx, const uint8_t* plaintext, uint8_t* ciphertext);
void blowfish_decrypt_block(blowfish_context* ctx, const uint8_t* ciphertext, uint8_t* plaintext);
int blowfish_encrypt(blowfish_context* ctx, const uint8_t* plaintext, size_t length, uint8_t* ciphertext);
int blowfish_decrypt(blowfish_context* ctx, const uint8_t* ciphertext, size_t length, uint8_t* plaintext);
void blowfish_set_iv(blowfish_context* ctx, const uint8_t* iv);

#endif // BLOWFISH_H
