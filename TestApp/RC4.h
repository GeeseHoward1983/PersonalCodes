#ifndef _RC4_H_
#define _RC4_H_
#include <stdlib.h>

typedef struct {
    unsigned char S[256]; // S盒
    int i, j;             // 状态索引
} RC4_CTX;
void rc4_init(RC4_CTX* ctx, const unsigned char* key, size_t key_len);
void rc4_crypt(RC4_CTX* ctx, unsigned char* data, size_t data_len);
#endif
