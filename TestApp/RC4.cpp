#include "stdio.h"
#include "string.h"
#include "RC4.h"

// 初始化RC4上下文
void rc4_init(RC4_CTX *ctx, const unsigned char *key, size_t key_len) {
    // 初始化S盒
    for (int k = 0; k < 256; k++) {
        ctx->S[k] = (unsigned char)k;
    }
    
    // 密钥调度算法（KSA）
    ctx->i = 0;
    ctx->j = 0;
    for (int k = 0, j = 0; k < 256; k++) {
        j = (j + ctx->S[k] + key[k % key_len]) % 256;
        // 交换S[k]和S[j]
        unsigned char temp = ctx->S[k];
        ctx->S[k] = ctx->S[j];
        ctx->S[j] = temp;
    }
}

// RC4加密/解密（原地操作）
void rc4_crypt(RC4_CTX *ctx, unsigned char *data, size_t data_len) {
    for (size_t k = 0; k < data_len; k++) {
        ctx->i = (ctx->i + 1) % 256;
        ctx->j = (ctx->j + ctx->S[ctx->i]) % 256;
        
        // 交换S[i]和S[j]
        unsigned char temp = ctx->S[ctx->i];
        ctx->S[ctx->i] = ctx->S[ctx->j];
        ctx->S[ctx->j] = temp;
        
        // 生成密钥流字节并异或
        unsigned char keystream = ctx->S[(ctx->S[ctx->i] + ctx->S[ctx->j]) % 256];
        data[k] ^= keystream;
    }
}
