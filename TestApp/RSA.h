#ifndef _RSA_H_
#define _RSA_H_ 
#include <stdlib.h>

#define RSA_BITS 2048
#define RSA_BYTES (RSA_BITS/8)
#define RSA_WORDS (RSA_BYTES/sizeof(unsigned))

// 大数结构（小端序）
typedef struct {
    unsigned words[RSA_WORDS];
} BigNum;

// RSA公钥结构
typedef struct {
    BigNum n; // 模数
    BigNum e; // 公钥指数
} RSAPublicKey;

// RSA私钥结构
typedef struct {
    BigNum n; // 模数
    BigNum d; // 私钥指数
} RSAPrivateKey;

// RSA加密
int rsa_encrypt(RSAPublicKey* key, const unsigned char* input, size_t len,
    unsigned char* output);

// RSA解密
int rsa_decrypt(RSAPrivateKey* key, const unsigned char* input,
    unsigned char* output, size_t* out_len);
// RSA签名
int rsa_sign(RSAPrivateKey* key, const unsigned char* msg, size_t len,
    unsigned char* signature);
// RSA验签
int rsa_verify(RSAPublicKey* key, const unsigned char* msg, size_t len,
    const unsigned char* signature);
#endif
