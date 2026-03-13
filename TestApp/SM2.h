#ifndef _SM2_H_
#define _SM2_H_
#include <stdint.h>

// 大整数结构 (256位)
typedef struct {
    uint32_t d[8]; // 小端序存储
} bignum256;

// 椭圆曲线点
typedef struct {
    bignum256 x;
    bignum256 y;
    int is_infinity; // 是否为无穷远点
} ec_point;

// 全局曲线参数
static bignum256 P, A, B, N;
static ec_point G;
// SM2密钥生成
void sm2_keygen(ec_point *pub_key, bignum256 *priv_key);

// SM2加密
int sm2_encrypt(uint8_t *cipher, const uint8_t *plain, size_t len, const ec_point *pub_key);

// SM2解密
int sm2_decrypt(uint8_t *plain, const uint8_t *cipher, size_t len, const bignum256 *priv_key);

// SM2签名
int sm2_sign(bignum256 *r, bignum256 *s, const uint8_t *msg, size_t len, const bignum256 *priv_key);

// SM2验签
int sm2_verify(const bignum256 *r, const bignum256 *s, const uint8_t *msg, size_t len, const ec_point *pub_key);
#endif