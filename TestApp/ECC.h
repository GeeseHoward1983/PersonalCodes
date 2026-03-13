#ifndef _ECC_H_
#define _ECC_H_
#include <stdint.h>

// 定义256位大整数结构
typedef struct {
    uint32_t d[8]; // 小端序存储: d[0]是最低32位
} uint256_t;

// 椭圆曲线点结构
typedef struct {
    uint256_t x;
    uint256_t y;
    int infinity; // 是否为无穷远点
} Point;

// 密钥生成
void ecc_keygen(uint256_t* private_key, Point* public_key);

// ECDSA签名
void ecdsa_sign(const uint256_t* private_key, const uint256_t* hash, uint256_t* r, uint256_t* s);

// ECDSA验签
int ecdsa_verify(const Point* public_key, const uint256_t* hash, const uint256_t* r, const uint256_t* s);

// ECC加密
void ecc_encrypt(const Point* public_key, const uint8_t* plain, size_t len, Point* c1, uint8_t* c2);

// ECC解密
void ecc_decrypt(const uint256_t* private_key, const Point* c1, const uint8_t* c2, size_t len, uint8_t* plain);
#endif
