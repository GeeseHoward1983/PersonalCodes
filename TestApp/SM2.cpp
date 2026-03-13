#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "SM2.h"

// 定义椭圆曲线参数 (SM2标准曲线)
static const char *P_hex = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF";
static const char *A_hex = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC";
static const char *B_hex = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93";
static const char *N_hex = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123";
static const char *Gx_hex = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
static const char *Gy_hex = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";

// 初始化大整数
void bignum_init(bignum256 *a, const char *hex) {
    memset(a->d, 0, sizeof(a->d));
    size_t len = strlen(hex);
    for (size_t i = 0; i < len; i++) {
        char c = hex[i];
        uint32_t val = (c >= 'A') ? (c - 'A' + 10) : (c - '0');
        size_t pos = (len - 1 - i) / 8;
        int shift = 4 * ((len - 1 - i) % 8);
        a->d[pos] |= val << shift;
    }
}

// 大整数比较
int bignum_cmp(const bignum256 *a, const bignum256 *b) {
    for (int i = 7; i >= 0; i--) {
        if (a->d[i] > b->d[i]) return 1;
        if (a->d[i] < b->d[i]) return -1;
    }
    return 0;
}

// 大整数加法 (模P)
void bignum_add_mod(bignum256 *res, const bignum256 *a, const bignum256 *b, const bignum256 *mod) {
    uint64_t carry = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t sum = (uint64_t)a->d[i] + b->d[i] + carry;
        res->d[i] = (uint32_t)(sum & 0xFFFFFFFF);
        carry = sum >> 32;
    }
    
    // 如果结果大于等于模数，则减去模数
    if (carry || bignum_cmp(res, mod) >= 0) {
        carry = 0;
        for (int i = 0; i < 8; i++) {
            uint64_t diff = (uint64_t)res->d[i] - mod->d[i] - carry;
            if (diff >> 32) {
                carry = 1;
                res->d[i] = (uint32_t)(diff + (1ULL << 32));
            } else {
                carry = 0;
                res->d[i] = (uint32_t)diff;
            }
        }
    }
}

// 大整数减法 (模P)
void bignum_sub_mod(bignum256 *res, const bignum256 *a, const bignum256 *b, const bignum256 *mod) {
    int borrow = 0;
    for (int i = 0; i < 8; i++) {
        int64_t diff = (int64_t)a->d[i] - b->d[i] - borrow;
        if (diff < 0) {
            borrow = 1;
            res->d[i] = (uint32_t)(diff + (1LL << 32));
        } else {
            borrow = 0;
            res->d[i] = (uint32_t)diff;
        }
    }
    
    // 处理结果为负数的情况
    if (borrow) {
        bignum_add_mod(res, res, mod, mod);
    }
}

// 大整数乘法 (模P)
void bignum_mul_mod(bignum256 *res, const bignum256 *a, const bignum256 *b, const bignum256 *mod) {
    uint64_t temp[16] = {0};
    
    // 计算标准乘法
    for (int i = 0; i < 8; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 8; j++) {
            int idx = i + j;
            if (idx >= 16) break;
            
            uint64_t product = (uint64_t)a->d[i] * b->d[j] + temp[idx] + carry;
            temp[idx] = product & 0xFFFFFFFF;
            carry = product >> 32;
        }
        if (i + 8 < 16) temp[i+8] = carry;
    }
    
    // 模约减 (Barrett约减简化版)
    bignum256 temp_bn;
    for (int i = 0; i < 8; i++) {
        temp_bn.d[i] = (uint32_t)temp[i];
    }
    
    while (bignum_cmp(&temp_bn, mod) >= 0) {
        bignum_sub_mod(&temp_bn, &temp_bn, mod, mod);
    }
    
    memcpy(res, &temp_bn, sizeof(bignum256));
}

// 扩展欧几里得求模逆
void bignum_mod_inv(bignum256 *res, const bignum256 *a, const bignum256 *mod) {
    bignum256 u = *mod, v = *a;
    bignum256 x1, x2;
    memset(&x1, 0, sizeof(bignum256));
    x1.d[0] = 1;
    memset(&x2, 0, sizeof(bignum256));
    
    while (bignum_cmp(&v, &x1) != 0) { // v != 1
        while ((v.d[0] & 1) == 0) { // v为偶数
            // v = v / 2
            for (int i = 7; i >= 0; i--) {
                if (i > 0 && (v.d[i] & 1)) {
                    v.d[i-1] |= 0x80000000;
                }
                v.d[i] >>= 1;
            }
            
            // x1 = x1 / 2 (模mod)
            if (x1.d[0] & 1) {
                bignum_add_mod(&x1, &x1, mod, mod);
            }
            for (int i = 7; i >= 0; i--) {
                if (i > 0 && (x1.d[i] & 1)) {
                    x1.d[i-1] |= 0x80000000;
                }
                x1.d[i] >>= 1;
            }
        }
        
        while ((u.d[0] & 1) == 0) { // u为偶数
            // u = u / 2
            for (int i = 7; i >= 0; i--) {
                if (i > 0 && (u.d[i] & 1)) {
                    u.d[i-1] |= 0x80000000;
                }
                u.d[i] >>= 1;
            }
            
            // x2 = x2 / 2 (模mod)
            if (x2.d[0] & 1) {
                bignum_add_mod(&x2, &x2, mod, mod);
            }
            for (int i = 7; i >= 0; i--) {
                if (i > 0 && (x2.d[i] & 1)) {
                    x2.d[i-1] |= 0x80000000;
                }
                x2.d[i] >>= 1;
            }
        }
        
        if (bignum_cmp(&u, &v) >= 0) {
            bignum_sub_mod(&u, &u, &v, mod);
            bignum_sub_mod(&x1, &x1, &x2, mod);
        } else {
            bignum_sub_mod(&v, &v, &u, mod);
            bignum_sub_mod(&x2, &x2, &x1, mod);
        }
    }
    
    memcpy(res, &x1, sizeof(bignum256));
}

// 椭圆曲线点加法
void ec_add(ec_point *res, const ec_point *p, const ec_point *q) {
    if (p->is_infinity) {
        *res = *q;
        return;
    }
    if (q->is_infinity) {
        *res = *p;
        return;
    }
    
    bignum256 lambda, temp1, temp2, temp3;
    
    if (bignum_cmp(&p->x, &q->x) == 0) {
        if (bignum_cmp(&p->y, &q->y) != 0) {
            res->is_infinity = 1;
            return;
        }
        
        // 点加倍 (P == Q)
        // lambda = (3*x^2 + a) / (2*y) mod P
        bignum_mul_mod(&temp1, &p->x, &p->x, &P); // x^2
        bignum_mul_mod(&temp1, &temp1, &p->x, &P); // x^3 (实际应为3*x^2)
        bignum_add_mod(&temp1, &temp1, &temp1, &P); // 2*x^2
        bignum_add_mod(&temp1, &temp1, &temp1, &P); // 3*x^2
        bignum_add_mod(&temp1, &temp1, &A, &P);     // 3*x^2 + a
        
        bignum_add_mod(&temp2, &p->y, &p->y, &P);  // 2*y
        bignum_mod_inv(&temp3, &temp2, &P);        // (2*y)^-1
        bignum_mul_mod(&lambda, &temp1, &temp3, &P);
    } else {
        // lambda = (yq - yp) / (xq - xp) mod P
        bignum_sub_mod(&temp1, &q->y, &p->y, &P); // yq - yp
        bignum_sub_mod(&temp2, &q->x, &p->x, &P); // xq - xp
        bignum_mod_inv(&temp3, &temp2, &P);       // (xq - xp)^-1
        bignum_mul_mod(&lambda, &temp1, &temp3, &P);
    }
    
    // xr = lambda^2 - xp - xq mod P
    bignum_mul_mod(&temp1, &lambda, &lambda, &P); // lambda^2
    bignum_sub_mod(&temp1, &temp1, &p->x, &P);    // -xp
    bignum_sub_mod(&res->x, &temp1, &q->x, &P);   // -xq
    
    // yr = lambda*(xp - xr) - yp mod P
    bignum_sub_mod(&temp1, &p->x, &res->x, &P);   // xp - xr
    bignum_mul_mod(&temp2, &lambda, &temp1, &P);  // lambda*(xp - xr)
    bignum_sub_mod(&res->y, &temp2, &p->y, &P);   // - yp
    
    res->is_infinity = 0;
}

// 椭圆曲线点倍乘 (double-and-add算法)
void ec_mult(ec_point *res, const ec_point *p, const bignum256 *k) {
    ec_point R;
    R.is_infinity = 1;
    
    ec_point Q = *p;
    
    for (int i = 0; i < 256; i++) {
        int word_idx = i / 32;
        int bit_idx = i % 32;
        if ((k->d[word_idx] >> bit_idx) & 1) {
            ec_add(&R, &R, &Q);
        }
        ec_add(&Q, &Q, &Q); // Q = 2*Q
    }
    
    *res = R;
}

// SM3哈希函数简化版 (实际应使用完整SM3)
static void sm3_hash(uint8_t *hash, const uint8_t *data, size_t len) {
    // 简化实现，实际应使用完整SM3算法
    memset(hash, 0, 32);
    for (size_t i = 0; i < len; i++) {
        hash[i % 32] ^= data[i];
    }
}

// KDF密钥派生函数
void kdf(uint8_t *out, size_t out_len, const uint8_t *z, size_t z_len) {
    uint32_t ctr = 1;
    size_t generated = 0;
    uint8_t counter[4];
    
    while (generated < out_len) {
        // 计算 Ha = H(Z || ctr)
        uint8_t ha[32];
        uint8_t *input = (uint8_t *) malloc(z_len + 4);
        if (input == NULL) {
            return;
        }
        memcpy(input, z, z_len);
        counter[0] = (ctr >> 24) & 0xFF;
        counter[1] = (ctr >> 16) & 0xFF;
        counter[2] = (ctr >> 8) & 0xFF;
        counter[3] = ctr & 0xFF;
        memcpy(input + z_len, counter, 4);
        
        sm3_hash(ha, input, z_len + 4);
        free(input);
        // 复制到输出
        size_t to_copy = (out_len - generated) > 32 ? 32 : (out_len - generated);
        memcpy(out + generated, ha, to_copy);
        generated += to_copy;
        ctr++;
    }
}

// 初始化SM2系统
void sm2_init() {
    bignum_init(&P, P_hex);
    bignum_init(&A, A_hex);
    bignum_init(&B, B_hex);
    bignum_init(&N, N_hex);
    bignum_init(&G.x, Gx_hex);
    bignum_init(&G.y, Gy_hex);
    G.is_infinity = 0;
}

// 生成随机大整数
void rand_bignum(bignum256 *r) {
    srand((unsigned int)time(NULL));
    for (int i = 0; i < 8; i++) {
        r->d[i] = rand();
        r->d[i] = (r->d[i] << 16) | rand();
    }
    // 确保小于N
    while (bignum_cmp(r, &N) >= 0) {
        r->d[0] = rand();
    }
}

// SM2密钥生成
void sm2_keygen(ec_point *pub_key, bignum256 *priv_key) {
    rand_bignum(priv_key); // 生成随机私钥
    ec_mult(pub_key, &G, priv_key); // 公钥 = 私钥 * G
}

// SM2加密
int sm2_encrypt(uint8_t *cipher, const uint8_t *plain, size_t len, const ec_point *pub_key) {
    bignum256 k;
    ec_point C1, point;
    uint8_t x2y2[64];
    uint8_t *t = (uint8_t*)malloc(len);
    if (t) {
        uint8_t hash[32];

        // 1. 生成随机数k
        do {
            rand_bignum(&k);
        } while (bignum_cmp(&k, &N) >= 0);

        // 2. 计算C1 = k * G
        ec_mult(&C1, &G, &k);

        // 3. 计算S = h * Pb (h=1，可忽略)

        // 4. 计算k * Pb = (x2, y2)
        ec_mult(&point, pub_key, &k);

        // 5. 计算t = KDF(x2||y2, len)
        memcpy(x2y2, &point.x.d, 32);
        memcpy(x2y2 + 32, &point.y.d, 32);
        kdf(t, len, x2y2, 64);
        // 6. 计算C2 = plain XOR t
        for (size_t i = 0; i < len; i++) {
            cipher[64 + i] = plain[i] ^ t[i]; // C2位置从64开始
        }
        free(t);

        // 7. 计算C3 = Hash(x2 || plain || y2)
        uint8_t* c3_input = (uint8_t*)malloc(32 + len + 32);
        if (c3_input)
        {
            memcpy(c3_input, &point.x.d, 32);
            memcpy(c3_input + 32, plain, len);
            memcpy(c3_input + 32 + len, &point.y.d, 32);
            sm3_hash(hash, c3_input, 32 + len + 32);
            free(c3_input);
            // 8. 输出C = C1 || C3 || C2
            memcpy(cipher, &C1.x.d, 32);      // C1.x
            memcpy(cipher + 32, &C1.y.d, 32);   // C1.y
            memcpy(cipher + 64, hash, 32);      // C3
            // C2已经在64+32位置

            return 0; // 成功
        }
        else
            return -1;
    }
    else
        return -1;
}

// SM2解密
int sm2_decrypt(uint8_t *plain, const uint8_t *cipher, size_t len, const bignum256 *priv_key) {
    ec_point C1, point;
    uint8_t x2y2[64], hash[32], c3[32];
    uint8_t* t = (uint8_t*)malloc(len);
    if (t) {
        // 1. 从C中提取C1, C3, C2
        memcpy(&C1.x.d, cipher, 32);
        memcpy(&C1.y.d, cipher + 32, 32);
        memcpy(c3, cipher + 64, 32); // C3
        const uint8_t* C2 = cipher + 96; // C2位置

        // 2. 验证C1是否在曲线上 (简化处理)
        C1.is_infinity = 0;

        // 3. 计算S = h * C1 (h=1，可忽略)

        // 4. 计算d * C1 = (x2, y2)
        ec_mult(&point, &C1, priv_key);

        // 5. 计算t = KDF(x2||y2, len)
        memcpy(x2y2, &point.x.d, 32);
        memcpy(x2y2 + 32, &point.y.d, 32);
        kdf(t, len, x2y2, 64);

        // 6. 计算plain = C2 XOR t
        for (size_t i = 0; i < len; i++) {
            plain[i] = C2[i] ^ t[i];
        }
        free(t);

        // 7. 验证C3 == Hash(x2 || plain || y2)
        uint8_t* c3_input = (uint8_t*)malloc(32 + len + 32);
        if (c3_input)
        {
            memcpy(c3_input, &point.x.d, 32);
            memcpy(c3_input + 32, plain, len);
            memcpy(c3_input + 32 + len, &point.y.d, 32);
            sm3_hash(hash, c3_input, 32 + len + 32);
            free(c3_input);

            if (memcmp(c3, hash, 32) != 0) {
                return -1; // 验证失败
            }

            return 0; // 成功
        }
        else
            return -1;
    }
    else
        return -1;
}

// SM2签名
int sm2_sign(bignum256 *r, bignum256 *s, const uint8_t *msg, size_t len, const bignum256 *priv_key) {
    bignum256 e, k, tmp1, tmp2, tmp3;
    ec_point point;
    uint8_t hash[32];
    bignum256 one = { {1} };

    // 1. 计算e = Hash(M)
    sm3_hash(hash, msg, len);
    memcpy(&e.d, hash, 32);
    
    do {
        // 2. 生成随机数k
        do {
            rand_bignum(&k);
        } while (bignum_cmp(&k, &N) >= 0);
        
        // 3. 计算(x1,y1) = k * G
        ec_mult(&point, &G, &k);
        
        // 4. r = (e + x1) mod n
        bignum_add_mod(r, &e, &point.x, &N);
        
        // 5. s = ((1 + d)^-1 * (k - r*d)) mod n
        bignum_add_mod(&tmp1, priv_key, &one, &N); // 1 + d
        bignum_mod_inv(&tmp1, &tmp1, &N);          // (1 + d)^-1
        
        bignum_mul_mod(&tmp2, r, priv_key, &N);    // r*d
        bignum_sub_mod(&tmp3, &k, &tmp2, &N);      // k - r*d
        bignum_mul_mod(s, &tmp1, &tmp3, &N);       // (1+d)^-1 * (k - r*d)
        
    } while (bignum_cmp(r, &one) == 0 || bignum_cmp(s, &one) == 0); // 确保r,s不为0
    
    return 0;
}

// SM2验签
int sm2_verify(const bignum256 *r, const bignum256 *s, const uint8_t *msg, size_t len, const ec_point *pub_key) {
    // 1. 检查r,s范围
    bignum256 zero = {{0}};
    bignum256 one = {{1}};
    if (bignum_cmp(r, &one) < 0 || bignum_cmp(r, &N) >= 0) return 0;
    if (bignum_cmp(s, &one) < 0 || bignum_cmp(s, &N) >= 0) return 0;
    
    // 2. 计算e = Hash(M)
    uint8_t hash[32];
    sm3_hash(hash, msg, len);
    bignum256 e;
    memcpy(&e.d, hash, 32);
    
    // 3. 计算t = (r + s) mod n
    bignum256 t;
    bignum_add_mod(&t, r, s, &N);
    
    // 4. 计算(x1,y1) = s*G + t*Pb
    ec_point sG, tPb, point;
    ec_mult(&sG, &G, s);         // s * G
    ec_mult(&tPb, pub_key, &t);  // t * Pb
    ec_add(&point, &sG, &tPb);   // sG + tPb
    
    if (point.is_infinity) return 0;
    
    // 5. 验证R = (e + x1) mod n
    bignum256 R;
    bignum_add_mod(&R, &e, &point.x, &N);
    
    return bignum_cmp(&R, r) == 0;
}
