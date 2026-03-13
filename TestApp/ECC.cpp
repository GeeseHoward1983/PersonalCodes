#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ECC.h"

// secp256k1曲线参数
static const uint256_t P = {{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFC2F}};
static const uint256_t A = {{0}};
static const uint256_t B = {{7, 0, 0, 0, 0, 0, 0, 0}};
static const Point G = {
    {{0x79BE667E, 0xF9DCBBAC, 0x55A06295, 0xCE870B07, 0x029BFCDB, 0x2DCE28D9, 0x59F2815B, 0x16F81798}},
    {{0x483ADA77, 0x26A3C465, 0x5DA4FBFC, 0x0E1108A8, 0xFD17B448, 0xA6855419, 0x9C47D08F, 0xFB10D4B8}},
    0
};
static const uint256_t N = {{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xBAAEDCE6, 0xAF48A03B, 0xBFD25E8C, 0xD0364141}};

// 比较两个大整数是否相等
static int uint256_equal(const uint256_t* a, const uint256_t* b) {
    for (int i = 0; i < 8; i++) {
        if (a->d[i] != b->d[i]) return 0;
    }
    return 1;
}

// 判断大整数是否为0
static int uint256_is_zero(const uint256_t* a) {
    for (int i = 0; i < 8; i++) {
        if (a->d[i] != 0) return 0;
    }
    return 1;
}

// 大整数复制
static void uint256_copy(uint256_t* dest, const uint256_t* src) {
    memcpy(dest, src, sizeof(uint256_t));
}

// 模加: result = (a + b) mod P
static void uint256_add(const uint256_t* a, const uint256_t* b, uint256_t* result) {
    uint64_t carry = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t sum = (uint64_t)a->d[i] + b->d[i] + carry;
        result->d[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    
    // 如果结果大于P，则减去P
    if (carry || !uint256_equal(result, &P) && (result->d[7] > P.d[7] || 
        (result->d[7] == P.d[7] && result->d[6] > P.d[6]) || 
        (result->d[7] == P.d[7] && result->d[6] == P.d[6] && result->d[5] > P.d[5]) ||
        (result->d[7] == P.d[7] && result->d[6] == P.d[6] && result->d[5] == P.d[5] && result->d[4] > P.d[4]) ||
        (result->d[7] == P.d[7] && result->d[6] == P.d[6] && result->d[5] == P.d[5] && result->d[4] == P.d[4] && result->d[3] > P.d[3]) ||
        (result->d[7] == P.d[7] && result->d[6] == P.d[6] && result->d[5] == P.d[5] && result->d[4] == P.d[4] && result->d[3] == P.d[3] && result->d[2] > P.d[2]) ||
        (result->d[7] == P.d[7] && result->d[6] == P.d[6] && result->d[5] == P.d[5] && result->d[4] == P.d[4] && result->d[3] == P.d[3] && result->d[2] == P.d[2] && result->d[1] > P.d[1]) ||
        (result->d[7] == P.d[7] && result->d[6] == P.d[6] && result->d[5] == P.d[5] && result->d[4] == P.d[4] && result->d[3] == P.d[3] && result->d[2] == P.d[2] && result->d[1] == P.d[1] && result->d[0] >= P.d[0]))) {
        uint256_t temp = *result;
        uint64_t borrow = 0;
        for (int i = 0; i < 8; i++) {
            uint64_t diff = (uint64_t)temp.d[i] - P.d[i] - borrow;
            result->d[i] = (uint32_t)diff;
            borrow = (diff >> 32) ? 1 : 0;
        }
    }
}

// 模减: result = (a - b) mod P
static void uint256_sub(const uint256_t* a, const uint256_t* b, uint256_t* result) {
    uint64_t borrow = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t diff = (uint64_t)a->d[i] - b->d[i] - borrow;
        result->d[i] = (uint32_t)diff;
        borrow = (diff >> 63) ? 1 : 0;
    }
    
    // 如果结果为负，则加上P
    if (borrow) {
        uint256_t temp = *result;
        uint64_t carry = 0;
        for (int i = 0; i < 8; i++) {
            uint64_t sum = (uint64_t)temp.d[i] + P.d[i] + carry;
            result->d[i] = (uint32_t)sum;
            carry = sum >> 32;
        }
    }
}

// 模乘: result = (a * b) mod P
static void uint256_mul(const uint256_t* a, const uint256_t* b, uint256_t* result) {
    uint64_t product[16] = {0};
    
    // 计算乘积
    for (int i = 0; i < 8; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 8; j++) {
            uint64_t temp = product[i+j] + (uint64_t)a->d[i] * b->d[j] + carry;
            product[i+j] = temp & 0xFFFFFFFF;
            carry = temp >> 32;
        }
        product[i+8] = carry;
    }
    
    // 模P约简 (使用secp256k1的特殊形式)
    for (int i = 15; i >= 8; i--) {
        uint64_t carry = 0;
        for (int j = 0; j < 8; j++) {
            uint64_t temp = (uint64_t)product[i-8+j] + (product[i] * P.d[j]) + carry;
            product[i-8+j] = temp & 0xFFFFFFFF;
            carry = temp >> 32;
        }
        if (i < 15) {
            product[i] = carry;
        }
    }
    
    // 复制结果
    for (int i = 0; i < 8; i++) {
        result->d[i] = (uint32_t)product[i];
    }
    
    // 最终模约简
    if (uint256_equal(result, &P) || !uint256_equal(result, &P) && (result->d[7] > P.d[7] || 
        (result->d[7] == P.d[7] && result->d[6] > P.d[6]) || 
        (result->d[7] == P.d[7] && result->d[6] == P.d[6] && result->d[5] > P.d[5]) ||
        (result->d[7] == P.d[7] && result->d[6] == P.d[6] && result->d[5] == P.d[5] && result->d[4] > P.d[4]) ||
        (result->d[7] == P.d[7] && result->d[6] == P.d[6] && result->d[5] == P.d[5] && result->d[4] == P.d[4] && result->d[3] > P.d[3]) ||
        (result->d[7] == P.d[7] && result->d[6] == P.d[6] && result->d[5] == P.d[5] && result->d[4] == P.d[4] && result->d[3] == P.d[3] && result->d[2] > P.d[2]) ||
        (result->d[7] == P.d[7] && result->d[6] == P.d[6] && result->d[5] == P.d[5] && result->d[4] == P.d[4] && result->d[3] == P.d[3] && result->d[2] == P.d[2] && result->d[1] > P.d[1]) ||
        (result->d[7] == P.d[7] && result->d[6] == P.d[6] && result->d[5] == P.d[5] && result->d[4] == P.d[4] && result->d[3] == P.d[3] && result->d[2] == P.d[2] && result->d[1] == P.d[1] && result->d[0] >= P.d[0]))) {
        uint256_t temp = *result;
        uint64_t borrow = 0;
        for (int i = 0; i < 8; i++) {
            uint64_t diff = (uint64_t)temp.d[i] - P.d[i] - borrow;
            result->d[i] = (uint32_t)diff;
            borrow = (diff >> 63) ? 1 : 0;
        }
    }
}

// 模逆元: result = a^{-1} mod P (使用扩展欧几里得算法)
static void uint256_inv(const uint256_t* a, uint256_t* result) {
    uint256_t u = *a;
    uint256_t v = P;
    uint256_t x1 = {{1,0,0,0,0,0,0,0}};
    uint256_t x2 = {{0,0,0,0,0,0,0,0}};
    uint256_t one = { {1,0,0,0,0,0,0,0} };
    while (!uint256_equal(&u, &one) && !uint256_equal(&v, &one)) {
        while ((u.d[0] & 1) == 0) { // u为偶数
            // u = u / 2
            for (int i = 7; i >= 0; i--) {
                if (i > 0 && (u.d[i] & 1)) {
                    u.d[i-1] |= 0x80000000;
                }
                u.d[i] >>= 1;
            }
            
            // x1 = x1 / 2
            if (x1.d[0] & 1) {
                uint256_add(&x1, &P, &x1);
            }
            for (int i = 7; i >= 0; i--) {
                if (i > 0 && (x1.d[i] & 1)) {
                    x1.d[i-1] |= 0x80000000;
                }
                x1.d[i] >>= 1;
            }
        }
        
        while ((v.d[0] & 1) == 0) { // v为偶数
            // v = v / 2
            for (int i = 7; i >= 0; i--) {
                if (i > 0 && (v.d[i] & 1)) {
                    v.d[i-1] |= 0x80000000;
                }
                v.d[i] >>= 1;
            }
            
            // x2 = x2 / 2
            if (x2.d[0] & 1) {
                uint256_add(&x2, &P, &x2);
            }
            for (int i = 7; i >= 0; i--) {
                if (i > 0 && (x2.d[i] & 1)) {
                    x2.d[i-1] |= 0x80000000;
                }
                x2.d[i] >>= 1;
            }
        }
        
        if (u.d[7] < v.d[7] || (u.d[7] == v.d[7] && u.d[6] < v.d[6]) || 
            (u.d[7] == v.d[7] && u.d[6] == v.d[6] && u.d[5] < v.d[5]) ||
            (u.d[7] == v.d[7] && u.d[6] == v.d[6] && u.d[5] == v.d[5] && u.d[4] < v.d[4]) ||
            (u.d[7] == v.d[7] && u.d[6] == v.d[6] && u.d[5] == v.d[5] && u.d[4] == v.d[4] && u.d[3] < v.d[3]) ||
            (u.d[7] == v.d[7] && u.d[6] == v.d[6] && u.d[5] == v.d[5] && u.d[4] == v.d[4] && u.d[3] == v.d[3] && u.d[2] < v.d[2]) ||
            (u.d[7] == v.d[7] && u.d[6] == v.d[6] && u.d[5] == v.d[5] && u.d[4] == v.d[4] && u.d[3] == v.d[3] && u.d[2] == v.d[2] && u.d[1] < v.d[1]) ||
            (u.d[7] == v.d[7] && u.d[6] == v.d[6] && u.d[5] == v.d[5] && u.d[4] == v.d[4] && u.d[3] == v.d[3] && u.d[2] == v.d[2] && u.d[1] == v.d[1] && u.d[0] < v.d[0])) {
            uint256_sub(&v, &u, &v);
            uint256_sub(&x2, &x1, &x2);
        } else {
            uint256_sub(&u, &v, &u);
            uint256_sub(&x1, &x2, &x1);
        }
    }
    if (uint256_equal(&u, &one)) {
        uint256_copy(result, &x1);
    } else {
        uint256_copy(result, &x2);
    }
    
    if (result->d[7] & 0x80000000) {
        uint256_add(result, &P, result);
    }
}

// 椭圆曲线点运算
static int point_is_zero(const Point* p) {
    return p->infinity;
}

static void point_set_zero(Point* p) {
    p->infinity = 1;
}

// 点加倍: result = 2 * P
static void point_double(const Point* p, Point* result) {
    if (point_is_zero(p)) {
        point_set_zero(result);
        return;
    }
    
    // λ = (3x² + a) / (2y)
    uint256_t lambda, numerator, denominator, temp;
    
    // 计算分子: 3x² + a
    uint256_mul(&p->x, &p->x, &temp);
    uint256_t three = {{3,0,0,0,0,0,0,0}};
    uint256_mul(&temp, &three, &numerator);
    uint256_add(&numerator, &A, &numerator);
    
    // 计算分母: 2y
    uint256_t two = {{2,0,0,0,0,0,0,0}};
    uint256_mul(&p->y, &two, &denominator);
    
    // 计算λ = 分子 / 分母
    uint256_inv(&denominator, &temp);
    uint256_mul(&numerator, &temp, &lambda);
    
    // 计算新点坐标
    // xr = λ² - 2x
    uint256_mul(&lambda, &lambda, &temp);
    uint256_mul(&p->x, &two, &denominator);
    uint256_sub(&temp, &denominator, &result->x);
    
    // yr = λ(x - xr) - y
    uint256_sub(&p->x, &result->x, &temp);
    uint256_mul(&lambda, &temp, &temp);
    uint256_sub(&temp, &p->y, &result->y);
    
    result->infinity = 0;
}

// 点加法: result = P + Q
static void point_add(const Point* p, const Point* q, Point* result) {
    if (point_is_zero(p)) {
        *result = *q;
        return;
    }
    if (point_is_zero(q)) {
        *result = *p;
        return;
    }
    
    // 处理相同点的情况
    if (uint256_equal(&p->x, &q->x)) {
        if (uint256_equal(&p->y, &q->y)) {
            point_double(p, result);
            return;
        } else {
            point_set_zero(result);
            return;
        }
    }
    
    // λ = (yq - yp) / (xq - xp)
    uint256_t lambda, numerator, denominator, temp;
    
    uint256_sub(&q->y, &p->y, &numerator);
    uint256_sub(&q->x, &p->x, &denominator);
    
    uint256_inv(&denominator, &temp);
    uint256_mul(&numerator, &temp, &lambda);
    
    // xr = λ² - xp - xq
    uint256_mul(&lambda, &lambda, &temp);
    uint256_sub(&temp, &p->x, &temp);
    uint256_sub(&temp, &q->x, &result->x);
    
    // yr = λ(xp - xr) - yp
    uint256_sub(&p->x, &result->x, &temp);
    uint256_mul(&lambda, &temp, &temp);
    uint256_sub(&temp, &p->y, &result->y);
    
    result->infinity = 0;
}

// 标量乘法: result = k * P
static void point_mul(const uint256_t* k, const Point* p, Point* result) {
    Point r;
    point_set_zero(&r);
    
    Point temp_point = *p;
    
    for (int i = 0; i < 256; i++) {
        int word_index = i / 32;
        int bit_index = i % 32;
        
        if ((k->d[word_index] >> bit_index) & 1) {
            if (point_is_zero(&r)) {
                r = temp_point;
            } else {
                point_add(&r, &temp_point, &r);
            }
        }
        
        Point new_point;
        point_double(&temp_point, &new_point);
        temp_point = new_point;
    }
    
    *result = r;
}

// 密钥生成
void ecc_keygen(uint256_t* private_key, Point* public_key) {
    // 生成随机私钥 (1 < d < N-1)
    do {
        for (int i = 0; i < 8; i++) {
            private_key->d[i] = rand() ^ (rand() << 16);
        }
    } while (uint256_equal(private_key, &N) || uint256_is_zero(private_key) || 
            private_key->d[7] >= N.d[7] || 
            (private_key->d[7] == N.d[7] && private_key->d[6] >= N.d[6]) ||
            (private_key->d[7] == N.d[7] && private_key->d[6] == N.d[6] && private_key->d[5] >= N.d[5]) ||
            (private_key->d[7] == N.d[7] && private_key->d[6] == N.d[6] && private_key->d[5] == N.d[5] && private_key->d[4] >= N.d[4]) ||
            (private_key->d[7] == N.d[7] && private_key->d[6] == N.d[6] && private_key->d[5] == N.d[5] && private_key->d[4] == N.d[4] && private_key->d[3] >= N.d[3]) ||
            (private_key->d[7] == N.d[7] && private_key->d[6] == N.d[6] && private_key->d[5] == N.d[5] && private_key->d[4] == N.d[4] && private_key->d[3] == N.d[3] && private_key->d[2] >= N.d[2]) ||
            (private_key->d[7] == N.d[7] && private_key->d[6] == N.d[6] && private_key->d[5] == N.d[5] && private_key->d[4] == N.d[4] && private_key->d[3] == N.d[3] && private_key->d[2] == N.d[2] && private_key->d[1] >= N.d[1]) ||
            (private_key->d[7] == N.d[7] && private_key->d[6] == N.d[6] && private_key->d[5] == N.d[5] && private_key->d[4] == N.d[4] && private_key->d[3] == N.d[3] && private_key->d[2] == N.d[2] && private_key->d[1] == N.d[1] && private_key->d[0] >= N.d[0]));
    
    // 公钥 = 私钥 * G
    point_mul(private_key, &G, public_key);
}

// ECDSA签名
void ecdsa_sign(const uint256_t* private_key, const uint256_t* hash, uint256_t* r, uint256_t* s) {
    uint256_t k = { 0 };
    Point kG;
    
    do {
        // 生成随机k
        for (int i = 0; i < 8; i++) {
            k.d[i] = rand() ^ (rand() << 16);
        }
        
        // 计算 r = (kG).x mod N
        point_mul(&k, &G, &kG);
        uint256_copy(r, &kG.x);
        while (!uint256_equal(r, &N) && (r->d[7] > N.d[7] || 
            (r->d[7] == N.d[7] && r->d[6] > N.d[6]) || 
            (r->d[7] == N.d[7] && r->d[6] == N.d[6] && r->d[5] > N.d[5]) ||
            (r->d[7] == N.d[7] && r->d[6] == N.d[6] && r->d[5] == N.d[5] && r->d[4] > N.d[4]) ||
            (r->d[7] == N.d[7] && r->d[6] == N.d[6] && r->d[5] == N.d[5] && r->d[4] == N.d[4] && r->d[3] > N.d[3]) ||
            (r->d[7] == N.d[7] && r->d[6] == N.d[6] && r->d[5] == N.d[5] && r->d[4] == N.d[4] && r->d[3] == N.d[3] && r->d[2] > N.d[2]) ||
            (r->d[7] == N.d[7] && r->d[6] == N.d[6] && r->d[5] == N.d[5] && r->d[4] == N.d[4] && r->d[3] == N.d[3] && r->d[2] == N.d[2] && r->d[1] > N.d[1]) ||
            (r->d[7] == N.d[7] && r->d[6] == N.d[6] && r->d[5] == N.d[5] && r->d[4] == N.d[4] && r->d[3] == N.d[3] && r->d[2] == N.d[2] && r->d[1] == N.d[1] && r->d[0] >= N.d[0]))) {
            uint256_sub(r, &N, r);
        }
    } while (uint256_is_zero(r));
    
    // 计算 s = (hash + r*d) * k^{-1} mod N
    uint256_t tmp1, kinv;
    uint256_mul(r, private_key, &tmp1);   // r * d
    uint256_add(&tmp1, hash, &tmp1);       // hash + r*d
    uint256_inv(&k, &kinv);               // k^{-1}
    uint256_mul(&tmp1, &kinv, s);          // s = (hash + r*d) * k^{-1}
    
    while (!uint256_equal(s, &N) && (s->d[7] > N.d[7] || 
        (s->d[7] == N.d[7] && s->d[6] > N.d[6]) || 
        (s->d[7] == N.d[7] && s->d[6] == N.d[6] && s->d[5] > N.d[5]) ||
        (s->d[7] == N.d[7] && s->d[6] == N.d[6] && s->d[5] == N.d[5] && s->d[4] > N.d[4]) ||
        (s->d[7] == N.d[7] && s->d[6] == N.d[6] && s->d[5] == N.d[5] && s->d[4] == N.d[4] && s->d[3] > N.d[3]) ||
        (s->d[7] == N.d[7] && s->d[6] == N.d[6] && s->d[5] == N.d[5] && s->d[4] == N.d[4] && s->d[3] == N.d[3] && s->d[2] > N.d[2]) ||
        (s->d[7] == N.d[7] && s->d[6] == N.d[6] && s->d[5] == N.d[5] && s->d[4] == N.d[4] && s->d[3] == N.d[3] && s->d[2] == N.d[2] && s->d[1] > N.d[1]) ||
        (s->d[7] == N.d[7] && s->d[6] == N.d[6] && s->d[5] == N.d[5] && s->d[4] == N.d[4] && s->d[3] == N.d[3] && s->d[2] == N.d[2] && s->d[1] == N.d[1] && s->d[0] >= N.d[0]))) {
        uint256_sub(s, &N, s);
    }
}

// ECDSA验签
int ecdsa_verify(const Point* public_key, const uint256_t* hash, const uint256_t* r, const uint256_t* s) {
    if (uint256_is_zero(r) || uint256_is_zero(s) || 
        !uint256_equal(r, &N) && (r->d[7] > N.d[7] || 
        (r->d[7] == N.d[7] && r->d[6] > N.d[6]) || 
        (r->d[7] == N.d[7] && r->d[6] == N.d[6] && r->d[5] > N.d[5]) ||
        (r->d[7] == N.d[7] && r->d[6] == N.d[6] && r->d[5] == N.d[5] && r->d[4] > N.d[4]) ||
        (r->d[7] == N.d[7] && r->d[6] == N.d[6] && r->d[5] == N.d[5] && r->d[4] == N.d[4] && r->d[3] > N.d[3]) ||
        (r->d[7] == N.d[7] && r->d[6] == N.d[6] && r->d[5] == N.d[5] && r->d[4] == N.d[4] && r->d[3] == N.d[3] && r->d[2] > N.d[2]) ||
        (r->d[7] == N.d[7] && r->d[6] == N.d[6] && r->d[5] == N.d[5] && r->d[4] == N.d[4] && r->d[3] == N.d[3] && r->d[2] == N.d[2] && r->d[1] > N.d[1]) ||
        (r->d[7] == N.d[7] && r->d[6] == N.d[6] && r->d[5] == N.d[5] && r->d[4] == N.d[4] && r->d[3] == N.d[3] && r->d[2] == N.d[2] && r->d[1] == N.d[1] && r->d[0] >= N.d[0])) ||
        !uint256_equal(s, &N) && (s->d[7] > N.d[7] || 
        (s->d[7] == N.d[7] && s->d[6] > N.d[6]) || 
        (s->d[7] == N.d[7] && s->d[6] == N.d[6] && s->d[5] > N.d[5]) ||
        (s->d[7] == N.d[7] && s->d[6] == N.d[6] && s->d[5] == N.d[5] && s->d[4] > N.d[4]) ||
        (s->d[7] == N.d[7] && s->d[6] == N.d[6] && s->d[5] == N.d[5] && s->d[4] == N.d[4] && s->d[3] > N.d[3]) ||
        (s->d[7] == N.d[7] && s->d[6] == N.d[6] && s->d[5] == N.d[5] && s->d[4] == N.d[4] && s->d[3] == N.d[3] && s->d[2] > N.d[2]) ||
        (s->d[7] == N.d[7] && s->d[6] == N.d[6] && s->d[5] == N.d[5] && s->d[4] == N.d[4] && s->d[3] == N.d[3] && s->d[2] == N.d[2] && s->d[1] > N.d[1]) ||
        (s->d[7] == N.d[7] && s->d[6] == N.d[6] && s->d[5] == N.d[5] && s->d[4] == N.d[4] && s->d[3] == N.d[3] && s->d[2] == N.d[2] && s->d[1] == N.d[1] && s->d[0] >= N.d[0]))) {
        return 0;
    }
    
    uint256_t w;
    uint256_inv(s, &w);  // w = s^{-1} mod N
    
    uint256_t u1, u2;
    uint256_mul(hash, &w, &u1);  // u1 = hash * w mod N
    uint256_mul(r, &w, &u2);     // u2 = r * w mod N
    
    Point p1, p2;
    point_mul(&u1, &G, &p1);     // u1 * G
    point_mul(&u2, public_key, &p2); // u2 * Q
    
    Point res;
    point_add(&p1, &p2, &res);   // 计算点 (x, y)
    
    if (point_is_zero(&res)) {
        return 0;
    }
    
    // 验证 r == x mod N
    uint256_t x = res.x;
    while (!uint256_equal(&x, &N) && (x.d[7] > N.d[7] || 
        (x.d[7] == N.d[7] && x.d[6] > N.d[6]) || 
        (x.d[7] == N.d[7] && x.d[6] == N.d[6] && x.d[5] > N.d[5]) ||
        (x.d[7] == N.d[7] && x.d[6] == N.d[6] && x.d[5] == N.d[5] && x.d[4] > N.d[4]) ||
        (x.d[7] == N.d[7] && x.d[6] == N.d[6] && x.d[5] == N.d[5] && x.d[4] == N.d[4] && x.d[3] > N.d[3]) ||
        (x.d[7] == N.d[7] && x.d[6] == N.d[6] && x.d[5] == N.d[5] && x.d[4] == N.d[4] && x.d[3] == N.d[3] && x.d[2] > N.d[2]) ||
        (x.d[7] == N.d[7] && x.d[6] == N.d[6] && x.d[5] == N.d[5] && x.d[4] == N.d[4] && x.d[3] == N.d[3] && x.d[2] == N.d[2] && x.d[1] > N.d[1]) ||
        (x.d[7] == N.d[7] && x.d[6] == N.d[6] && x.d[5] == N.d[5] && x.d[4] == N.d[4] && x.d[3] == N.d[3] && x.d[2] == N.d[2] && x.d[1] == N.d[1] && x.d[0] >= N.d[0]))) {
        uint256_sub(&x, &N, &x);
    }
    
    return uint256_equal(&x, r);
}

// ECC加密
void ecc_encrypt(const Point* public_key, const uint8_t* plain, size_t len, Point* c1, uint8_t* c2) {
    uint256_t k = { 0 };
    Point kQ;
    
    // 生成临时密钥k
    do {
        for (int i = 0; i < 8; i++) {
            k.d[i] = rand() ^ (rand() << 16);
        }
    } while (uint256_is_zero(&k));
    
    // c1 = k * G
    point_mul(&k, &G, c1);
    
    // 共享密钥 S = k * Q
    point_mul(&k, public_key, &kQ);
    
    // 使用S.x的低32位作为XOR密钥
    uint32_t key = kQ.x.d[0];
    for (size_t i = 0; i < len; i++) {
        c2[i] = plain[i] ^ (key & 0xFF);
        key = (key >> 8) | (key << 24); // 循环移位
    }
}

// ECC解密
void ecc_decrypt(const uint256_t* private_key, const Point* c1, const uint8_t* c2, size_t len, uint8_t* plain) {
    // 计算共享密钥 S = d * c1
    Point S;
    point_mul(private_key, c1, &S);
    
    // 使用S.x的低32位作为XOR密钥
    uint32_t key = S.x.d[0];
    for (size_t i = 0; i < len; i++) {
        plain[i] = c2[i] ^ (key & 0xFF);
        key = (key >> 8) | (key << 24); // 循环移位
    }
}
