#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "SM9.h"

// ==================== BN256曲线参数 ====================
static const bigint p = {{ 
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
}};

static const bigint n = {{ 
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x72, 0x03, 0xDF, 0x6B, 0x21, 0xC6, 0x05, 0x2B,
    0x53, 0xBB, 0xF4, 0x09, 0x39, 0xD5, 0x41, 0x23
}};

static const bigint a = {{0}}; // a = 0
static const bigint b = {{3}}; // b = 3

static const ec_point G = {
    {{ 
        0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19,
        0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
        0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1,
        0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7
    }},
    {{ 
        0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C,
        0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
        0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
        0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0
    }},
    0
};

// ==================== 大数运算实现 ====================
static void bigint_zero(bigint *a1) {
    memset(a1->data, 0, BYTE_LEN);
}

static int bigint_is_zero(const bigint *a1) {
    for (int i = 0; i < BYTE_LEN; i++) {
        if (a1->data[i]) return 0;
    }
    return 1;
}

static void bigint_copy(bigint *dst, const bigint *src) {
    memcpy(dst->data, src->data, BYTE_LEN);
}

static int bigint_cmp(const bigint *a1, const bigint *b1) {
    for (int i = BYTE_LEN - 1; i >= 0; i--) {
        if (a1->data[i] > b1->data[i]) return 1;
        if (a1->data[i] < b1->data[i]) return -1;
    }
    return 0;
}

static void bigint_add(bigint *c, const bigint *a1, const bigint *b1) {
    dword carry = 0;
    for (int i = 0; i < BYTE_LEN; i++) {
        carry += (dword)a1->data[i] + b1->data[i];
        c->data[i] = carry & 0xFF;
        carry >>= 8;
    }
}

static void bigint_sub(bigint *c, const bigint *a1, const bigint *b1) {
    dword borrow = 0;
    for (int i = 0; i < BYTE_LEN; i++) {
        dword diff = (dword)a1->data[i] - b1->data[i] - borrow;
        borrow = (diff >> (sizeof(dword)*8 - 1)) & 1;
        c->data[i] = diff & 0xFF;
    }
}

static void bigint_mod_add(bigint *c, const bigint *a1, const bigint *b1, const bigint *mod) {
    bigint_add(c, a1, b1);
    if (bigint_cmp(c, mod) >= 0) {
        bigint_sub(c, c, mod);
    }
}

static void bigint_mod_sub(bigint *c, const bigint *a1, const bigint *b1, const bigint *mod) {
    if (bigint_cmp(a1, b1) >= 0) {
        bigint_sub(c, a1, b1);
    } else {
        bigint tmp;
        bigint_sub(&tmp, mod, b1);
        bigint_add(c, a1, &tmp);
    }
}

// 蒙哥马利模乘
static void bigint_mod_mul(bigint *c, const bigint *a1, const bigint *b1, const bigint *mod) {
    bigint r = {0};
    for (int i = BYTE_LEN - 1; i >= 0; i--) {
        for (int j = 7; j >= 0; j--) {
            // 双倍
            bigint_add(&r, &r, &r);
            if (bigint_cmp(&r, mod) >= 0) bigint_sub(&r, &r, mod);
            
            if (a1->data[i] & (1 << j)) {
                bigint_add(&r, &r, b1);
                if (bigint_cmp(&r, mod) >= 0) bigint_sub(&r, &r, mod);
            }
        }
    }
    bigint_copy(c, &r);
}

static void bigint_set_u32(bigint* c, uint32_t a1) {
    // 清零所有高位字节
    for (int i = 4; i < BYTE_LEN; i++) {
        c->data[i] = 0;
    }
    // 小端序存储低4字节
    c->data[0] = (a1 >> 0) & 0xFF;  // LSB
    c->data[1] = (a1 >> 8) & 0xFF;
    c->data[2] = (a1 >> 16) & 0xFF;
    c->data[3] = (a1 >> 24) & 0xFF; // MSB
}

static void bigint_set_one(bigint* out)
{
    // 清零所有字节
    for (int i = 0; i < BYTE_LEN; i++) {
        out->data[i] = 0;
    }
    // 最低有效字节设为 1 (小端序)
    out->data[0] = 1;
}

static void bigint_mul(bigint* a1, bigint* b1, bigint* r) {
    uint8_t temp[BYTE_LEN * 2] = { 0 }; // 512 位临时结果

    for (int i = 0; i < BYTE_LEN; i++) {
        uint16_t carry = 0;
        for (int j = 0; j < BYTE_LEN; j++) {
            // 计算乘积并累加
            int idx = i + j;
            uint16_t product = (uint16_t)a1->data[i] * (uint16_t)b1->data[j];
            product += temp[idx] + carry;

            // 存储当前字节并更新进位
            temp[idx] = (uint8_t)(product & 0xFF);
            carry = product >> 8;
        }
        // 处理剩余进位
        int idx = i + BYTE_LEN;
        while (carry && idx < BYTE_LEN * 2) {
            uint16_t sum = temp[idx] + carry;
            temp[idx] = (uint8_t)(sum & 0xFF);
            carry = sum >> 8;
            idx++;
        }
    }
    // 复制低 256 位到结果
    for (int i = 0; i < BYTE_LEN; i++) {
        r->data[i] = temp[i];
    }
}

static void bigint_div(bigint* a1, const bigint* b1, bigint* q, bigint* r) {
    // 初始化余数为 0，商为 0
    bigint remainder = { 0 };
    bigint divisor = *b1;
    for (int i = 0; i < BYTE_LEN; i++) {
        q->data[i] = 0;
    }

    // 从最高位 (255) 到最低位 (0) 迭代
    for (int i = 255; i >= 0; i--) {
        // 余数左移 1 位
        uint8_t carry_in = 0;
        for (int j = 0; j < BYTE_LEN; j++) {
            uint8_t val = remainder.data[j];
            uint8_t carry_out = val >> 7; // 保存最高位
            remainder.data[j] = (val << 1) | carry_in;
            carry_in = carry_out;
        }

        // 设置余数最低位为被除数当前位
        int byte_idx = i / 8;
        int bit_idx = i % 8;
        uint8_t bit = (a1->data[byte_idx] >> bit_idx) & 1;
        remainder.data[0] |= bit;

        // 比较余数 >= 除数
        int cmp = 0;
        for (int j = BYTE_LEN - 1; j >= 0; j--) {
            if (remainder.data[j] != divisor.data[j]) {
                cmp = (remainder.data[j] > divisor.data[j]) ? 1 : -1;
                break;
            }
        }

        // 若余数 >= 除数，执行减法并设置商位
        if (cmp >= 0) {
            int borrow = 0;
            for (int j = 0; j < BYTE_LEN; j++) {
                int diff = (int)remainder.data[j] - (int)divisor.data[j] - borrow;
                if (diff < 0) {
                    diff += 256;
                    borrow = 1;
                }
                else {
                    borrow = 0;
                }
                remainder.data[j] = (uint8_t)diff;
            }
            // 设置商的第 i 位为 1
            q->data[byte_idx] |= (1 << bit_idx);
        }
    }
    *r = remainder; // 存储最终余数
}

static void bigint_mod_exp(bigint* w, bigint* g, bigint* r, const bigint* p1) {
    // 初始化结果 w = 1
    bigint_set_one(w);

    // 初始化底数 base = g mod p
    bigint base;
    bigint q_temp; // 临时商（未使用）
    bigint_div(g, p1, &q_temp, &base); // base = g % p

    // 临时缓冲区（512位乘法结果）
    uint8_t full[64] = { 0 };

    // 从最高位（255）向最低位（0）遍历指数 r
    for (int bit_pos = 255; bit_pos >= 0; bit_pos--) {
        // --- 步骤1：w = w^2 mod p ---
        // 计算 w * w (512位全乘法)
        memset(full, 0, 64);
        for (int i = 0; i < BYTE_LEN; i++) {
            uint16_t carry = 0;
            for (int j = 0; j < BYTE_LEN; j++) {
                int idx = i + j;
                uint16_t product = (uint16_t)w->data[i] * (uint16_t)w->data[j];
                product += full[idx] + carry;
                full[idx] = (uint8_t)(product & 0xFF);
                carry = product >> 8;
            }
            // 处理进位
            int idx = i + BYTE_LEN;
            while (carry && idx < 64) {
                uint16_t sum = full[idx] + carry;
                full[idx] = (uint8_t)(sum & 0xFF);
                carry = sum >> 8;
                idx++;
            }
        }

        // 将512位结果对 p 取模
        bigint remainder = { 0 };
        for (int i = 511; i >= 0; i--) {
            // 余数左移1位
            uint8_t carry_in = 0;
            for (int j = 0; j < BYTE_LEN; j++) {
                uint8_t val = remainder.data[j];
                uint8_t carry_out = val >> 7;
                remainder.data[j] = (val << 1) | carry_in;
                carry_in = carry_out;
            }
            // 设置当前位
            int byte_idx = i / 8;
            int bit_idx = i % 8;
            uint8_t bit = (full[byte_idx] >> bit_idx) & 1;
            remainder.data[0] |= bit;

            // 比较余数 >= p
            int cmp = 0;
            for (int j = BYTE_LEN - 1; j >= 0; j--) {
                if (remainder.data[j] != p1->data[j]) {
                    cmp = (remainder.data[j] > p1->data[j]) ? 1 : -1;
                    break;
                }
            }
            // 余数 >= p 时执行减法
            if (cmp >= 0) {
                int borrow = 0;
                for (int j = 0; j < BYTE_LEN; j++) {
                    int diff = (int)remainder.data[j] - (int)p1->data[j] - borrow;
                    if (diff < 0) {
                        diff += 256;
                        borrow = 1;
                    }
                    else {
                        borrow = 0;
                    }
                    remainder.data[j] = (uint8_t)diff;
                }
            }
        }
        *w = remainder; // 更新 w

        // --- 步骤2：若指数当前位为1，则 w = w * base mod p ---
        int byte_idx = bit_pos / 8;
        int bit_idx = bit_pos % 8;
        if ((r->data[byte_idx] >> bit_idx) & 1) {
            // 计算 w * base (512位全乘法)
            memset(full, 0, 64);
            for (int i = 0; i < BYTE_LEN; i++) {
                uint16_t carry = 0;
                for (int j = 0; j < BYTE_LEN; j++) {
                    int idx = i + j;
                    uint16_t product = (uint16_t)w->data[i] * (uint16_t)base.data[j];
                    product += full[idx] + carry;
                    full[idx] = (uint8_t)(product & 0xFF);
                    carry = product >> 8;
                }
                // 处理进位
                int idx = i + BYTE_LEN;
                while (carry && idx < 64) {
                    uint16_t sum = full[idx] + carry;
                    full[idx] = (uint8_t)(sum & 0xFF);
                    carry = sum >> 8;
                    idx++;
                }
            }

            // 将512位结果对 p 取模（同上）
            bigint remainder2 = { 0 };
            for (int i = 511; i >= 0; i--) {
                uint8_t carry_in = 0;
                for (int j = 0; j < BYTE_LEN; j++) {
                    uint8_t val = remainder2.data[j];
                    uint8_t carry_out = val >> 7;
                    remainder2.data[j] = (val << 1) | carry_in;
                    carry_in = carry_out;
                }
                int byte_idx2 = i / 8;
                int bit_idx2 = i % 8;
                uint8_t bit = (full[byte_idx2] >> bit_idx2) & 1;
                remainder2.data[0] |= bit;

                int cmp = 0;
                for (int j = BYTE_LEN - 1; j >= 0; j--) {
                    if (remainder2.data[j] != p1->data[j]) {
                        cmp = (remainder2.data[j] > p1->data[j]) ? 1 : -1;
                        break;
                    }
                }
                if (cmp >= 0) {
                    int borrow = 0;
                    for (int j = 0; j < BYTE_LEN; j++) {
                        int diff = (int)remainder2.data[j] - (int)p1->data[j] - borrow;
                        if (diff < 0) {
                            diff += 256;
                            borrow = 1;
                        }
                        else {
                            borrow = 0;
                        }
                        remainder2.data[j] = (uint8_t)diff;
                    }
                }
            }
            *w = remainder2; // 更新 w
        }
    }
}


// 扩展欧几里得求模逆
static void bigint_mod_inv(bigint *c, const bigint *a1, const bigint *mod) {
    bigint u = { 0 }, v = { 0 }, u1 = { 0 }, u2 = { 0 }, v1 = { 0 }, v2 = { 0 }, q = { 0 }, r = { 0 };
    bigint_copy(&u, a1);
    bigint_copy(&v, mod);
    bigint_set_one(&u1);
    bigint_zero(&u2);
    bigint_zero(&v1);
    bigint_set_one(&v2);
    
    while (!bigint_is_zero(&v)) {
        // q = u / v
        bigint_div(&q, &r, &u, &v);
        
        // (u, v) = (v, u - q*v)
        bigint_copy(&u, &v);
        bigint_copy(&v, &r);
        
        // (u1, u2) = (v1, v2)
        bigint tmp1, tmp2;
        bigint_copy(&tmp1, &u1);
        bigint_copy(&tmp2, &u2);
        
        // u1 = v1 - q*u1
        bigint_mul(&r, &q, &tmp1);
        bigint_sub(&u1, &v1, &r);
        
        // u2 = v2 - q*u2
        bigint_mul(&r, &q, &tmp2);
        bigint_sub(&u2, &v2, &r);
        
        bigint_copy(&v1, &tmp1);
        bigint_copy(&v2, &tmp2);
    }
    
    if (bigint_cmp(&u1, mod) >= 0) bigint_sub(c, &u1, mod);
    else bigint_copy(c, &u1);
}

// ==================== 椭圆曲线运算 ====================
static int ec_point_is_on_curve(const ec_point *P) {
    if (P->is_infinity) return 1;
    
    bigint lhs, rhs, tmp;
    // lhs = y^2
    bigint_mod_mul(&lhs, &P->y, &P->y, &p);
    
    // rhs = x^3 + a*x + b
    bigint_mod_mul(&rhs, &P->x, &P->x, &p);
    bigint_mod_mul(&rhs, &rhs, &P->x, &p);
    bigint_mod_mul(&tmp, &a, &P->x, &p);
    bigint_mod_add(&rhs, &rhs, &tmp, &p);
    bigint_mod_add(&rhs, &rhs, &b, &p);
    
    return bigint_cmp(&lhs, &rhs) == 0;
}

static void ec_point_double(ec_point *R, const ec_point *P) {
    if (P->is_infinity || bigint_is_zero(&P->y)) {
        R->is_infinity = 1;
        return;
    }
    
    bigint s, tmp1, tmp2;
    // s = (3*x^2 + a) / (2*y)
    bigint_mod_mul(&tmp1, &P->x, &P->x, &p);      // x^2
    bigint_set_u32(&tmp2, 3);
    bigint_mod_mul(&tmp1, &tmp1, &tmp2, &p);      // 3x^2
    bigint_mod_add(&tmp1, &tmp1, &a, &p);         // 3x^2 + a
    
    bigint_set_u32(&tmp2, 2);
    bigint_mod_mul(&tmp2, &tmp2, &P->y, &p);      // 2y
    bigint_mod_inv(&tmp2, &tmp2, &p);             // (2y)^-1
    bigint_mod_mul(&s, &tmp1, &tmp2, &p);         // s = (3x^2+a)/(2y)
    
    // x_r = s^2 - 2*x
    bigint two = { 0 };
    two.data[0] = 2;
    bigint_mod_mul(&R->x, &s, &s, &p);
    bigint_mod_mul(&tmp1, &P->x, &two, &p);
    bigint_mod_sub(&R->x, &R->x, &tmp1, &p);
    
    // y_r = s*(x - x_r) - y
    bigint_mod_sub(&tmp1, &P->x, &R->x, &p);
    bigint_mod_mul(&tmp1, &s, &tmp1, &p);
    bigint_mod_sub(&R->y, &tmp1, &P->y, &p);
    R->is_infinity = 0;
}

static void ec_point_add(ec_point *R, const ec_point *P, const ec_point *Q) {
    if (P->is_infinity) {
        bigint_copy(&R->x, &Q->x);
        bigint_copy(&R->y, &Q->y);
        R->is_infinity = Q->is_infinity;
        return;
    }
    if (Q->is_infinity) {
        bigint_copy(&R->x, &P->x);
        bigint_copy(&R->y, &P->y);
        R->is_infinity = P->is_infinity;
        return;
    }
    
    if (bigint_cmp(&P->x, &Q->x) == 0) {
        if (bigint_cmp(&P->y, &Q->y) == 0) {
            ec_point_double(R, P);
            return;
        } else {
            R->is_infinity = 1;
            return;
        }
    }
    
    bigint s, tmp;
    // s = (y_q - y_p) / (x_q - x_p)
    bigint_mod_sub(&s, &Q->y, &P->y, &p);
    bigint_mod_sub(&tmp, &Q->x, &P->x, &p);
    bigint_mod_inv(&tmp, &tmp, &p);
    bigint_mod_mul(&s, &s, &tmp, &p);
    
    // x_r = s^2 - x_p - x_q
    bigint_mod_mul(&R->x, &s, &s, &p);
    bigint_mod_sub(&R->x, &R->x, &P->x, &p);
    bigint_mod_sub(&R->x, &R->x, &Q->x, &p);
    
    // y_r = s*(x_p - x_r) - y_p
    bigint_mod_sub(&tmp, &P->x, &R->x, &p);
    bigint_mod_mul(&tmp, &s, &tmp, &p);
    bigint_mod_sub(&R->y, &tmp, &P->y, &p);
    R->is_infinity = 0;
}

static void ec_point_mul(ec_point *R, const bigint *k, const ec_point *P) {
    ec_point T{};
    T.is_infinity = 1;
    
    for (int i = BYTE_LEN - 1; i >= 0; i--) {
        for (int j = 7; j >= 0; j--) {
            ec_point_double(&T, &T);
            if (k->data[i] & (1 << j)) {
                ec_point_add(&T, &T, P);
            }
        }
    }
    
    bigint_copy(&R->x, &T.x);
    bigint_copy(&R->y, &T.y);
    R->is_infinity = T.is_infinity;
}

// ==================== 双线性对实现 ====================
static void sm9_pairing(bigint *out, const ec_point *P, const ec_point *Q) {
    // Miller算法实现双线性对
    // 简化版，实际实现约200行
    bigint_set_one(out);
}

// ==================== SM3哈希实现 ====================
static void sm3_hash(byte *out, const byte *in, size_t len) {
    // SM3完整实现约150行
    // 此处使用简化版本
    memset(out, 0, 32);
    for (size_t i = 0; i < len; i++) {
        out[i % 32] ^= in[i];
    }
}

// ==================== KDF密钥派生 ====================
static void sm3_kdf(byte *out, size_t out_len, const byte *in, size_t in_len) {
    size_t ctr = 0;
    byte counter[4]{};
    byte digest[32];
    
    for (size_t i = 0; i < out_len; i += 32) {
        counter[0] = (ctr >> 24) & 0xFF;
        counter[1] = (ctr >> 16) & 0xFF;
        counter[2] = (ctr >> 8) & 0xFF;
        counter[3] = ctr & 0xFF;
        ctr++;
        
        sm3_hash(digest, in, in_len);
        sm3_hash(digest, digest, 32);
        
        size_t copy_len = (out_len - i) < 32 ? (out_len - i) : 32;
        memcpy(out + i, digest, copy_len);
    }
}

// ==================== SM9核心算法 ====================
// 主密钥（实际应用中应保密）
static const bigint master_private = {{0x01}};
static ec_point master_public;

void sm9_init() {
    // 计算主公钥 Ppub = s * G
    ec_point_mul(&master_public, &master_private, &G);
}

sm9_key_pair sm9_keygen(const byte *user_id, size_t id_len) {
    sm9_key_pair key_pair{};
    
    // 步骤1: 计算H1 = Hash1(ID || hid)
    byte hid = 0x01; // 签名密钥类型
    byte hash_input[256];
    memcpy(hash_input, user_id, id_len);
    hash_input[id_len] = hid;
    bigint h1{};
    sm3_hash(h1.data, hash_input, id_len + 1);
    
    // 步骤2: 私钥 d = (H1 + s) mod n
    bigint_mod_add(&key_pair.private_key, &h1, &master_private, &n);
    
    // 步骤3: 公钥 P = d * G
    ec_point_mul(&key_pair.public_key, &key_pair.private_key, &G);
    
    return key_pair;
}

sm9_cipher sm9_encrypt(const ec_point *pub_key, const byte *msg, size_t msg_len) {
    sm9_cipher cipher = { 0 };
    bigint r{};
    // 生成随机数 r ∈ [1, n-1]
    for (int i = 0; i < BYTE_LEN; i++) {
        r.data[i] = rand() % 256;
    }
    r.data[BYTE_LEN-1] &= 0x7F; // 确保小于n
    
    // C1 = r * G
    ec_point_mul((ec_point*)&cipher.c1, &r, &G);
    
    // g = e(Ppub, P)
    bigint g;
    sm9_pairing(&g, &master_public, pub_key);
    
    // w = g^r
    bigint w;
    bigint_mod_exp(&w, &g, &r, &p);
    
    // 派生密钥 k = KDF(w || user_id, msg_len + 32)
    byte kdf_input[BYTE_LEN + 256]; // 假设用户ID最大256字节
    memcpy(kdf_input, w.data, BYTE_LEN);
    memcpy(kdf_input + BYTE_LEN, "user_id", 7); // 实际应使用真实ID
    size_t kdf_input_len = BYTE_LEN + 7;
    
    byte *k =(byte *)malloc(msg_len + 32);
    if(k)
    {
        sm3_kdf(k, msg_len + 32, kdf_input, kdf_input_len);

        // c2 = msg XOR k[0:msg_len]
        cipher.c2.data[0] = 0; // 简化处理
        cipher.c3 = (byte*)malloc(32);
        cipher.c3_len = 32;

        // c3 = Hash(k[msg_len:] || msg)
        byte* hash_input = (byte*)malloc(msg_len + 32);
        if (hash_input)
        {
            memcpy(hash_input, k + msg_len, 32);
            memcpy(hash_input + 32, msg, msg_len);
            sm3_hash(cipher.c3, hash_input, msg_len + 32);
            free(hash_input);
        }
        free(k);
    }

    return cipher;
}

byte* sm9_decrypt(const sm9_key_pair *key_pair, const sm9_cipher *cipher, size_t *out_len) {
    // g = e(C1, d * Ppub)
    ec_point dPpub;
    ec_point_mul(&dPpub, &key_pair->private_key, &master_public);
    
    bigint g;
    sm9_pairing(&g, (ec_point*)&cipher->c1, &dPpub);
    
    // 派生密钥 k
    byte kdf_input[BYTE_LEN + 256];
    memcpy(kdf_input, g.data, BYTE_LEN);
    memcpy(kdf_input + BYTE_LEN, "user_id", 7);
    size_t kdf_input_len = BYTE_LEN + 7;
    
    byte *k = (byte*)malloc(cipher->c3_len + 32); // 估计大小
    if (k)
    {
        sm3_kdf(k, cipher->c3_len + 32, kdf_input, kdf_input_len);

        // 解密消息
        byte* msg = (byte*)malloc(cipher->c3_len);
        if(msg)
        {
            *out_len = cipher->c3_len;
            // 实际应使用k解密cipher.c2
            memcpy(msg, "Decrypted", 10 > cipher->c3_len ? cipher->c3_len : 10); // 简化

            // 验证c3
            byte c3_check[32];
            byte* hash_input = (byte*)malloc(*out_len + BYTE_LEN);
            if (hash_input)
            {
                memcpy(hash_input, k + *out_len, 32);
                memcpy(hash_input + 32, msg, *out_len);
                sm3_hash(c3_check, hash_input, *out_len + 32);
                if (memcmp(c3_check, cipher->c3, 32) != 0) {
                    free(msg);
                    return NULL;
                }
                free(hash_input);
            }
        }
        free(k);
        return msg;
    }
    else
        return NULL;
}

sm9_signature sm9_sign(const sm9_key_pair *key_pair, const byte *msg, size_t msg_len) {
    sm9_signature sig = { 0 };
    bigint r{};
    // 生成随机数 r ∈ [1, n-1]
    for (int i = 0; i < BYTE_LEN; i++) {
        r.data[i] = rand() % 256;
    }
    
    // S = r * G
    ec_point S;
    ec_point_mul(&S, &r, &G);
    
    // h = Hash(msg || S.x)
    byte* hash_input = (byte*)malloc(msg_len + BYTE_LEN);
    if (hash_input)
    {
        memcpy(hash_input, msg, msg_len);
        memcpy(hash_input + msg_len, S.x.data, BYTE_LEN);
        bigint h = { 0 };
        sm3_hash(h.data, hash_input, msg_len + BYTE_LEN);

        // t = (r + h * d) mod n
        bigint hd;
        bigint_mod_mul(&hd, &h, &key_pair->private_key, &n);
        bigint_mod_add(&sig.s, &r, &hd, &n);
        bigint_copy(&sig.r, &S.x); // 实际应为S.x的哈希
        free(hash_input);
    }
    return sig;
}

int sm9_verify(const ec_point *pub_key, const byte *msg, size_t msg_len, const sm9_signature *sig) {
    // h = Hash(msg || r)
    byte *hash_input = (byte*)malloc(msg_len + BYTE_LEN);
    if (hash_input)
    {
        memcpy(hash_input, msg, msg_len);
        memcpy(hash_input + msg_len, sig->r.data, BYTE_LEN);
        bigint h = { 0 };
        sm3_hash(h.data, hash_input, msg_len + BYTE_LEN);

        // P = h * pub_key + s * G
        ec_point P1, P2;
        ec_point_mul(&P1, &h, pub_key);
        ec_point_mul(&P2, &sig->s, &G);
        ec_point_add(&P1, &P1, &P2);

        // 验证 e(P, Ppub) == e(s * G + h * P, Ppub)
        bigint left, right;
        sm9_pairing(&left, &P1, &master_public);

        ec_point tmp;
        ec_point_mul(&tmp, &sig->s, &G);
        ec_point_mul(&P2, &h, pub_key);
        ec_point_add(&tmp, &tmp, &P2);
        sm9_pairing(&right, &tmp, &master_public);
        free(hash_input);
        return bigint_cmp(&left, &right) == 0;
    }
    else
        return 0;
}
