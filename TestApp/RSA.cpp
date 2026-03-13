#include <stdio.h>
#include <string.h>
#include <time.h>
#include "RSA.h"

// SHA-256上下文
typedef struct {
    unsigned total[2];
    unsigned state[8];
    unsigned char buffer[64];
} SHA256_CTX;

// 大数初始化
void bn_zero(BigNum *a) {
    memset(a->words, 0, sizeof(a->words));
}

// 大数设置为1
void bn_one(BigNum *a) {
    bn_zero(a);
    a->words[0] = 1;
}

// 从字节数组初始化大数（小端序）
void bn_from_bytes(BigNum *a, const unsigned char *bytes) {
    bn_zero(a);
    for (int i = 0; i < RSA_BYTES; i++) {
        a->words[i / sizeof(unsigned)] |= ((unsigned)bytes[i]) << (8 * (i % sizeof(unsigned)));
    }
}

// 大数转字节数组
void bn_to_bytes(const BigNum *a, unsigned char *bytes) {
    for (int i = 0; i < RSA_BYTES; i++) {
        bytes[i] = (a->words[i / sizeof(unsigned)] >> (8 * (i % sizeof(unsigned)))) & 0xFF;
    }
}

// 生成随机大数
void bn_rand(BigNum *a, int bits) {
    bn_zero(a);
    if (bits <= 0)
        return;
    int words_needed = (bits + 31) / 32;
    for (int i = 0; i < words_needed; i++) {
        a->words[i] = rand() ^ (rand() << 16);
    }
    // 设置最高位确保位数
    a->words[words_needed - 1] |= (1u << ((bits - 1) % 32));
}

// 大数比较：1(a>b), 0(a==b), -1(a<b)
int bn_cmp(const BigNum *a, const BigNum *b) {
    for (int i = RSA_WORDS - 1; i >= 0; i--) {
        if (a->words[i] > b->words[i]) return 1;
        if (a->words[i] < b->words[i]) return -1;
    }
    return 0;
}

// 大数加法（a + b = res）
void bn_add(const BigNum *a, const BigNum *b, BigNum *res) {
    unsigned long long carry = 0;
    for (int i = 0; i < RSA_WORDS; i++) {
        unsigned long long sum = (unsigned long long)a->words[i] + b->words[i] + carry;
        res->words[i] = (unsigned)(sum & 0xFFFFFFFF);
        carry = sum >> 32;
    }
}

// 大数减法（a - b = res，要求a >= b）
void bn_sub(const BigNum *a, const BigNum *b, BigNum *res) {
    unsigned long long borrow = 0;
    for (int i = 0; i < RSA_WORDS; i++) {
        unsigned long long diff = (unsigned long long)a->words[i] - b->words[i] - borrow;
        res->words[i] = (unsigned)diff;
        borrow = (diff > a->words[i]) ? 1 : 0;
    }
}

// 大数乘法（a * b = res）
void bn_mul(const BigNum *a, const BigNum *b, BigNum *res) {
    bn_zero(res);
    for (int i = 0; i < RSA_WORDS; i++) {
        unsigned long long carry = 0;
        for (int j = 0; j < RSA_WORDS; j++) {
            int k = i + j;
            if (k >= RSA_WORDS) continue;
            unsigned long long product = (unsigned long long)a->words[i] * b->words[j] + res->words[k] + carry;
            res->words[k] = (unsigned)(product & 0xFFFFFFFF);
            carry = product >> 32;
        }
    }
}

// 大数移位（左移1位）
void bn_shift_left(BigNum *a) {
    unsigned carry = 0;
    for (int i = 0; i < RSA_WORDS; i++) {
        unsigned new_carry = a->words[i] >> 31;
        a->words[i] = (a->words[i] << 1) | carry;
        carry = new_carry;
    }
}

// 大数移位（右移1位）
void bn_shift_right(BigNum *a) {
    unsigned carry = 0;
    for (int i = RSA_WORDS - 1; i >= 0; i--) {
        unsigned new_carry = a->words[i] & 1;
        a->words[i] = (a->words[i] >> 1) | (carry << 31);
        carry = new_carry;
    }
}

// 大数取模（res = a mod m）
void bn_mod(const BigNum *a, const BigNum *m, BigNum *res) {
    BigNum temp = *a;
    BigNum divisor = *m;
    BigNum quotient;
    bn_zero(&quotient);
    
    // 标准化除数
    int shift = 0;
    while (bn_cmp(&divisor, &temp) <= 0) {
        bn_shift_left(&divisor);
        shift++;
    }
    
    for (int i = 0; i <= shift; i++) {
        bn_shift_left(&quotient);
        if (bn_cmp(&divisor, &temp) <= 0) {
            bn_sub(&temp, &divisor, &temp);
            quotient.words[0] |= 1;
        }
        bn_shift_right(&divisor);
    }
    
    *res = temp;
}

// 蒙哥马利模乘（res = a * b * R⁻¹ mod m）
void bn_mont_mul(const BigNum *a, const BigNum *b, const BigNum *m, BigNum *res) {
    BigNum s;
    bn_zero(&s);
    
    for (int i = 0; i < RSA_BITS; i++) {
        // 计算q = (s0 + a_i * b0) * m' mod R
        unsigned a_i = (a->words[i / 32] >> (i % 32)) & 1;
        unsigned b0 = b->words[0] & 1;
        unsigned s0 = s.words[0] & 1;
        unsigned q = (s0 + a_i * b0) * (m->words[0] & 1);
        
        // s = (s + a_i * b + q * m) / 2
        if (a_i) {
            bn_add(&s, b, &s);
        }
        if (q) {
            bn_add(&s, m, &s);
        }
        
        bn_shift_right(&s);
    }
    
    if (bn_cmp(&s, m) >= 0) {
        bn_sub(&s, m, res);
    } else {
        *res = s;
    }
}

// 快速幂模运算（res = base^exp mod mod）
void bn_mod_exp(const BigNum *base, const BigNum *exp, const BigNum *mod, BigNum *res) {
    BigNum base_temp = *base;
    BigNum exp_temp = *exp;
    BigNum one;
    bn_one(&one);
    
    bn_one(res);
    
    while (bn_cmp(&exp_temp, &one) >= 0) {
        if (exp_temp.words[0] & 1) {
            BigNum temp;
            bn_mont_mul(res, &base_temp, mod, &temp);
            *res = temp;
        }
        
        bn_shift_right(&exp_temp);
        
        BigNum temp;
        bn_mont_mul(&base_temp, &base_temp, mod, &temp);
        base_temp = temp;
    }
}

// 扩展欧几里得算法求模逆元
void bn_mod_inv(const BigNum *a, const BigNum *m, BigNum *inv) {
    BigNum t = {0}, newt = {1};
    BigNum r = *m, newr = *a;
    BigNum ZERO = { 0 };
    BigNum ONE = { 0 };
    ONE.words[0] = 1;

    while (bn_cmp(&newr, &ZERO) != 0) {
        BigNum quotient;
        // 简化除法：计算 r / newr
        unsigned long long approx = (r.words[RSA_WORDS-1] * (1ULL << 32) + r.words[RSA_WORDS-2]) / 
                                   (newr.words[RSA_WORDS-1] + 1);
        bn_from_bytes(&quotient, (unsigned char*)&approx);
        
        BigNum temp = t;
        bn_mul(&quotient, &newt, &t);
        bn_sub(&temp, &t, &t);
        
        temp = newt;
        newt = t;
        t = temp;
        
        temp = r;
        bn_mul(&quotient, &newr, &r);
        bn_sub(&temp, &r, &r);
        
        temp = newr;
        newr = r;
        r = temp;
    }
    
    if (bn_cmp(&r, &ONE) > 0) {
        bn_zero(inv); // 逆元不存在
        return;
    }
    
    if (bn_cmp(&t, &ZERO) < 0) {
        bn_add(&t, m, inv);
    } else {
        *inv = t;
    }
}

// 米勒-拉宾素性测试
int bn_is_prime(const BigNum *n, int k) {
    if (n->words[0] % 2 == 0) return 0;
    BigNum ONE = { 0 };
    ONE.words[0] = 1;
    BigNum TWO = { 0 };
    TWO.words[0] = 2;

    BigNum n1 = *n;
    bn_sub(&n1, &ONE, &n1);
    BigNum ZERO = { 0 };
    unsigned s = 0;
    BigNum d = n1;
    while (d.words[0] % 2 == 0) {
        s++;
        bn_shift_right(&d);
    }
    
    for (int i = 0; i < k; i++) {
        BigNum a;
        do {
            bn_rand(&a, RSA_BITS-1);
        } while (bn_cmp(&a, &TWO) < 0);
        
        BigNum x;
        bn_mod_exp(&a, &d, n, &x);
        
        if (bn_cmp(&x, &ONE) == 0 || bn_cmp(&x, &n1) == 0) continue;
        
        int found = 0;
        for (unsigned r = 1; r < s; r++) {
            BigNum temp;
            bn_mont_mul(&x, &x, n, &temp);
            x = temp;
            
            if (bn_cmp(&x, &n1) == 0) {
                found = 1;
                break;
            }
        }
        
        if (!found) return 0;
    }
    return 1;
}

// 生成大素数
void bn_gen_prime(BigNum *p, int bits) {
    do {
        bn_rand(p, bits);
        p->words[0] |= 1; // 确保奇数
    } while (!bn_is_prime(p, 5));
}

// SHA-256常量
static const unsigned K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// SHA-256初始化
void sha256_init(SHA256_CTX *ctx) {
    ctx->total[0] = 0;
    ctx->total[1] = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

// SHA-256处理块
void sha256_process(SHA256_CTX *ctx, const unsigned char *data) {
    unsigned W[64], T1, T2;
    unsigned A = ctx->state[0];
    unsigned B = ctx->state[1];
    unsigned C = ctx->state[2];
    unsigned D = ctx->state[3];
    unsigned E = ctx->state[4];
    unsigned F = ctx->state[5];
    unsigned G = ctx->state[6];
    unsigned H = ctx->state[7];
    
    for (int t = 0; t < 16; t++) {
        W[t] = ((unsigned)data[t*4] << 24) | ((unsigned)data[t*4+1] << 16) | 
               ((unsigned)data[t*4+2] << 8) | data[t*4+3];
    }
    
    for (int t = 16; t < 64; t++) {
        unsigned s0 = (W[t-15] >> 7 | W[t-15] << 25) ^ (W[t-15] >> 18 | W[t-15] << 14) ^ (W[t-15] >> 3);
        unsigned s1 = (W[t-2] >> 17 | W[t-2] << 15) ^ (W[t-2] >> 19 | W[t-2] << 13) ^ (W[t-2] >> 10);
        W[t] = W[t-16] + s0 + W[t-7] + s1;
    }
    
    for (int t = 0; t < 64; t++) {
        unsigned S1 = (E >> 6 | E << 26) ^ (E >> 11 | E << 21) ^ (E >> 25 | E << 7);
        unsigned ch = (E & F) ^ (~E & G);
        T1 = H + S1 + ch + K[t] + W[t];
        unsigned S0 = (A >> 2 | A << 30) ^ (A >> 13 | A << 19) ^ (A >> 22 | A << 10);
        unsigned maj = (A & B) ^ (A & C) ^ (B & C);
        T2 = S0 + maj;
        
        H = G; G = F; F = E; E = D + T1;
        D = C; C = B; B = A; A = T1 + T2;
    }
    
    ctx->state[0] += A; ctx->state[1] += B; ctx->state[2] += C; ctx->state[3] += D;
    ctx->state[4] += E; ctx->state[5] += F; ctx->state[6] += G; ctx->state[7] += H;
}

// SHA-256更新
void sha256_update(SHA256_CTX *ctx, const unsigned char *input, size_t length) {
    size_t fill, index = (size_t)((ctx->total[0] >> 3) & 0x3F);
    
    ctx->total[0] += (unsigned)length << 3;
    if (ctx->total[0] < (unsigned)length << 3) ctx->total[1]++;
    ctx->total[1] += (unsigned)length >> 29;
    
    fill = 64 - index;
    
    if (length >= fill) {
        memcpy(ctx->buffer + index, input, fill);
        sha256_process(ctx, ctx->buffer);
        for (size_t i = fill; i + 63 < length; i += 64) {
            sha256_process(ctx, input + i);
        }
        index = 0;
    } else {
        fill = length;
    }
    
    memcpy(ctx->buffer + index, input + (length - fill), fill);
}

// SHA-256结束
void sha256_final(SHA256_CTX *ctx, unsigned char *digest) {
    unsigned char msglen[8];
    unsigned high = (ctx->total[0] >> 29) | (ctx->total[1] << 3);
    unsigned low = (ctx->total[0] << 3);
    
    msglen[0] = (unsigned char)(high >> 24); msglen[1] = (high >> 16) & 0xFF;
    msglen[2] = (high >> 8) & 0xFF; msglen[3] = high & 0xFF;
    msglen[4] = (low >> 24); msglen[5] = (low >> 16) & 0xFF;
    msglen[6] = (low >> 8) & 0xFF; msglen[7] = low & 0xFF;
    
    size_t last = (size_t)(ctx->total[0] & 0x3F);
    size_t padn = (last < 56) ? (56 - last) : (120 - last);
    
    unsigned char padding[64] = {0x80};
    sha256_update(ctx, padding, padn);
    sha256_update(ctx, msglen, 8);
    
    for (int i = 0; i < 8; i++) {
        digest[i*4]   = (ctx->state[i] >> 24) & 0xFF;
        digest[i*4+1] = (ctx->state[i] >> 16) & 0xFF;
        digest[i*4+2] = (ctx->state[i] >> 8) & 0xFF;
        digest[i*4+3] = ctx->state[i] & 0xFF;
    }
}

// 计算SHA-256哈希
void sha256(const unsigned char *input, size_t length, unsigned char *digest) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, input, length);
    sha256_final(&ctx, digest);
}

// 生成RSA密钥对
void rsa_generate_keys(RSAPublicKey *pub, RSAPrivateKey *priv) {
    BigNum p, q;
    printf("生成素数 p...");
    bn_gen_prime(&p, RSA_BITS/2);
    printf("完成\n生成素数 q...");
    bn_gen_prime(&q, RSA_BITS/2);
    printf("完成\n");
    
    // 计算 n = p * q
    bn_mul(&p, &q, &pub->n);
    priv->n = pub->n;
    BigNum ONE = { 0 };
    ONE.words[0] = 1;

    // 计算 φ(n) = (p-1)(q-1)
    BigNum p1 = p, q1 = q;
    bn_sub(&p, &ONE, &p1);
    bn_sub(&q, &ONE, &q1);
    BigNum phi;
    bn_mul(&p1, &q1, &phi);
    
    // 选择公钥指数 e (通常为65537)
    bn_one(&pub->e);
    pub->e.words[0] = 65537;
    
    // 计算私钥指数 d = e⁻¹ mod φ(n)
    bn_mod_inv(&pub->e, &phi, &priv->d);
}

// PKCS#1 v1.5 加密填充
int rsa_pkcs1_encrypt_pad(const unsigned char *input, size_t len, 
                          unsigned char *padded, size_t padded_len) {
    if (len > padded_len - 11) return 0; // 输入太长
    
    padded[0] = 0x00;
    padded[1] = 0x02; // 公钥操作填充
    
    // 随机填充
    size_t pad_len = padded_len - len - 3;
    for (size_t i = 0; i < pad_len; i++) {
        padded[2 + i] = rand() % 255 + 1; // 非零字节
    }
    padded[2 + pad_len] = 0x00;
    memcpy(padded + 3 + pad_len, input, len);
    return 1;
}

// PKCS#1 v1.5 解密去除填充
int rsa_pkcs1_decrypt_unpad(const unsigned char *padded, size_t padded_len, 
                            unsigned char *output, size_t *out_len) {
    if (padded[0] != 0x00 || padded[1] != 0x02) return 0;
    
    size_t pos = 2;
    while (pos < padded_len && padded[pos] != 0x00) {
        pos++;
    }
    
    if (pos >= padded_len - 1 || pos < 10) return 0; // 无效填充
    
    *out_len = padded_len - pos - 1;
    memcpy(output, padded + pos + 1, *out_len);
    return 1;
}

// RSA加密
int rsa_encrypt(RSAPublicKey *key, const unsigned char *input, size_t len, 
                unsigned char *output) {
    unsigned char padded[RSA_BYTES];
    if (!rsa_pkcs1_encrypt_pad(input, len, padded, RSA_BYTES)) {
        return 0;
    }
    
    BigNum m, c;
    bn_from_bytes(&m, padded);
    bn_mod_exp(&m, &key->e, &key->n, &c);
    bn_to_bytes(&c, output);
    return 1;
}

// RSA解密
int rsa_decrypt(RSAPrivateKey *key, const unsigned char *input, 
                unsigned char *output, size_t *out_len) {
    BigNum c, m;
    bn_from_bytes(&c, input);
    bn_mod_exp(&c, &key->d, &key->n, &m);
    
    unsigned char padded[RSA_BYTES];
    bn_to_bytes(&m, padded);
    
    return rsa_pkcs1_decrypt_unpad(padded, RSA_BYTES, output, out_len);
}

// RSA签名
int rsa_sign(RSAPrivateKey *key, const unsigned char *msg, size_t len, 
             unsigned char *signature) {
    // 计算消息哈希
    unsigned char hash[32];
    sha256(msg, len, hash);
    
    // 构造PKCS#1 v1.5签名填充
    unsigned char padded[RSA_BYTES];
    padded[0] = 0x00;
    padded[1] = 0x01; // 私钥操作填充
    size_t pad_len = RSA_BYTES - 3 - 32 - 19;
    memset(padded + 2, 0xFF, pad_len);
    padded[2 + pad_len] = 0x00;
    
    // ASN.1 SHA-256头
    const unsigned char sha256_header[] = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 
        0x00, 0x04, 0x20
    };
    memcpy(padded + 3 + pad_len, sha256_header, 19);
    memcpy(padded + 3 + pad_len + 19, hash, 32);
    
    // 使用私钥加密
    BigNum s, sig;
    bn_from_bytes(&s, padded);
    bn_mod_exp(&s, &key->d, &key->n, &sig);
    bn_to_bytes(&sig, signature);
    return 1;
}

// RSA验签
int rsa_verify(RSAPublicKey *key, const unsigned char *msg, size_t len, 
               const unsigned char *signature) {
    // 使用公钥解密签名
    BigNum sig, dec;
    bn_from_bytes(&sig, signature);
    bn_mod_exp(&sig, &key->e, &key->n, &dec);
    
    unsigned char padded[RSA_BYTES];
    bn_to_bytes(&dec, padded);
    
    // 验证填充格式
    if (padded[0] != 0x00 || padded[1] != 0x01) return 0;
    
    // 查找0x00分隔符
    size_t pos = 2;
    while (pos < RSA_BYTES && padded[pos] == 0xFF) {
        pos++;
    }
    if (pos >= RSA_BYTES || padded[pos] != 0x00) return 0;
    pos++;
    
    // 验证ASN.1头
    const unsigned char sha256_header[] = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 
        0x00, 0x04, 0x20
    };
    if (memcmp(padded + pos, sha256_header, 19) != 0) return 0;
    pos += 19;
    
    // 提取哈希值
    unsigned char signature_hash[32];
    memcpy(signature_hash, padded + pos, 32);
    
    // 计算消息哈希
    unsigned char computed_hash[32];
    sha256(msg, len, computed_hash);
    
    // 比较哈希值
    return memcmp(signature_hash, computed_hash, 32) == 0;
}
