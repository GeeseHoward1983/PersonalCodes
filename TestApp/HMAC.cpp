#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// ======================== 通用定义 ========================
#define HMAC_MAX_BLOCK_SIZE 128  // 支持最大块大小（SHA384/512）

typedef struct {
    void (*init)(void*);
    void (*update)(void*, const uint8_t*, size_t);
    void (*final)(uint8_t*, void*);
    size_t block_size;
    size_t output_size;
    size_t ctx_size;
} HashInfo;

// ======================== HMAC 核心实现 ========================
void hmac_compute(
    const HashInfo* info,
    const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len,
    uint8_t* digest
) {
    uint8_t k_ipad[HMAC_MAX_BLOCK_SIZE] = {0};
    uint8_t k_opad[HMAC_MAX_BLOCK_SIZE] = {0};
    uint8_t* temp = malloc(info->output_size);
    void* ctx = malloc(info->ctx_size);

    // 步骤1: 密钥处理
    if (key_len > info->block_size) {
        info->init(ctx);
        info->update(ctx, key, key_len);
        info->final(temp, ctx);
        key = temp;
        key_len = info->output_size;
    } else if (key_len < info->block_size) {
        // 填充密钥到块大小
        memcpy(k_ipad, key, key_len);
        memcpy(k_opad, key, key_len);
    } else {
        memcpy(k_ipad, key, key_len);
        memcpy(k_opad, key, key_len);
    }

    // 步骤2: 生成内/外填充键
    for (size_t i = 0; i < info->block_size; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5C;
    }

    // 步骤3: 计算内部哈希
    info->init(ctx);
    info->update(ctx, k_ipad, info->block_size);
    info->update(ctx, data, data_len);
    info->final(temp, ctx);

    // 步骤4: 计算外部哈希
    info->init(ctx);
    info->update(ctx, k_opad, info->block_size);
    info->update(ctx, temp, info->output_size);
    info->final(digest, ctx);

    free(temp);
    free(ctx);
}

// ======================== MD5 实现 ========================
typedef struct {
    uint32_t state[4];
    uint64_t count;
    uint8_t buffer[64];
} MD5_CTX;

void md5_init(MD5_CTX* ctx);
void md5_update(MD5_CTX* ctx, const uint8_t* data, size_t len);
void md5_final(uint8_t digest[16], MD5_CTX* ctx);

// MD5包装函数
void md5_init_wrapper(void* ctx) {
    md5_init((MD5_CTX*)ctx);
}
void md5_update_wrapper(void* ctx, const uint8_t* data, size_t len) {
    md5_update((MD5_CTX*)ctx, data, len);
}
void md5_final_wrapper(uint8_t* digest, void* ctx) {
    md5_final(digest, (MD5_CTX*)ctx);
}

// ======================== SHA1 实现 ========================
typedef struct {
    uint32_t state[5];
    uint64_t count;
    uint8_t buffer[64];
} SHA1_CTX;

void sha1_init(SHA1_CTX* ctx);
void sha1_update(SHA1_CTX* ctx, const uint8_t* data, size_t len);
void sha1_final(uint8_t digest[20], SHA1_CTX* ctx);

// SHA1包装函数
void sha1_init_wrapper(void* ctx) {
    sha1_init((SHA1_CTX*)ctx);
}
void sha1_update_wrapper(void* ctx, const uint8_t* data, size_t len) {
    sha1_update((SHA1_CTX*)ctx, data, len);
}
void sha1_final_wrapper(uint8_t* digest, void* ctx) {
    sha1_final(digest, (SHA1_CTX*)ctx);
}

// ======================== SHA2 实现 ========================
// SHA224/256共享上下文
typedef struct {
    uint32_t total[2];
    uint32_t state[8];
    uint8_t buffer[64];
} SHA256_CTX;

// SHA384/512共享上下文
typedef struct {
    uint64_t total[2];
    uint64_t state[8];
    uint8_t buffer[128];
} SHA512_CTX;

// SHA224 函数
void sha224_init(SHA256_CTX* ctx);
void sha224_update(SHA256_CTX* ctx, const uint8_t* data, size_t len);
void sha224_final(uint8_t digest[28], SHA256_CTX* ctx);

// SHA256 函数
void sha256_init(SHA256_CTX* ctx);
void sha256_update(SHA256_CTX* ctx, const uint8_t* data, size_t len);
void sha256_final(uint8_t digest[32], SHA256_CTX* ctx);

// SHA384 函数
void sha384_init(SHA512_CTX* ctx);
void sha384_update(SHA512_CTX* ctx, const uint8_t* data, size_t len);
void sha384_final(uint8_t digest[48], SHA512_CTX* ctx);

// SHA512 函数
void sha512_init(SHA512_CTX* ctx);
void sha512_update(SHA512_CTX* ctx, const uint8_t* data, size_t len);
void sha512_final(uint8_t digest[64], SHA512_CTX* ctx);

// SHA224包装函数
void sha224_init_wrapper(void* ctx) {
    sha224_init((SHA256_CTX*)ctx);
}
void sha224_update_wrapper(void* ctx, const uint8_t* data, size_t len) {
    sha224_update((SHA256_CTX*)ctx, data, len);
}
void sha224_final_wrapper(uint8_t* digest, void* ctx) {
    sha224_final(digest, (SHA256_CTX*)ctx);
}

// SHA256包装函数
void sha256_init_wrapper(void* ctx) {
    sha256_init((SHA256_CTX*)ctx);
}
void sha256_update_wrapper(void* ctx, const uint8_t* data, size_t len) {
    sha256_update((SHA256_CTX*)ctx, data, len);
}
void sha256_final_wrapper(uint8_t* digest, void* ctx) {
    sha256_final(digest, (SHA256_CTX*)ctx);
}

// SHA384包装函数
void sha384_init_wrapper(void* ctx) {
    sha384_init((SHA512_CTX*)ctx);
}
void sha384_update_wrapper(void* ctx, const uint8_t* data, size_t len) {
    sha384_update((SHA512_CTX*)ctx, data, len);
}
void sha384_final_wrapper(uint8_t* digest, void* ctx) {
    sha384_final(digest, (SHA512_CTX*)ctx);
}

// SHA512包装函数
void sha512_init_wrapper(void* ctx) {
    sha512_init((SHA512_CTX*)ctx);
}
void sha512_update_wrapper(void* ctx, const uint8_t* data, size_t len) {
    sha512_update((SHA512_CTX*)ctx, data, len);
}
void sha512_final_wrapper(uint8_t* digest, void* ctx) {
    sha512_final(digest, (SHA512_CTX*)ctx);
}

// ======================== HMAC 包装函数 ========================
// HMAC-MD5
void hmac_md5(const uint8_t* key, size_t key_len, 
              const uint8_t* data, size_t data_len, 
              uint8_t digest[16]) 
{
    HashInfo info;
    info.init = md5_init_wrapper;
    info.update = md5_update_wrapper;
    info.final = md5_final_wrapper;
    info.block_size = 64;
    info.output_size = 16;
    info.ctx_size = sizeof(MD5_CTX);
    hmac_compute(&info, key, key_len, data, data_len, digest);
}

// HMAC-SHA1
void hmac_sha1(const uint8_t* key, size_t key_len, 
               const uint8_t* data, size_t data_len, 
               uint8_t digest[20]) 
{
    HashInfo info;
    info.init = sha1_init_wrapper;
    info.update = sha1_update_wrapper;
    info.final = sha1_final_wrapper;
    info.block_size = 64;
    info.output_size = 20;
    info.ctx_size = sizeof(SHA1_CTX);
    hmac_compute(&info, key, key_len, data, data_len, digest);
}

// HMAC-SHA224
void hmac_sha224(const uint8_t* key, size_t key_len, 
                 const uint8_t* data, size_t data_len, 
                 uint8_t digest[28]) 
{
    HashInfo info;
    info.init = sha224_init_wrapper;
    info.update = sha224_update_wrapper;
    info.final = sha224_final_wrapper;
    info.block_size = 64;
    info.output_size = 28;
    info.ctx_size = sizeof(SHA256_CTX);
    hmac_compute(&info, key, key_len, data, data_len, digest);
}

// HMAC-SHA256
void hmac_sha256(const uint8_t* key, size_t key_len, 
                 const uint8_t* data, size_t data_len, 
                 uint8_t digest[32]) 
{
    HashInfo info;
    info.init = sha256_init_wrapper;
    info.update = sha256_update_wrapper;
    info.final = sha256_final_wrapper;
    info.block_size = 64;
    info.output_size = 32;
    info.ctx_size = sizeof(SHA256_CTX);
    hmac_compute(&info, key, key_len, data, data_len, digest);
}

// HMAC-SHA384
void hmac_sha384(const uint8_t* key, size_t key_len, 
                 const uint8_t* data, size_t data_len, 
                 uint8_t digest[48]) 
{
    HashInfo info;
    info.init = sha384_init_wrapper;
    info.update = sha384_update_wrapper;
    info.final = sha384_final_wrapper;
    info.block_size = 128;  // SHA384使用128字节块
    info.output_size = 48;
    info.ctx_size = sizeof(SHA512_CTX);
    hmac_compute(&info, key, key_len, data, data_len, digest);
}

// HMAC-SHA512
void hmac_sha512(const uint8_t* key, size_t key_len, 
                 const uint8_t* data, size_t data_len, 
                 uint8_t digest[64]) 
{
    HashInfo info;
    info.init = sha512_init_wrapper;
    info.update = sha512_update_wrapper;
    info.final = sha512_final_wrapper;
    info.block_size = 128;  // SHA512使用128字节块
    info.output_size = 64;
    info.ctx_size = sizeof(SHA512_CTX);
    hmac_compute(&info, key, key_len, data, data_len, digest);
}

// HMAC-SHA128 (实际使用SHA1)
void hmac_sha128(const uint8_t* key, size_t key_len, 
                 const uint8_t* data, size_t data_len, 
                 uint8_t digest[16]) 
{
    // SHA128通常指SHA1的截断版本
    uint8_t sha1_digest[20];
    hmac_sha1(key, key_len, data, data_len, sha1_digest);
    memcpy(digest, sha1_digest, 16);  // 取前128位(16字节)
}

// HMAC-SHA192 (实际使用SHA256的截断)
void hmac_sha192(const uint8_t* key, size_t key_len, 
                 const uint8_t* data, size_t data_len, 
                 uint8_t digest[24]) 
{
    uint8_t sha256_digest[32];
    hmac_sha256(key, key_len, data, data_len, sha256_digest);
    memcpy(digest, sha256_digest, 24);  // 取前192位(24字节)
}
