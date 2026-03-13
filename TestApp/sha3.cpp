#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// SHA3常量定义
#define KECCAK_ROUNDS 24
#define SHA3_STATE_SIZE 200
#define SHA3_MAX_DIGEST_SIZE 64

// 旋转操作宏
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

// SHA3上下文结构
typedef struct {
    uint64_t state[25];  // 5x5状态矩阵
    unsigned char buffer[144];  // 输入缓冲区
    unsigned int bufferIndex;   // 缓冲区索引
    unsigned int rate;          // 速率（字节）
    unsigned int digestSize;    // 输出长度（字节）
} sha3_ctx;

// Keccak-f[1600]轮常量
static const uint64_t round_constants[KECCAK_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

// 旋转偏移量表
static const unsigned int rotation_offsets[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

// Keccak-f[1600]置换函数
static void keccak_f(sha3_ctx *ctx) {
    uint64_t C[5], D[5];
    
    for (int round = 0; round < KECCAK_ROUNDS; round++) {
        // Theta步骤
        for (int i = 0; i < 5; i++) {
            C[i] = ctx->state[i] ^ ctx->state[i + 5] ^ 
                   ctx->state[i + 10] ^ ctx->state[i + 15] ^ 
                   ctx->state[i + 20];
        }
        
        for (int i = 0; i < 5; i++) {
            D[i] = C[(i + 4) % 5] ^ ROTL64(C[(i + 1) % 5], 1);
            for (int j = 0; j < 5; j++) {
                ctx->state[i + 5 * j] ^= D[i];
            }
        }
        
        // Rho和Pi步骤
        uint64_t temp = ctx->state[1];
        for (int i = 0; i < 24; i++) {
            unsigned int index = rotation_offsets[i];
            uint64_t t = ctx->state[index];
            ctx->state[index] = ROTL64(temp, rotation_offsets[(i + 1) % 25]);
            temp = t;
        }
        
        // Chi步骤
        for (int j = 0; j < 5; j++) {
            for (int i = 0; i < 5; i++) {
                C[i] = ctx->state[i + 5 * j];
            }
            for (int i = 0; i < 5; i++) {
                ctx->state[i + 5 * j] = C[i] ^ ((~C[(i + 1) % 5]) & C[(i + 2) % 5]);
            }
        }
        
        // Iota步骤
        ctx->state[0] ^= round_constants[round];
    }
}

// SHA3初始化
void sha3_init(sha3_ctx *ctx, unsigned int digest_size) {
    memset(ctx, 0, sizeof(sha3_ctx));
    ctx->digestSize = digest_size;
    
    // 设置速率 (1600 - 2*digest_size*8) / 8
    switch (digest_size) {
        case 28:  // 224位
            ctx->rate = 144; break;
        case 32:  // 256位
            ctx->rate = 136; break;
        case 48:  // 384位
            ctx->rate = 104; break;
        case 64:  // 512位
            ctx->rate = 72; break;
        default:
            // 默认256位
            ctx->rate = 136;
            ctx->digestSize = 32;
    }
}

// 更新SHA3状态
void sha3_update(sha3_ctx *ctx, const uint8_t *data, size_t len) {
    size_t block_size = ctx->rate;
    
    while (len > 0) {
        size_t to_copy = block_size - ctx->bufferIndex;
        if (to_copy > len) to_copy = len;
        
        memcpy(ctx->buffer + ctx->bufferIndex, data, to_copy);
        ctx->bufferIndex += to_copy;
        data += to_copy;
        len -= to_copy;
        
        if (ctx->bufferIndex == block_size) {
            // 处理完整块
            for (int i = 0; i < block_size / 8; i++) {
                ctx->state[i] ^= ((uint64_t*)ctx->buffer)[i];
            }
            keccak_f(ctx);
            ctx->bufferIndex = 0;
        }
    }
}

// 生成最终哈希值
void sha3_final(sha3_ctx *ctx, uint8_t *digest) {
    // 填充: 0x06 + 0x80... + 0x01
    ctx->buffer[ctx->bufferIndex++] = 0x06;
    memset(ctx->buffer + ctx->bufferIndex, 0, ctx->rate - ctx->bufferIndex);
    ctx->buffer[ctx->rate - 1] |= 0x80;
    
    // 处理最后一个块
    for (int i = 0; i < ctx->rate / 8; i++) {
        ctx->state[i] ^= ((uint64_t*)ctx->buffer)[i];
    }
    
    keccak_f(ctx);
    
    // 输出哈希值
    for (unsigned int i = 0; i < ctx->digestSize; i++) {
        digest[i] = (ctx->state[i / 8] >> (8 * (i % 8))) & 0xFF;
    }
}

// 包装函数：计算SHA3哈希
void sha3_hash(const uint8_t *input, size_t len, uint8_t *digest, unsigned int digest_size) {
    sha3_ctx ctx;
    sha3_init(&ctx, digest_size);
    sha3_update(&ctx, input, len);
    sha3_final(&ctx, digest);
}

// 测试函数
int main() {
    const char *test_str = "Hello, SHA3!";
    uint8_t digest[SHA3_MAX_DIGEST_SIZE];
    
    // 测试不同长度
    printf("SHA3-224: ");
    sha3_hash((uint8_t*)test_str, strlen(test_str), digest, 28);
    for (int i = 0; i < 28; i++) printf("%02x", digest[i]);
    printf("\n");
    
    printf("SHA3-256: ");
    sha3_hash((uint8_t*)test_str, strlen(test_str), digest, 32);
    for (int i = 0; i < 32; i++) printf("%02x", digest[i]);
    printf("\n");
    
    printf("SHA3-384: ");
    sha3_hash((uint8_t*)test_str, strlen(test_str), digest, 48);
    for (int i = 0; i < 48; i++) printf("%02x", digest[i]);
    printf("\n");
    
    printf("SHA3-512: ");
    sha3_hash((uint8_t*)test_str, strlen(test_str), digest, 64);
    for (int i = 0; i < 64; i++) printf("%02x", digest[i]);
    printf("\n");
    
    return 0;
}