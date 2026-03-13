#include <stdint.h>
#include <stddef.h>

// CRC64多项式定义
#define CRC64_POLY_ECMA 0x42F0E1EBA9EA3693ULL
#define CRC64_POLY_ISO  0xD800000000000000ULL

// CRC64模式枚举
typedef enum {
    CRC64_MODE_ECMA = 0,
    CRC64_MODE_ISO  = 1
} crc64_mode_t;

// CRC64上下文结构
typedef struct {
    uint64_t state;
    uint64_t polynomial;
    uint64_t table[256];
} crc64_context_t;

// 初始化CRC64上下文
void crc64_init(crc64_context_t *ctx, crc64_mode_t mode) {
    if (!ctx) return;
    
    // 设置多项式
    switch (mode) {
        case CRC64_MODE_ECMA:
            ctx->polynomial = CRC64_POLY_ECMA;
            ctx->state = 0x0000000000000000ULL;
            break;
        case CRC64_MODE_ISO:
            ctx->polynomial = CRC64_POLY_ISO;
            ctx->state = 0xFFFFFFFFFFFFFFFFULL;
            break;
        default:
            ctx->polynomial = CRC64_POLY_ECMA;
            ctx->state = 0x0000000000000000ULL;
            break;
    }
    
    // 生成查找表
    for (int i = 0; i < 256; i++) {
        uint64_t crc = (uint64_t)i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ ctx->polynomial;
            } else {
                crc >>= 1;
            }
        }
        ctx->table[i] = crc;
    }
}

// 更新CRC64校验值
void crc64_update(crc64_context_t *ctx, const void *data, size_t length) {
    if (!ctx || !data) return;
    
    const uint8_t *buf = (const uint8_t *)data;
    uint64_t crc = ctx->state;
    
    for (size_t i = 0; i < length; i++) {
        uint8_t table_index = (crc ^ buf[i]) & 0xFF;
        crc = (crc >> 8) ^ ctx->table[table_index];
    }
    
    ctx->state = crc;
}

// 完成CRC64计算并返回结果
uint64_t crc64_finalize(crc64_context_t *ctx) {
    if (!ctx) return 0;
    
    // 根据模式处理最终值
    if (ctx->polynomial == CRC64_POLY_ISO) {
        return ctx->state ^ 0xFFFFFFFFFFFFFFFFULL;
    }
    return ctx->state;
}

// 一次性计算CRC64校验值
uint64_t crc64_compute(crc64_mode_t mode, const void *data, size_t length) {
    crc64_context_t ctx;
    crc64_init(&ctx, mode);
    crc64_update(&ctx, data, length);
    return crc64_finalize(&ctx);
}

// 重置CRC64上下文状态
void crc64_reset(crc64_context_t *ctx) {
    if (!ctx) return;
    
    if (ctx->polynomial == CRC64_POLY_ISO) {
        ctx->state = 0xFFFFFFFFFFFFFFFFULL;
    } else {
        ctx->state = 0x0000000000000000ULL;
    }
}
