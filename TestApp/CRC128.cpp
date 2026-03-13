#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// CRC128数据结构
typedef struct {
    uint64_t high;  // 高64位
    uint64_t low;   // 低64位
} crc128_t;

// CRC128模式定义
typedef enum {
    CRC128_MODE_ECMA,     // ECMA-288标准
    CRC128_MODE_CRC128,   // 通用CRC128
    CRC128_MODE_CUSTOM    // 自定义模式
} crc128_mode_t;

// CRC128上下文
typedef struct {
    crc128_t polynomial;  // 多项式
    crc128_t initial;     // 初始值
    crc128_t final_xor;   // 最终异或值
    int reflect_input;    // 输入是否翻转
    int reflect_output;   // 输出是否翻转
    crc128_t *table;      // 查找表
    crc128_mode_t mode;   // 模式
} crc128_context_t;

// 初始化CRC128值
crc128_t crc128_init_value(uint64_t high, uint64_t low) {
    crc128_t val;
    val.high = high;
    val.low = low;
    return val;
}

// 翻转64位值的位顺序
uint64_t reflect64(uint64_t value) {
    uint64_t reflected = 0;
    for (int i = 0; i < 64; i++) {
        if (value & (1ULL << i)) {
            reflected |= (1ULL << (63 - i));
        }
    }
    return reflected;
}

// 翻转8位值的位顺序
uint8_t reflect8(uint8_t value) {
    uint8_t reflected = 0;
    for (int i = 0; i < 8; i++) {
        if (value & (1 << i)) {
            reflected |= (1 << (7 - i));
        }
    }
    return reflected;
}

// 128位左移
void crc128_shift_left(crc128_t* value) {
    uint64_t carry = value->low & 0x8000000000000000ULL;
    value->low <<= 1;
    value->high <<= 1;
    if (carry) {
        value->high |= 1;
    }
}

// 128位右移
void crc128_shift_right(crc128_t* value) {
    uint64_t carry = value->high & 1;
    value->high >>= 1;
    value->low >>= 1;
    if (carry) {
        value->low |= 0x8000000000000000ULL;
    }
}

// 128位异或
void crc128_xor(crc128_t* a, const crc128_t* b) {
    a->high ^= b->high;
    a->low ^= b->low;
}

// 初始化ECMA-288模式上下文
void crc128_init_ecma(crc128_context_t* ctx) {
    ctx->mode = CRC128_MODE_ECMA;
    ctx->polynomial = crc128_init_value(0x0000000000000001ULL, 0xFFFFFFFFFFFFFFFFULL);
    ctx->initial = crc128_init_value(0x0000000000000000ULL, 0x0000000000000000ULL);
    ctx->final_xor = crc128_init_value(0x0000000000000000ULL, 0x0000000000000000ULL);
    ctx->reflect_input = 0;
    ctx->reflect_output = 0;
    ctx->table = NULL;
}

// 初始化通用CRC128模式上下文
void crc128_init_crc128(crc128_context_t* ctx) {
    ctx->mode = CRC128_MODE_CRC128;
    ctx->polynomial = crc128_init_value(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL);
    ctx->initial = crc128_init_value(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL);
    ctx->final_xor = crc128_init_value(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL);
    ctx->reflect_input = 1;
    ctx->reflect_output = 1;
    ctx->table = NULL;
}

// 初始化自定义模式上下文
void crc128_init_custom(crc128_context_t* ctx, 
                       uint64_t poly_high, uint64_t poly_low,
                       uint64_t init_high, uint64_t init_low,
                       uint64_t xor_high, uint64_t xor_low,
                       int reflect_in, int reflect_out) {
    ctx->mode = CRC128_MODE_CUSTOM;
    ctx->polynomial = crc128_init_value(poly_high, poly_low);
    ctx->initial = crc128_init_value(init_high, init_low);
    ctx->final_xor = crc128_init_value(xor_high, xor_low);
    ctx->reflect_input = reflect_in;
    ctx->reflect_output = reflect_out;
    ctx->table = NULL;
}

// 生成查找表
void crc128_generate_table(crc128_context_t* ctx) {
    if (ctx->table) {
        free(ctx->table);
    }
    
    ctx->table = (crc128_t*)malloc(256 * sizeof(crc128_t));
    if (!ctx->table) {
        return;
    }
    
    for (int i = 0; i < 256; i++) {
        crc128_t crc = {0, 0};
        
        // 根据输入反射设置初始值
        uint8_t byte = ctx->reflect_input ? reflect8(i) : i;
        crc.low = (uint64_t)byte << 56;
        
        // 计算8位
        for (int j = 0; j < 8; j++) {
            if (crc.high & 0x8000000000000000ULL) {
                crc128_shift_left(&crc);
                crc128_xor(&crc, &ctx->polynomial);
            } else {
                crc128_shift_left(&crc);
            }
        }
        
        // 根据输出反射决定是否翻转结果
        if (ctx->reflect_output) {
            crc.high = reflect64(crc.high);
            crc.low = reflect64(crc.low);
        }
        
        ctx->table[i] = crc;
    }
}

// 初始化CRC128上下文
void crc128_init(crc128_context_t* ctx, crc128_mode_t mode) {
    switch (mode) {
        case CRC128_MODE_ECMA:
            crc128_init_ecma(ctx);
            break;
        case CRC128_MODE_CRC128:
            crc128_init_crc128(ctx);
            break;
        case CRC128_MODE_CUSTOM:
        default:
            // 默认使用ECMA模式
            crc128_init_ecma(ctx);
            break;
    }
    
    crc128_generate_table(ctx);
}

// 释放CRC128上下文
void crc128_free(crc128_context_t* ctx) {
    if (ctx->table) {
        free(ctx->table);
        ctx->table = NULL;
    }
}

// 计算CRC128校验值
crc128_t crc128_update(crc128_context_t* ctx, const uint8_t* data, size_t length) {
    crc128_t crc = ctx->initial;
    
    if (!ctx->table) {
        crc128_generate_table(ctx);
    }
    
    for (size_t i = 0; i < length; i++) {
        uint8_t byte = data[i];
        
        // 根据输入反射处理字节
        if (ctx->reflect_input) {
            byte = reflect8(byte);
        }
        
        // 查找表索引
        uint8_t table_index = ((crc.high >> 56) ^ byte) & 0xFF;
        
        // 更新CRC值
        crc.high <<= 8;
        crc.high |= crc.low >> 56;
        crc.low <<= 8;
        crc128_xor(&crc, &ctx->table[table_index]);
    }
    
    // 应用最终异或值
    crc128_xor(&crc, &ctx->final_xor);
    
    // 根据输出反射处理结果
    if (ctx->reflect_output) {
        crc128_t reflected;
        reflected.high = reflect64(crc.low);
        reflected.low = reflect64(crc.high);
        return reflected;
    }
    
    return crc;
}

// 简化接口 - 计算指定模式的CRC128
crc128_t crc128_compute(crc128_mode_t mode, const uint8_t* data, size_t length) {
    crc128_context_t ctx;
    crc128_init(&ctx, mode);
    crc128_t result = crc128_update(&ctx, data, length);
    crc128_free(&ctx);
    return result;
}

