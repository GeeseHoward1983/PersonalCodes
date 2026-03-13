#ifndef _SM3_H_
#define _SM3_H_ 
#include <stdint.h>
// 定义常量
#define SM3_DIGEST_SIZE 32    // 摘要长度(字节)

// SM3上下文结构
typedef struct {
    uint32_t state[8];      // 中间状态
    uint64_t count;         // 已处理消息长度(位)
    uint8_t buffer[64];     // 当前分组
} SM3_CTX;

void sm3_init(SM3_CTX* ctx);
void sm3_update(SM3_CTX* ctx, const uint8_t* data, size_t len);
void sm3_final(SM3_CTX* ctx, uint8_t digest[SM3_DIGEST_SIZE]);

#endif
