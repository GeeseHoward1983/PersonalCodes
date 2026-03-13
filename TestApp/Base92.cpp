#include <stdint.h>
#include <string.h>

// Base92编码表（92个字符）
static const char enctab[] = 
    "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`"
    "abcdefghijklmnopqrstuvwxyz{|}~";

// Base92解码表（256个条目，无效字符标记为0xFF）
static uint8_t dectab[256];

// 初始化解码表
void base92_init() {
    memset(dectab, 0xFF, sizeof(dectab)); // 初始化为0xFF（无效）
    for (uint8_t i = 0; i < 92; i++) {
        dectab[(uint8_t)enctab[i]] = i;
    }
}

// Base92编码函数
// 输入: in-二进制数据, len-输入长度
// 输出: out-编码结果（需预分配足够空间，建议长度 >= len*1.4）
// 返回: 编码后字符数
size_t base92_encode(const uint8_t *in, size_t len, uint8_t *out) {
    uint32_t acc = 0;   // 比特累加器
    uint32_t bits = 0;  // 当前比特数
    size_t out_pos = 0; // 输出位置
    size_t i = 0;       // 输入位置

    while (i < len || bits > 0) {
        // 填充比特（每次8位）
        if (i < len && bits <= 24) {
            acc |= (uint32_t)in[i++] << bits;
            bits += 8;
        }

        // 处理13位数据块
        if (bits >= 13) {
            uint32_t val = acc & 0x1FFF; // 取13位
            bits -= 13;
            acc >>= 13;
            
            // 输出两个字符
            out[out_pos++] = enctab[val % 92];
            out[out_pos++] = enctab[val / 92];
        } 
        // 处理剩余比特（<13位）
        else if (bits > 0) {
            uint32_t val = acc;
            out[out_pos++] = enctab[val % 92];
            // 判断是否需要第二个字符
            if (bits > 6 || val >= 92) {
                out[out_pos++] = enctab[val / 92];
            }
            bits = 0; // 清空剩余比特
        }
    }
    return out_pos;
}

// Base92解码函数
// 输入: in-编码数据, len-输入长度
// 输出: out-解码结果（需预分配足够空间，建议长度 >= len*0.75）
// 返回: 解码后字节数
size_t base92_decode(const uint8_t *in, size_t len, uint8_t *out) {
    uint32_t acc = 0;   // 比特累加器
    uint32_t bits = 0;  // 当前比特数
    int32_t db = -1;    // 字符对缓存（-1表示未存储）
    size_t out_pos = 0; // 输出位置

    for (size_t i = 0; i < len; i++) {
        uint8_t c = dectab[in[i]]; // 字符映射
        if (c == 0xFF) continue;   // 跳过无效字符

        if (db == -1) {
            db = c; // 存储第一个字符
        } else {
            // 组合两个字符（13位）
            uint32_t val = db + c * 92;
            acc = (acc << 13) | val;
            bits += 13;
            db = -1; // 重置缓存

            // 输出完整字节
            while (bits >= 8) {
                out[out_pos++] = (acc >> (bits - 8)) & 0xFF;
                bits -= 8;
            }
            acc &= (1U << bits) - 1; // 保留剩余比特
        }
    }

    // 处理最后一个字符（奇数长度）
    if (db != -1) {
        acc = (acc << 7) | db; // 视为7位数据
        bits += 7;
        while (bits >= 8) {
            out[out_pos++] = (acc >> (bits - 8)) & 0xFF;
            bits -= 8;
        }
    }
    return out_pos;
}
