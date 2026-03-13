#include <stdint.h>
#include <string.h>

// Base91编码表（91个字符）
static const char enctab[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "!#$%&()*+,./:;<=>?@[]^_`{|}~\"";

// Base91解码表（256个条目，无效字符标记为0xFF）
static uint8_t dectab[256];

// 初始化解码表（需在编解码前调用）
void base91_init() {
    memset(dectab, 0xFF, sizeof(dectab)); // 初始化为0xFF（无效）
    for (uint8_t i = 0; i < 91; i++) {
        dectab[(uint8_t)enctab[i]] = i;
    }
}

// Base91编码函数
// 输入: in-二进制数据, len-输入长度
// 输出: out-编码结果（需预分配足够空间，建议长度 >= len*1.3）
// 返回: 编码后字符数
size_t base91_encode(const uint8_t *in, size_t len, uint8_t *out) {
    uint32_t queue = 0; // 比特缓冲区
    uint32_t nbits = 0; // 缓冲区当前比特数
    size_t out_pos = 0; // 输出位置
    size_t i = 0;       // 输入位置

    while (i < len) {
        queue |= (uint32_t)in[i++] << nbits; // 读入8比特
        nbits += 8;

        if (nbits > 13) { // 缓冲区有足够比特
            uint32_t val = queue & 0x1FFF; // 取13位
            if (val <= 88) {   // 若≤88则取14位
                val = queue & 0x3FFF;
                queue >>= 14;
                nbits -= 14;
            } else {            // 否则取13位
                queue >>= 13;
                nbits -= 13;
            }
            // 输出两个字符（先余数后商）
            out[out_pos++] = enctab[val % 91];
            out[out_pos++] = enctab[val / 91];
        }
    }

    // 处理剩余比特
    if (nbits > 0) {
        out[out_pos++] = enctab[queue % 91];
        if (nbits > 7 || queue > 90) { // 需输出第二个字符
            out[out_pos++] = enctab[queue / 91];
        }
    }
    return out_pos;
}

// Base91解码函数
// 输入: in-编码数据, len-输入长度
// 输出: out-解码结果（需预分配足够空间，建议长度 >= len*0.8）
// 返回: 解码后字节数
size_t base91_decode(const uint8_t *in, size_t len, uint8_t *out) {
    uint32_t queue = 0; // 比特缓冲区
    uint32_t nbits = 0; // 缓冲区当前比特数
    int32_t val = -1;   // 当前字符组合值（-1表示未初始化）
    size_t out_pos = 0; // 输出位置

    for (size_t i = 0; i < len; i++) {
        uint8_t c = dectab[in[i]]; // 字符映射为值
        if (c == 0xFF) continue;   // 跳过无效字符

        if (val == -1) {
            val = c; // 第一个字符
        } else {
            val += c * 91; // 组合两个字符
            queue |= (uint32_t)val << nbits; // 存入缓冲区
            // 根据值决定读取比特数
            nbits += (val & 0x1FFF) > 88 ? 13 : 14;
            val = -1; // 重置组合值

            // 输出完整字节
            while (nbits >= 8) {
                out[out_pos++] = queue & 0xFF;
                queue >>= 8;
                nbits -= 8;
            }
        }
    }

    // 处理最后一个字符（奇数长度）
    if (val != -1) {
        queue |= (uint32_t)val << nbits;
        nbits += 7; // 补足7位
        while (nbits >= 8) {
            out[out_pos++] = queue & 0xFF;
            queue >>= 8;
            nbits -= 8;
        }
    }
    return out_pos;
}
