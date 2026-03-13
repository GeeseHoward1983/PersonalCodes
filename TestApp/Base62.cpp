#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

// Base62字符集 (0-9, A-Z, a-z)
static const char BASE62_CHARSET[63] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

// 解码查找表 (256字节)
static int8_t base62_decode_map[256] = {0};

// 初始化解码表 (线程安全)
static void init_base62_decode_map() {
    static volatile int initialized = 0;
    if (!initialized) {
        // 初始化无效字符为-1
        memset(base62_decode_map, -1, sizeof(base62_decode_map));
        
        // 填充有效字符映射
        for (int i = 0; i < 62; i++) {
            uint8_t ascii = (uint8_t)BASE62_CHARSET[i];
            base62_decode_map[ascii] = i;
        }
        initialized = 1;
    }
}

/**
 * Base62编码 - 将二进制数据编码为Base62字符串
 * @param data 输入二进制数据
 * @param len  输入数据长度
 * @return     编码后的字符串 (需调用者释放内存), NULL表示失败
 */
char* base62_encode(const uint8_t* data, size_t len) {
    if (!data && len > 0) return NULL;
    if (len == 0) return strdup("");  // 空输入返回空字符串

    // 计算最大输出长度 (ceil(len * 8 / log2(62)) ≈ len * 1.34 + 1)
    size_t max_out_len = (size_t)ceil(len * 1.34) + 12;
    char* output = malloc(max_out_len);
    if (!output) return NULL;

    size_t out_pos = 0;
    uint32_t buffer = 0;
    int bits_in_buffer = 0;

    for (size_t i = 0; i < len; i++) {
        // 将新字节移入缓冲区
        buffer = (buffer << 8) | data[i];
        bits_in_buffer += 8;
        
        // 当缓冲区有至少6位时处理
        while (bits_in_buffer >= 6) {
            // 提取高6位
            uint8_t index = (buffer >> (bits_in_buffer - 6)) & 0x3F;
            bits_in_buffer -= 6;
            
            // 添加到输出
            output[out_pos++] = BASE62_CHARSET[index];
        }
    }

    // 处理剩余位
    if (bits_in_buffer > 0) {
        // 左对齐剩余位并取高6位
        uint8_t index = (buffer << (6 - bits_in_buffer)) & 0x3F;
        output[out_pos++] = BASE62_CHARSET[index];
    }

    output[out_pos] = '\0';  // 终止字符串
    return output;
}

/**
 * Base62解码 - 将Base62字符串解码为二进制数据
 * @param str      输入Base62字符串
 * @param out_len  输出解码后的数据长度
 * @return         解码后的二进制数据 (需调用者释放内存), NULL表示失败
 */
uint8_t* base62_decode(const char* str, size_t* out_len) {
    if (!str || !out_len) return NULL;
    
    init_base62_decode_map();  // 确保解码表初始化
    size_t len = strlen(str);
    *out_len = 0;
    
    if (len == 0) {
        uint8_t* data = malloc(1);
        if (data) *data = '\0';
        return data;  // 空输入返回空缓冲区
    }

    // 计算最大输出长度 (ceil(len * log2(62) / 8) ≈ len * 0.75)
    size_t max_data_len = (size_t)ceil(len * 0.75) + 4;
    uint8_t* data = malloc(max_data_len);
    if (!data) return NULL;
    
    uint32_t buffer = 0;
    int bits_in_buffer = 0;
    size_t data_pos = 0;

    for (size_t i = 0; i < len; i++) {
        int8_t value = base62_decode_map[(uint8_t)str[i]];
        if (value < 0) {  // 无效字符检查
            fprintf(stderr, "[ERROR] Invalid Base62 character: %c\n", str[i]);
            free(data);
            *out_len = 0;
            return NULL;
        }
        
        // 将新值移入缓冲区
        buffer = (buffer << 6) | value;
        bits_in_buffer += 6;
        
        // 当缓冲区有至少8位时处理
        if (bits_in_buffer >= 8) {
            // 提取高8位
            uint8_t byte = (buffer >> (bits_in_buffer - 8)) & 0xFF;
            bits_in_buffer -= 8;
            
            // 添加到输出
            data[data_pos++] = byte;
        }
    }

    // 验证剩余位 (必须为0)
    if (bits_in_buffer > 0) {
        // 检查剩余位是否非零
        uint8_t mask = (1 << bits_in_buffer) - 1;
        if ((buffer & mask) != 0) {
            fprintf(stderr, "[ERROR] Non-zero padding bits\n");
            free(data);
            *out_len = 0;
            return NULL;
        }
    }
    
    *out_len = data_pos;
    return data;
}

// ===================== 测试工具函数 =====================
static int test_encode_decode(const char* input) {
    size_t len = input ? strlen(input) : 0;
    printf("测试: \"%s\"\n", input ? input : "(null)");
    
    // 编码
    char* encoded = base62_encode((uint8_t*)input, len);
    if (!encoded) {
        printf("  编码失败!\n");
        return 0;
    }
    printf("  编码: %s\n", encoded);
    
    // 解码
    size_t decoded_len;
    uint8_t* decoded = base62_decode(encoded, &decoded_len);
    
    int success = 0;
    if (decoded) {
        success = (len == decoded_len) && 
                 (len == 0 || memcmp(input, decoded, len) == 0);
        printf("  解码: %.*s\n", (int)decoded_len, decoded);
        free(decoded);
    } else {
        printf("  解码失败!\n");
    }
    
    free(encoded);
    printf("  结果: %s\n\n", success ? "✓ 成功" : "✗ 失败");
    return success;
}

static void boundary_tests() {
    printf("=== 边界测试 ===\n");
    
    // 测试1: 空输入
    test_encode_decode("");
    
    // 测试2: 单字节
    test_encode_decode("A");
    test_encode_decode("\0");
    
    // 测试3: 特殊字符
    test_encode_decode("Hello World!");
    test_encode_decode("123!@#$%^&*()");
    
    // 测试4: 二进制数据
    uint8_t binary_data[] = {0x00, 0xFF, 0x55, 0xAA};
    char* encoded = base62_encode(binary_data, sizeof(binary_data));
    printf("二进制测试:\n  输入: [0x00, 0xFF, 0x55, 0xAA]\n  编码: %s\n", encoded);
    
    size_t decoded_len;
    uint8_t* decoded = base62_decode(encoded, &decoded_len);
    if (decoded) {
        int match = (decoded_len == sizeof(binary_data)) && 
                   (memcmp(binary_data, decoded, sizeof(binary_data)) == 0);
        printf("  解码: [");
        for (size_t i = 0; i < decoded_len; i++) {
            printf("0x%02X%s", decoded[i], (i < decoded_len-1) ? ", " : "");
        }
        printf("]\n  结果: %s\n", match ? "✓ 成功" : "✗ 失败");
        free(decoded);
    }
    free(encoded);
    
    // 测试5: 无效输入
    printf("\n无效输入测试:\n");
    const char* invalid_str = "Hello@World";  // @ 不是Base62字符
    size_t decoded_size;
    uint8_t* result = base62_decode(invalid_str, &decoded_size);
    if (!result) {
        printf("  无效字符处理: ✓ 成功\n");
    } else {
        printf("  无效字符处理: ✗ 失败\n");
        free(result);
    }
}

// 主测试函数
int main() {
    int success_count = 0;
    int total_tests = 0;
    
    // 基础测试用例
    const char* test_cases[] = {
        "",
        "a",
        "abc",
        "1234567890",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "abcdefghijklmnopqrstuvwxyz",
        "The quick brown fox jumps over the lazy dog",
        NULL
    };
    
    printf("=== Base62 编码/解码测试 ===\n");
    for (int i = 0; test_cases[i]; i++) {
        success_count += test_encode_decode(test_cases[i]);
        total_tests++;
    }
    
    // 运行边界测试
    boundary_tests();
    
    printf("\n测试结果: %d/%d 通过\n", success_count, total_tests);
    return success_count == total_tests ? 0 : 1;
}
