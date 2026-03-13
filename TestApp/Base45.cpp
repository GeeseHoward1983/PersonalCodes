#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Base45字符集 (RFC 9285规范)
static const char BASE45_CHARSET[46] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";  // 45字符+终止符

// 解码查找表 (256字节)
static int8_t base45_decode_map[256] = {0};

// 初始化解码表 (线程安全)
static void init_base45_decode_map() {
    static volatile int initialized = 0;
    if (!initialized) {
        for (int i = 0; i < 256; i++) 
            base45_decode_map[i] = -1;
        
        for (int i = 0; i < 45; i++) 
            base45_decode_map[(uint8_t)BASE45_CHARSET[i]] = i;
        
        initialized = 1;
    }
}

/**
 * Base45编码 - 将二进制数据编码为Base45字符串
 * @param data 输入二进制数据
 * @param len  输入数据长度
 * @return     编码后的字符串 (需调用者释放内存), NULL表示失败
 */
char* base45_encode(const uint8_t* data, size_t len) {
    if (!data && len > 0) return NULL;
    
    // 计算输出缓冲区大小 (每2字节→3字符，单字节→2字符)
    size_t out_len = (len / 2) * 3 + (len % 2 ? 2 : 0);
    char* output = malloc(out_len + 1);  // +1 for null-terminator
    if (!output) return NULL;
    
    size_t out_pos = 0;
    const uint8_t* end = data + len;
    
    // 处理完整2字节组
    while (data + 2 <= end) {
        uint16_t value = (data[0] << 8) | data[1];
        output[out_pos++] = BASE45_CHARSET[value / (45*45)];
        output[out_pos++] = BASE45_CHARSET[(value / 45) % 45];
        output[out_pos++] = BASE45_CHARSET[value % 45];
        data += 2;
    }
    
    // 处理剩余单字节
    if (data < end) {
        output[out_pos++] = BASE45_CHARSET[*data / 45];
        output[out_pos++] = BASE45_CHARSET[*data % 45];
    }
    
    output[out_pos] = '\0';
    return output;
}

/**
 * Base45解码 - 将Base45字符串解码为二进制数据
 * @param str      输入Base45字符串
 * @param out_len  输出解码后的数据长度
 * @return         解码后的二进制数据 (需调用者释放内存), NULL表示失败
 */
uint8_t* base45_decode(const char* str, size_t* out_len) {
    if (!str || !out_len) return NULL;
    
    init_base45_decode_map();  // 确保解码表初始化
    size_t len = strlen(str);
    *out_len = 0;
    
    // 验证输入长度有效性 (RFC规范要求)
    if (len % 3 == 1) {
        fprintf(stderr, "[ERROR] Invalid Base45 length: %zu\n", len);
        return NULL;
    }
    
    // 计算输出缓冲区大小
    size_t data_len = (len / 3) * 2 + (len % 3 ? 1 : 0);
    uint8_t* data = malloc(data_len);
    if (!data) return NULL;
    
    size_t data_pos = 0;
    for (size_t i = 0; i < len; ) {
        uint32_t value = 0;
        uint8_t digit_count = 0;
        
        // 读取1-3个字符
        for (uint8_t j = 0; j < 3 && i < len; j++, i++) {
            int8_t digit = base45_decode_map[(uint8_t)str[i]];
            if (digit < 0) {
                fprintf(stderr, "[ERROR] Invalid character: %c\n", str[i]);
                free(data);
                return NULL;
            }
            value = value * 45 + digit;
            digit_count++;
        }
        
        // 处理解码值
        if (digit_count == 3) {
            if (value > 0xFFFF) {
                fprintf(stderr, "[ERROR] Value overflow: %u\n", value);
                free(data);
                return NULL;
            }
            data[data_pos++] = (value >> 8) & 0xFF;
            data[data_pos++] = value & 0xFF;
        } else if (digit_count == 2) {
            if (value > 0xFF) {
                fprintf(stderr, "[ERROR] Value overflow: %u\n", value);
                free(data);
                return NULL;
            }
            data[data_pos++] = value & 0xFF;
        }
    }
    
    *out_len = data_pos;
    return data;
}

// 测试用例
int main() {
    // 测试用例集
    struct test_case {
        const char* input;
        const char* expected;
    } tests[] = {
        {"Hello", "%69 VD92EX0"},
        {"", ""},
        {"A", "G8"},
        {"\x12\xAB\xFC", "1.0W"},
        {NULL, NULL}  // 哨兵值
    };
    
    printf("=== Base45 测试 ===\n");
    for (int i = 0; tests[i].input; i++) {
        size_t len = tests[i].input ? strlen(tests[i].input) : 0;
        
        // 编码测试
        char* encoded = base45_encode((uint8_t*)tests[i].input, len);
        printf("测试 %d:\n  输入: \"%s\"\n  编码: \"%s\"", 
               i+1, tests[i].input, encoded ? encoded : "(null)");
        
        // 验证编码结果
        if (encoded && strcmp(encoded, tests[i].expected) == 0) {
            printf(" \033[32m✓\033[0m");
        } else {
            printf(" \033[31m✗ (预期: %s)\033[0m", tests[i].expected);
        }
        
        // 解码测试
        if (encoded) {
            size_t decoded_len;
            uint8_t* decoded = base45_decode(encoded, &decoded_len);
            printf("\n  解码: \"%.*s\"", (int)decoded_len, decoded);
            
            // 验证解码结果
            if (decoded && memcmp(decoded, tests[i].input, len) == 0) {
                printf(" \033[32m✓\033[0m");
            } else {
                printf(" \033[31m✗\033[0m");
            }
            free(decoded);
        }
        
        printf("\n\n");
        free(encoded);
    }
    
    // 边界测试
    printf("=== 边界测试 ===\n");
    size_t len;
    uint8_t* data = base45_decode("Invalid$", &len);  // 包含非法字符
    if (!data) printf("非法字符测试: \033[32m通过\033[0m\n");
    
    data = base45_decode("ABC", &len);  // 有效长度
    free(data);
    
    data = base45_decode("AB", &len);   // 有效长度
    free(data);
    
    data = base45_decode("A", &len);    // 无效长度
    if (!data) printf("长度验证测试: \033[32m通过\033[0m\n");
    
    return 0;
}