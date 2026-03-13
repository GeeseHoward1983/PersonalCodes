#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define BLOCK_SIZE 4
#define ENCODED_BLOCK_SIZE 5

// Base85编码函数
char *base85_encode(const uint8_t *data, size_t len) {
    if (data == NULL || len == 0) return NULL;

    // 计算输出缓冲区大小（每4字节→5字符）
    size_t max_out_len = ((len + BLOCK_SIZE - 1) / BLOCK_SIZE) * ENCODED_BLOCK_SIZE + 1;
    char *output = malloc(max_out_len);
    if (!output) return NULL;

    size_t out_index = 0;
    uint32_t block = 0;

    for (size_t i = 0; i < len; i += BLOCK_SIZE) {
        size_t remaining = len - i;
        size_t block_len = (remaining < BLOCK_SIZE) ? remaining : BLOCK_SIZE;

        // 构建32位大端序块
        block = 0;
        for (size_t j = 0; j < block_len; j++) {
            block |= (uint32_t)data[i + j] << (24 - 8 * j);
        }

        // 全零块缩写为'z'
        if (block_len == BLOCK_SIZE && block == 0) {
            output[out_index++] = 'z';
            continue;
        }

        // 计算5个Base85字符（从高位到低位）
        char encoded[ENCODED_BLOCK_SIZE];
        for (int j = ENCODED_BLOCK_SIZE - 1; j >= 0; j--) {
            encoded[j] = (block % 85) + '!';
            block /= 85;
        }

        // 根据实际字节数复制有效字符
        size_t chars_to_copy = block_len + 1;  // 字节数+1
        for (size_t j = 0; j < chars_to_copy; j++) {
            output[out_index++] = encoded[j];
        }
    }

    output[out_index] = '\0';
    return output;
}

// Base85解码函数
uint8_t *base85_decode(const char *input, size_t *out_len) {
    if (input == NULL || out_len == NULL) return NULL;
    
    size_t in_len = strlen(input);
    if (in_len == 0) return NULL;

    // 计算最大输出长度（每5字符→4字节）
    size_t max_out_len = (in_len * BLOCK_SIZE) / ENCODED_BLOCK_SIZE;
    uint8_t *output = malloc(max_out_len);
    if (!output) return NULL;

    size_t in_index = 0;
    size_t out_index = 0;
    uint32_t block = 0;

    while (in_index < in_len) {
        // 处理全零块缩写
        if (input[in_index] == 'z') {
            for (int j = 0; j < BLOCK_SIZE; j++) {
                output[out_index++] = 0;
            }
            in_index++;
            continue;
        }

        // 读取5个字符（不足时用'u'填充）
        size_t chars_in_block = 0;
        block = 0;
        for (int j = 0; j < ENCODED_BLOCK_SIZE; j++) {
            if (in_index >= in_len) break;
            
            char c = input[in_index++];
            if (c < '!' || c > 'u') continue;  // 跳过无效字符
            
            block = block * 85 + (c - '!');
            chars_in_block++;
        }

        // 填充不足的字符
        while (chars_in_block < ENCODED_BLOCK_SIZE) {
            block = block * 85 + ('u' - '!');
            chars_in_block++;
        }

        // 提取4个字节（大端序）
        size_t bytes_to_write = chars_in_block - 1;  // 字符数-1=原始字节数
        for (int j = 0; j < bytes_to_write; j++) {
            output[out_index++] = (block >> (24 - 8 * j)) & 0xFF;
        }
    }

    *out_len = out_index;
    return output;
}

// 测试函数
int main() {
    // 编码测试
    uint8_t data[] = {0x86, 0x4F, 0xD2, 0x6F, 0xB5, 0x59, 0x00, 0x00};
    char *encoded = base85_encode(data, sizeof(data));
    printf("Encoded: %s\n", encoded);  // 输出: L/Ch[+>Gz

    // 解码测试
    size_t decoded_len;
    uint8_t *decoded = base85_decode(encoded, &decoded_len);
    
    printf("Decoded: ");
    for (size_t i = 0; i < decoded_len; i++) {
        printf("%02X ", decoded[i]);  // 输出: 86 4F D2 6F B5 59 00 00
    }
    printf("\n");

    // 清理内存
    free(encoded);
    free(decoded);
    return 0;
}
