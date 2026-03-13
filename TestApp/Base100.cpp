#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

// Base100字符集 - 256个Emoji表情（每个4字节UTF-8编码）
static const char* const BASE100_EMOJIS[256] = {
    "🐀", "🐁", "🐂", "🐃", "🐄", "🐅", "🐆", "🐇", "🐈", "🐉", "🐊", "🐋", "🐌", "🐍", "🐎", "🐏",
    "🐐", "🐑", "🐒", "🐓", "🐔", "🐕", "🐖", "🐗", "🐘", "🐙", "🐚", "🐛", "🐜", "🐝", "🐞", "🐟",
    "🐠", "🐡", "🐢", "🐣", "🐤", "🐥", "🐦", "🐧", "🐨", "🐩", "🐪", "🐫", "🐬", "🐭", "🐮", "🐯",
    "🐰", "🐱", "🐲", "🐳", "🐴", "🐵", "🐶", "🐷", "🐸", "🐹", "🐺", "🐻", "🐼", "🐽", "🐾", "🐿",
    "👀", "👁", "👂", "👃", "👄", "👅", "👆", "👇", "👈", "👉", "👊", "👋", "👌", "👍", "👎", "👏",
    "👐", "👑", "👒", "👓", "👔", "👕", "👖", "👗", "👘", "👙", "👚", "👛", "👜", "👝", "👞", "👟",
    "👠", "👡", "👢", "👣", "👤", "👥", "👦", "👧", "👨", "👩", "👪", "👫", "👬", "👭", "👮", "👯",
    "👰", "👱", "👲", "👳", "👴", "👵", "👶", "👷", "👸", "👹", "👺", "👻", "👼", "👽", "👾", "👿",
    "💀", "💁", "💂", "💃", "💄", "💅", "💆", "💇", "💈", "💉", "💊", "💋", "💌", "💍", "💎", "💏",
    "💐", "💑", "💒", "💓", "💔", "💕", "💖", "💗", "💘", "💙", "💚", "💛", "💜", "💝", "💞", "💟",
    "💠", "💡", "💢", "💣", "💤", "💥", "💦", "💧", "💨", "💩", "💪", "💫", "💬", "💭", "💮", "💯",
    "💰", "💱", "💲", "💳", "💴", "💵", "💶", "💷", "💸", "💹", "💺", "💻", "💼", "💽", "💾", "💿",
    "📀", "📁", "📂", "📃", "📄", "📅", "📆", "📇", "📈", "📉", "📊", "📋", "📌", "📍", "📎", "📏",
    "📐", "📒", "📓", "📔", "📕", "📖", "📗", "📘", "📙", "📚", "📛", "📜", "📝", "📞", "📟", "📠",
    "📡", "📢", "📣", "📤", "📥", "📦", "📧", "📨", "📩", "📪", "📫", "📬", "📭", "📮", "📯", "📰",
    "📱", "📲", "📳", "📴", "📵", "📶", "📷", "📸", "📹", "📺", "📻", "📼", "📽", "📿", "🔀", "🔁"
};

// 解码映射表（Emoji到字节值的映射）
static uint8_t base100_decode_map[256][256] = {0};
static bool decode_map_initialized = false;

// 初始化解码映射表
static void init_decode_map() {
    if (decode_map_initialized) return;
    
    for (int i = 0; i < 256; i++) {
        const char* emoji = BASE100_EMOJIS[i];
        // 使用前4个字节作为键（Emoji通常是4字节UTF-8）
        uint32_t key = (emoji[0] << 24) | (emoji[1] << 16) | (emoji[2] << 8) | emoji[3];
        int index = key & 0xFF; // 使用低8位作为索引
        
        // 存储字节值
        base100_decode_map[index][0] = (key >> 24) & 0xFF;
        base100_decode_map[index][1] = (key >> 16) & 0xFF;
        base100_decode_map[index][2] = (key >> 8) & 0xFF;
        base100_decode_map[index][3] = key & 0xFF;
        base100_decode_map[index][4] = i; // 存储原始字节值
    }
    
    decode_map_initialized = true;
}

/**
 * Base100编码 - 将二进制数据编码为Emoji字符串
 * @param data 输入二进制数据
 * @param len  输入数据长度
 * @return     编码后的Emoji字符串 (需调用者释放内存), NULL表示失败
 */
char* base100_encode(const uint8_t* data, size_t len) {
    if (!data && len > 0) return NULL;
    
    // 每个字节编码为4字节的Emoji + 1字节分隔符（可选）
    size_t out_len = len * 4 + 1; // +1 for null-terminator
    char* output = malloc(out_len);
    if (!output) return NULL;
    
    size_t out_pos = 0;
    for (size_t i = 0; i < len; i++) {
        const char* emoji = BASE100_EMOJIS[data[i]];
        // 复制Emoji的4个字节
        memcpy(output + out_pos, emoji, 4);
        out_pos += 4;
    }
    
    output[out_pos] = '\0'; // 终止字符串
    return output;
}

/**
 * Base100解码 - 将Emoji字符串解码为二进制数据
 * @param str      输入Base100字符串
 * @param out_len  输出解码后的数据长度
 * @return         解码后的二进制数据 (需调用者释放内存), NULL表示失败
 */
uint8_t* base100_decode(const char* str, size_t* out_len) {
    if (!str || !out_len) return NULL;
    
    init_decode_map(); // 确保解码表初始化
    
    size_t len = strlen(str);
    if (len == 0) {
        *out_len = 0;
        return malloc(0); // 返回空缓冲区
    }
    
    // 验证长度有效性（必须是4的倍数）
    if (len % 4 != 0) {
        fprintf(stderr, "[ERROR] Invalid Base100 length: %zu (must be multiple of 4)\n", len);
        *out_len = 0;
        return NULL;
    }
    
    size_t data_len = len / 4;
    uint8_t* data = malloc(data_len);
    if (!data) return NULL;
    
    size_t data_pos = 0;
    for (size_t i = 0; i < len; i += 4) {
        // 构建Emoji的4字节键
        uint32_t key = ((uint32_t)(uint8_t)str[i] << 24) |
                       ((uint32_t)(uint8_t)str[i+1] << 16) |
                       ((uint32_t)(uint8_t)str[i+2] << 8) |
                       (uint8_t)str[i+3];
        
        // 使用低8位作为索引
        int index = key & 0xFF;
        
        // 验证Emoji是否匹配
        if (base100_decode_map[index][0] == (key >> 24) &&
            base100_decode_map[index][1] == ((key >> 16) & 0xFF) &&
            base100_decode_map[index][2] == ((key >> 8) & 0xFF) &&
            base100_decode_map[index][3] == (key & 0xFF)) {
            
            data[data_pos++] = base100_decode_map[index][4];
        } else {
            fprintf(stderr, "[ERROR] Invalid Emoji sequence at position %zu\n", i);
            free(data);
            *out_len = 0;
            return NULL;
        }
    }
    
    *out_len = data_pos;
    return data;
}

// ===================== 测试工具函数 =====================
static void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: [", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
        if (i < len - 1) printf(" ");
    }
    printf("]\n");
}

static void test_encode_decode(const uint8_t* input, size_t len) {
    printf("测试: ");
    if (len == 0) {
        printf("(空输入)");
    } else if (len < 16) {
        // 尝试作为字符串打印
        int printable = 1;
        for (size_t i = 0; i < len; i++) {
            if (input[i] < 32 || input[i] > 126) printable = 0;
        }
        
        if (printable) {
            printf("\"%.*s\"", (int)len, (const char*)input);
        } else {
            print_hex("二进制数据", input, len);
        }
    } else {
        printf("(%zu字节数据)", len);
    }
    printf("\n");
    
    // 编码
    char* encoded = base100_encode(input, len);
    if (encoded) {
        printf("  编码: %s\n", encoded);
    } else {
        printf("  编码失败!\n");
        return;
    }
    
    // 解码
    size_t decoded_len;
    uint8_t* decoded = base100_decode(encoded, &decoded_len);
    
    if (decoded) {
        if (len == decoded_len && (len == 0 || memcmp(input, decoded, len) == 0)) {
            printf("  解码: ");
            if (len == 0) {
                printf("(空)");
            } else if (len < 16) {
                int printable = 1;
                for (size_t i = 0; i < len; i++) {
                    if (decoded[i] < 32 || decoded[i] > 126) printable = 0;
                }
                
                if (printable) {
                    printf("\"%.*s\"", (int)len, (const char*)decoded);
                } else {
                    print_hex("二进制数据", decoded, len);
                }
            } else {
                printf("(%zu字节数据)", len);
            }
            printf(" \033[32m✓ 成功\033[0m\n");
        } else {
            printf("  解码结果不匹配!\n");
            print_hex("  预期", input, len);
            print_hex("  实际", decoded, decoded_len);
        }
        free(decoded);
    } else {
        printf("  解码失败!\n");
    }
    
    free(encoded);
    printf("\n");
}

static void run_tests() {
    printf("=== Base100 编码/解码测试 ===\n\n");
    
    // 测试用例1: 空输入
    test_encode_decode(NULL, 0);
    
    // 测试用例2: 简单文本
    const char* text1 = "Hello";
    test_encode_decode((const uint8_t*)text1, strlen(text1));
    
    // 测试用例3: 单个字节
    uint8_t single_byte = 0xAB;
    test_encode_decode(&single_byte, 1);
    
    // 测试用例4: 二进制数据
    uint8_t binary_data[] = {0x00, 0xFF, 0x55, 0xAA, 0x01, 0x02, 0x80, 0x7F};
    test_encode_decode(binary_data, sizeof(binary_data));
    
    // 测试用例5: 长文本
    const char* long_text = "Base100编码将数据转换为Emoji表情符号，适用于趣味性数据传输";
    test_encode_decode((const uint8_t*)long_text, strlen(long_text));
    
    // 边界测试
    printf("=== 边界测试 ===\n\n");
    
    // 测试1: 无效长度
    const char* invalid_length = "🐀🐁"; // 只有2个字节
    size_t decoded_len;
    uint8_t* result = base100_decode(invalid_length, &decoded_len);
    if (!result) {
        printf("无效长度测试: \033[32m通过\033[0m\n");
    } else {
        printf("无效长度测试: \033[31m失败\033[0m\n");
        free(result);
    }
    
    // 测试2: 无效Emoji
    const char* invalid_emoji = "ABCD"; // 不是有效的Emoji
    result = base100_decode(invalid_emoji, &decoded_len);
    if (!result) {
        printf("无效Emoji测试: \033[32m通过\033[0m\n");
    } else {
        printf("无效Emoji测试: \033[31m失败\033[0m\n");
        free(result);
    }
    
    // 测试3: 最大字节值
    uint8_t max_byte = 0xFF;
    test_encode_decode(&max_byte, 1);
    
    // 测试4: 最小字节值
    uint8_t min_byte = 0x00;
    test_encode_decode(&min_byte, 1);
    
    printf("\n测试完成\n");
}

int main() {
    run_tests();
    return 0;
}
