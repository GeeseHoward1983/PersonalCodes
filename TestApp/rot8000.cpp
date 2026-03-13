#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <locale.h>
#include <wchar.h>
#include <uchar.h>

// ROT8000常量
#define ROT8000_SHIFT 0x8000
#define UNICODE_MAX 0x10FFFF

/**
 * ROT8000编码/解码函数
 * 将每个Unicode码点旋转32768个位置（0x8000）
 * 旋转后仍在有效Unicode范围内（0x0-0x10FFFF）
 * 
 * 注意：ROT8000是对称密码，编码和解码使用相同的算法
 * 
 * @param input 输入UTF-8字符串
 * @return 转换后的新字符串（需调用者释放内存）
 */
char* rot8000_transform(const char* input) {
    if (!input) return NULL;
    
    // 获取输入长度
    size_t len = strlen(input);
    if (len == 0) return strdup("");
    
    // 创建输出缓冲区（足够大）
    size_t max_out_size = len * 4 + 1; // 最坏情况：每个字符4字节
    char* output = malloc(max_out_size);
    if (!output) return NULL;
    
    // 设置Unicode环境
    setlocale(LC_ALL, "en_US.UTF-8");
    
    // 转换状态
    mbstate_t ps = {0};
    const char* p = input;
    char* out_ptr = output;
    
    while (*p != '\0') {
        // 解码下一个Unicode码点
        char32_t codepoint;
        size_t bytes_consumed = mbrtoc32(&codepoint, p, MB_CUR_MAX, &ps);
        
        if (bytes_consumed == (size_t)-1 || bytes_consumed == (size_t)-2) {
            // 无效序列处理：直接复制字节
            *out_ptr++ = *p++;
            continue;
        }
        
        if (bytes_consumed == 0) break; // 空字符
        
        // 应用ROT8000转换
        if (codepoint <= UNICODE_MAX) {
            codepoint = (codepoint + ROT8000_SHIFT) % (UNICODE_MAX + 1);
        }
        
        // 重新编码为UTF-8
        char temp[MB_CUR_MAX];
        mbstate_t out_ps = {0};
        size_t bytes_written = c32rtomb(temp, codepoint, &out_ps);
        
        if (bytes_written != (size_t)-1) {
            memcpy(out_ptr, temp, bytes_written);
            out_ptr += bytes_written;
        }
        
        p += bytes_consumed;
    }
    
    *out_ptr = '\0'; // 终止字符串
    
    // 优化内存使用
    size_t actual_len = out_ptr - output;
    char* final_output = realloc(output, actual_len + 1);
    return final_output ? final_output : output;
}

// 为清晰起见定义别名
#define rot8000_encode(input) rot8000_transform(input)
#define rot8000_decode(input) rot8000_transform(input)

// ===================== 测试工具函数 =====================
static void print_hex(const char* str) {
    printf("十六进制: ");
    for (const char* p = str; *p; p++) {
        printf("%02X ", (unsigned char)*p);
    }
    printf("\n");
}

static bool run_test(const char* test_name, const char* input, const char* expected) {
    printf("测试 '%s':\n  输入: \"%s\"\n", test_name, input);
    
    char* result = rot8000_transform(input);
    if (!result) {
        printf("  \033[31m错误: 内存分配失败\033[0m\n\n");
        return false;
    }
    
    bool success = strcmp(result, expected) == 0;
    printf("  结果: \"%s\"\n", result);
    
    if (expected) {
        printf("  预期: \"%s\"\n", expected);
        printf("  %s\n", success ? "\033[32m✓ 通过\033[0m" : "\033[31m✗ 失败\033[0m");
    } else {
        printf("  预期: (未知)\n");
        print_hex(result);
    }
    
    free(result);
    printf("\n");
    return success;
}

static bool run_round_trip_test(const char* test_name, const char* input) {
    printf("往返测试 '%s':\n  原始: \"%s\"\n", test_name, input);
    
    // 编码
    char* encoded = rot8000_encode(input);
    if (!encoded) {
        printf("  \033[31m错误: 编码内存分配失败\033[0m\n\n");
        return false;
    }
    printf("  编码后: \"%s\"\n", encoded);
    
    // 解码
    char* decoded = rot8000_decode(encoded);
    if (!decoded) {
        printf("  \033[31m错误: 解码内存分配失败\033[0m\n\n");
        free(encoded);
        return false;
    }
    printf("  解码后: \"%s\"\n", decoded);
    
    // 验证
    bool success = strcmp(input, decoded) == 0;
    printf("  %s\n\n", success ? 
        "\033[32m✓ 通过\033[0m" : "\033[31m✗ 失败\033[0m");
    
    free(encoded);
    free(decoded);
    return success;
}

static void boundary_tests() {
    printf("=== 边界测试 ===\n");
    
    // 测试1: 空输入
    run_test("空输入", "", "");
    
    // 测试2: ASCII字符
    run_test("ASCII字符", "Hello", "䄁䄂䄃䄃䄄");
    
    // 测试3: 基本多语言平面边界
    run_test("BMP最小值", "A", "䐀");
    run_test("BMP最大值", "￿", "\xF0\x90\x80\x80"); // U+10000
    
    // 测试4: Unicode边界
    run_test("Unicode最小值", "\0", "");
    run_test("Unicode最大值", "\xF4\x8F\xBF\xBF", "䐀"); // U+10FFFF -> U+8000
    
    // 测试5: 混合内容
    run_test("混合内容", "Hello 世界! 123", "䄁䄂䄃䄃䄄 䔀䔁䔂! `ab");
    
    // 测试6: NULL输入
    char* result = rot8000_transform(NULL);
    if (result == NULL) {
        printf("NULL输入测试: \033[32m✓ 通过 (返回NULL)\033[0m\n");
    } else {
        printf("NULL输入测试: \033[31m✗ 失败 (应返回NULL)\033[0m\n");
        free(result);
    }
    
    printf("\n");
}

static void round_trip_tests() {
    printf("=== 往返测试 ===\n");
    run_round_trip_test("ASCII文本", "ROT8000 is powerful!");
    run_round_trip_test("中文文本", "你好，世界！");
    run_round_trip_test("日文文本", "こんにちは世界");
    run_round_trip_test("韩文文本", "안녕하세요 세계");
    run_round_trip_test("表情符号", "😀🌟🚀🎉");
    run_round_trip_test("混合内容", "Hello 世界! 123 @#$% 😊");
    run_round_trip_test("特殊字符", "ΓΔΘΛΞΠΣΦΨΩ");
    run_round_trip_test("长文本", "ROT8000是一种基于Unicode的旋转密码，将字符旋转32768个位置，支持整个Unicode字符集。");
    printf("\n");
}

static void performance_test() {
    printf("=== 性能测试 ===\n");
    
    // 创建长字符串 (100KB)
    const size_t size = 100 * 1024;
    char* long_str = malloc(size + 1);
    if (!long_str) {
        printf("内存分配失败\n");
        return;
    }
    
    // 填充混合字符 (ASCII、中文、表情符号)
    for (size_t i = 0; i < size; ) {
        int type = i % 5;
        if (type == 0) {
            // ASCII
            long_str[i++] = 'A' + (rand() % 26);
        } else if (type == 1) {
            // 中文 (UTF-8)
            if (size - i >= 3) {
                long_str[i++] = 0xE4;
                long_str[i++] = 0xB8 + (rand() % 16);
                long_str[i++] = 0x80 + (rand() % 64);
            }
        } else if (type == 2) {
            // 表情符号 (UTF-8)
            if (size - i >= 4) {
                long_str[i++] = 0xF0;
                long_str[i++] = 0x9F;
                long_str[i++] = 0x80 + (rand() % 64);
                long_str[i++] = 0x80 + (rand() % 64);
            }
        } else {
            // 其他字符
            long_str[i++] = 33 + (rand() % 94);
        }
    }
    long_str[size] = '\0';
    
    printf("测试字符串长度: %zu KB\n", size / 1024);
    
    // 执行转换
    clock_t start = clock();
    char* transformed = rot8000_transform(long_str);
    clock_t end = clock();
    
    if (transformed) {
        double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
        printf("处理时间: %.4f 秒\n", elapsed);
        printf("吞吐量: %.2f KB/s\n", (size / 1024.0) / elapsed);
        
        // 验证往返转换
        char* roundtrip = rot8000_transform(transformed);
        if (roundtrip) {
            bool success = strcmp(long_str, roundtrip) == 0;
            printf("往返验证: %s\n", success ? 
                "\033[32m✓ 成功\033[0m" : "\033[31m✗ 失败\033[0m");
            free(roundtrip);
        }
        free(transformed);
    }
    
    free(long_str);
    printf("\n");
}

// 主测试函数
int main() {
    setlocale(LC_ALL, "en_US.UTF-8"); // 设置Unicode环境
    
    printf("================================\n");
    printf("        ROT8000 编码/解码测试\n");
    printf("================================\n\n");
    
    // 基础功能测试
    printf("=== 基础功能测试 ===\n");
    run_test("A → U+8000", "A", "䀀");
    run_test("U+8000 → A", "䀀", "A");
    run_test("中文测试", "中", "蠀");
    run_test("表情符号测试", "😊", "🀀");
    run_test("数字测试", "123", "`ab");
    
    // 边界测试
    boundary_tests();
    
    // 往返测试
    round_trip_tests();
    
    // 性能测试
    performance_test();
    
    // 实用示例
    printf("=== 实用示例 ===\n");
    const char* sensitive = "敏感数据: 用户名=admin, 密码=Secret123! 😊";
    char* encoded = rot8000_encode(sensitive);
    printf("原始敏感数据: \"%s\"\n", sensitive);
    printf("ROT8000编码后: \"%s\"\n", encoded);
    
    char* decoded = rot8000_decode(encoded);
    printf("解码恢复后: \"%s\"\n", decoded);
    
    free(encoded);
    free(decoded);
    
    printf("\n测试完成\n");
    return 0;
}
