#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

/**
 * ROT13编码/解码函数
 * ROT13是一种简单的替换密码，将每个字母旋转13位：
 *   A → N, B → O, ..., M → Z
 *   N → A, O → B, ..., Z → M
 *   a → n, b → o, ..., m → z
 *   n → a, o → b, ..., z → m
 * 
 * 注意：ROT13是对称密码，编码和解码使用相同的算法
 * 
 * @param input 输入字符串
 * @return 转换后的新字符串（需调用者释放内存）
 */
char* rot13_transform(const char* input) {
    if (!input) return NULL;
    
    size_t len = strlen(input);
    char* output = malloc(len + 1);  // +1 for null terminator
    if (!output) return NULL;
    
    for (size_t i = 0; i < len; i++) {
        unsigned char c = input[i];
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            // 应用ROT13转换
            output[i] = ((c - base + 13) % 26) + base;
        } else {
            // 非字母字符保持不变
            output[i] = c;
        }
    }
    output[len] = '\0';
    return output;
}

// 为清晰起见定义别名
#define rot13_encode(input) rot13_transform(input)
#define rot13_decode(input) rot13_transform(input)

// ===================== 测试工具函数 =====================
static void run_test(const char* test_name, const char* input, const char* expected) {
    printf("测试 '%s':\n  输入: \"%s\"\n", test_name, input);
    
    char* result = rot13_transform(input);
    if (!result) {
        printf("  \033[31m错误: 内存分配失败\033[0m\n\n");
        return;
    }
    
    bool success = strcmp(result, expected) == 0;
    printf("  结果: \"%s\"\n  预期: \"%s\"\n", result, expected);
    printf("  %s\n\n", success ? 
        "\033[32m✓ 通过\033[0m" : "\033[31m✗ 失败\033[0m");
    
    free(result);
}

static void run_round_trip_test(const char* test_name, const char* input) {
    printf("往返测试 '%s':\n  原始: \"%s\"\n", test_name, input);
    
    // 编码
    char* encoded = rot13_encode(input);
    if (!encoded) {
        printf("  \033[31m错误: 编码内存分配失败\033[0m\n\n");
        return;
    }
    printf("  编码后: \"%s\"\n", encoded);
    
    // 解码
    char* decoded = rot13_decode(encoded);
    if (!decoded) {
        printf("  \033[31m错误: 解码内存分配失败\033[0m\n\n");
        free(encoded);
        return;
    }
    printf("  解码后: \"%s\"\n", decoded);
    
    // 验证
    bool success = strcmp(input, decoded) == 0;
    printf("  %s\n\n", success ? 
        "\033[32m✓ 通过\033[0m" : "\033[31m✗ 失败\033[0m");
    
    free(encoded);
    free(decoded);
}

static void boundary_tests() {
    printf("=== 边界测试 ===\n");
    
    // 测试1: 空输入
    run_test("空输入", "", "");
    
    // 测试2: 全字母
    run_test("全大写字母", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "NOPQRSTUVWXYZABCDEFGHIJKLM");
    run_test("全小写字母", "abcdefghijklmnopqrstuvwxyz", "nopqrstuvwxyzabcdefghijklm");
    
    // 测试3: 无字母
    run_test("无字母", "12345!@#$%", "12345!@#$%");
    
    // 测试4: 混合内容
    run_test("混合内容", "Hello World! 123", "Uryyb Jbeyq! 123");
    
    // 测试5: 边界字母
    run_test("边界字母", "AMNZamzn", "NZMANzam");
    
    // 测试6: NULL输入
    char* result = rot13_transform(NULL);
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
    run_round_trip_test("简单文本", "ROT13 is fun!");
    run_round_trip_test("混合内容", "User123: Password456!");
    run_round_trip_test("特殊字符", "Hello! @#$%^&*()_+");
    run_round_trip_test("边界值", "AzaZ");
    run_round_trip_test("长文本", "The quick brown fox jumps over the lazy dog. 1234567890");
    printf("\n");
}

static void performance_test() {
    printf("=== 性能测试 ===\n");
    
    // 创建长字符串 (1MB)
    const size_t size = 1024 * 1024;
    char* long_str = malloc(size + 1);
    if (!long_str) {
        printf("内存分配失败\n");
        return;
    }
    
    // 填充字母和数字
    for (size_t i = 0; i < size; i++) {
        long_str[i] = (i % 62 < 26) ? 'A' + (i % 26) : 
                     (i % 62 < 52) ? 'a' + (i % 26) : 
                     '0' + (i % 10);
    }
    long_str[size] = '\0';
    
    printf("测试字符串长度: %zu MB\n", size / (1024 * 1024));
    
    // 执行转换
    clock_t start = clock();
    char* transformed = rot13_transform(long_str);
    clock_t end = clock();
    
    if (transformed) {
        double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
        printf("处理时间: %.4f 秒\n", elapsed);
        printf("吞吐量: %.2f MB/s\n", (size / (1024.0 * 1024.0)) / elapsed);
        
        // 验证往返转换
        char* roundtrip = rot13_transform(transformed);
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
    printf("=====================\n");
    printf("  ROT13 编码/解码测试\n");
    printf("=====================\n\n");
    
    // 基础功能测试
    printf("=== 基础功能测试 ===\n");
    run_test("A → N", "A", "N");
    run_test("N → A", "N", "A");
    run_test("a → n", "a", "n");
    run_test("z → m", "z", "m");
    run_test("Hello → Uryyb", "Hello", "Uryyb");
    run_test("Uryyb → Hello", "Uryyb", "Hello");
    run_test("数字不变", "12345", "12345");
    run_test("特殊字符不变", "!@#$%", "!@#$%");
    
    // 边界测试
    boundary_tests();
    
    // 往返测试
    round_trip_tests();
    
    // 性能测试
    performance_test();
    
    printf("测试完成\n");
    return 0;
}
