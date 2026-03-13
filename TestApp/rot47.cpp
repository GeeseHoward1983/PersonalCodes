#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <time.h>

/**
 * ROT47编码/解码函数
 * ROT47对所有可打印ASCII字符（33-126）进行47位旋转：
 *   ! → P, " → Q, # → R, ..., ~ → }
 *   旋转后仍在33-126范围内
 * 
 * 注意：ROT47是对称密码，编码和解码使用相同的算法
 * 
 * @param input 输入字符串
 * @return 转换后的新字符串（需调用者释放内存）
 */
char* rot47_transform(const char* input) {
    if (!input) return NULL;
    
    size_t len = strlen(input);
    char* output = malloc(len + 1);  // +1 for null terminator
    if (!output) return NULL;
    
    for (size_t i = 0; i < len; i++) {
        unsigned char c = input[i];
        // 仅处理33-126范围内的可打印ASCII字符
        if (c >= 33 && c <= 126) {
            // 应用ROT47转换
            output[i] = 33 + ((c - 33 + 47) % 94);
        } else {
            // 非可打印字符保持不变
            output[i] = c;
        }
    }
    output[len] = '\0';
    return output;
}

// 为清晰起见定义别名
#define rot47_encode(input) rot47_transform(input)
#define rot47_decode(input) rot47_transform(input)

// ===================== 测试工具函数 =====================
static void run_test(const char* test_name, const char* input, const char* expected) {
    printf("测试 '%s':\n  输入: \"%s\"\n", test_name, input);
    
    char* result = rot47_transform(input);
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
    char* encoded = rot47_encode(input);
    if (!encoded) {
        printf("  \033[31m错误: 编码内存分配失败\033[0m\n\n");
        return;
    }
    printf("  编码后: \"%s\"\n", encoded);
    
    // 解码
    char* decoded = rot47_decode(encoded);
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
    
    // 测试2: 边界字符
    run_test("最小字符", "!", "P");
    run_test("最大字符", "~", "}");
    run_test("中间字符", "O", "b");
    
    // 测试3: 非可打印字符
    run_test("控制字符", "\x01\x02\x03\x04\x05", "\x01\x02\x03\x04\x05");
    run_test("换行符", "Hello\nWorld", "w6==@\?~@C=5");
    
    // 测试4: 混合内容
    run_test("混合内容", "Hello World! 123 @#$%", "w6==@ (9=5P `ab 23 _^&*");
    
    // 测试5: URL编码示例
    run_test("URL编码", "https://example.com?user=admin&pass=secret", 
             "EEADi^^i^^6I2I2>2I2>6@>]U:FD6:?6Cl25>:?U?2DDlD64C6E");
    
    // 测试6: NULL输入
    char* result = rot47_transform(NULL);
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
    run_round_trip_test("简单文本", "ROT47 is powerful!");
    run_round_trip_test("特殊字符", "!@#$%^&*()_+-={}[]|\\:;\"'<>,.?/~");
    run_round_trip_test("边界值", "!~O");
    run_round_trip_test("长文本", "The quick brown fox jumps over the lazy dog. 1234567890!@#$%^&*()_+");
    run_round_trip_test("密码示例", "Username: admin, Password: P@ssw0rd!123");
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
    
    // 填充可打印ASCII字符
    for (size_t i = 0; i < size; i++) {
        // 在33-126范围内生成随机字符
        long_str[i] = 33 + (rand() % 94);
    }
    long_str[size] = '\0';
    
    printf("测试字符串长度: %zu MB\n", size / (1024 * 1024));
    
    // 执行转换
    clock_t start = clock();
    char* transformed = rot47_transform(long_str);
    clock_t end = clock();
    
    if (transformed) {
        double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
        printf("处理时间: %.4f 秒\n", elapsed);
        printf("吞吐量: %.2f MB/s\n", (size / (1024.0 * 1024.0)) / elapsed);
        
        // 验证往返转换
        char* roundtrip = rot47_transform(transformed);
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
    srand(time(NULL)); // 初始化随机数生成器
    
    printf("================================\n");
    printf("      ROT47 编码/解码测试\n");
    printf("================================\n\n");
    
    // 基础功能测试
    printf("=== 基础功能测试 ===\n");
    run_test("A → p", "A", "p");
    run_test("a → 2", "a", "2");
    run_test("0 → _", "0", "_");
    run_test("! → P", "!", "P");
    run_test("~ → }", "~", "}");
    run_test("Hello → w6==@", "Hello", "w6==@");
    run_test("123 → `ab", "123", "`ab");
    run_test("特殊字符转换", "@#$%", "_^&*");
    
    // 边界测试
    boundary_tests();
    
    // 往返测试
    round_trip_tests();
    
    // 性能测试
    performance_test();
    
    // 实用示例
    printf("=== 实用示例 ===\n");
    const char* sensitive = "Sensitive: user=admin&password=Secret123!";
    char* encoded = rot47_encode(sensitive);
    printf("原始敏感数据: \"%s\"\n", sensitive);
    printf("ROT47编码后: \"%s\"\n", encoded);
    
    char* decoded = rot47_decode(encoded);
    printf("解码恢复后: \"%s\"\n", decoded);
    
    free(encoded);
    free(decoded);
    
    printf("\n测试完成\n");
    return 0;
}
