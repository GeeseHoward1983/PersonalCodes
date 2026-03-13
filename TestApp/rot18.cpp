#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <time.h>

/**
 * ROT18编码/解码函数
 * ROT18 = ROT13(字母) + ROT5(数字)
 * 
 * 字母转换 (ROT13):
 *   A → N, B → O, ..., M → Z
 *   N → A, O → B, ..., Z → M
 *   a → n, b → o, ..., m → z
 *   n → a, o → b, ..., z → m
 * 
 * 数字转换 (ROT5):
 *   0 → 5, 1 → 6, 2 → 7, 3 → 8, 4 → 9
 *   5 → 0, 6 → 1, 7 → 2, 8 → 3, 9 → 4
 * 
 * 注意：ROT18是对称密码，编码和解码使用相同的算法
 * 
 * @param input 输入字符串
 * @return 转换后的新字符串（需调用者释放内存）
 */
char* rot18_transform(const char* input) {
    if (!input) return NULL;
    
    size_t len = strlen(input);
    char* output = malloc(len + 1);  // +1 for null terminator
    if (!output) return NULL;
    
    for (size_t i = 0; i < len; i++) {
        unsigned char c = input[i];
        if (isalpha(c)) {
            // ROT13转换
            char base = isupper(c) ? 'A' : 'a';
            output[i] = ((c - base + 13) % 26) + base;
        } else if (isdigit(c)) {
            // ROT5转换
            output[i] = '0' + ((c - '0' + 5) % 10);
        } else {
            // 非字母数字字符保持不变
            output[i] = c;
        }
    }
    output[len] = '\0';
    return output;
}

// 为清晰起见定义别名
#define rot18_encode(input) rot18_transform(input)
#define rot18_decode(input) rot18_transform(input)

// ===================== 测试工具函数 =====================
static void run_test(const char* test_name, const char* input, const char* expected) {
    printf("测试 '%s':\n  输入: \"%s\"\n", test_name, input);
    
    char* result = rot18_transform(input);
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
    char* encoded = rot18_encode(input);
    if (!encoded) {
        printf("  \033[31m错误: 编码内存分配失败\033[0m\n\n");
        return;
    }
    printf("  编码后: \"%s\"\n", encoded);
    
    // 解码
    char* decoded = rot18_decode(encoded);
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
    
    // 测试3: 全数字
    run_test("全数字", "0123456789", "5678901234");
    
    // 测试4: 混合内容
    run_test("混合内容", "User123: Password456!", "Hfre678: Cnffjbeq901!");
    
    // 测试5: 边界值
    run_test("边界字母", "AMNZamzn", "NZMANzam");
    run_test("边界数字", "0495", "5940");
    
    // 测试6: 特殊字符
    run_test("特殊字符", "Hello! @#$%^&*()_+", "Uryyb! @#$%^&*()_+");
    
    // 测试7: NULL输入
    char* result = rot18_transform(NULL);
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
    run_round_trip_test("简单文本", "ROT18 is fun!");
    run_round_trip_test("混合内容", "User123: Password456!");
    run_round_trip_test("特殊字符", "Hello! @#$%^&*()_+");
    run_round_trip_test("边界值", "AzaZ0495");
    run_round_trip_test("长文本", "The quick brown fox jumps over 12345 lazy dogs. 67890 times!");
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
    
    // 填充字母、数字和符号
    for (size_t i = 0; i < size; i++) {
        int type = i % 3;
        if (type == 0) {
            long_str[i] = 'A' + (i % 26);  // 大写字母
        } else if (type == 1) {
            long_str[i] = '0' + (i % 10);  // 数字
        } else {
            long_str[i] = 33 + (i % 15);   // 符号
        }
    }
    long_str[size] = '\0';
    
    printf("测试字符串长度: %zu MB\n", size / (1024 * 1024));
    
    // 执行转换
    clock_t start = clock();
    char* transformed = rot18_transform(long_str);
    clock_t end = clock();
    
    if (transformed) {
        double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
        printf("处理时间: %.4f 秒\n", elapsed);
        printf("吞吐量: %.2f MB/s\n", (size / (1024.0 * 1024.0)) / elapsed);
        
        // 验证往返转换
        char* roundtrip = rot18_transform(transformed);
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
    printf("================================\n");
    printf("  ROT18 编码/解码测试 (ROT13 + ROT5)\n");
    printf("================================\n\n");
    
    // 基础功能测试
    printf("=== 基础功能测试 ===\n");
    run_test("A → N (字母)", "A", "N");
    run_test("0 → 5 (数字)", "0", "5");
    run_test("a → n (字母)", "a", "n");
    run_test("5 → 0 (数字)", "5", "0");
    run_test("混合转换", "Hello123", "Uryyb678");
    run_test("逆转换", "Uryyb678", "Hello123");
    run_test("特殊字符不变", "!@#$%^&*()", "!@#$%^&*()");
    
    // 边界测试
    boundary_tests();
    
    // 往返测试
    round_trip_tests();
    
    // 性能测试
    performance_test();
    
    printf("测试完成\n");
    return 0;
}
