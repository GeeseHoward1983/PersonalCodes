#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

/**
 * ROT5编码/解码函数
 * ROT5是一种数字旋转密码，将每个数字字符旋转5位：
 *   0->5, 1->6, 2->7, 3->8, 4->9, 
 *   5->0, 6->1, 7->2, 8->3, 9->4
 * 
 * 注意：ROT5是对称密码，编码和解码使用相同的算法
 * 
 * @param input 输入字符串
 * @return 转换后的新字符串（需调用者释放内存）
 */
char* rot5_transform(const char* input) {
    if (!input) return NULL;
    
    size_t len = strlen(input);
    char* output = malloc(len + 1);  // +1 for null terminator
    if (!output) return NULL;
    
    for (size_t i = 0; i < len; i++) {
        if (isdigit((unsigned char)input[i])) {
            // 数字转换: (digit - '0' + 5) % 10 + '0'
            output[i] = '0' + ((input[i] - '0' + 5) % 10);
        } else {
            // 非数字字符保持不变
            output[i] = input[i];
        }
    }
    output[len] = '\0';
    return output;
}

// 为清晰起见定义别名
#define rot5_encode(input) rot5_transform(input)
#define rot5_decode(input) rot5_transform(input)

// ===================== 测试工具函数 =====================
static void run_test(const char* test_name, const char* input, const char* expected) {
    printf("测试 '%s':\n  输入: \"%s\"\n", test_name, input);
    
    char* result = rot5_transform(input);
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
    char* encoded = rot5_encode(input);
    if (!encoded) {
        printf("  \033[31m错误: 编码内存分配失败\033[0m\n\n");
        return;
    }
    printf("  编码后: \"%s\"\n", encoded);
    
    // 解码
    char* decoded = rot5_decode(encoded);
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
    
    // 测试2: 全数字
    run_test("全数字", "0123456789", "5678901234");
    
    // 测试3: 无数字
    run_test("无数字", "Hello! @#$%^&*()", "Hello! @#$%^&*()");
    
    // 测试4: 混合内容
    run_test("混合内容", "ID: 12345, PIN: 9876", "ID: 67890, PIN: 4321");
    
    // 测试5: 长数字
    run_test("长数字", "98765432100123456789", "43210987655678901234");
    
    // 测试6: NULL输入
    char* result = rot5_transform(NULL);
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
    run_round_trip_test("简单数字", "42");
    run_round_trip_test("混合内容", "User123: Password456!");
    run_round_trip_test("特殊字符", "100% secure! 999.99");
    run_round_trip_test("边界值", "0000000000");
    run_round_trip_test("长文本", "The quick brown fox jumps over 12345 lazy dogs. 67890 times!");
    printf("\n");
}

// 主测试函数
int main() {
    printf("=====================\n");
    printf("  ROT5 编码/解码测试\n");
    printf("=====================\n\n");
    
    // 基础功能测试
    printf("=== 基础功能测试 ===\n");
    run_test("0 → 5", "0", "5");
    run_test("5 → 0", "5", "0");
    run_test("9 → 4", "9", "4");
    run_test("123 → 678", "123", "678");
    run_test("678 → 123", "678", "123");
    run_test("字母不变", "ABC", "ABC");
    run_test("特殊字符不变", "!@#$%", "!@#$%");
    
    // 边界测试
    boundary_tests();
    
    // 往返测试
    round_trip_tests();
    
    printf("测试完成\n");
    return 0;
}
