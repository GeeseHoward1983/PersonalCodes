#include <stdio.h>
#include <ctype.h>
#include <string.h>

// ROT Special 编码函数
void rot_special_encode(char *str) {
    int count = 0;
    for (int i = 0; str[i]; i++) {
        if (isalpha(str[i])) {
            count++;
            int rot = (count - 1) % 26 + 1;
            char base = islower(str[i]) ? 'a' : 'A';
            str[i] = base + (str[i] - base + rot) % 26;
        }
    }
}

// ROT Special 解码函数
void rot_special_decode(char *str) {
    int count = 0;
    for (int i = 0; str[i]; i++) {
        if (isalpha(str[i])) {
            count++;
            int rot = (count - 1) % 26 + 1;
            char base = islower(str[i]) ? 'a' : 'A';
            
            // 反向旋转（处理负偏移）
            int offset = (str[i] - base - rot) % 26;
            if (offset < 0) offset += 26;
            
            str[i] = base + offset;
        }
    }
}

// 测试函数
void test_rot_special(const char *input) {
    char encode_buf[256], decode_buf[256];
    
    // 复制输入到缓冲区
    strcpy(encode_buf, input);
    strcpy(decode_buf, input);
    
    // 执行编码和解码
    rot_special_encode(encode_buf);
    rot_special_decode(decode_buf);
    
    // 显示结果
    printf("原始: %-20s → 编码: %-20s → 解码: %s\n", 
           input, encode_buf, 
           strcmp(input, decode_buf) == 0 ? "成功" : "失败");
    printf("解码结果: %s\n\n", decode_buf);
}

int main() {
    printf("===== ROT Special 编解码测试 =====\n");
    
    // 基本测试
    test_rot_special("Hello");
    test_rot_special("C++ Programming");
    test_rot_special("a1b2c3d4");
    
    // 边界测试
    test_rot_special("XYZ");
    test_rot_special("zZzZ");
    
    // 长文本测试
    test_rot_special("The quick brown fox jumps over the lazy dog");
    
    // 空字符串测试
    test_rot_special("");
    
    // 纯非字母测试
    test_rot_special("123!@#$%");
    
    return 0;
}
