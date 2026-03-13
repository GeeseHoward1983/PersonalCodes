#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "DES3.h"

/* 类型定义 */
typedef uint64_t des_block;

/* DES 核心算法实现 */

// 初始置换表 (IP)
constexpr int IP[] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

// 逆初始置换表 (IP^-1)
constexpr int FP[] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25
};

// 扩展置换表 (E)
constexpr int E[] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

// S-Boxes (6位输入 -> 4位输出)
constexpr uint8_t SBOX[8][64] = {
    { // S1
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
    },
    { // S2
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
    },
    { // S3
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
    },
    { // S4
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
    },
    { // S5
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
    },
    { // S6
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
    },
    { // S7
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
    },
    { // S8
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
    }
};

// 轮函数P置换
constexpr int P[] = {
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
};

// 密钥置换表 (PC1)
constexpr int PC1[] = {
    57, 49, 41, 33, 25, 17, 9, 1,
    58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3,
    60, 52, 44, 36, 63, 55, 47, 39,
    31, 23, 15, 7, 62, 54, 46, 38,
    30, 22, 14, 6, 61, 53, 45, 37,
    29, 21, 13, 5, 28, 20, 12, 4
};

// 密钥压缩置换表 (PC2)
static const int PC2[] = {
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
};

// 轮数移位表
constexpr int SHIFTS[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

// 通用置换函数
static uint64_t permute(const uint8_t *input, const int *table, int size) {
    uint64_t result = 0;
    for (int i = 0; i < size; i++) {
        int pos = table[i] - 1;
        int byte_idx = pos / 8;
        int bit_idx = 7 - (pos % 8);
        uint8_t bit = (input[byte_idx] >> bit_idx) & 1;
        result = (result << 1) | bit;
    }
    return result;
}

// 生成轮密钥
static void generate_subkeys(uint64_t key, uint64_t *subkeys) {
    uint8_t key_bytes[8] = { 0 };
    for (int i = 0; i < 8; i++) {
        key_bytes[7-i] = (key >> (i * 8)) & 0xFF;
    }
    
    // PC1置换
    uint64_t permuted = permute(key_bytes, PC1, 56);
    
    uint32_t left = (permuted >> 28) & 0xFFFFFFF;
    uint32_t right = permuted & 0xFFFFFFF;
    
    for (int round = 0; round < 16; round++) {
        // 循环左移
        left = ((left << SHIFTS[round]) | (left >> (28 - SHIFTS[round]))) & 0xFFFFFFF;
        right = ((right << SHIFTS[round]) | (right >> (28 - SHIFTS[round]))) & 0xFFFFFFF;
        
        // 合并左右部分
        uint64_t combined = ((uint64_t)left << 28) | right;
        
        // PC2置换生成子密钥
        uint8_t combined_bytes[7] = { 0 };
        for (int i = 0; i < 7; i++) {
            combined_bytes[i] = (combined >> (42 - i*6)) & 0x3F;
        }
        
        subkeys[round] = permute(combined_bytes, PC2, 48);
    }
}

// Feistel轮函数
static uint32_t feistel(uint32_t right, uint64_t subkey) {
    // 扩展置换 (32位 -> 48位)
    uint8_t right_bytes[4] = { 0 };
    for (int i = 0; i < 4; i++) {
        right_bytes[3-i] = (right >> (i * 8)) & 0xFF;
    }
    uint64_t expanded = permute(right_bytes, E, 48);
    
    // 与子密钥异或
    uint64_t xored = expanded ^ subkey;
    
    // S-Box代换 (48位 -> 32位)
    uint32_t substituted = 0;
    for (int i = 0; i < 8; i++) {
        // 提取6位输入
        uint8_t sbox_input = (xored >> (42 - i*6)) & 0x3F;
        
        // 计算S-Box行列索引
        uint8_t row = ((sbox_input & 0x20) >> 4) | (sbox_input & 1);
        uint8_t col = (sbox_input >> 1) & 0x0F;
        
        // 获取S-Box输出
        uint8_t sbox_output = SBOX[i][row * 16 + col];
        substituted = (substituted << 4) | sbox_output;
    }
    
    // P置换
    uint8_t sub_bytes[4] = { 0 };
    for (int i = 0; i < 4; i++) {
        sub_bytes[3-i] = (substituted >> (i * 8)) & 0xFF;
    }
    return (uint32_t)permute(sub_bytes, P, 32);
}

// 核心DES加密/解密函数
static void des_core(uint64_t *data, uint64_t key, int encrypt) {
    uint64_t subkeys[16];
    generate_subkeys(key, subkeys);
    
    // 初始置换
    uint8_t data_bytes[8] = { 0 };
    for (int i = 0; i < 8; i++) {
        data_bytes[7-i] = (*data >> (i * 8)) & 0xFF;
    }
    uint64_t permuted = permute(data_bytes, IP, 64);
    
    uint32_t left = (permuted >> 32) & 0xFFFFFFFF;
    uint32_t right = permuted & 0xFFFFFFFF;
    
    // 16轮Feistel网络
    for (int round = 0; round < 16; round++) {
        uint32_t next_left = right;
        uint64_t round_key = encrypt ? subkeys[round] : subkeys[15 - round];
        uint32_t feistel_out = feistel(right, round_key);
        right = left ^ feistel_out;
        left = next_left;
    }
    
    // 最终置换 (左右交换)
    uint64_t combined = ((uint64_t)right << 32) | left;
    
    uint8_t combined_bytes[8] = { 0 };
    for (int i = 0; i < 8; i++) {
        combined_bytes[7-i] = (combined >> (i * 8)) & 0xFF;
    }
    *data = permute(combined_bytes, FP, 64);
}

/* 3DES 实现 (EDE模式) */
static void des3_encrypt_block(uint64_t *block, uint64_t k1, uint64_t k2, uint64_t k3) {
    des_core(block, k1, 1); // Encrypt with K1
    des_core(block, k2, 0); // Decrypt with K2
    des_core(block, k3, 1); // Encrypt with K3
}

static void des3_decrypt_block(uint64_t *block, uint64_t k1, uint64_t k2, uint64_t k3) {
    des_core(block, k3, 0); // Decrypt with K3
    des_core(block, k2, 1); // Encrypt with K2
    des_core(block, k1, 0); // Decrypt with K1
}

// PKCS#7填充
static size_t pkcs7_pad(uint8_t *data, size_t len, size_t block_size) {
    size_t pad_len = block_size - (len % block_size);
    for (size_t i = 0; i < pad_len; i++) {
        data[len + i] = (uint8_t)pad_len;
    }
    return len + pad_len;
}

static size_t pkcs7_unpad(uint8_t *data, size_t len) {
    if (len == 0) return 0;
    uint8_t pad_len = data[len - 1];
    if (pad_len > 0 && pad_len <= 8) {
        // 验证填充是否正确
        for (size_t i = 1; i <= pad_len; i++) {
            if (data[len - i] != pad_len) {
                return len; // 无效填充
            }
        }
        return len - pad_len;
    }
    return len; // 无效填充
}

// ECB模式加密/解密
static void des3_ecb_crypt(uint8_t *data, size_t len,
                   uint64_t k1, uint64_t k2, uint64_t k3,
                   int encrypt) {
    for (size_t i = 0; i < len; i += 8) {
        if (encrypt) {
            des3_encrypt_block((uint64_t*)(data + i), k1, k2, k3);
        } else {
            des3_decrypt_block((uint64_t*)(data + i), k1, k2, k3);
        }
    }
}

// CBC模式加密
static void des3_cbc_encrypt(uint8_t *data, size_t len,
                     uint64_t k1, uint64_t k2, uint64_t k3,
                     const uint8_t *iv) {
    uint64_t prev_block = *(uint64_t*)iv;
    
    for (size_t i = 0; i < len; i += 8) {
        uint64_t block = *(uint64_t*)(data + i);
        block ^= prev_block;
        
        des3_encrypt_block(&block, k1, k2, k3);
        
        *(uint64_t*)(data + i) = block;
        prev_block = block;
    }
}

// CBC模式解密
static void des3_cbc_decrypt(uint8_t *data, size_t len,
                     uint64_t k1, uint64_t k2, uint64_t k3,
                     const uint8_t *iv) {
    uint64_t prev_block = *(uint64_t*)iv;
    
    for (size_t i = 0; i < len; i += 8) {
        uint64_t block = *(uint64_t*)(data + i);
        uint64_t save_block = block;
        
        des3_decrypt_block(&block, k1, k2, k3);
        block ^= prev_block;
        
        *(uint64_t*)(data + i) = block;
        prev_block = save_block;
    }
}

// CFB模式加密
static void des3_cfb_encrypt(uint8_t *data, size_t len,
                     uint64_t k1, uint64_t k2, uint64_t k3,
                     const uint8_t *iv) {
    uint64_t shift_register = *(uint64_t*)iv;
    
    for (size_t i = 0; i < len; i++) {
        // 加密移位寄存器
        uint64_t encrypted = shift_register;
        des3_encrypt_block(&encrypted, k1, k2, k3);
        
        // 加密1字节数据
        data[i] ^= (uint8_t)(encrypted >> 56);
        
        // 更新移位寄存器
        shift_register = (shift_register << 8) | data[i];
    }
}

// CFB模式解密
static void des3_cfb_decrypt(uint8_t *data, size_t len,
                     uint64_t k1, uint64_t k2, uint64_t k3,
                     const uint8_t *iv) {
    uint64_t shift_register = *(uint64_t*)iv;
    
    for (size_t i = 0; i < len; i++) {
        // 加密移位寄存器
        uint64_t encrypted = shift_register;
        des3_encrypt_block(&encrypted, k1, k2, k3);
        
        // 保存当前密文字节用于更新寄存器
        uint8_t cipher_byte = data[i];
        
        // 解密1字节数据
        data[i] ^= (uint8_t)(encrypted >> 56);
        
        // 更新移位寄存器
        shift_register = (shift_register << 8) | cipher_byte;
    }
}

// OFB模式加密/解密
static void des3_ofb_crypt(uint8_t *data, size_t len,
                   uint64_t k1, uint64_t k2, uint64_t k3,
                   const uint8_t *iv) {
    uint64_t shift_register = *(uint64_t*)iv;
    
    for (size_t i = 0; i < len; i++) {
        // 加密移位寄存器
        des3_encrypt_block(&shift_register, k1, k2, k3);
        
        // 加密/解密1字节数据
        data[i] ^= (uint8_t)(shift_register >> 56);
        
        // 更新移位寄存器
        shift_register = (shift_register << 8) | (data[i] & 0xFF);
    }
}

/* 完整3DES接口 */
void des3_crypt(uint8_t *data, size_t *len,
               const uint8_t *key, // 24字节密钥
               const uint8_t *iv,  // 8字节IV (CBC/CFB/OFB需要)
               int encrypt,        // 0=解密, 1=加密
               DES3CipherMode mode,    // 工作模式
               int padding) {      // 0=无填充, 1=PKCS7
    
    // 参数校验
    if (!data || !len || !key || (*len == 0)) {
        fprintf(stderr, "参数错误\n");
        return;
    }

    // 密钥与IV安全读取
    uint64_t k1 = 0, k2 = 0, k3 = 0, iv64 = 0;
    memcpy(&k1, key, 8);
    memcpy(&k2, key + 8, 8);
    memcpy(&k3, key + 16, 8);
    if (iv) memcpy(&iv64, iv, 8);
    
    // 处理填充
    if (encrypt && padding) {
        *len = pkcs7_pad(data, *len, 8);
    }
    
    // 分块处理
    switch (mode) {
    case ECB:
        des3_ecb_crypt(data, *len, k1, k2, k3, encrypt);
        break;
    case CBC:
        if (encrypt) {
            des3_cbc_encrypt(data, *len, k1, k2, k3, (const uint8_t*)&iv64);
        }
        else {
            des3_cbc_decrypt(data, *len, k1, k2, k3, (const uint8_t*)&iv64);
        }
        break;
    case CFB:
        if (encrypt) {
            des3_cfb_encrypt(data, *len, k1, k2, k3, (const uint8_t*)&iv64);
        }
        else {
            des3_cfb_decrypt(data, *len, k1, k2, k3, (const uint8_t*)&iv64);
        }
        break;
    case OFB:
        des3_ofb_crypt(data, *len, k1, k2, k3, (const uint8_t*)&iv64);
        break;
    default:
        fprintf(stderr, "Unsupported cipher mode\n");
        break;
    }

    // 去除填充
    if (!encrypt && padding) {
        *len = pkcs7_unpad(data, *len);
    }
}
