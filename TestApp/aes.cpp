#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "immintrin.h"
#include "aes.h"

// 密钥长度枚举
typedef enum {
    AES_128 = 0,
    AES_192,
    AES_256
} KeyLength;

// 根据密钥长度自动确定参数
constexpr auto AES_BLOCK_SIZE = 16;

// S盒和逆S盒（保持不变）
const uint8_t SBOX[256] = { 
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};
const uint8_t INV_SBOX[256] = { 
    0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
    0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
    0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
    0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
    0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
    0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
    0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
    0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
    0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
    0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
    0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
    0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
    0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
    0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
    0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
    0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
};

// 轮常量（扩展为15个）
const uint8_t RCON[15] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d
};

// 根据密钥长度获取轮数
static int get_rounds(KeyLength key_len) {
    switch(key_len) {
        case AES_128: return 10;
        case AES_192: return 12;
        case AES_256: return 14;
        default: return 10;
    }
}

// 根据密钥长度获取密钥字数量
static int get_nk(KeyLength key_len) {
    switch(key_len) {
        case AES_128: return 4;
        case AES_192: return 6;
        case AES_256: return 8;
        default: return 4;
    }
}

// 密钥扩展（支持128/192/256位）
static void KeyExpansion(const uint8_t *key, uint8_t *w, KeyLength key_len) {
    int Nk = get_nk(key_len);
    int Nr = get_rounds(key_len);
    int total_words = 4 * (Nr + 1);
    
    uint8_t temp[4] = { 0 };
    
    // 初始密钥复制
    for (int i = 0; i < 4 * Nk; i++) {
        w[i] = key[i];
    }

    // 生成后续轮密钥
    for (int i = Nk; i < total_words; i++) {
        temp[0] = w[4*(i-1)];
        temp[1] = w[4*(i-1)+1];
        temp[2] = w[4*(i-1)+2];
        temp[3] = w[4*(i-1)+3];

        if (i % Nk == 0) {
            // 字节循环移位
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            // S盒替换
            temp[0] = SBOX[temp[0]];
            temp[1] = SBOX[temp[1]];
            temp[2] = SBOX[temp[2]];
            temp[3] = SBOX[temp[3]];

            // 与轮常量异或
            temp[0] ^= RCON[i/Nk];
        } 
        // AES-256的特殊处理
        else if (key_len == AES_256 && i % Nk == 4) {
            temp[0] = SBOX[temp[0]];
            temp[1] = SBOX[temp[1]];
            temp[2] = SBOX[temp[2]];
            temp[3] = SBOX[temp[3]];
        }

        w[4*i]   = w[4*(i-Nk)]   ^ temp[0];
        w[4*i+1] = w[4*(i-Nk)+1] ^ temp[1];
        w[4*i+2] = w[4*(i-Nk)+2] ^ temp[2];
        w[4*i+3] = w[4*(i-Nk)+3] ^ temp[3];
    }
}

// 字节替换（保持不变）
static void SubBytes(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = SBOX[state[i][j]];
        }
    }
}

// 逆行移位
static void InvShiftRows(uint8_t state[4][4]) {
    uint8_t temp;

    // 第二行循环右移1字节
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    // 第三行循环右移2字节
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // 第四行循环右移3字节
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

// 行移位
static void ShiftRows(uint8_t state[4][4]) {
    uint8_t temp;

    // 第二行循环左移1字节
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // 第三行循环左移2字节
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // 第四行循环左移3字节
    temp = state[3][0];
    state[3][0] = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = temp;
}

// GF(2^8)上的乘法
static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    uint8_t counter;
    uint8_t hi_bit_set;
    for (counter = 0; counter < 8; counter++) {
        if (b & 1) p ^= a;
        hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set) a ^= 0x1B; // x^8 + x^4 + x^3 + x + 1
        b >>= 1;
    }
    return p;
}

// 列混合
static void MixColumns(uint8_t state[4][4]) {
    uint8_t temp[4] = { 0 };
    for (int i = 0; i < 4; i++) {
        temp[0] = state[0][i];
        temp[1] = state[1][i];
        temp[2] = state[2][i];
        temp[3] = state[3][i];

        state[0][i] = gmul(0x02, temp[0]) ^ gmul(0x03, temp[1]) ^ temp[2] ^ temp[3];
        state[1][i] = temp[0] ^ gmul(0x02, temp[1]) ^ gmul(0x03, temp[2]) ^ temp[3];
        state[2][i] = temp[0] ^ temp[1] ^ gmul(0x02, temp[2]) ^ gmul(0x03, temp[3]);
        state[3][i] = gmul(0x03, temp[0]) ^ temp[1] ^ temp[2] ^ gmul(0x02, temp[3]);
    }
}

// 逆列混合
static void InvMixColumns(uint8_t state[4][4]) {
    uint8_t temp[4] = { 0 };
    for (int i = 0; i < 4; i++) {
        temp[0] = state[0][i];
        temp[1] = state[1][i];
        temp[2] = state[2][i];
        temp[3] = state[3][i];

        state[0][i] = gmul(0x0e, temp[0]) ^ gmul(0x0b, temp[1]) ^ gmul(0x0d, temp[2]) ^ gmul(0x09, temp[3]);
        state[1][i] = gmul(0x09, temp[0]) ^ gmul(0x0e, temp[1]) ^ gmul(0x0b, temp[2]) ^ gmul(0x0d, temp[3]);
        state[2][i] = gmul(0x0d, temp[0]) ^ gmul(0x09, temp[1]) ^ gmul(0x0e, temp[2]) ^ gmul(0x0b, temp[3]);
        state[3][i] = gmul(0x0b, temp[0]) ^ gmul(0x0d, temp[1]) ^ gmul(0x09, temp[2]) ^ gmul(0x0e, temp[3]);
    }
}

// 轮密钥加
static void AddRoundKey(uint8_t state[4][4], const uint8_t* roundKey) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[j][i] ^= roundKey[i * 4 + j];
        }
    }
}

// AES加密核心函数
static void AES_EncryptBlock(uint8_t *input, uint8_t *output, uint8_t *roundKey, KeyLength key_len) {
    uint8_t state[4][4] = { 0 };
    int Nr = get_rounds(key_len);
    
    // 初始化状态矩阵
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[j][i] = input[i*4 + j];
        }
    }
    
    // 初始轮密钥加
    AddRoundKey(state, roundKey);
    
    // 主循环
    for (int round = 1; round < Nr; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKey + round * AES_BLOCK_SIZE);
    }
    
    // 最后一轮
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKey + Nr * AES_BLOCK_SIZE);
    
    // 输出结果
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            output[i*4 + j] = state[j][i];
        }
    }
}

// AES解密核心函数
static void AES_DecryptBlock(uint8_t *input, uint8_t *output, uint8_t *roundKey, KeyLength key_len) {
    uint8_t state[4][4] = { 0 };
    int Nr = get_rounds(key_len);
    
    // 初始化状态矩阵
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[j][i] = input[i*4 + j];
        }
    }
    
    // 初始轮
    AddRoundKey(state, roundKey + Nr * AES_BLOCK_SIZE);
    InvShiftRows(state);
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = INV_SBOX[state[i][j]];
        }
    }
    
    // 主循环
    for (int round = Nr-1; round > 0; round--) {
        AddRoundKey(state, roundKey + round * AES_BLOCK_SIZE);
        InvMixColumns(state);
        InvShiftRows(state);
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] = INV_SBOX[state[i][j]];
            }
        }
    }
    
    // 最后一轮
    AddRoundKey(state, roundKey);
    
    // 输出结果
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            output[i*4 + j] = state[j][i];
        }
    }
}

// PKCS#7填充
static int pkcs7_pad(const uint8_t* input, int input_len, uint8_t** padded_data, int block_size, PaddingMode paddingmode) {
    // 计算需要的新内存大小
    if (paddingmode == AES_MODE_NOPADDING)
    {
        *padded_data = (uint8_t*)malloc(input_len);
        memcpy(*padded_data, input, input_len);
        return input_len;
    }
    if (paddingmode == AES_MODE_PKCS5)
    {
        block_size = 8;
    }
    int padded_len = input_len + (block_size - (input_len % block_size));

    // 分配新内存
    *padded_data = (uint8_t*)malloc(padded_len);
    if (*padded_data == NULL)
        return -1;
    // 复制原始数据
    memcpy(*padded_data, input, input_len);

    // 安全添加填充
    if (paddingmode == AES_MODE_PKCS5 || paddingmode == AES_MODE_PKCS7)
    {
        memset(*padded_data + input_len, padded_len - input_len, padded_len - input_len);
    }
    else if(paddingmode == AES_MODE_ISO10126PADDING)
    {
        (*padded_data)[padded_len - 1] = (uint8_t)(padded_len - input_len);
    }
    else if (paddingmode == AES_MODE_ISO7816_4PADDING)
    {
        (*padded_data)[input_len] = 0x80;
        memset(*padded_data + input_len + 1, 0, padded_len - input_len - 1);
    }
    else if (paddingmode == AES_MODE_ZEROPADDING)
    {
        memset(*padded_data + input_len, 0, padded_len - input_len);
    }

    return padded_len;
}

// PKCS#7去除填充
static int pkcs7_unpad(uint8_t *data, int data_len, PaddingMode paddingmode)
{
    if (data_len <= 0) return 0;
    if (paddingmode != AES_MODE_NOPADDING && paddingmode != AES_MODE_ZEROPADDING && paddingmode != AES_MODE_ISO7816_4PADDING)
    {
        int padding_len = data[data_len - 1];
        if (padding_len > 0 && padding_len <= AES_BLOCK_SIZE) {
            return data_len - padding_len;
        }
    }
    else if (paddingmode == AES_MODE_ZEROPADDING)
    {
        for (int i = data_len - 1; i >= 0; i--)
        {
            if (data[i] != 0)
            {
                return i + 1;
            }
        }
    }
    else if (paddingmode == AES_MODE_ISO7816_4PADDING)
    {
        for (int i = data_len - 1; i >= 0; i--)
        {
            if (data[i] == 0x80)
            {
                return i;
            }
        }
    }
    return data_len; // 无效填充返回原长度
}

// CBC模式加密
static void cbc_encrypt(uint8_t *plaintext, int plaintext_len, uint8_t *key, KeyLength key_len,
                 uint8_t *iv, uint8_t *ciphertext) {
    int Nr = get_rounds(key_len);
    int key_exp_size = AES_BLOCK_SIZE * (Nr + 1);
    uint8_t *roundKey =(uint8_t*) malloc(key_exp_size);
    KeyExpansion(key, roundKey, key_len);
    
    uint8_t block[AES_BLOCK_SIZE] = { 0 };
    uint8_t xor_block[AES_BLOCK_SIZE] = { 0 };
    if (iv)
        memcpy(xor_block, iv, AES_BLOCK_SIZE);

    for (int i = 0; i < plaintext_len; i += AES_BLOCK_SIZE) {
        // CBC模式异或操作
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            block[j] = plaintext[i + j] ^ xor_block[j];
        }

        AES_EncryptBlock(block, &ciphertext[i], roundKey, key_len);
        if (iv)
            memcpy(xor_block, &ciphertext[i], AES_BLOCK_SIZE);
    }

    free(roundKey);
}

// CBC模式解密
static void cbc_decrypt(uint8_t *ciphertext, int ciphertext_len, uint8_t *key, KeyLength key_len,
                 uint8_t *iv, uint8_t *plaintext) {
    int Nr = get_rounds(key_len);
    int key_exp_size = AES_BLOCK_SIZE * (Nr + 1);
    uint8_t *roundKey = (uint8_t*)malloc(key_exp_size);
    KeyExpansion(key, roundKey, key_len);
    
    uint8_t block[AES_BLOCK_SIZE];
    uint8_t xor_block[AES_BLOCK_SIZE] = { 0 };
    if(iv)
        memcpy(xor_block, iv, AES_BLOCK_SIZE);
    
    for (int i = 0; i < ciphertext_len; i += AES_BLOCK_SIZE) {
        AES_DecryptBlock(&ciphertext[i], block, roundKey, key_len);
        
        // CBC模式异或操作
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            plaintext[i + j] = block[j] ^ xor_block[j];
        }
        if (iv)
            memcpy(xor_block, &ciphertext[i], AES_BLOCK_SIZE);
    }
    
    free(roundKey);
}

static void ctr_crypt(const uint8_t* input, int len, uint8_t* key, KeyLength key_len,
    const uint8_t* nonce, uint8_t* output) {
    int Nr = get_rounds(key_len);
    int key_exp_size = AES_BLOCK_SIZE * (Nr + 1);
    uint8_t* roundKey = (uint8_t*)malloc(key_exp_size);
    KeyExpansion(key, roundKey, key_len);

    uint8_t counter_block[AES_BLOCK_SIZE];
    uint8_t encrypted_counter[AES_BLOCK_SIZE];
    uint64_t counter = 0;

    // 初始化counter_block：前8字节为nonce，后8字节为计数器
    memcpy(counter_block, nonce, 8);

    for (int i = 0; i < len; i += AES_BLOCK_SIZE) {
        // 设置计数器（大端序）
        for (int j = 0; j < 8; j++) {
            counter_block[15 - j] = (counter >> (j * 8)) & 0xFF;
        }

        // 加密计数器块
        AES_EncryptBlock(counter_block, encrypted_counter, roundKey, key_len);

        // 计算当前块大小
        int block_size = (len - i) < AES_BLOCK_SIZE ? (len - i) : AES_BLOCK_SIZE;

        // 与输入异或
        for (int j = 0; j < block_size; j++) {
            output[i + j] = input[i + j] ^ encrypted_counter[j];
        }

        // 计数器递增
        counter++;
    }

    free(roundKey);
}

// AES加密入口函数
int AES_Encrypt(uint8_t *plaintext, int plaintext_len, uint8_t *key, int key_size, 
                uint8_t *iv, CipherMode mode, PaddingMode paddingmode, uint8_t **ciphertext) {
    // 确定密钥类型
    KeyLength key_len;
    if (key_size == 16) key_len = AES_128;
    else if (key_size == 24) key_len = AES_192;
    else if (key_size == 32) key_len = AES_256;
    else return -1; // 无效密钥长度
    
    // 应用PKCS#7填充
    uint8_t* padded_plaintext = NULL;
    int padded_len = pkcs7_pad(plaintext, plaintext_len, &padded_plaintext, AES_BLOCK_SIZE, paddingmode);
    if (padded_len < 0) return -2; // 填充失败    *ciphertext = (uint8_t*)malloc(padded_len);
    // 分配输出缓冲区
    *ciphertext = (uint8_t*)malloc(padded_len);
    if (!*ciphertext) {
        free(padded_plaintext);
        return -3; // 内存分配失败
    }
    // 选择加密模式
    if (mode == AES_MODE_ECB) {
        cbc_encrypt(padded_plaintext, padded_len, key, key_len, NULL, *ciphertext);
    }
    else if (mode == AES_MODE_CBC) {
        cbc_encrypt(padded_plaintext, padded_len, key, key_len, iv, *ciphertext);
    }
    else if (mode == AES_MODE_CTR)
    {
        ctr_crypt(padded_plaintext, padded_len, key, key_len, iv, *ciphertext);
    }
    
    
    return padded_len;
}

// AES解密入口函数
int AES_Decrypt(uint8_t *ciphertext, int ciphertext_len, uint8_t *key, int key_size, 
                uint8_t *iv, CipherMode mode, PaddingMode paddingmode, uint8_t **plaintext) {
    // 确定密钥类型
    KeyLength key_len;
    if (key_size == 16) key_len = AES_128;
    else if (key_size == 24) key_len = AES_192;
    else if (key_size == 32) key_len = AES_256;
    else return -1; // 无效密钥长度
    
    if (ciphertext_len % AES_BLOCK_SIZE != 0) return -3; // 密文长度错误
    
    *plaintext = (uint8_t*)malloc(ciphertext_len);
    if (!*plaintext) return -2; // 内存分配失败
    
    // 选择解密模式
    if (mode == AES_MODE_ECB) {
        cbc_decrypt(ciphertext, ciphertext_len, key, key_len, NULL, *plaintext);
    } else if (mode == AES_MODE_CBC) {
        cbc_decrypt(ciphertext, ciphertext_len, key, key_len, iv, *plaintext);
    }
    
    // 去除填充
    return pkcs7_unpad(*plaintext, ciphertext_len, paddingmode);
}
