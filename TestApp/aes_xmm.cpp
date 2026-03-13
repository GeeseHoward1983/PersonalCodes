#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <immintrin.h>

// AES常量
#define AES_BLOCK_SIZE 16

// 密钥长度枚举
typedef enum {
    AES_128 = 0,
    AES_192,
    AES_256
} KeyLength;

// 工作模式枚举
typedef enum {
    ECB = 0,
    CBC
} CipherMode;

// S盒和逆S盒（保持不变）
const uint8_t SBOX[256] = { /* 同前 */ };
const uint8_t INV_SBOX[256] = { /* 同前 */ };

// 轮常量（扩展为15个）
const uint8_t RCON[15] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d
};

// 根据密钥长度获取轮数
static inline int get_rounds(KeyLength key_len) {
    static const int rounds[] = { 10, 12, 14 };
    return rounds[key_len];
}

// 根据密钥长度获取密钥字数量
static inline int get_nk(KeyLength key_len) {
    static const int nk[] = { 4, 6, 8 };
    return nk[key_len];
}

// SSE优化的密钥扩展
void KeyExpansion(const uint8_t* key, uint8_t* w, KeyLength key_len) {
    int Nk = get_nk(key_len);
    int Nr = get_rounds(key_len);
    int total_words = 4 * (Nr + 1);

    __m128i temp;
    __m128i* w128 = (__m128i*)w;

    // 加载初始密钥
    w128[0] = _mm_loadu_si128((const __m128i*)key);

    if (key_len == AES_192) {
        __m128i key_hi = _mm_loadl_epi64((const __m128i*)(key + 16));
        w128[0] = _mm_insert_epi64(w128[0], _mm_extract_epi64(key_hi, 0), 1);
    }
    else if (key_len == AES_256) {
        w128[1] = _mm_loadu_si128((const __m128i*)(key + 16));
    }

    // 密钥扩展主循环
    for (int i = Nk; i < total_words; i += 4) {
        __m128i prev = w128[(i / 4) - 1];

        if (i % Nk == 0) {
            // 字节移位
            temp = _mm_shuffle_epi32(prev, _MM_SHUFFLE(3, 3, 2, 1));
            temp = _mm_shuffle_epi8(temp, _mm_set_epi8(12, 15, 14, 13, 8, 11, 10, 9, 4, 7, 6, 5, 0, 3, 2, 1));

            // S盒替换
            __m128i mask = _mm_set1_epi32(0xff);
            __m128i sbox0 = _mm_set_epi8(
                SBOX[0], SBOX[1], SBOX[2], SBOX[3],
                SBOX[4], SBOX[5], SBOX[6], SBOX[7],
                SBOX[8], SBOX[9], SBOX[10], SBOX[11],
                SBOX[12], SBOX[13], SBOX[14], SBOX[15]
            );
            // 实际实现需要完整的256字节S盒映射，此处简化
            temp = _mm_shuffle_epi8(sbox0, temp);

            // 轮常量异或
            temp = _mm_xor_si128(temp, _mm_set1_epi32(RCON[i / Nk] << 24));
        }
        // AES-256的特殊处理
        else if (key_len == AES_256 && i % Nk == 4) {
            __m128i sbox0 = _mm_set_epi8(12, 15, 14, 13, 8, 11, 10, 9, 4, 7, 6, 5, 0, 3, 2, 1);
            temp = _mm_shuffle_epi8(sbox0, prev);
        }
        else {
            temp = prev;
        }

        w128[i / 4] = _mm_xor_si128(w128[(i / 4) - Nk / 4], temp);
    }
}

// SSE优化的S盒查找
static inline __m128i sse_sbox(__m128i x) {
    // 实际实现需要完整的256字节查找表
    // 这里使用伪代码表示S盒映射
    alignas(16) static const uint8_t sbox_table[256] = { /* SBOX数据 */ };
    __m128i result = _mm_shuffle_epi8(_mm_load_si128((const __m128i*)sbox_table), x);
    return result;
}

// SSE优化的逆S盒查找
static inline __m128i sse_inv_sbox(__m128i x) {
    // 类似sse_sbox但使用INV_SBOX
    return x; // 简化表示
}

// SSE优化的行移位
static inline __m128i sse_shift_rows(__m128i state) {
    return _mm_shuffle_epi8(state, _mm_set_epi8(
        12, 9, 6, 3, 15, 10, 5, 0,
        14, 11, 4, 1, 13, 8, 7, 2
    ));
}

// SSE优化的逆行移位
static inline __m128i sse_inv_shift_rows(__m128i state) {
    return _mm_shuffle_epi8(state, _mm_set_epi8(
        12, 1, 6, 11, 8, 5, 2, 15,
        0, 13, 10, 7, 4, 9, 14, 3
    ));
}

// GF(2^8)乘法查找表（预计算）
static uint8_t gmul_table[256][256];
static int gmul_initialized = 0;

static void init_gmul_table() {
    if (gmul_initialized) return;
    for (int a = 0; a < 256; a++) {
        for (int b = 0; b < 256; b++) {
            uint8_t p = 0;
            for (int i = 0; i < 8; i++) {
                if (b & 1) p ^= a;
                uint8_t carry = a & 0x80;
                a = (a << 1) ^ (carry ? 0x1b : 0);
                b >>= 1;
            }
            gmul_table[a][b] = p;
        }
    }
    gmul_initialized = 1;
}

// SSE优化的列混合
static __m128i sse_mix_columns(__m128i state) {
    if (!gmul_initialized) init_gmul_table();

    __m128i result = _mm_setzero_si128();
    const __m128i mask = _mm_set1_epi32(0xff);

    for (int i = 0; i < 4; i++) {
        __m128i col = _mm_srli_si128((const __m128i)state, i * 4);
        col = _mm_and_si128(col, mask);

        __m128i mixed = _mm_setzero_si128();
        for (int j = 0; j < 4; j++) {
            uint8_t val = _mm_extract_epi8(col, j);
            __m128i prod = _mm_set_epi8(
                gmul_table[0x02][val], gmul_table[0x03][val],
                gmul_table[0x01][val], gmul_table[0x01][val],
                gmul_table[0x01][val], gmul_table[0x02][val],
                gmul_table[0x03][val], gmul_table[0x01][val],
                gmul_table[0x01][val], gmul_table[0x01][val],
                gmul_table[0x02][val], gmul_table[0x03][val],
                gmul_table[0x03][val], gmul_table[0x01][val],
                gmul_table[0x01][val], gmul_table[0x02][val]
            );
            mixed = _mm_xor_si128(mixed, _mm_slli_si128(prod, j));
        }
        result = _mm_or_si128(result, _mm_slli_si128(mixed, i * 4));
    }
    return result;
}

// SSE优化的AES加密块
void AES_EncryptBlock(const uint8_t* input, uint8_t* output,
    const uint8_t* round_key, KeyLength key_len) {
    int Nr = get_rounds(key_len);
    const __m128i* rk = (const __m128i*)round_key;

    __m128i state = _mm_loadu_si128((const __m128i*)input);
    state = _mm_xor_si128(state, rk[0]);

    for (int round = 1; round < Nr; round++) {
        state = sse_sbox(state);
        state = sse_shift_rows(state);
        state = sse_mix_columns(state);
        state = _mm_xor_si128(state, rk[round]);
    }

    state = sse_sbox(state);
    state = sse_shift_rows(state);
    state = _mm_xor_si128(state, rk[Nr]);

    _mm_storeu_si128((__m128i*)output, state);
}

// SSE优化的AES解密块
void AES_DecryptBlock(const uint8_t* input, uint8_t* output,
    const uint8_t* round_key, KeyLength key_len) {
    int Nr = get_rounds(key_len);
    const __m128i* rk = (const __m128i*)round_key;

    __m128i state = _mm_loadu_si128((const __m128i*)input);
    state = _mm_xor_si128(state, rk[Nr]);

    for (int round = Nr - 1; round > 0; round--) {
        state = sse_inv_shift_rows(state);
        state = sse_inv_sbox(state);
        state = _mm_xor_si128(state, rk[round]);
        // 逆列混合需要单独实现（类似sse_mix_columns但使用逆系数）
    }

    state = sse_inv_shift_rows(state);
    state = sse_inv_sbox(state);
    state = _mm_xor_si128(state, rk[0]);

    _mm_storeu_si128((__m128i*)output, state);
}

// PKCS#7填充（安全版本）
int pkcs7_pad(const uint8_t* input, int input_len, uint8_t** padded_data, int block_size) {
    int padding_len = block_size - (input_len % block_size);
    int padded_len = input_len + padding_len;

    *padded_data = (uint8_t*)malloc(padded_len);
    if (!*padded_data) return -1;

    memcpy(*padded_data, input, input_len);
    memset(*padded_data + input_len, padding_len, padding_len);

    return padded_len;
}

// PKCS#7去除填充
int pkcs7_unpad(const uint8_t* data, int data_len, uint8_t** unpadded_data) {
    if (data_len <= 0) return 0;

    int padding_len = data[data_len - 1];
    int unpadded_len = data_len - padding_len;

    if (padding_len <= 0 || padding_len > AES_BLOCK_SIZE || unpadded_len < 0) {
        *unpadded_data = (uint8_t*)malloc(data_len);
        memcpy(*unpadded_data, data, data_len);
        return data_len;
    }

    *unpadded_data = (uint8_t*)malloc(unpadded_len);
    memcpy(*unpadded_data, data, unpadded_len);

    return unpadded_len;
}

// CBC模式加密（SSE优化）
void cbc_encrypt(const uint8_t* plaintext, int plaintext_len,
    const uint8_t* key, KeyLength key_len,
    const uint8_t* iv, uint8_t* ciphertext) {
    int Nr = get_rounds(key_len);
    int key_exp_size = AES_BLOCK_SIZE * (Nr + 1);
    uint8_t* roundKey = (uint8_t*)malloc(key_exp_size);
    KeyExpansion(key, roundKey, key_len);

    __m128i iv_reg = _mm_loadu_si128((const __m128i*)iv);

    for (int i = 0; i < plaintext_len; i += AES_BLOCK_SIZE) {
        __m128i block = _mm_loadu_si128((const __m128i*)(plaintext + i));
        block = _mm_xor_si128(block, iv_reg);

        AES_EncryptBlock(block.m128i_u8, ciphertext + i, roundKey, key_len);
        iv_reg = _mm_loadu_si128((const __m128i*)(ciphertext + i));
    }

    free(roundKey);
}

// CBC模式解密（SSE优化）
void cbc_decrypt(const uint8_t* ciphertext, int ciphertext_len,
    const uint8_t* key, KeyLength key_len,
    const uint8_t* iv, uint8_t* plaintext) {
    int Nr = get_rounds(key_len);
    int key_exp_size = AES_BLOCK_SIZE * (Nr + 1);
    uint8_t* roundKey = (uint8_t*)malloc(key_exp_size);
    KeyExpansion(key, roundKey, key_len);

    __m128i prev_cipher = _mm_loadu_si128((const __m128i*)iv);

    for (int i = 0; i < ciphertext_len; i += AES_BLOCK_SIZE) {
        __m128i cipher_block = _mm_loadu_si128((const __m128i*)(ciphertext + i));
        __m128i decrypted;

        AES_DecryptBlock(ciphertext + i, decrypted.m128i_u8, roundKey, key_len);
        decrypted = _mm_xor_si128(decrypted, prev_cipher);

        _mm_storeu_si128((__m128i*)(plaintext + i), decrypted);
        prev_cipher = cipher_block;
    }

    free(roundKey);
}

// AES加密入口函数
int AES_Encrypt(const uint8_t* plaintext, int plaintext_len,
    const uint8_t* key, int key_size,
    const uint8_t* iv, CipherMode mode,
    uint8_t** ciphertext) {
    KeyLength key_len;
    if (key_size == 16) key_len = AES_128;
    else if (key_size == 24) key_len = AES_192;
    else if (key_size == 32) key_len = AES_256;
    else return -1;

    uint8_t* padded_plaintext = NULL;
    int padded_len = pkcs7_pad(plaintext, plaintext_len, &padded_plaintext, AES_BLOCK_SIZE);
    if (padded_len < 0) return -2;

    *ciphertext = (uint8_t*)malloc(padded_len);
    if (!*ciphertext) {
        free(padded_plaintext);
        return -3;
    }

    if (mode == ECB) {
        int Nr = get_rounds(key_len);
        int key_exp_size = AES_BLOCK_SIZE * (Nr + 1);
        uint8_t* roundKey = (uint8_t*)malloc(key_exp_size);
        KeyExpansion(key, roundKey, key_len);

        for (int i = 0; i < padded_len; i += AES_BLOCK_SIZE) {
            AES_EncryptBlock(padded_plaintext + i, (*ciphertext) + i, roundKey, key_len);
        }

        free(roundKey);
    }
    else if (mode == CBC) {
        if (!iv) {
            free(padded_plaintext);
            free(*ciphertext);
            return -4;
        }
        cbc_encrypt(padded_plaintext, padded_len, key, key_len, iv, *ciphertext);
    }

    free(padded_plaintext);
    return padded_len;
}

// AES解密入口函数
int AES_Decrypt(const uint8_t* ciphertext, int ciphertext_len,
    const uint8_t* key, int key_size,
    const uint8_t* iv, CipherMode mode,
    uint8_t** plaintext) {
    KeyLength key_len;
    if (key_size == 16) key_len = AES_128;
    else if (key_size == 24) key_len = AES_192;
    else if (key_size == 32) key_len = AES_256;
    else return -1;

    if (ciphertext_len % AES_BLOCK_SIZE != 0) return -3;

    uint8_t* decrypted_data = (uint8_t*)malloc(ciphertext_len);
    if (!decrypted_data) return -2;

    if (mode == ECB) {
        int Nr = get_rounds(key_len);
        int key_exp_size = AES_BLOCK_SIZE * (Nr + 1);
        uint8_t* roundKey = (uint8_t*)malloc(key_exp_size);
        KeyExpansion(key, roundKey, key_len);

        for (int i = 0; i < ciphertext_len; i += AES_BLOCK_SIZE) {
            AES_DecryptBlock(ciphertext + i, decrypted_data + i, roundKey, key_len);
        }

        free(roundKey);
    }
    else if (mode == CBC) {
        if (!iv) {
            free(decrypted_data);
            return -4;
        }
        cbc_decrypt(ciphertext, ciphertext_len, key, key_len, iv, decrypted_data);
    }

    int result_len = pkcs7_unpad(decrypted_data, ciphertext_len, plaintext);
    free(decrypted_data);
    return result_len;
}
