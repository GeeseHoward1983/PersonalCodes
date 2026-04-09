#include "stdlib.h"
#include "string.h"
#include "stdio.h"
#include "ctype.h"
#include "time.h"
#include "math.h"
#include <intrin.h>

#include "defs.h"
//#include <windows.h>

#include "SM4.h"
#include "Base.h"
//#include "aes.h"
#include "sha.h"
//#include "SM3.h"
//#include "RC4.h"
//#include "DES3.h"
#include "miracl.h"
#include "mirdef.h"
#define DECLSPEC_IMPORT __declspec(dllimport)
#define WINBASEAPI DECLSPEC_IMPORT
extern "C" WINBASEAPI DWORD
__stdcall GetTickCount(
    void
);
#pragma comment(linker, "/NODEFAULTLIB:LIBC")
/****************************** MACROS ******************************/
#define NEWLINE_INVL 76

/**************************** VARIABLES *****************************/
// Note: To change the charset to a URL encoding, replace the '+' and '/' with '*' and '-'
static const unsigned char charset[] = { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" };
//static const unsigned char charset[] = { "[@WP!3C75LfM8iwR2UO;(N>A6*&ut%#SIBhY1$j|kD{]0lx,.md9<4HayrzbXsg_" };

/*********************** FUNCTION DEFINITIONS ***********************/
static unsigned char revchar(char ch)
{
    for (int i = 0; i < 64; i++)
    {
        if (ch == charset[i])
            return i;
    }
    return 0;
}
static size_t base64_decode(const char in[], unsigned char out[], size_t len)
{
    size_t idx, idx2, blks, blk_ceiling, left_over;

    if (in[len - 1] == '=')
        len--;
    if (in[len - 1] == '=')
        len--;

    blks = len / 4;
    left_over = len % 4;

    if (out == nullptr) {
        if (len >= 77 && in[NEWLINE_INVL] == '\n')   // Verify that newlines where used.
            len -= len / (NEWLINE_INVL + 1);
        blks = len / 4;
        left_over = len % 4;

        idx = blks * 3;
        if (left_over == 2)
            idx++;
        else if (left_over == 3)
            idx += 2;
    }
    else {
        blk_ceiling = blks * 4;
        for (idx = 0, idx2 = 0; idx2 < blk_ceiling; idx += 3, idx2 += 4) {
            if (in[idx2] == '\n')
                idx2++;
            out[idx] = (revchar(in[idx2]) << 2) | ((revchar(in[idx2 + 1]) & 0x30) >> 4);
            out[idx + 1] = (revchar(in[idx2 + 1]) << 4) | (revchar(in[idx2 + 2]) >> 2);
            out[idx + 2] = (revchar(in[idx2 + 2]) << 6) | revchar(in[idx2 + 3]);
        }

        if (left_over == 2) {
            out[idx] = (revchar(in[idx2]) << 2) | ((revchar(in[idx2 + 1]) & 0x30) >> 4);
            idx++;
        }
        else if (left_over == 3) {
            out[idx] = (revchar(in[idx2]) << 2) | ((revchar(in[idx2 + 1]) & 0x30) >> 4);
            out[idx + 1] = (revchar(in[idx2 + 1]) << 4) | (revchar(in[idx2 + 2]) >> 2);
            idx += 2;
        }
    }

    return(idx);
}

//#if _MSC_VER >= 1900
//extern "C" {
//    FILE _iob‌ : ml - citation{ ref = "3" data = "citationList" } = { *stdin, *stdout, *stderr };
//}
//#endif

//#include <openssl/aes.h>
//#include <openssl/evp.h>
//
//static int aes_cbc_decrypt(const unsigned char *ciphertext, int ciphertext_len,
//    const unsigned char *key, const unsigned char *iv,
//    unsigned char *plaintext) {
//    EVP_CIPHER_CTX *ctx;
//    int len;
//    int plaintext_len;
//
//    // 创建并初始化上下文
//    if (!(ctx = EVP_CIPHER_CTX_new())) {
//        return -1;
//    }
//
//    // 初始化解密操作
//    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
//        EVP_CIPHER_CTX_free(ctx);
//        return -1;
//    }
//
//    // 执行解密
//    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
//        EVP_CIPHER_CTX_free(ctx);
//        return -1;
//    }
//    plaintext_len = len;
//
//    // 完成解密（处理填充）
//    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
//        EVP_CIPHER_CTX_free(ctx);
//        return -1;
//    }
//    plaintext_len += len;
//
//    // 清理上下文
//    EVP_CIPHER_CTX_free(ctx);
//
//    return plaintext_len;
//}

//typedef struct {
//    const char *name;
//    const char *signature;
//    void *fnPtr;
//} JNINativeMethod;
//struct JavaVM_;
//typedef JavaVM_ JavaVM;
//struct _jobject;
//
//typedef struct _jobject *jobject;
//typedef jobject jclass;
//typedef jobject jstring;
//
//typedef const struct JNINativeInterface_ *JNIEnv;
//
//#define JNI_VERSION_1_6  (0x00010006)
//#define JNI_OK           ( 0）             /* success */
//#define JNI_ERR          (-1)              /* unknown error */
//#define JNI_EDETACHED    (-2)              /* thread detached from the VM */
//#define JNI_EVERSION     (-3)              /* JNI version error */
//#define JNI_ENOMEM       (-4)              /* not enough memory */
//#define JNI_EEXIST       (-5)              /* VM already created */
//#define JNI_EINVAL       (-6)              /* invalid arguments */

/*
static int factorial(int n)
{
    if (n)
    {
        return n * factorial(n - 1);
    }
    else
    {
        return 1;
    }
}

static int Sum(const char* Nome)
{
    size_t len = strlen(Nome);
    int sum = 0;
    for (size_t i = 0; i < len; i++)
    {
        sum += Nome[i];
    }
    return sum;
}

static void CRC16(unsigned char *di, size_t len, unsigned char* crc)
{
    unsigned short crc_poly = 0x1021;  //X^16+X^15+X^2+1 total 16 effective bits without X^16. 
    unsigned short data_t = 0; //CRC register

    for (size_t i = 0; i < len; i++)
    {
        data_t ^= di[i] << 8; //8-bit data

        for (unsigned char j = 0; j < 8; j++)
        {
            if (data_t & 0x8000)
                data_t = (data_t << 1) ^ crc_poly;
            else
                data_t <<= 1;

        }
    }
    crc[0] = (data_t >> 8) & 0x00FF;
    crc[1] = data_t & 0x00FF;
}

static unsigned short crc16(unsigned char* di, size_t len) {
    unsigned short crc = 0xFFFF;
    for (int i = 0; i < len;i++) {
        crc ^= di[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc & 1) ? (crc >> 1) ^ 0x1021 : crc >> 1;
        }
    }
    return crc & 0xFFFF;
}

static int is_numeric(const char *str, size_t len) {
    for (size_t i = 0; i < len;i++) {
        if (!isdigit(str[i]))
            return 0;
    }
    return 1;
}

static void str_replace(char* src, const char find, const char repl) {
    if (!src || !find) return;
    char* end = src + strlen(src);
    for (char* p = src;;)
    {
        p = strchr(p, find);
        if (p)
        {
            if (repl == 0)
            {
                memmove(p, p + 1, end - p);
            }
            else
            {
                *p = repl;
                p++;
            }
        }
        else
        {
            break;
        }
    }
}

*/
//
//static char hexChrToIdx(char ch)
//{
//    if (ch >= '0' && ch <= '9')
//        return ch - '0';
//    if (ch >= 'A' && ch <= 'F')
//        return ch - 'A' + 10;
//    if (ch >= 'a' && ch <= 'f')
//        return ch - 'a' + 10;
//    return -1;
//}
//
//static void HexToBytes(const char* hex, size_t len, uint8* bytes)
//{
//    for (size_t i = 0; i < len; i += 2)
//    {
//        bytes[i / 2] = (hexChrToIdx(hex[i]) << 4) | hexChrToIdx(hex[i + 1]);
//    }
//}
//
//static int hamming_distance(int x) {
//    int count = 0;
//    while (x) {
//        x &= x - 1;
//        count++;
//    }
//    return count;
//}
//
//static _DWORD haming_weight(_QWORD x)
//{
//    x = (x >> 32) ^ (x & 0xffffffff);
//    x = (x >> 16) ^ (x & 0xffff);
//    x = (x >> 8) ^ (x & 0xff);
//    x = (x >> 4) ^ (x & 0xf);
//    x = (x >> 2) ^ (x & 0x3);
//    x = (x >> 1) ^ (x & 0x1);
//    return (_DWORD)x;
//}
////汉明距离奇偶性加密
//static void __cdecl encrypt(_DWORD* Data, _DWORD* maskKey1, _DWORD* maskKey2)
//{
//    _DWORD v8 = 0;
//    _DWORD v6 = 0;
//    for (int i = 0;i < 32;++i)
//    {
//        _QWORD data = (_QWORD)Data[1]          << 32 | Data[0];
//        _QWORD key  = (_QWORD)maskKey2[i]      << 32 | maskKey1[i];
//        _QWORD key2 = (_QWORD)maskKey2[i + 32] << 32 | (_QWORD)maskKey1[i + 32];
//        v6 = haming_weight(data & key)  ^ (v6 << 1);
//        v8 = haming_weight(data & key2) ^ (v8 << 1);
//    }
//    Data[0] = v6;
//    Data[1] = v8;
//}
//
//// 预计算密钥的奇偶性矩阵
//static void build_key_matrix(_DWORD* maskKey1, _DWORD* maskKey2, _DWORD matrix[64][64]) {
//    for (int i = 0; i < 32; ++i) {
//        _QWORD key1 = (((_QWORD)maskKey2[31 - i]) << 32) | (_QWORD)maskKey1[31 - i];
//        _QWORD key2 = (((_QWORD)maskKey2[63 - i]) << 32) | (_QWORD)maskKey1[63 - i];
//
//        // 填充矩阵的奇数行(key1)和偶数行(key2)
//        for (int j = 0; j < 64; ++j) {
//            matrix[i][j] = (key1 >> j) & 1;
//            matrix[i + 32][j] = (key2 >> j) & 1;
//        }
//    }
//}
////高斯消元求逆矩阵
//static bool matrix_inverse(_DWORD input[64][64], _DWORD output[64][64])
//{
//    _DWORD **aug = (_DWORD**)malloc(64 * sizeof(_DWORD*)); // 增广矩阵 [I | A]
//    if (aug)
//    {
//        for (int i = 0;i < 64; ++i)
//        {
//            aug[i] = (_DWORD*)malloc(128 * sizeof(_DWORD));
//            if (aug[i] == NULL)
//            {
//                for (int j = 0; j < i; ++j)
//                {
//                    free(aug[j]);
//                }
//                free(aug);
//                return false;
//            }
//        }
//        // 初始化增广矩阵
//        for (int i = 0; i < 64; ++i) {
//            for (int j = 0; j < 64; ++j) {
//                aug[i][j] = input[i][j];
//                aug[i][j + 64] = (i == j) ? 1 : 0; // 右侧初始化为单位矩阵
//            }
//        }
//
//        // 高斯-若尔当消元法
//        for (int col = 0; col < 64; ++col) {
//            // 寻找主元
//            int pivot = -1;
//            for (int row = col; row < 64; ++row) {
//                if (aug[row][col]) {
//                    pivot = row;
//                    break;
//                }
//            }
//            if (pivot == -1) return false; // 矩阵不可逆
//
//            // 交换行
//            if (pivot != col) {
//                for (int j = 0; j < 128; ++j) {
//                    uint32 temp = aug[col][j];
//                    aug[col][j] = aug[pivot][j];
//                    aug[pivot][j] = temp;
//                }
//            }
//
//            // 消元处理
//            for (int row = 0; row < 64; ++row) {
//                if (row != col && aug[row][col]) {
//                    for (int j = 0; j < 128; ++j) {
//                        aug[row][j] ^= aug[col][j];
//                    }
//                }
//            }
//        }
//
//        // 提取逆矩阵
//        for (int i = 0; i < 64; ++i) {
//            for (int j = 0; j < 64; ++j) {
//                output[i][j] = aug[i][j + 64];
//            }
//        }
//
//        for (int i = 0;i < 64; ++i)
//        {
//            free(aug[i]);
//        }
//        free(aug);
//        return true;
//    }
//    else
//        return false;
//}
//
//static void __cdecl decrypt(_DWORD* Data, _DWORD* maskKey1, _DWORD* maskKey2) {
//    _DWORD key_matrix[64][64];
//    _DWORD inv_matrix[64][64];
//
//    // 预计算阶段
//    build_key_matrix(maskKey1, maskKey2, key_matrix);
//    matrix_inverse(key_matrix, inv_matrix); // 需实现矩阵求逆
//
//    // 解密阶段
//    _DWORD cipher_bits[64] = { 0 };
//    for (int i = 0; i < 32; i++) {
//        cipher_bits[i] = (Data[0] >> (i)) & 1;
//        cipher_bits[i + 32] = (Data[1] >> (i)) & 1;
//    }
//
//    // 矩阵乘法恢复原始数据
//    _QWORD plain = 0;
//    for (int i = 0; i < 64; i++) {
//        _DWORD bit = 0;
//        for (int j = 0; j < 64; j++) {
//            bit ^= inv_matrix[i][j] & cipher_bits[j];
//        }
//        plain ^= (_QWORD)bit << i;
//    }
//
//    Data[0] = (DWORD)(plain & 0xFFFFFFFF);
//    Data[1] = (DWORD)(plain >> 32);
//}
//
static unsigned char sub_4485D0(_WORD* Key, unsigned __int8 a2, unsigned __int8 a3)
{
    _WORD v3; // edi
    _WORD v4; // eax
    int v5; // esi
    _WORD v6; // eax
    bool v7; // zf
    _WORD v8; // eax
    _WORD v9; // eax
    _WORD v11; // [esp+10h] [ebp+8h]
    _WORD v12; // [esp+10h] [ebp+8h]
    _WORD v13; // [esp+10h] [ebp+8h]
    _WORD v14; // [esp+10h] [ebp+8h]

    v3 = 0;
    v4 = a3;
    v5 = 2;
    while (1)
    {
        v11 = 2 * v3;
        if (((2 * v3) & 0x100) != 0)
            v11 = *Key ^ v11;
        v6 = 2 * v4;
        if ((v6 & 0x100) != 0)
            v11 = a2 ^ v11;
        v7 = ((2 * v11) & 0x100) == 0;
        v12 = 2 * v11;
        if (!v7)
            v12 = *Key ^ v12;
        v8 = 2 * v6;
        if ((v8 & 0x100) != 0)
            v12 = a2 ^ v12;
        v7 = ((2 * v12) & 0x100) == 0;
        v13 = 2 * v12;
        if (!v7)
            v13 = *Key ^ v13;
        v9 = 2 * v8;
        if ((v9 & 0x100) != 0)
            v13 = a2 ^ v13;
        v7 = ((2 * v13) & 0x100) == 0;
        v14 = 2 * v13;
        if (!v7)
            v14 = *Key ^ v14;
        v4 = 2 * v9;
        if ((v4 & 0x100) != 0)
            v14 = a2 ^ v14;
        if (!--v5)
            break;
        v3 = v14;
    }
    return (unsigned char)v14;
}

static unsigned char sub_4486C0(_WORD* Key, unsigned __int8 a2)
{
    return sub_4485D0(Key, a2, a2);
}

static unsigned char __stdcall sub_4486D0(_WORD* Key, unsigned __int8 a1)
{
    unsigned __int8 v1; // ebx
    int v2; // esi
    char v3; // al

    v1 = a1;
    v2 = 6;
    do
    {
        v3 = sub_4486C0(Key, a1);
        --v2;
        a1 = sub_4485D0(Key, v3, v1);
    } while (v2);
    return sub_4486C0(Key, a1);
}
//
//
unsigned int dword_455E38[] = { 0x4D0EF68C, 0x0A107EBEE, 0x0E3FF4CC5, 0x696DA9BE, 0x0B4726BCF, 0x64B93DF4, 0x0AC4670DD, 0x70D8739D, 0x241950F8, 0x0AFEFB3BC, 0x6C658E56, 0x0B14A27CA, 0x812CB4A2, 0x511450E7, 0x0B5B1D1E7, 0x0D5A43704, 0x0A16C5ED6, 0x577B6B9D, 0x93F5E943, 0x0ABE60F53, 0x9E3B6D44, 0x8C782130, 0x3E24A84C, 0x2D77434, 0x0C0B8B004, 0x691821A8, 0x8D1F6D3F, 0x0BDD3FC4A, 0x1D6D9B5D, 0x7A0E7FA4, 0x0B81D3335, 0x6E962A04, 0x0BF28E4F4, 0x0F3B3BFC6, 0x2BF1F6F2, 0x0BE771D44, 0x8F82311A, 0x0E0B34C85, 0x0BAC55EA3, 0x90C3EF93, 0x0D3521141, 0x1DCAA43, 0x0E4F24252, 0x152770CE, 0x505710BC, 0x6D63AC64, 0x3311A7B, 0x3BCE665F, 0x8B326FB, 0x0F8BFE2DD, 0x0F281C30D, 0x4A52B6E1, 0x0B42E2C02, 0x1F817127, 0x0BDB0A48D, 0x0E2D9BB55, 0x0F64950F1, 0x3AE9CCE0, 0x0C56D95DD, 0x98583217, 0x0A8FB4DFA, 0x88B0BF5B, 0x0FC79AA1B, 0x0B4F351C0, 0x16D948C5, 0x33EE4813, 0x9279AF06, 0x649B2C07, 0x668B3F1D, 0x8DB14785, 0x0C680FE2, 0x552C21DC, 0x0AA972C53, 0x5F7AFFA8, 0x9B049880, 0x2A7D9073, 0x4C350DBF, 0x0E776E6D5, 0x0E692FAF6, 0x28404CF7, 0x0D1DC86F, 0x44CE64AA, 0x662E83AB, 0x338C8671, 0x0B1F6A028, 0x0A32B60EA, 0x51540B84, 0x5D24F893, 0x0DB9D605C, 0x0D185A9C8, 0x0C2534CC4, 0x21A1C0E3, 0x0D3893F11, 0x17AF55AE, 0x0AC7DB02C, 0x699D4E31, 0x0AD591C44, 0x564FE117, 0x0FB550F8, 0x574FFFC1, 0x5F1F2D7C, 0x6D8B5DC1, 0x0CE645E9A, 0x4CF591E4, 0x6FBB1847, 0x6B07294C, 0x5099F30, 0x0C5D89086, 0x0B01CAA6E, 0x341AB5CE, 0x70824F82, 0x9656017, 0x0BE0F9E8, 0x56603CCD, 0x0B03E83D7, 0x0B5351BDD, 0x2FA563CC, 0x95FC8CB8, 0x0B45BF505, 0x924A21C5, 0x7EAEDB23, 0x71542651, 0x0B6FCF946, 0x41C7725B, 0x0C2F750CC, 0x90DAFDF2, 0x0B1EEF4DA, 0x83C464A0, 0x8ED35FEF, 0x98BC3260, 0x0D5FD0F38, 0x50A6091F, 0x0B7B841C7, 0x4C1E4155, 0x727807D8, 0x37323CA5, 0x0F9ACB934, 0x0DECA8621, 0x7CF03A2C, 0x0FF6D785D, 0x0D78BFF18, 0x296308E4, 0x0A480656, 0x0EBF31EC8, 0x3F90839E, 0x0F031BE2F, 0x7F9AEBDC, 0x5CC86017, 0x0C03AE15B, 0x6ADB9232, 0x972C53D6, 0x994E5CBF, 0x182214B1, 0x7F97FE28, 0x324C5280, 0x0AB19ECD9, 0x8C7F2A06, 0x15D351C, 0x4BAFF748, 0x0E1389F59, 0x6227EDA5, 0x0C5DB77B0, 0x40E6080D, 0x1A697472, 0x507F0160, 0x109342D3, 0x7E6DE9CD, 0x0FE9DBE44, 0x0E442DBB8, 0x9C780F22, 0x0C0B3EEF6, 0x958726AE, 0x6AA11481, 0x0D7073473, 0x0FA3B72CC, 0x0A4889A8C, 0x37FFBEA, 0x5CC3FAF8, 0x6C29E70F, 0x24B5F2EC, 0x69BAA609, 0x8011F4E8, 0x8B835BFE, 0x0E472D992, 0x2DA5EB04, 0x2EF33B44, 0x0FE06C479, 0x60C50A31, 0x0B24B8143, 0x40D72E36, 0x234241B0, 0x707C1BE, 0x9E1FD60D, 0x9576C16A, 0x0E80A6B41, 0x2B9C88B6, 0x6D7B1DF8, 0x8A2F744B, 0x76FA9455, 0x2A7218CE, 0x1ECC066E, 0x35CCCEA8, 0x0B545F330, 0x0AC1F74DA, 0x17403235, 0x34C8C544, 0x0BF2BBB94, 0x0F95F3F9, 0x220CD5D4, 0x6C7E8664, 0x9BACD0A5, 0x0C27ECF35, 0x0B92EAA7C, 0x5FCC924, 0x8EAD91EB, 0x9C71B69D, 0x9DD55736, 0x7564ADB, 0x0DE99CC9F, 0x6DBC45EB, 0x0A55AF6B0, 0x0E3A12201, 0x259A0C27, 0x4DDB16CD, 0x79F76BBD, 0x0AF1D8B35, 0x7AECB0B0, 0x0A0B9838B, 0x64FEB5E8, 0x0C106FFAE, 0x904EC76F, 0x4A50647F, 0x5FF204DB, 0x0A1FCE69F, 0x16AB2C81, 0x0E67D0048, 0x8541CE3C, 0x1563C989, 0x0C609B8BB, 0x0FDC088F8, 0x3818ACDC, 0x305F84EE, 0x5646126, 0x568D1555, 0x9A5D071B, 0x0C94DBAF1, 0x0CEECDAE0, 0x811012A3, 0x8DB0D395, 0x2DDFE926, 0x0B598FD32, 0x6CAD805C, 0x19F92F7D, 0x7DAB27EF, 0x0D33117D7, 0x7E4EC3DB, 0x0C946F2C5, 0x0C2EF51A2, 0x0F53D6BF2, 0x0B8ECB059, 0x0D7229F17, 0x0DDD5D80A, 0x36EC9255, 0x0F5C59B3F, 0x2CBF159F, 0x2632C17E, 0x0C892508, 0x8FD783, 0x0FABC94E3, 0x7B0EB537, 0x8C78B03, 0x9549190A, 0x237CD448, 0x6F7181F2, 0x0C9B8889E, 0x35351B2F, 0x0E2499337, 0x708A0042, 0x9535A3AC, 0x0C3C62B54, 0x9AB435FD, 0x0D04DAE5D, 0x1C2AC642, 0x0A839C24F, 0x89031EAB, 0x5C4A464F, 0x71D4C7B6, 0x0C852432B, 0x44C1AEDA, 0x0D99C1F1B, 0x14FAA9E7, 0x0EEDD0312, 0x0CD83E048, 0x0F0AA339, 0x64576846, 0x0F90A6B43, 0x0F431F7C1, 0x0E0C22AB3, 0x49550497, 0x5B7DD0A6, 0x198F78B3, 0x0CDEB691E, 0x987BB6D9, 0x74492E60, 0x3BA6A163, 0x3F641058, 0x24A7F312, 0x7026137C, 0x49A2F42F, 0x87124EB7, 0x0CEE3143C, 0x941F95C4, 0x0DEDA02E5, 0x4F9B67E6, 0x753159BE, 0x9CB34281, 0x87B6B02A, 0x86110297, 0x51D6D8D4, 0x0DAF2D4E4, 0x8CED5053, 0x0B21B84A1, 0x67ED11F, 0x71E771CD, 0x9F3A2BBC, 0x7357F2B7, 0x0DE80DD18, 0x385BCC4A, 0x6FD5D14A, 0x3E6F92B6, 0x86E4649D, 0x0D29C4144, 0x6F116A1A, 0x0A21E8DBE, 0x97E44FCC, 0x7167AA45, 0x1AAF69CF, 0x0F0D91F15, 0x73E260C1, 0x0E43BAF85, 0x0DA63B26A, 0x4A512EB, 0x0F376199E, 0x45CA02B0, 0x7B8A34E5, 0x56E14146, 0x9EBB1CCE, 0x4C7DBBF6, 0x0B8F09CD2, 0x92DA5C6, 0x9D8375A1, 0x4CCFD625, 0x685999B7, 0x72BB32DB, 0x7015EC52, 0x0F13C5569, 0x485173D5, 0x0FD971B62, 0x1FB50985, 0x12EC96A9, 0x3011BC99, 0x55D5F041, 0x772BF225, 0x0B872B7F9, 0x20C0CEE7, 0x0E1BB8A58, 0x0F5F53010, 0x88E709EB, 0x6BB8A011, 0x0E52C1EC1, 0x14D24C0D, 0x6FBFBE02, 0x410C5442, 0x9271842C, 0x0E76C2447, 0x9553A3FA, 0x0A994C1CF, 0x8B5D1819, 0x0B9181662, 0x475A994C, 0x6165F4BF, 0x7949613F, 0x0A5F522B, 0x0BED3236C, 0x0DE262E9C, 0x0F85DF040, 0x0C96884EC, 0x4EC14016, 0x0FC556A6B, 0x6DC75A35, 0x73540B41, 0x5461DF6, 0x0AD5C5115, 0x1465F2BE, 0x0BA7BA89E, 0x10953A1F, 0x644A28AC, 0x288C95AC, 0x92E28401, 0x0C0CCBDBB, 0x7062D744, 0x228F87CE, 0x8B7EE88F, 0x2DF0AAB7, 0x5ED7A5C7, 0x0FC288C85, 0x975902DD, 0x0C0AA62B6, 0x0FE583B40, 0x9B03DF3D, 0x0A41A0FA2, 0x0C38390A1, 0x64008F6E, 0x1B475E3C, 0x5CA3DA10, 0x0FC0C0465, 0x2F578BA6, 0x462807AD, 0x0C29C73D9, 0x75C84E9E, 0x0DC6B914B, 0x95A30FB3, 0x4CE00F5C, 0x9241FE9F, 0x2619FCFD, 0x0FA4C6C47, 0x22FD7345, 0x86AF4BAA, 0x61D87EC8, 0x0DFDFEC6D, 0x9D26F0F6, 0x6F9CB037, 0x5E837E07, 0x3F36F331, 0x9C143C3C, 0x40C1D611, 0x0FC2CB0E3, 0x5B55DA44, 0x0B94DEC48, 0x745E7B14, 0x0BCB957C9, 0x67752B98, 0x0A753C81E, 0x0CB18B360, 0x0FFD1078D, 0x0BFE4C389, 0x0F3735CC2, 0x0FF62E35, 0x0DCFB012A, 0x5A66F38, 0x0A8718AE0, 0x0AC6146FF, 0x6B5B35C0, 0x528DC3F8, 0x0A2BBF3E1, 0x2EC767B1, 0x0AC8B8FD8, 0x34D57A06, 0x0C7550ED7, 0x0FEB29B85, 0x44CA0B1C, 0x8849C28F, 0x84CB68A6, 0x1F02E307, 0x49182DCD, 0x0FF1BB2CF, 0x72A247ED, 0x2C70AA8D, 0x7F105B9, 0x0B03A47AE, 0x5A005244, 0x0BCEFC8D1, 0x3A3F773C, 0x34967208, 0x558402F2, 0x27103605, 0x0F38221B4, 0x48D6CAFC, 0x0A2707F24, 0x86FED4DE, 0x1B7D7BFB, 0x926BE508, 0x0F26E4001, 0x1FC7686D, 0x74883923, 0x27C4BD9D, 0x0E39F7B15, 0x0B6413882, 0x0C129CF02, 0x0F874D23F, 0x4103C0D7, 0x0C9B02F6D, 0x9358BC28, 0x9D1B79F5, 0x0D682EBD, 0x0FF4F2404, 0x5AC79E5A, 0x9110D349, 0x0A27B8802, 0x0C968BFA5, 0x0AB18A9FE, 0x742ED9EC, 0x0A8BD78F6, 0x6A8E9C83, 0x418A5B57, 0x2584EAE, 0x0C93818BA, 0x6912EAB7, 0x0F32EBA26, 0x49A4737C, 0x0C8E58D6F, 0x92A1E494, 0x2A18DDE5, 0x843AAF13, 0x249A8405, 0x99C9B047, 0x56780156, 0x13898195, 0x715090A5, 0x87498F9B, 0x5E1406C3, 0x0A549F47A, 0x121C0394, 0x0A962577E, 0x0CCFD7BFB, 0x6A6B8489, 0x7009741D, 0x7423F0E1, 0x299B3640, 0x74A6C8F9, 0x5780F8D9, 0x0F667ED91, 0x2E04EB8B, 0x0BFA152E5, 0x790C25CE, 0x4C06D6D7, 0x0DBD6E036, 0x0C5DD5F0D, 0x7B484C43, 0x0B50F4087, 0x5C9214FA, 0x0A0DDAE8E, 0x0EF969A43, 0x52506920, 0x7534A46B, 0x2D27857D, 0x0AB95E75, 0x0B3C3470E, 0x3B70729A, 0x66BF399, 0x169D2898, 0x0E8D10DDA, 0x3ACA8857, 0x0B49F5680, 0x9A6ADB21, 0x3C299C82, 0x1372417D, 0x24DB472A, 0x0DAE0A8DA, 0x0B8C7F985, 0x953293E9, 0x7D8B7E48, 0x0F63344CE, 0x11556C31, 0x387E185, 0x7DA8B975, 0x0F3C5EEA3, 0x27E4214A, 0x9C626A45, 0x5B38528F, 0x3505B38F, 0x0F5C6DA44, 0x53E880A7, 0x5B821531, 0x0BB95A3EB, 0x44458D3E, 0x5D1B2D6A, 0x3FF103B7, 0x3185A8D, 0x0DBEF4287, 0x10CAB115, 0x0E5B7B622, 0x3B5518C3, 0x94B79DAC, 0x6AB0B259, 0x44601702, 0x96E4D041, 0x40D02422, 0x0B398B382, 0x604BD277, 0x0E8E8657A, 0x9D54FD02, 0x95EFB267, 0x97C1C4CB, 0x36E6C1C6, 0x2F2835F2, 0x3C3F9416, 0x65F598BE, 0x29AC4225, 0x6B2B762B, 0x0C4758FEB, 0x0BD0D781C, 0x259E9059, 0x674C390D, 0x4C310667, 0x0DAF0E64F, 0x0B19823A9, 0x0A71472E4, 0x0E9A592A5, 0x8F816B69, 0x7D218862, 0x9A29029, 0x0D27DFC54, 0x9197281F, 0x77DF087D, 0x58C9268A, 0x0E511B314, 0x42002725, 0x0E96C2D4B, 0x833EF5D8, 0x5D1A581D, 0x0FCCD96EB, 0x19A2F0B9, 0x7230D54, 0x190E163A, 0x33805ECC, 0x7AD05B9D, 0x5A65633C, 0x38BD084B, 0x5D468C7B, 0x0E81D907F, 0x183A772C, 0x16230189, 0x75524F97, 0x76846132, 0x66550E65, 0x9CC68DE, 0x8670A3B1, 0x0FF25C5A9, 0x9D52BFE, 0x0F8043DF, 0x1B1770FB, 0x107EF3A1, 0x776F1EB6, 0x5257EDB1, 0x2C55FEA7, 0x0A980E375, 0x0AE9DC4CF, 0x0B25500A, 0x92C525DB, 0x18D0DC79, 0x1789F171, 0x0B3DBD50F, 0x828647D5, 0x242F4B5, 0x8920E4A6, 0x0D2EB0C2B, 0x0F78760BC, 0x0B619630F, 0x0E23E87C7, 0x0BB9EB076, 0x46DD96A8, 0x42616BB3, 0x2353D9E7, 0x0D76D8B3B, 0x1594CCDE, 0x0D076CD86, 0x124FD79A, 0x0D7D4F3E3, 0x59D4EB4E, 0x0FB9B0548, 0x19AEF54D, 0x0EA942CD1, 0x0A8416A0C, 0x68407891, 0x0FF5FF7CC, 0x0FDD03622, 0x74CB2995, 0x0B904C6A6, 0x8DD1426A, 0x111C3EA3, 0x208E1721, 0x0AEC46415, 0x829EBC0B, 0x435361D, 0x7CB6A164, 0x56984149, 0x0E8B03E7B, 0x5079E086, 0x32CF6958, 0x29AA490A, 0x0E70F7A3A, 0x928866AE, 0x0E000A933, 0x301A87F4, 0x1CC2A6A6, 0x0FCEC043B, 0x73256424, 0x4DD63DF5, 0x0BE9F0C5D, 0x0C236863B, 0x33AAD8F1, 0x8F1AC131, 0x74B00667, 0x90A9756F, 0x82275100, 0x0C2433597, 0x99A73E00, 0x9CC8C8AF, 0x492CBCB8, 0x3341EE98, 0x875205CA, 0x0D0A4274F, 0x0A33E18C, 0x50625F8A, 0x0D34C3CBE, 0x784C07E2, 0x85386527, 0x0D19B3B2, 0x0B53905, 0x9099D185, 0x6AD4470C, 0x6BDB5049, 0x6AB57ED7, 0x0CE1DAC58, 0x0F51F9E54, 0x38FBF949, 0x627978CA, 0x8C92078F, 0x0E437AED9, 0x0EA546852, 0x0F10212FC, 0x78779F55, 0x98B11998, 0x21547487, 0x637F3BDF, 0x0D103BC7F, 0x86F3355, 0x71E52401, 0x41A183EE, 0x3D3426DA, 0x0A5CCAF0A, 0x4077EF65, 0x51A2B63D, 0x6143052C, 0x7331481D, 0x0F051ABFD, 0x1A9B500D, 0x241C24CA, 0x6E575567, 0x61F1BA79, 0x37473434, 0x3350ED06, 0x2C61D57C, 0x7304FABE, 0x5284A24, 0x67E580FB, 0x0E9EF975A, 0x0FDE3C1B0, 0x10AC3476, 0x7F664147, 0x3C2B2522, 0x0E2BA00B5, 0x0D958510A, 0x4C4D901A, 0x7D300E2B, 0x43027577, 0x976E17AE, 0x2212E53, 0x48DF9542, 0x3D8B1E58, 0x0B5A73013, 0x0E75BE3AB, 0x0D59A2437, 0x6DA276F1, 0x0B6C60643, 0x0F75DA229, 0x0A4E8CF63, 0x0FBFFF2E3, 0x173A9350, 0x8112BD74, 0x42EB77DB, 0x53B0DD89, 0x0BBF012EE, 0x0FD23F8F4, 0x0FACE82EC, 0x410F43BE, 0x0A0775E51, 0x0F30F01C, 0x3383D52B, 0x754185DA, 0x43645320, 0x0CA4B18D, 0x0C7282FAA, 0x27FA8310, 0x98CB7A47, 0x75B3AE87, 0x30E601DF, 0x0A448BF37, 0x6D9317BD, 0x0EFECC6A, 0x4BC684B3, 0x67872997, 0x4580376E, 0x95C9BD47, 0x0D38EF86C, 0x0F36F0102, 0x0F83E5A9, 0x0F192A394, 0x85ABA799, 0x7D3D8570, 0x0B0450768, 0x57F416F9, 0x11FE6A11, 0x5D51C79A, 0x0E83BFBFC, 0x0FB3F8427, 0x9DB2E430, 0x0C96F898E, 0x5D2AEC92, 0x5281FDCF, 0x3E08AC4D, 0x5AE5DEF7, 0x48738A22, 0x0B073272B, 0x540FEE81, 0x0BE7B6503, 0x1C9698AF, 0x0F5E4BF76, 0x8E648E58, 0x0DDF14830, 0x0C6F786E0, 0x906220C3, 0x62A42F93, 0x72885584, 0x3403F677, 0x3C541144, 0x28818CDC, 0x0A28DA089, 0x528CA22F, 0x8659521E, 0x0BCB214EF, 0x0CD950AA8, 0x0BFF61551, 0x414A27B8, 0x1A0E7B95, 0x39E83CC3, 0x4F567DA4, 0x613C72E7, 0x0F0514CC9, 0x21E1FF1C, 0x0E139A5CD, 0x6F9E1D4B, 0x2B768EB9, 0x8316BA1C, 0x0AC98CD48, 0x0EE51C7B6, 0x626B9819, 0x0EBE64D96, 0x34053FB1, 0x0C7F2290C, 0x0F1144E7A, 0x655A67C2, 0x0DBC6CB12, 0x0DE46EDE9, 0x0BF45BD71, 0x96AF6C36, 0x4DF19BD4, 0x5602402B, 0x201DED42, 0x0FB8CE6E3, 0x0EEE82171, 0x0BA4337D2, 0x0BBE88FF2, 0x0C8EB5309, 0x2D80AB73, 0x447A35D2, 0x0F5A964C3, 0x5270C6D2, 0x1E74AE1C, 0x597B5E54, 0x106151BB, 0x0A6CC9A31, 0x0D74B1A9B, 0x8101FAB3, 0x5B338459, 0x6BB4A4AC, 0x50A5D796, 0x98867C6, 0x0AFBC968B, 0x86A0A06A, 0x0E5FAA862, 0x0F5EE732A, 0x438EEC58, 0x4FA41DDC, 0x37E5C456, 0x9980812A, 0x49BD86EE, 0x0AC80ED8C, 0x0F188D578, 0x6EAB6CCB, 0x89D8637F, 0x77EC8ED8, 0x18E199CE, 0x7FD5BC7, 0x4D06E4EA, 0x53112753, 0x0D3F01924, 0x9A5A9BF2, 0x3D2D01CE, 0x0C8898AAF, 0x61C78512, 0x0A5F87B41, 0x88D2629, 0x0FE0A19D6, 0x8B5E091B, 0x32F5B20D, 0x4A6C0B63, 0x4B1AF4D7, 0x0B2314CD0, 0x37B58D37, 0x25C8E1C6, 0x4E57387B, 0x4CEAB46D, 0x424570EC, 0x76FFD418, 0x1DDF4F36, 0x6A94CF16, 0x9487F38B, 0x0D0FFD93D, 0x2AC2324A, 0x944B923A, 0x7797D0F5, 0x0A9FDAACD, 0x3E6DA87B, 0x0CF8D6C77, 0x0AB30CDC3, 0x0F9AB590B, 0x8E7CC17D, 0x0D1402605, 0x670CD719, 0x0ECED6126, 0x967D5428, 0x0A09DF8CD, 0x9CAAED21, 0x16CAD2D2, 0x14DB0BCF, 0x561F1431, 0x0C391D5BA, 0x28CA012C, 0x20157324, 0x654DC34E, 0x68662B7D, 0x4B3F487F, 0x0D89E5304, 0x6B8E74A, 0x54A6E133, 0x61923326, 0x0B008BDA2, 0x0CD5BF8E, 0x0A8220CC, 0x53CD765C, 0x0FF8F5210, 0x58E1043F, 0x0E108B0FE, 0x3D58E542, 0x855613CD, 0x57F5323A, 0x0B14D9999, 0x4523DEE3, 0x0BA85373, 0x0E29F2AA3, 0x0DD427664, 0x7EBE5925, 0x7094E452, 0x73B7DC52, 0x0DB598DCB, 0x2E1620BE, 0x7E7DE24A, 0x0DB374056, 0x0B7234E51, 0x0E708123B, 0x66A54C25, 0x0BBA5E279, 0x0ADB044FD, 0x5832B4F6, 0x95825E3F, 0x6730497A, 0x1D23A8FA, 0x0F3945228, 0x799E02BD, 0x0E6A5E5A5, 0x0E38E0E7A, 0x65C2FE14, 0x21C99A8D, 0x9438B8F6, 0x0A7D347FE, 0x5CA19AD6, 0x0E1C2C9A3, 0x0B2B28AF4, 0x1D91ECF4, 0x39A3F962, 0x0DD38FBD0, 0x16802910, 0x217E00B, 0x557F0861, 0x1AC5C32A, 0x19F3B8B0, 0x2949C312, 0x928F1BBB, 0x47B895FE, 0x0D05FAE3A, 0x0E62DD85C, 0x16971C70, 0x565A1F77, 0x63CBC20E, 0x582B9409, 0x0A8130DC9, 0x271D3821, 0x741412AC, 0x0D250A0AA, 0x6023039C, 0x0B1DDA950, 0x0ABB80431 };

static void sub_448710(_DWORD* table, _DWORD* a2)
{
    unsigned int v4;
    unsigned int v5;

    v4 = table[0] ^ __ROL4__((*a2 << 8) ^ ((*a2 << 8) ^ (*a2 >> 8)) & 0xFF00FF, 16);
    v5 = __ROL4__((a2[1] << 8) ^ ((a2[1] << 8) ^ (a2[1] >> 8)) & 0xFF00FF, 16);
    for (int i = 1; i < 17;)
    {
		//printf("table[i] = %08x\n", table[i]);
		//printf("LOBYTE(v4) = %02x\n", LOBYTE(v4));
		//printf("dword_455E38[LOBYTE(v4) + 768] = %08x\n", dword_455E38[LOBYTE(v4) + 768]);
		//printf("BYTE1(v4) = %02x\n", BYTE1(v4));
		//printf("dword_455E38[BYTE1(v4) + 512] = %08x\n", dword_455E38[BYTE1(v4) + 512]);
		//printf("BYTE2(v4) = %02x\n", BYTE2(v4));
		//printf("dword_455E38[BYTE2(v4) + 256] = %08x\n", dword_455E38[BYTE2(v4) + 256]);
		//printf("HIBYTE(v4) = %02x\n", HIBYTE(v4));
		//printf("dword_455E38[HIBYTE(v4)] = %08x\n", dword_455E38[HIBYTE(v4)]);
  //      printf("(dword_455E38[LOBYTE(v4) + 768] + (dword_455E38[BYTE1(v4) + 512] ^ (dword_455E38[BYTE2(v4) + 256] + dword_455E38[HIBYTE(v4)]))) = %08x\n", (dword_455E38[LOBYTE(v4) + 768] + (dword_455E38[BYTE1(v4) + 512] ^ (dword_455E38[BYTE2(v4) + 256] + dword_455E38[HIBYTE(v4)]))));
        v5 ^= table[i++] ^ (dword_455E38[LOBYTE(v4) + 768] + (dword_455E38[BYTE1(v4) + 512] ^ (dword_455E38[BYTE2(v4) + 256] + dword_455E38[HIBYTE(v4)])));
        v4 ^= table[i++] ^ (dword_455E38[LOBYTE(v5) + 768] + (dword_455E38[BYTE1(v5) + 512] ^ (dword_455E38[BYTE2(v5) + 256] + dword_455E38[HIBYTE(v5)])));
    }
    a2[0] = __ROL4__(((table[17] ^ v5) << 8) ^ (((table[17] ^ v5) << 8) ^ ((table[17] ^ v5) >> 8)) & 0xFF00FF, 16);
    a2[1] = __ROL4__((v4 << 8) ^ ((v4 << 8) ^ (v4 >> 8)) & 0xFF00FF, 16);
}

static void printHex(unsigned char* data, int len)
{
    for (int i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");
}
static unsigned long _bswap(unsigned long a)
{
    unsigned long res = a;
    __asm
    {
        mov eax, res;
        bswap eax;
        mov res, eax;
    }
    return res;
}

static void GetSign(const char* name, unsigned int* sign)
{
	unsigned char aucSHA1[20] = { 0 };
	sha1((unsigned char*)name, strlen(name), aucSHA1);
	printHex(aucSHA1, 20);
    unsigned char aucSHA256[32] = { 0 };
    SHA256((unsigned char*)name, strlen(name), aucSHA256);
	printHex(aucSHA256, 32);
    unsigned char aucSHA512[64] = { 0 };
    SHA512((unsigned char*)name, strlen(name), aucSHA512);
	printHex(aucSHA512, 64);

    DWORD Hash[2] = { 0 };
	Hash[0] = aucSHA1[3] << 24 | aucSHA1[2] << 16 | aucSHA1[1] << 8 | aucSHA1[0];
	Hash[1] = aucSHA1[7] << 24 | aucSHA1[6] << 16 | aucSHA1[5] << 8 | aucSHA1[4];
    miracl* mip = mirsys(800, 16);
    mip->IOBASE = 16;
    big h = mirvar(0);
    big a = mirvar(-3);
    big b = mirvar(0);
    big r = mirvar(0x01000000);
    big s = mirvar(0);
    big Px = mirvar(0);
    big Py = mirvar(0);
    big Qx = mirvar(0);
    big Qy = mirvar(0);
    big q = mirvar(0);
    big d = mirvar(0);
    big k = mirvar(0);
    big n = mirvar(0);
    big zero = mirvar(0);
    epoint* G = epoint_init();
    epoint* Q = epoint_init();
    epoint* kG = epoint_init();
	//big tartgetr = mirvar(1);
    irand(GetTickCount());

    bytes_to_big(8, (char*)Hash, h);

    cinstr(b, (char*)"22996B9C33AEEFDB");
    cinstr(q, (char*)"C564EEF070E69193");
    cinstr(Px, (char*)"2223A1D595845FA2");
    cinstr(Py, (char*)"1C4EEE9222DDDA62");
    cinstr(n, (char*)"C564EEF19A080B07");

    cinstr(d, (char*)"54656E63656E7420");	//ECDLP Solver
    cinstr(Qx, (char*)"297A4A1E5B1FC99B");
    cinstr(Qy, (char*)"880198E3724F9FEE");

    ecurve_init(a, b, q, MR_PROJECTIVE);
    while (1)
    {
        decr(n, 1, n);
        bigrand(n, k);
        incr(n, 1, n);
		printf("k->w[0] = %08x, k->w[1] = %08x\n", k->w[0], k->w[1]);
        if (compare(k, zero) == 0) // 随机数k不能为0
        {
            continue;
        }
        else
        {
            if (!epoint_set(Px, Py, 0, G))
            {
                continue;
            }
            ecurve_mult(k, G, kG);
            epoint_get(kG, r, kG->Y);
            divide(r, n, n);
            printf("r->w[0] = %08x, r->w[1] = %08x\n", r->w[0], r->w[1]);
            if (compare(r, zero) == 0) // 签名r不能为0
            {
                continue;
            }
            else
            {
                big inv_k = mirvar(0);
                xgcd(k, n, inv_k, inv_k, inv_k); // 求出k的逆元
                multiply(d, r, s);
                add(h, s, s);
                multiply(s, inv_k, s); // s=k^-1.(h+dr) mod n
                divide(s, n, n);
                mirkill(inv_k);
                if (compare(s, zero) == 0) // 签名s不能为0
                {
                    continue;
                }
                else
                {
                    big w = mirvar(0);
                    xgcd(s, n, w, w, w);
                    big u1 = mirvar(0);
                    mad(h, w, u1, n, n, u1);
                    big u2 = mirvar(0);
                    mad(r, w, u2, n, n, u2);
                    epoint_set(Qx, Qy, 0, Q);
                    epoint* temp_point = epoint_init();
                    ecurve_mult(d, G, temp_point);
                    if (epoint_comp(Q, temp_point)) {
                        printf("公钥验证成功: Q = d*G\n");
                    }
                    else {
                        printf("公钥验证失败: Q ≠ d*G\n");
                    }
                    ecurve_mult2(u1, G, u2, Q, temp_point);
                    big x1 = mirvar(0);
                    epoint_get(temp_point, x1, temp_point->Y);
                    epoint_free(temp_point);
                    divide(x1, n, n);
                    mirkill(u1);
                    mirkill(u2);
                    mirkill(w);
                    if (compare(x1, r) == 0) {
                        printf("签名验证成功！\n");
                        mirkill(x1);
                    }
                    else {
                        mirkill(x1);
                        printf("签名验证失败！\n");
                        continue;
                    }
					//if (compare(r, tartgetr) == 0)
     //               {
     //                   printf("找到目标签名！\n");
     //                   break;
     //               }
                    break;
                }
            }
            break;
        }
    }

    // 输出
    sign[0] = _bswap(r->w[1]);
    sign[1] = _bswap(r->w[0]);
    sign[2] = _bswap(s->w[1]);
    sign[3] = _bswap(s->w[0]);
    printf("%08X-%08X-%08X-%08X\n", sign[0], sign[1], sign[2], sign[3]);

    epoint_free(Q);
    epoint_free(G);
    epoint_free(kG);
    mirkill(h);
    mirkill(a);
    mirkill(b);
    mirkill(q);
    mirkill(r);
    mirkill(s);
    mirkill(d);
    mirkill(n);
    mirkill(k);
    mirkill(Px);
    mirkill(Py);
    mirkill(Qx);
    mirkill(Qy);
    mirkill(zero);
    mirexit();

}

//TencentPediyKeygenMe2
static unsigned char __fastcall decrypt_maze(unsigned char* encryptedMaze, int realPos)
{
    _BYTE Key[] = "tgrddf55";
    return encryptedMaze[realPos] ^ Key[realPos % 8];
}
static unsigned char __fastcall Calc_maze(unsigned char* encryptedMaze, int row, int col)
{
    return decrypt_maze(encryptedMaze, (99 * row + col) / 8) >> (7 - (99 * row + col) % 8) & 1;
}
static unsigned char __fastcall Set_maze(unsigned char* encryptedMaze, int row, int col)
{
    int v4; // [rsp+1Ch] [rbp-4h]

    v4 = Calc_maze(encryptedMaze, row, col);
    if (!v4)
        return 32;
    if (v4 == 1)
        return 49;
    return 101;
}
unsigned char encryptedMaze[] = { 0x8b, 0x98, 0x8d, 0x9b, 0x9b, 0x99, 0xca, 0xca, 0x8b, 0x98, 0x8d, 0x9b, 0x94, 0x22, 0x74, 0x25,
        0x70, 0x26, 0x76, 0x64, 0x74, 0x72, 0x35, 0x75, 0x63, 0xcc, 0xd9, 0xce, 0x9a, 0xcd, 0xdb, 0x8a,
        0x8e, 0x9d, 0xcd, 0xcf, 0x9e, 0xb3, 0x20, 0x20, 0x34, 0x23, 0x62, 0x35, 0x60, 0x22, 0x61, 0x71,
        0x30, 0x3d, 0xc8, 0xde, 0xcf, 0x99, 0xcf, 0xce, 0xca, 0xd9, 0xc8, 0xcf, 0x9a, 0xdd, 0x24, 0x64,
        0x31, 0x26, 0x32, 0x35, 0x65, 0x72, 0x24, 0x20, 0x30, 0x36, 0x1d, 0xce, 0x8b, 0xcd, 0x9e, 0xcf,
        0xcb, 0xc9, 0x99, 0x8a, 0xcf, 0xcd, 0x99, 0x70, 0x25, 0x73, 0x37, 0x25, 0x34, 0x72, 0x64, 0x74,
        0x60, 0x72, 0x67, 0x8f, 0xca, 0x9c, 0xce, 0x9e, 0xdf, 0x99, 0x98, 0x9f, 0x8f, 0x8c, 0x9b, 0x84,
        0x30, 0x37, 0x32, 0x71, 0x35, 0x26, 0x24, 0x74, 0x25, 0x62, 0x26, 0x32, 0x8a, 0x8c, 0xca, 0xcf,
        0xdf, 0x8c, 0x8c, 0x8f, 0xce, 0x9c, 0x8f, 0xdf, 0xb0, 0x76, 0x22, 0x65, 0x75, 0x63, 0x31, 0x24,
        0x30, 0x23, 0x22, 0x21, 0x7b, 0x9c, 0xdf, 0xca, 0xdf, 0x89, 0xcc, 0xde, 0x8f, 0x89, 0x8a, 0xcb,
        0xcf, 0x66, 0x33, 0x34, 0x71, 0x77, 0x75, 0x61, 0x25, 0x26, 0x76, 0x64, 0x34, 0x08, 0x9b, 0xdf,
        0x8e, 0x9d, 0x9d, 0xde, 0xde, 0x8c, 0xda, 0x8a, 0x9e, 0x8a, 0x66, 0x25, 0x25, 0x23, 0x64, 0x31,
        0x25, 0x23, 0x33, 0x71, 0x65, 0x33, 0x9a, 0xda, 0x9b, 0xc9, 0xd8, 0x8a, 0xcf, 0x8d, 0xda, 0x9f,
        0xdb, 0x8d, 0xc6, 0x61, 0x60, 0x72, 0x65, 0x71, 0x21, 0x66, 0x37, 0x71, 0x30, 0x77, 0x23, 0xcf,
        0xda, 0x9c, 0xd9, 0x9e, 0x8e, 0x9d, 0xdf, 0xdf, 0xde, 0x9d, 0x8c, 0xb5, 0x30, 0x26, 0x70, 0x75,
        0x35, 0x26, 0x32, 0x35, 0x30, 0x27, 0x65, 0x6f, 0xde, 0xc8, 0x88, 0x8f, 0x9b, 0x99, 0x9e, 0xdb,
        0x9a, 0x99, 0x98, 0x8f, 0x71, 0x33, 0x25, 0x64, 0x30, 0x77, 0x37, 0x21, 0x71, 0x72, 0x24, 0x30,
        0x0f, 0xdc, 0xd8, 0x9e, 0x8a, 0xdc, 0xde, 0x8f, 0xda, 0xc9, 0xdc, 0x9b, 0xc9, 0x77, 0x20, 0x71,
        0x25, 0x76, 0x66, 0x20, 0x30, 0x23, 0x71, 0x25, 0x71, 0xdc, 0xc8, 0x8e, 0xdf, 0xc9, 0x8b, 0xce,
        0xcf, 0x89, 0xd9, 0x9b, 0xcb, 0xd7, 0x65, 0x70, 0x20, 0x23, 0x63, 0x61, 0x61, 0x63, 0x20, 0x31,
        0x61, 0x20, 0xd9, 0x9a, 0xde, 0xdd, 0xce, 0x9b, 0xcb, 0xd9, 0xdc, 0xdf, 0xdf, 0xcd, 0xf1, 0x24,
        0x60, 0x33, 0x72, 0x21, 0x74, 0x72, 0x61, 0x24, 0x31, 0x62, 0x29, 0x9e, 0xca, 0xdc, 0xca, 0xde,
        0xce, 0xdd, 0x98, 0x9b, 0xcf, 0xd9, 0x9e, 0x74, 0x65, 0x62, 0x32, 0x71, 0x70, 0x32, 0x64, 0x64,
        0x70, 0x27, 0x63, 0x0f, 0xdb, 0x88, 0x9a, 0xcf, 0xce, 0xdd, 0x98, 0xce, 0xcf, 0x98, 0xcf, 0xd8,
        0x65, 0x62, 0x27, 0x64, 0x20, 0x32, 0x70, 0x20, 0x21, 0x67, 0x22, 0x35, 0xdf, 0xc9, 0x9f, 0x8a,
        0xcb, 0x89, 0xcc, 0xcf, 0xce, 0xd9, 0x9f, 0xce, 0xc0, 0x73, 0x63, 0x30, 0x74, 0x22, 0x74, 0x60,
        0x61, 0x33, 0x76, 0x30, 0x22, 0xd8, 0xce, 0xdf, 0xcf, 0x8d, 0xdd, 0xce, 0x9e, 0xcd, 0x8a, 0xcf,
        0xcf, 0xb3, 0x62, 0x65, 0x60, 0x23, 0x61, 0x60, 0x34, 0x32, 0x77, 0x64, 0x70, 0x7c, 0x9f, 0xca,
        0x9b, 0x9d, 0xd8, 0x8e, 0xcb, 0x9c, 0x8a, 0x9a, 0x8a, 0x9c, 0x67, 0x74, 0x65, 0x76, 0x64, 0x64,
        0x71, 0x76, 0x23, 0x75, 0x60, 0x22, 0x4b, 0xcb, 0x8b, 0x89, 0x89, 0x8a, 0x9a, 0xcc, 0x9f, 0x9b,
        0x9e, 0x89, 0xce, 0x75, 0x74, 0x23, 0x24, 0x31, 0x65, 0x76, 0x67, 0x30, 0x75, 0x23, 0x24, 0x8b,
        0xdb, 0xdd, 0xdc, 0xde, 0x9a, 0xc9, 0xcb, 0x9b, 0x9b, 0x89, 0xdc, 0xd0, 0x71, 0x62, 0x71, 0x64,
        0x24, 0x76, 0x76, 0x75, 0x75, 0x63, 0x20, 0x23, 0x8f, 0xcc, 0xcc, 0x8e, 0xce, 0x99, 0xdb, 0x8e,
        0x9a, 0x9d, 0xdc, 0xca, 0xa5, 0x63, 0x21, 0x64, 0x21, 0x37, 0x66, 0x21, 0x21, 0x66, 0x71, 0x60,
        0x6a, 0xdc, 0x88, 0xce, 0x9e, 0xcd, 0xcf, 0xda, 0xda, 0xd8, 0x8d, 0x8e, 0x8b, 0x77, 0x35, 0x61,
        0x25, 0x32, 0x33, 0x20, 0x20, 0x36, 0x71, 0x21, 0x34, 0x08, 0xcd, 0x9e, 0x9e, 0xdc, 0xde, 0x9e,
        0x9e, 0x8c, 0xd8, 0xde, 0xdb, 0x8a, 0x74, 0x35, 0x35, 0x76, 0x33, 0x30, 0x61, 0x22, 0x31, 0x64,
        0x31, 0x62, 0xc9, 0x8b, 0x9b, 0xd9, 0x9a, 0xdf, 0xcf, 0xc9, 0x9d, 0x9f, 0xcb, 0xcc, 0x81, 0x74,
        0x30, 0x73, 0x62, 0x21, 0x70, 0x22, 0x64, 0x31, 0x60, 0x66, 0x24, 0xdf, 0xce, 0xdc, 0xde, 0xdf,
        0xcf, 0xdc, 0x9c, 0x8a, 0x9a, 0x99, 0xdb, 0xe5, 0x30, 0x36, 0x23, 0x60, 0x35, 0x77, 0x31, 0x20,
        0x30, 0x37, 0x33, 0x7f, 0x9f, 0xdd, 0xdf, 0xce, 0x8f, 0xdc, 0xcc, 0xda, 0xca, 0xcd, 0xde, 0x9a,
        0x65, 0x26, 0x37, 0x65, 0x25, 0x62, 0x24, 0x21, 0x60, 0x22, 0x33, 0x21, 0x1a, 0xc9, 0x9f, 0x8a,
        0xcf, 0xd8, 0x89, 0xca, 0x8a, 0x89, 0x9e, 0xda, 0xd8, 0x32, 0x66, 0x24, 0x20, 0x36, 0x74, 0x60,
        0x74, 0x26, 0x67, 0x60, 0x61, 0xcc, 0x9f, 0xda, 0x9f, 0xdd, 0x99, 0xce, 0xdb, 0x89, 0x9f, 0x8b,
        0x8b, 0xd3, 0x37, 0x21, 0x65, 0x66, 0x70, 0x64, 0x65, 0x63, 0x33, 0x34, 0x25, 0x60, 0xca, 0x9b,
        0xdb, 0x88, 0x8c, 0x8f, 0x9f, 0xd8, 0xda, 0x8e, 0x9f, 0x89, 0xb3, 0x60, 0x71, 0x62, 0x31, 0x71,
        0x34, 0x73, 0x32, 0x70, 0x21, 0x27, 0x2a, 0x8a, 0x8a, 0x89, 0x8c, 0xda, 0xca, 0xd8, 0x9a, 0xcb,
        0xce, 0xcc, 0x89, 0x70, 0x64, 0x77, 0x25, 0x71, 0x60, 0x33, 0x66, 0x74, 0x74, 0x33, 0x31, 0x5f,
        0xcb, 0x89, 0x9c, 0xdf, 0xdb, 0x8c, 0x8b, 0x8f, 0x8f, 0x8d, 0xcc, 0xd9, 0x30, 0x72, 0x64, 0x61,
        0x25, 0x62, 0x26, 0x75, 0x25, 0x77, 0x65, 0x24, 0xce, 0xdd, 0x98, 0x8e, 0xde, 0xc8, 0x8f, 0x8a,
        0x9b, 0xd9, 0x89, 0x9b, 0xd5, 0x22, 0x64, 0x70, 0x34, 0x33, 0x32, 0x20, 0x60, 0x62, 0x25, 0x75,
        0x72, 0xc8, 0xc8, 0x8a, 0xcb, 0x9d, 0xda, 0xce, 0xce, 0x98, 0xc8, 0x9f, 0x9a, 0xb3, 0x31, 0x24,
        0x70, 0x27, 0x32, 0x25, 0x75, 0x26, 0x31, 0x65, 0x30, 0x3d, 0xdd, 0x9a, 0x9a, 0x8d, 0xde, 0x8e,
        0xca, 0xc8, 0x8c, 0x9f, 0xde, 0xdd, 0x70, 0x35, 0x34, 0x22, 0x63, 0x70, 0x34, 0x33, 0x30, 0x25,
        0x30, 0x33, 0x1d, 0xcb, 0xdb, 0xd8, 0xce, 0x8f, 0xcf, 0x89, 0xdc, 0xca, 0x9f, 0xdc, 0x88, 0x24,
        0x64, 0x77, 0x32, 0x20, 0x30, 0x22, 0x21, 0x64, 0x24, 0x33, 0x27, 0xce, 0x8e, 0x99, 0xda, 0xce,
        0xca, 0xcd, 0x8d, 0xde, 0x8e, 0x9c, 0x8f, 0x80, 0x35, 0x27, 0x76, 0x75, 0x20, 0x73, 0x71, 0x31,
        0x25, 0x26, 0x63, 0x72, 0xdb, 0x88, 0x8b, 0xcf, 0xcf, 0xd8, 0xd9, 0xdb, 0xce, 0xcd, 0x8b, 0xdb,
        0xa4, 0x66, 0x66, 0x21, 0x74, 0x22, 0x24, 0x34, 0x61, 0x72, 0x26, 0x20, 0x3f, 0xd9, 0xca, 0x9b,
        0xcb, 0x9c, 0xc9, 0xdb, 0x8e, 0xc8, 0x9f, 0x9b, 0x9f, 0x73, 0x66, 0x20, 0x70, 0x67, 0x30, 0x25,
        0x25, 0x32, 0x66, 0x30, 0x61, 0x1c, 0x8f, 0x9e, 0x9a, 0xd9, 0xcd, 0xdf, 0x8e, 0x8d, 0x9b, 0xcf,
        0xcb, 0xcb, 0x36, 0x30, 0x25, 0x66, 0x61, 0x34, 0x61, 0x32, 0x76, 0x24, 0x30, 0x63, 0x8a, 0xdf,
        0x8f, 0x98, 0x89, 0xdb, 0xde, 0xcc, 0x8a, 0xca, 0x8f, 0xd8, 0xc2, 0x60, 0x30, 0x26, 0x31, 0x75,
        0x65, 0x26, 0x62, 0x74, 0x60, 0x62, 0x32, 0xcb, 0x9e, 0xdd, 0x8c, 0xdf, 0x9f, 0xc8, 0xce, 0xcf,
        0x8a, 0xd8, 0xcd, 0xa4, 0x75, 0x22, 0x64, 0x24, 0x35, 0x22, 0x63, 0x25, 0x34, 0x76, 0x24, 0x2e,
        0x8a, 0x89, 0x88, 0xcb, 0xcf, 0xdd, 0x8b, 0x9a, 0xde, 0x9c, 0x88, 0xcf, 0x74, 0x22, 0x75, 0x61,
        0x65, 0x76, 0x62, 0x71, 0x60, 0x22, 0x74, 0x24, 0x0e, 0x98, 0x9d, 0x9a, 0x9f, 0x9d, 0x8e, 0xcb,
        0xdb, 0x99, 0x98, 0x9a, 0x99, 0x76, 0x24, 0x35, 0x24, 0x26, 0x62, 0x70, 0x20, 0x27, 0x30, 0x65,
        0x65, 0xdd, 0x88, 0x9b, 0xce, 0x9c, 0x8e, 0xcf, 0xdb, 0x8c, 0xcc, 0xde, 0x9a, 0xd7, 0x74, 0x25,
        0x60, 0x37, 0x22, 0x34, 0x20, 0x67, 0x61, 0x65, 0x31, 0x70, 0xd9, 0xda, 0x9e, 0x8d, 0xce, 0xcf,
        0x8b, 0x9c, 0x98, 0xcf, 0x9a, 0xc8, 0xf0, 0x71, 0x24, 0x76, 0x63, 0x60, 0x30, 0x67, 0x74, 0x21,
        0x34, 0x32, 0x68, 0xdf, 0x8e, 0x98, 0xcf, 0x8b, 0x9e, 0xdc, 0xd9, 0x8a, 0x8f, 0x8c, 0x9a, 0x61,
        0x34, 0x37, 0x23, 0x35, 0x61, 0x27, 0x60, 0x25, 0x65, 0x23, 0x36, 0x1e, 0xdf, 0x98, 0xdb, 0x9f,
        0xca, 0xc8, 0x98, 0xdf, 0x9a, 0x88, 0xca, 0xd9, 0x35, 0x66, 0x66, 0x75, 0x30, 0x73, 0x34, 0x74,
        0x34, 0x22, 0x72, 0x61, 0xdb, 0x89, 0x9f, 0xca, 0x9e, 0xd9, 0xc9, 0x8b, 0xce, 0x89, 0x9a, 0xcb,
        0xc4, 0x67, 0x63, 0x64, 0x65, 0x22, 0x35, 0x31, 0x70, 0x23, 0x73, 0x64, 0x63, 0x99, 0xca, 0xca,
        0x8b, 0x98, 0x8d, 0x9b, 0x9b, 0x99, 0xca, 0xca, 0x8b, 0xe7
};
_DWORD rowMask[] = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0 };
_DWORD colMask[] = { 0xFFFFFFFF, 0, 1, 0, 0xFFFFFFFF, 0, 1, 0, 0xFFFFFFFF, 0, 1, 0, 0, 0, 0, 0 };
static char* __fastcall Init_maze(char** maze, int row, int col)
{
    int i; // [rsp+14h] [rbp-3Ch]
    int j; // [rsp+18h] [rbp-38h]
    int k; // [rsp+1Ch] [rbp-34h]

    for (i = 0; i <= 2; ++i)
        maze[row - 1][col - 1 + i] = Set_maze(encryptedMaze, rowMask[i] + row, colMask[i] + col);
    for (j = 4; j <= 6; ++j)
        maze[row][col - 1 + j - 4] = Set_maze(encryptedMaze, rowMask[j] + row, colMask[j] + col);
    for (k = 8; k <= 10 ; ++k)
        maze[row + 1][col - 1 + k - 8] = Set_maze(encryptedMaze, rowMask[k] + row, colMask[k] + col);
    return 0;
}
typedef struct _stPOS
{
	int x;
	int y;
} stPOS;
static BOOL NextW(const char** maze, stPOS start, stPOS end, char* path, int pathCnt);
static BOOL NextA(const char** maze, stPOS start, stPOS end, char* path, int pathCnt);
static BOOL NextS(const char** maze, stPOS start, stPOS end, char* path, int pathCnt);
static BOOL NextD(const char** maze, stPOS start, stPOS end, char* path, int pathCnt);
static BOOL NextW(const char** maze, stPOS start, stPOS end, char* path, int pathCnt)
{
    BOOL result = FALSE;
	path[pathCnt++] = 'w';
	start.x -= 1;
    if (start.x > 0 && maze[start.x - 1][start.y] != '1')
    {
        int ret = NextW(maze, start, end, path, pathCnt);
        if (ret)
        {

        }
        result |= ret;
    }
    if (start.y > 0 && maze[start.x][start.y - 1] != '1')
    {
        int ret = NextA(maze, start, end, path, pathCnt);
        if (ret)
        {

        }
        result |= ret;
    }
    if (start.y < end.y && maze[start.x][start.y + 1] != '1')
    {
        int ret = NextD(maze, start, end, path, pathCnt);
        if (ret)
        {

        }
        result |= ret;
    }

	return FALSE;
}
static BOOL NextD(const char** maze, stPOS start, stPOS end, char* path, int pathCnt)
{
    BOOL result = FALSE;
    path[pathCnt++] = 'd';
    start.y += 1;
    if (start.x == end.x && start.y == end.y)
    {
        path[pathCnt] = 0;
        printf("path:%s\npathCnt:%d", path, pathCnt);
		return TRUE;
    }
    if (start.x > 0 && maze[start.x - 1][start.y] != '1')
    {
        int ret = NextW(maze, start, end, path, pathCnt);
        if (ret)
        {

        }
        result |= ret;
    }
    if (start.x < end.x && maze[start.x + 1][start.y] != '1')
    {
        int ret = NextS(maze, start, end, path, pathCnt);
        if (ret)
        {

        }
        result |= ret;
    }
    if (start.y < end.y && maze[start.x][start.y + 1] != '1')
    {
        int ret = NextD(maze, start, end, path, pathCnt);
        if (ret)
        {

        }
        result |= ret;
    }
    return FALSE;
}
static BOOL NextA(const char** maze, stPOS start, stPOS end, char* path, int pathCnt)
{
    BOOL result = FALSE;
    path[pathCnt++] = 'a';
    start.y -= 1;

    if (start.x > 0 && maze[start.x - 1][start.y] != '1')
    {
        int ret = NextW(maze, start, end, path, pathCnt);
        if (ret)
        {

        }
        result |= ret;
    }
    if (start.x < end.x && maze[start.x + 1][start.y] != '1')
    {
        int ret = NextS(maze, start, end, path, pathCnt);
        if (ret)
        {

        }
        result |= ret;
    }
    if (start.y > 0 && maze[start.x][start.y - 1] != '1')
    {
        int ret = NextA(maze, start, end, path, pathCnt);
        if (ret)
        {

        }
        result |= ret;
    }
    return FALSE;
}
static BOOL NextS(const char** maze, stPOS start, stPOS end, char* path, int pathCnt)
{
    BOOL result = FALSE;
    path[pathCnt++] = 's';
    start.x += 1;
    if (start.x == end.x && start.y == end.y)
    {
        path[pathCnt] = 0;
        printf("path:%s\npathCnt:%d", path, pathCnt);
        return TRUE;
    }
    if (start.x < end.x && maze[start.x + 1][start.y] != '1')
    {
        int ret = NextS(maze, start, end, path, pathCnt);
        if (ret)
        {

        }
        result |= ret;
    }
    if (start.y > 0 && maze[start.x][start.y - 1] != '1')
    {
        int ret = NextA(maze, start, end, path, pathCnt);
        if (ret)
        {

        }
        result |= ret;
    }
    if (start.y < end.y && maze[start.x][start.y + 1] != '1')
    {
        int ret = NextD(maze, start, end, path, pathCnt);
        if (ret)
        {

        }
        result |= ret;
    }
    return FALSE;
}
static BOOL findPath(const char** maze, stPOS start, stPOS end, char* path, int pathCnt)
{
    BOOL result = FALSE;
    if (maze[start.x - 1][start.y] != '1')
    {
        int ret = NextW(maze, start, end, path, pathCnt);
        if (ret)
        {

        }
        result |= ret;
    }
    if (maze[start.x + 1][start.y] != '1')
    {
        int ret = NextS(maze, start, end, path, pathCnt);
        if (ret)
        {

        }
        result |= ret;
    }
    if (maze[start.x][start.y - 1] != '1')
    {
        int ret = NextA(maze, start, end, path, pathCnt);
        if (ret)
        {

        }
        result |= ret;
    }
    if (maze[start.x][start.y + 1] != '1')
    {
        int ret = NextD(maze, start, end, path, pathCnt);
        if (ret)
        {

        }
        result |= ret;
    }

	return 0;
}
int main(void)
{
    system("chcp 65001");
    // unsigned char crc[4] = { 0 };
    // unsigned int dword_455DF0[] = { 0xF35AF301, 0x4BA5308F, 0x3E78B787, 0x3B28EDC8, 0x5D9D9334, 0x69B78D4C, 0x6AA9CE9E, 0x0E8DC9EF8, 0x0AB3FA2AE, 0x0A41A08D1, 0x182E4462, 0x7D6A8455, 0x0EB85AD5D, 0x4051D52F, 0x0A8C782C2, 0x0D5E8EB10, 0x2F80CE14, 0x811C88D7 };

    // unsigned int calc_455DF0[18] = { 0 };

    // const char pKey[] = "DEADBEEF";

    // unsigned int pKey2[2] = { 0 };

    // pKey2[0] = pKey[0] << 24 | pKey[1] << 16 | pKey[2] << 8 | pKey[3];
    // pKey2[1] = pKey[4] << 24 | pKey[5] << 16 | pKey[6] << 8 | pKey[7];
    // for (int i = 0;i < 18;i++)
    // {
    //     calc_455DF0[i] = dword_455DF0[i] ^ pKey2[i % 2];
    // }

    // unsigned int v29[2] = { 0 };
    // for (int i = 0; i < 0x12; i += 2)
    // {
    //     sub_448710(calc_455DF0, v29);
    //     calc_455DF0[i] = v29[0];
    //     calc_455DF0[i + 1] = v29[1];
    // }
    // for (int i = 0; i < 1024; i += 2)
    // {
    //     sub_448710(calc_455DF0, v29);
    //     dword_455E38[i] = v29[0];
    //     dword_455E38[i + 1] = v29[1];
    // }

    // unsigned char crcReal[8] = { 0 };
    // unsigned int sign[4] = { 0 };
    // GetSign("KCTF", sign);
    // unsigned char encDest[16] = { 0 };
    // *((unsigned int *)crc) = sign[0] ^ sign[1] ^ sign[2] ^ sign[3];
    // int flag = 1;
    // if (flag)
    // {
    //     unsigned int tmp = 0;
    //     for (int i = 0; i < 9;i++)
    //     {
    //         tmp = calc_455DF0[i];
    //         calc_455DF0[i] = calc_455DF0[17 - i];
    //         calc_455DF0[17 - i] = tmp;
    //     }
    // }
    // flag = 1;
    // memcpy(crcReal, crc, 4);
    // sign[0] ^= *((unsigned int*)crcReal);
    // sign[1] ^= *((unsigned int*)(crcReal + 4));
    // sub_448710(calc_455DF0, sign);
    // memcpy(crcReal, sign, 8);
    // sign[2] ^= *((unsigned int*)crcReal);
    // sign[3] ^= *((unsigned int*)(crcReal + 4));
    // sub_448710(calc_455DF0, sign + 2);
    // memcpy(encDest, sign, 16);
    // _WORD Xorkey = 0x011B;
    // for (int i = 0;i < 16;i++)
    // {
    //     unsigned char ret = sub_4486D0(&Xorkey, encDest[i]);
    //     printf("%02X, %02X\n", encDest[i], ret);
    //     encDest[i] = ret;
    // }

    // for (int i = 0;i < 4;i++)
    // {
    //     unsigned char ret = sub_4486D0(&Xorkey, crc[i]);
    //     printf("%02X, %02X\n", crc[i], ret);
    //     crc[i] = ret;
    // }

    // unsigned char base32Decode[20] = { 0 };
    // memcpy(base32Decode + 16, crc, 4);

    // unsigned char key[] = "Security@Tencent";
    // sm4_context ctx;
    // sm4_setkey_dec(&ctx, key);
    // sm4_crypt_ecb(&ctx, SM4_DECRYPT, 16, encDest, base32Decode);
    // size_t encodeLen = Base32_Encode(base32Decode, 20, NULL, "ABCDEFGHJKMNPQRSTVWXYZ1234567890");
    // char* base32EncodeStr = (char*)malloc(encodeLen + 1);
    // if (base32EncodeStr)
    // {
    //     memset(base32EncodeStr, 0, encodeLen + 1);
    //     Base32_Encode(base32Decode, 20, base32EncodeStr, "ABCDEFGHJKMNPQRSTVWXYZ1234567890");
    //     char code[36] = { 0 };
    //     code[8] = '-';
    //     code[17] = '-';
    //     code[26] = '-';
    //     memcpy(code, base32EncodeStr, 8);
    //     memcpy(code + 9, base32EncodeStr + 8, 8);
    //     memcpy(code + 18, base32EncodeStr + 16, 8);
    //     memcpy(code + 27, base32EncodeStr + 24, 8);
    //     printf("%s\n", base32EncodeStr);
    //     printf("%s\n", code);
    //     size_t decode_len = Base32_Decode(base32EncodeStr, encodeLen, NULL, "ABCDEFGHJKMNPQRSTVWXYZ1234567890");
    //     unsigned char* decDest = (unsigned char*)malloc(decode_len);
    //     if(decDest)
    //     {
    //         Base32_Decode(base32EncodeStr, encodeLen, decDest, "ABCDEFGHJKMNPQRSTVWXYZ1234567890");
    //         for (size_t i = 0; i < decode_len; i++)
    //         {
    //             printf("%02X ", decDest[i]);
    //         }
    //         printf("\n");

    //         sm4_setkey_enc(&ctx, key);
    //         int encLen = sm4_crypt_ecb(&ctx, SM4_ENCRYPT, 16, decDest, encDest);
    //         for (int i = 0; i < 16; i++)
    //         {
    //             unsigned char ret = sub_4486D0(&Xorkey, encDest[i]);
    //             printf("%02X, %02X\n", encDest[i], ret);
    //             encDest[i] = ret;
    //         }

    //         for (int i = 0; i < 4; i++)
    //         {
    //             unsigned char ret = sub_4486D0(&Xorkey, crc[i]);
    //             printf("%02X, %02X\n", crc[i], ret);
    //             crc[i] = ret;
    //         }

    //         if (flag)
    //         {
    //             unsigned int tmp = 0;
    //             for (int i = 0; i < 9; i++)
    //             {
    //                 tmp = calc_455DF0[i];
    //                 calc_455DF0[i] = calc_455DF0[17 - i];
    //                 calc_455DF0[17 - i] = tmp;
    //             }
    //             flag = 1;
    //         }
    //         memset(crcReal, 0, 8);
    //         memcpy(crcReal, crc, 4);
    //         memcpy(sign, encDest, 16);
    //         sub_448710(calc_455DF0, sign);
    //         sign[0] ^= *((unsigned int*)crcReal);
    //         sign[1] ^= *((unsigned int*)(crcReal + 4));
    //         memcpy(crcReal, encDest, 8);
    //         sub_448710(calc_455DF0, sign + 2);
    //         sign[2] ^= *((unsigned int*)crcReal);
    //         sign[3] ^= *((unsigned int*)(crcReal + 4));
    //         free(decDest);
    //         printf("%08X-%08X-%08X-%08X\n", sign[0], sign[1], sign[2], sign[3]);
    //     }
    //     free(base32EncodeStr);
    //}
    char ** maze = (char**)malloc(99 * sizeof(char*));
    if (maze)
    {
		memset(maze, 0, 99 * sizeof(char*));
		for (int i = 0; i < 99; i++)
        {
            maze[i] = (char*)malloc(100);
            if (maze[i])
            {
                memset(maze[i], 48, 100);
                maze[i][99] = 0;
            }
        }
		for (int i = 1; i < 99; i = i + 3)
        {
            for (int j = 1; j < 99; j = j + 3)
            {
                Init_maze(maze, i, j);
            }
        }
        for (int i = 0; i < 99; i++)
            printf("%s\n", maze[i]);
		stPOS start = { 1, 1 };
		stPOS end = { 97, 97 };
		char path[2048] = { 0 };
		int pathCnt = 0;
		findPath((const char**)maze, start, end, path, 0);
        for (int i = 0; i < 99; i++)
        {
            if (maze[i])
                free(maze[i]);
        }
        free(maze);
    }
    return 0;

}

