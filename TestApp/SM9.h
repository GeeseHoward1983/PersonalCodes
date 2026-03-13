#ifndef _SM9_H_
#define _SM9_H_
#include <stdint.h>
// ==================== 基础类型定义 ====================
typedef uint8_t byte;
typedef uint32_t word;
typedef uint64_t dword;

#define BIT_LEN 256
#define BYTE_LEN 32

typedef struct {
    byte data[BYTE_LEN];
} bigint;

typedef struct {
    bigint x;
    bigint y;
    int is_infinity; // 是否为无穷远点
} ec_point;

typedef struct {
    bigint c1;
    bigint c2;
    byte* c3;
    size_t c3_len;
} sm9_cipher;

typedef struct {
    ec_point public_key;
    bigint private_key;
} sm9_key_pair;

typedef struct {
    bigint r;
    bigint s;
} sm9_signature;

void sm9_init();

sm9_key_pair sm9_keygen(const byte *user_id, size_t id_len);

sm9_cipher sm9_encrypt(const ec_point *pub_key, const byte *msg, size_t msg_len);

byte* sm9_decrypt(const sm9_key_pair *key_pair, const sm9_cipher *cipher, size_t *out_len);

sm9_signature sm9_sign(const sm9_key_pair *key_pair, const byte *msg, size_t msg_len);

int sm9_verify(const ec_point *pub_key, const byte *msg, size_t msg_len, const sm9_signature *sig);
#endif
