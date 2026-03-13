#ifndef _DES3_H_
#define _DES3_H_ 
#include <stdint.h>

/* 工作模式实现 */
typedef enum { ECB, CBC, CFB, OFB } DES3CipherMode;

void des3_crypt(uint8_t* data, size_t* len,
    const uint8_t* key, // 24字节密钥
    const uint8_t* iv,  // 8字节IV (CBC/CFB/OFB需要)
    int encrypt,        // 0=解密, 1=加密
    DES3CipherMode mode,    // 工作模式
    int padding);       // 0=无填充, 1=PKCS7

#endif
