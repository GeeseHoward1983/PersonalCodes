#ifndef SM4_H
#define SM4_H

/**
* \file sm4.h
*/
#define SM4_ENCRYPT     1
#define SM4_DECRYPT     0

/**
* \brief          SM4 context structure 上下文结构
*/
typedef struct
{
    int mode;                   /*!<  encrypt/decrypt 控制加密还是解密 */
    unsigned long sk[32];       /*!<  SM4 subkeys  存放每次迭代的轮密钥     */
}sm4_context;


#ifdef __cplusplus
extern "C" {
#endif
    //
        /**
        * \brief          SM4 key schedule (128-bit, encryption)设置加密秘钥
        *
        * \param ctx      SM4 context to be initialized
        * \param key      16-byte secret key
        */
    void sm4_setkey_enc(sm4_context* ctx, unsigned char key[16]);

    /**
    * \brief          SM4 key schedule (128-bit, decryption)
    *
    * \param ctx      SM4 context to be initialized
    * \param key      16-byte secret key
    */
    void sm4_setkey_dec(sm4_context* ctx, unsigned char key[16]);

    /**
    * \brief          SM4-ECB block encryption/decryption
    * \param ctx      SM4 context
    * \param mode     SM4_ENCRYPT or SM4_DECRYPT
    * \param length   length of the input data
    * \param input    input block
    * \param output   output block
    */
    int sm4_crypt_ecb(sm4_context* ctx,
        int mode,
        int length,
        unsigned char* input,
        unsigned char* output);

    /**
    * \brief          SM4-CBC buffer encryption/decryption
    * \param ctx      SM4 context
    * \param mode     SM4_ENCRYPT or SM4_DECRYPT
    * \param length   length of the input data
    * \param iv       initialization vector (updated after use)
    * \param input    buffer holding the input data
    * \param output   buffer holding the output data
    */
    int sm4_crypt_cbc(sm4_context* ctx,
        int mode,
        int length,
        unsigned char iv[16],
        unsigned char* input,
        unsigned char* output);

#ifdef __cplusplus
}
#endif
#endif // SM4_H
