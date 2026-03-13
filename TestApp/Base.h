#ifndef __BASE_H__
#define __BASE_H__


size_t Base64_Encode(const unsigned char*src, size_t src_len, char* dst, const char* pcharset, int newline_flag);
size_t Base64_Decode(const char* src, size_t src_len, unsigned char* dst, const char* pcharset, int newline_flag);
size_t Base16_Encode(const unsigned char* src, size_t src_len, char* dst, const char* pcharset);
size_t Base16_Decode(const char* src, size_t src_len, unsigned char* dst, const char* pcharset);
size_t Base24_Encode(const unsigned char* src, size_t src_len, char* dst, const char* pcharset);
size_t Base24_Decode(const char* src, size_t src_len, unsigned char* dst, const char* pcharset);
size_t Base32_Encode(const unsigned char* src, size_t src_len, char* dst, const char* pcharset);
size_t Base32_Decode(const char* src, size_t src_len, unsigned char* dst, const char* pcharset);
size_t Base58_Encode(const unsigned char* src, size_t src_len, char* dst, const char* pcharset);
size_t Base58_Decode(const char* src, size_t src_len, unsigned char* dst, const char* pcharset);
size_t Base36_Encode(const char* src, size_t src_len, char* dst, const char* pcharset);
size_t Base36_Decode(const char* src, size_t src_len, char* dst, const char* pcharset);
size_t Base62_Encode(const char* src, size_t src_len, char* dst, const char* pcharset);
size_t Base62_Decode(const char* src, size_t src_len, char* dst, const char* pcharset);
size_t Base85b_Encode(const unsigned char* src, size_t src_len, char* dst, const char* pcharset);
size_t Base85b_Decode(const char* src, size_t src_len, unsigned char* dst, const char* pcharset);
#endif
