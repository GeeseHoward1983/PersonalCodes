#include "stdlib.h"
#include "string.h"
#ifndef _WINDOWS
#include <sys/types.h>
#endif
#include "ctype.h"
#include "Base.h"

typedef enum _BaseType
{
    En_Base_Type_Base16,
    En_Base_Type_Base24,
    En_Base_Type_Base32,
    En_Base_Type_Base64,
    En_Base_Type_Base36,
    En_Base_Type_Base58,
    En_Base_Type_Base62,
    En_Base_Type_Base85,
    En_Base_Type_Base91,
    En_Base_Type_Base92,
    En_Base_Type_Base45,
    En_Base_Type_Base100,
}En_Base_Type;


constexpr auto NEWLINE_INVL = 76;

static const char* pacCharset[] =
{
    "0123456789ABCDEF",
    "BCDFGHJKMPQRTVWXY2346789",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    "0123456789abcdefghijklmnopqrstuvwxyz",
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~",
};

static const unsigned char blkLen[] =
{
    4,
    4,
    5,
    6,
};

//encodeBlkLen控制编码模块大小,其中base36、base58、base62代表字符串转换进制数
static const short encodeBlkLen[] =
{
    1,
    1,
    5,
    3,
    10,
    256,
    10,
    256
};

//encodeBlkLen控制编码目标模块大小,其中base36、base58、base62代表字符串转换目标进制数
static const short targetBlkLen[] =
{
    2,
    2,
    8,
    4,
    36,
    58,
    62,
    85
};

static int is_numeric(const char* str, size_t len) {
    for (size_t i = 0; i < len;i++) {
        if (!isdigit(str[i]))
            return 0;
    }
    return 1;
}

static unsigned char revchar(char ch, const char* charset)
{
    for (unsigned char c = 0;c < strlen(charset); c++)
    {
        if (charset[c] == ch)
            return c;
    }
    return 0xFF;
}

static unsigned char divmod(unsigned char* number, size_t len, unsigned short base, unsigned short divisor) {
    unsigned char remainder = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char digit = number[i];
        int temp = remainder * base + digit;
        number[i] = static_cast<unsigned char>(temp / divisor);
        remainder = static_cast<unsigned char>(temp % divisor);
    }
    return remainder;
}

static size_t Base_Encode(En_Base_Type type, const unsigned char* src, size_t src_len, char* dst, const char* pcharset, int newline_flag)
{
    const char* charset = pacCharset[type];
    if (pcharset)
        charset = pcharset;

    if (type <= En_Base_Type_Base64 && type >= En_Base_Type_Base16)
    {
        if (type != En_Base_Type_Base64 && type >= En_Base_Type_Base16)
        {
            newline_flag = 0;
        }
        size_t idx, idx2 = 0, blks, left_over, newline_count = 0;

        blks = (src_len / encodeBlkLen[type]);
        left_over = src_len % encodeBlkLen[type];

        if (dst == nullptr) {
            idx2 = blks * targetBlkLen[type];
            if (left_over)
                idx2 += targetBlkLen[type];
            if (newline_flag)
                idx2 += src_len / ((NEWLINE_INVL / targetBlkLen[type]) * encodeBlkLen[type]);
        }
        else {
            int tmpVlaue = 0;
            int pos = blkLen[type];
            for (idx = 0; idx < src_len; idx++) {
                int right_shift = 8 - pos % 8;
                dst[idx2] = charset[tmpVlaue | (src[idx] >> right_shift)];
                while (right_shift > blkLen[type])
                {
                    right_shift -= blkLen[type];
                    tmpVlaue = (((src[idx] >> right_shift) & ((1 << blkLen[type]) - 1)));
                    dst[++idx2] = charset[tmpVlaue];
                    pos += blkLen[type];
                }
                int left_shift = blkLen[type] - right_shift;
                tmpVlaue = ((src[idx] & ((1 << right_shift) - 1)) << left_shift);
                pos += blkLen[type];
                if (pos % 8 == 0)
                {
                    pos = blkLen[type];
                    dst[++idx2] = charset[tmpVlaue];
                    if (type == En_Base_Type_Base24)
                    {
                        dst[idx2] = charset[23 - tmpVlaue];
                    }
                    idx2++;
                    tmpVlaue = 0;
                }
                else
                {
                    idx2++;
                }
                if (((idx2 - newline_count + targetBlkLen[type]) % NEWLINE_INVL == 0) && newline_flag) {
                    dst[idx2 + targetBlkLen[type]] = '\n';
                    idx2++;
                    newline_count++;
                }
            }
            if (left_over)
            {
                dst[idx2++] = charset[tmpVlaue];
                size_t leftChar = targetBlkLen[type] - ((left_over * 8 + blkLen[type] - 1) / blkLen[type]);
                for (size_t i = 0;i < leftChar;i++)
                {
                    dst[idx2++] = '=';
                }
            }
        }

        return(idx2);
    }
    else if (type <= En_Base_Type_Base85 && type >= En_Base_Type_Base16)
    {
        unsigned char* psrc = (unsigned char*)malloc(src_len);
        if (psrc)
        {
            memcpy(psrc, src, src_len);
            char* p = (char*)malloc(src_len * 2 + 1);
            if(!p)
                return 0;
            size_t dstLen = 0;
            memset(p, 0, src_len * 2 + 1);
            for (size_t i = 0;i < src_len;)
            {
                p[dstLen++] = divmod(psrc + i, src_len - i, encodeBlkLen[type], targetBlkLen[type]);
                while (psrc[i] == 0)
                {
                    i++;
                }
            }
            if (dst)
            {
                for (size_t i = 0;i < dstLen;i++)
                {
                    dst[i] = charset[p[dstLen - i - 1]];
                }
            }
            return dstLen;
        }
        else
            return 0;
    }
    else
    {
        return 0;
    }
}

static size_t Base_Decode(En_Base_Type type, const char* src, size_t src_len, unsigned char* dst, const char* pcharset, int newline_flag)
{
    const char* charset = pacCharset[type];
    if (pcharset)
        charset = pcharset;
    if (type <= En_Base_Type_Base64 && type >= En_Base_Type_Base16)
    {
        size_t idx = 0, blks, left_over;

        while (src[src_len - 1] == '=')
            src_len--;

        blks = src_len / targetBlkLen[type];
        left_over = src_len % targetBlkLen[type];

        if (dst == nullptr) {
            if (src_len > NEWLINE_INVL && src[NEWLINE_INVL] == '\n')   // Verify that newlines where used.
                src_len -= src_len / (NEWLINE_INVL + 1);
            blks = src_len / targetBlkLen[type];
            left_over = src_len % targetBlkLen[type];

            idx = blks * encodeBlkLen[type];
            idx += (left_over * blkLen[type]) / 8;
        }
        else {
            for (unsigned char idx2 = 0; idx2 < src_len; idx2++) {
                if (src[idx2] == '\n')
                    idx2++;
                int left_shift = ((8 - blkLen[type]) * (idx2 + 1)) % 8;
                dst[idx] = (revchar(src[idx2], charset) << left_shift);
                while (blkLen[type] <= left_shift)
                {
                    left_shift -= blkLen[type];
                    if (type == En_Base_Type_Base24)
                        dst[idx] |= ((23 - revchar(src[++idx2], charset)) << left_shift);
                    else
                        dst[idx] |= (revchar(src[++idx2], charset) << left_shift);
                }
                if (left_shift)
                {
                    int right_shift = blkLen[type] - left_shift;
                    dst[idx] |= ((revchar(src[idx2 + 1], charset)) >> right_shift);
                }
                idx++;
            }
        }

        return(idx);
    }
    else if (type <= En_Base_Type_Base85 && type >= En_Base_Type_Base16)
    {
        unsigned char* psrc = (unsigned char*)malloc(src_len);
        if (psrc)
        {
            for (size_t i = 0;i < src_len;i++)
            {
                psrc[i] = revchar(src[i], charset);
            }
            char* p = (char*)malloc(src_len * 2 + 1);
            if (!p)
                return 0;
            memset(p, 0, src_len * 2 + 1);
            size_t dstLen = 0;
            for (size_t i = 0;i < src_len;)
            {
                p[dstLen++] = divmod(psrc + i, src_len - i, targetBlkLen[type], encodeBlkLen[type]);
                while (psrc[i] == 0)
                {
                    i++;
                }
            }
            if (dst)
            {
                for (size_t i = 0;i < dstLen;i++)
                {
                    dst[i] = p[dstLen - i - 1];
                }
            }
            return dstLen;
        }
        else
            return 0;
    }
    else
    {
        return 0;
    }

}

size_t Base64_Encode(const unsigned char* src, size_t src_len, char* dst, const char* pcharset, int newline_flag)
{
    return Base_Encode(En_Base_Type_Base64, src, src_len, dst, pcharset, newline_flag);
}
size_t Base64_Decode(const char* src, size_t src_len, unsigned char* dst, const char* pcharset, int newline_flag)
{
    return Base_Decode(En_Base_Type_Base64, src, src_len, dst, pcharset, newline_flag);
}

size_t Base16_Encode(const unsigned char* src, size_t src_len, char* dst, const char* pcharset)
{
    return Base_Encode(En_Base_Type_Base16, src, src_len, dst, pcharset, 0);
}
size_t Base16_Decode(const char* src, size_t src_len, unsigned char* dst, const char* pcharset)
{
    return Base_Decode(En_Base_Type_Base16, src, src_len, dst, pcharset, 0);
}

size_t Base24_Encode(const unsigned char* src, size_t src_len, char* dst, const char* pcharset)
{
    return Base_Encode(En_Base_Type_Base24, src, src_len, dst, pcharset, 0);
}
size_t Base24_Decode(const char* src, size_t src_len, unsigned char* dst, const char* pcharset)
{
    return Base_Decode(En_Base_Type_Base24, src, src_len, dst, pcharset, 0);
}

size_t Base32_Encode(const unsigned char* src, size_t src_len, char* dst, const char* pcharset)
{
    return Base_Encode(En_Base_Type_Base32, src, src_len, dst, pcharset, 0);
}
size_t Base32_Decode(const char* src, size_t src_len, unsigned char* dst, const char* pcharset)
{
    return Base_Decode(En_Base_Type_Base32, src, src_len, dst, pcharset, 0);
}

size_t Base58_Encode(const unsigned char* src, size_t src_len, char* dst, const char* pcharset)
{
    return Base_Encode(En_Base_Type_Base58, src, src_len, dst, pcharset, 0);
}


size_t Base58_Decode(const char* src, size_t src_len, unsigned char* dst, const char* pcharset)
{
    return Base_Decode(En_Base_Type_Base58, src, src_len, dst, pcharset, 0);
}

size_t Base36_Encode(const char* src, size_t src_len, char* dst, const char* pcharset)
{
    size_t ret = 0;
    if (is_numeric(src, src_len))
    {
        unsigned char *src_buf = (unsigned char*)malloc(src_len);
        if(src_buf)
        {
            for (size_t i = 0; i < src_len; i++)
                src_buf[i] = (unsigned char)src[i] - 48;
            ret = Base_Encode(En_Base_Type_Base36, src_buf, src_len, dst, pcharset, 0);
            free(src_buf);
        }
    }
    return ret;
}


size_t Base36_Decode(const char* src, size_t src_len, char* dst, const char* pcharset)
{
    size_t ret = Base_Decode(En_Base_Type_Base36, src, src_len, (unsigned char*)dst, pcharset, 0);
    if (dst)
    {
        for (size_t i = 0; i < ret; i++)
        {
            dst[i] += 48;
        }
    }
    return ret;
}

size_t Base62_Encode(const char* src, size_t src_len, char* dst, const char* pcharset)
{

    size_t ret = 0;
    if (is_numeric(src, src_len))
    {
        unsigned char* src_buf = (unsigned char*)malloc(src_len);
        if (src_buf)
        {
            for (size_t i = 0; i < src_len; i++)
                src_buf[i] = (unsigned char)src[i] - 48;
            ret = Base_Encode(En_Base_Type_Base62, src_buf, src_len, dst, pcharset, 0);
            free(src_buf);
        }
    }
    return ret;
}


size_t Base62_Decode(const char* src, size_t src_len, char* dst, const char* pcharset)
{
    size_t ret = Base_Decode(En_Base_Type_Base62, src, src_len, (unsigned char*)dst, pcharset, 0);
    if (dst)
    {
        for (size_t i = 0; i < ret; i++)
        {
            dst[i] += 48;
        }
    }
    return ret;
}

size_t Base85b_Encode(const unsigned char* src, size_t src_len, char* dst, const char* pcharset)
{ 
    if (dst)
    {
        for (size_t i = 0; i < src_len; i += 4)
        {
            char dst_buf[5] = { 0 };
            unsigned char src_buf[4] = { 0 };
            memcpy(src_buf, src + i, i + 4 < src_len ? 4 : src_len - i);
            Base_Encode(En_Base_Type_Base85, src_buf, 4, dst_buf, pcharset, 0);
            if (i + 4 <= src_len)
                memcpy(dst + i / 4 * 5, dst_buf, 5);
            else
                memcpy(dst + i / 4 * 5, dst_buf, src_len % 4 + 1);
        }
    }
    return src_len / 4 * 5 + (src_len % 4 == 0 ? 0 : src_len % 4 + 1);
}

size_t Base85b_Decode(const char* src, size_t src_len, unsigned char* dst, const char* pcharset)
{
    if (dst)
    {
        for (size_t i = 0; i < src_len; i += 5)
        {
            unsigned char dst_buf[4] = { 0 };
            char src_buf[5] = { 0 };
            memcpy(src_buf, src + i, i + 5 < src_len ? 5 : src_len - i);
            if (i + 5 > src_len)
                memset(src_buf + src_len - i, pcharset ? pcharset[0] : pacCharset[En_Base_Type_Base85][0], i + 5 - src_len);
            Base_Decode(En_Base_Type_Base85, src_buf, 5, dst_buf, pcharset, 0);
            if (i + 5 <= src_len)
                memcpy(dst + i / 5 * 4, dst_buf, 4);
            else
            {
                dst_buf[src_len % 5 - 2] += 1;
                memcpy(dst + i / 5 * 4, dst_buf, src_len % 5 - 1);

            }
        }
    }
    return src_len / 5 * 4 + (src_len % 5 ? src_len % 5 - 1 : 0);
}

