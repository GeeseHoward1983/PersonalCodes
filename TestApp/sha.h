#ifndef __SHA__
#define __SHA__

#include <stdint.h>

# define SHA_LONG unsigned int
# define SHA_LBLOCK      16
# define SHA224_DIGEST_LENGTH    28
# define SHA256_DIGEST_LENGTH    32
# define SHA_CBLOCK      (SHA_LBLOCK*4)/* SHA treats input data as a
                                        * contiguous array of 32 bit wide
                                        * big-endian values. */

#ifndef MD32_REG_T
# if defined(__alpha) || defined(__sparcv9) || defined(__mips)
#  define MD32_REG_T long
# else
#  define MD32_REG_T int
# endif
#endif


void sha1(const uint8_t* data, size_t len, uint8_t digest[20]);

void sha128(const uint8_t* data, size_t len, uint8_t digest[16]);

unsigned char* SHA224(const unsigned char* d, size_t n, unsigned char* md);

unsigned char* SHA256(const unsigned char* d, size_t n, unsigned char* md);

unsigned char* SHA384(const unsigned char* d, size_t n, unsigned char* md);

unsigned char* SHA512(const unsigned char* d, size_t n, unsigned char* md);

#endif
