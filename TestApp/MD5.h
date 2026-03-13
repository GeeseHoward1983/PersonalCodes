#ifndef MD5_H
#define MD5_H
 
#define MD5_SIZE (32)                                            
void ComputeMD5(unsigned char* pucData, unsigned int uiDataLen, unsigned char* md5_value);
#endif
