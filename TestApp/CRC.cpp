#include <stdint.h>
#include <stdbool.h>

// ===================== 通用工具函数 =====================
// 反转8位数据的位顺序
uint8_t reverse8(uint8_t data) {
    data = (data & 0xF0) >> 4 | (data & 0x0F) << 4;
    data = (data & 0xCC) >> 2 | (data & 0x33) << 2;
    data = (data & 0xAA) >> 1 | (data & 0x55) << 1;
    return data;
}

// 反转16位数据的位顺序
uint16_t reverse16(uint16_t data) {
    data = (data & 0xFF00) >> 8 | (data & 0x00FF) << 8;
    data = (data & 0xF0F0) >> 4 | (data & 0x0F0F) << 4;
    data = (data & 0xCCCC) >> 2 | (data & 0x3333) << 2;
    data = (data & 0xAAAA) >> 1 | (data & 0x5555) << 1;
    return data;
}

// 反转32位数据的位顺序
uint32_t reverse32(uint32_t data) {
    data = (data & 0xFFFF0000) >> 16 | (data & 0x0000FFFF) << 16;
    data = (data & 0xFF00FF00) >> 8 | (data & 0x00FF00FF) << 8;
    data = (data & 0xF0F0F0F0) >> 4 | (data & 0x0F0F0F0F) << 4;
    data = (data & 0xCCCCCCCC) >> 2 | (data & 0x33333333) << 2;
    data = (data & 0xAAAAAAAA) >> 1 | (data & 0x55555555) << 1;
    return data;
}

// ===================== CRC8 =====================
uint8_t crc8(const uint8_t *data, size_t len, 
             uint8_t poly, uint8_t init, 
             bool refin, bool refout, 
             uint8_t xorout) {
    uint8_t crc = init;
    
    for (size_t i = 0; i < len; i++) {
        uint8_t d = data[i];
        if (refin) d = reverse8(d);
        
        crc ^= d;
        for (int j = 0; j < 8; j++) {
            if (crc & 0x80) {
                crc = (crc << 1) ^ poly;
            } else {
                crc <<= 1;
            }
        }
    }
    
    if (refout) crc = reverse8(crc);
    return crc ^ xorout;
}

// ===================== CRC16 =====================
uint16_t crc16(const uint8_t *data, size_t len, 
               uint16_t poly, uint16_t init, 
               bool refin, bool refout, 
               uint16_t xorout) {
    uint16_t crc = init;
    
    for (size_t i = 0; i < len; i++) {
        uint8_t d = data[i];
        if (refin) d = reverse8(d);
        
        crc ^= (uint16_t)d << 8;
        for (int j = 0; j < 8; j++) {
            if (crc & 0x8000) {
                crc = (crc << 1) ^ poly;
            } else {
                crc <<= 1;
            }
        }
    }
    
    if (refout) crc = reverse16(crc);
    return crc ^ xorout;
}

// ===================== CRC32 =====================
uint32_t crc32(const uint8_t *data, size_t len, 
               uint32_t poly, uint32_t init, 
               bool refin, bool refout, 
               uint32_t xorout) {
    uint32_t crc = init;
    
    for (size_t i = 0; i < len; i++) {
        uint8_t d = data[i];
        if (refin) d = reverse8(d);
        
        crc ^= (uint32_t)d << 24;
        for (int j = 0; j < 8; j++) {
            if (crc & 0x80000000) {
                crc = (crc << 1) ^ poly;
            } else {
                crc <<= 1;
            }
        }
    }
    
    if (refout) crc = reverse32(crc);
    return crc ^ xorout;
}
