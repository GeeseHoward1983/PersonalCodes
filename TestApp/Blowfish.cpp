// blowfish.c
#include "blowfish.h"
#include <string.h>
#include <stdlib.h>

// Blowfish算法所需的常量
static const uint32_t ORIG_P[18] = {
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
    0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
    0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
    0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
    0x9216D5D9, 0x8979FB1B
};

static const uint32_t ORIG_S[4][256] = {
    { 0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7, 0xB8E1AFED, 0x6A267E96,
      0xBA7C9045, 0xF12C7F99, 0x24A19947, 0xB3916CF7, 0x0801F2E2, 0x858EFC16,
      0x636920D8, 0x71574E69, 0xA458FEA3, 0xF4933D7E, 0x0D95748F, 0x728EB658,
      0x718BCD58, 0x82154AEE, 0x7B54A41D, 0xC25A59B5, 0x9C30D539, 0x2AF26013,
      0xC5D1B023, 0x286085F0, 0xCA417918, 0xB8DB38EF, 0x8E79DCB0, 0x603A180E,
      0x6C9E0E8B, 0xB01E8A3E, 0xD71577C1, 0xBD314B27, 0x78AF2FDA, 0x55605C60,
      0xE65525F3, 0xAA55AB94, 0x57489862, 0x63E81440, 0x55CA396A, 0x2AAB10B6,
      0xB4CC5C34, 0x1141E8CE, 0xA15486AF, 0x7C72E993, 0xB3EE1411, 0x636FBC2A,
      0x2BA9C55D, 0x741831F6, 0xCE5C3E16, 0x9B87931E, 0xAFD6BA33, 0x6C24CF5C,
      0x7A325381, 0x28958677, 0x3B8F4898, 0x6B4BB9AF, 0xC4BFE81B, 0x66282193,
      0x61D809CC, 0xFB21A991, 0x487CAC60, 0x5DEC8032, 0xEF845D5D, 0xE98575B1,
      0xDC262302, 0xEB651B88, 0x23893E81, 0xD396ACC5, 0x0F6D6FF3, 0x83F44239,
      0x2E0B4482, 0xA4842004, 0x69C8F04A, 0x9E1F9B5E, 0x21C66842, 0xF6E96C9A,
      0x670C9C61, 0xABD388F0, 0x6A51A0D2, 0xD8542F68, 0x960FA728, 0xAB5133A3,
      0x6EEF0B6C, 0x137A3BE4, 0xBA3BF050, 0x7EFB2A98, 0xA1F1651D, 0x39AF0176,
      0x66CA593E, 0x82430E88, 0x8CEE8619, 0x456F9FB4, 0x7D84A5C3, 0x3B8B5EBE,
      0xE06F75D8, 0x85C12073, 0x401A449F, 0x56C16AA6, 0x4ED3AA62, 0x363F7706,
      0x1BFEDF72, 0x429B023D, 0x37D0D724, 0xD00A1248, 0xDB0FEAD3, 0x49F1C09B,
      0x075372C9, 0x80991B7B, 0x25D479D8, 0xF6E8DEF7, 0xE3FE501A, 0xB6794C3B,
      0x976CE0BD, 0x04C006BA, 0xC1A94FB6, 0x409F60C4, 0x5E5C9EC2, 0x196A2463,
      0x68FB6FAF, 0x3E6C53B5, 0x1339B2EB, 0x3B52EC6F, 0x6DFC511F, 0x9B30952C,
      0xCC814544, 0xAF5EBD09, 0xBEE3D004, 0xDE334AFD, 0x660F2807, 0x192E4BB3,
      0xC0CBA857, 0x45C8740F, 0xD20B5F39, 0xB9D3FBDB, 0x5579C0BD, 0x1A60320A,
      0xD6A100C6, 0x402C7279, 0x679F25FE, 0xFB1FA3CC, 0x8EA5E9F8, 0xDB3222F8,
      0x3C7516DF, 0xFD616B15, 0x2F501EC8, 0xAD0552AB, 0x323DB5FA, 0xFD238760,
      0x53317B48, 0x3E00DF82, 0x9E5C57BB, 0xCA6F8CA0, 0x1A87562E, 0xDF1769DB,
      0xD542A8F6, 0x287EFFC3, 0xAC6732C6, 0x8C4F5573, 0x695B27B0, 0xBBCA58C8,
      0xE1FFA35D, 0xB8F011A0, 0x10FA3D98, 0xFD2183B8, 0x4AFCB56C, 0x2DD1D35B,
      0x9A53E479, 0xB6F84565, 0xD28E49BC, 0x4BFB9790, 0xE1DDF2DA, 0xA4CB7E33,
      0x62FB1341, 0xCEE4C6E8, 0xEF20CADA, 0x36774C01, 0xD07E9EFE, 0x2BF11FB4,
      0x95DBDA4D, 0xAE909198, 0xEAAD8E71, 0x6B93D5A0, 0xD08ED1D0, 0xAFC725E0,
      0x8E3C5B2F, 0x8E7594B7, 0x8FF6E2FB, 0xF2122B64, 0x8888B812, 0x900DF01C,
      0x4FAD5EA0, 0x688FC31C, 0xD1CFF191, 0xB3A8C1AD, 0x2F2F2218, 0xBE0E1777,
      0xEA752DFE, 0x8B021FA1, 0xE5A0CC0F, 0xB56F74E8, 0x18ACF3D6, 0xCE89E299,
      0xB4A84FE0, 0xFD13E0B7, 0x7CC43B81, 0xD2ADA8D9, 0x165FA266, 0x80957705,
      0x93CC7314, 0x211A1477, 0xE6AD2065, 0x77B5FA86, 0xC75442F5, 0xFB9D35CF,
      0xEBCDAF0C, 0x7B3E89A0, 0xD6411BD3, 0xAE1E7E49, 0x00250E2D, 0x2071B35E,
      0x226800BB, 0x57B8E0AF, 0x2464369B, 0xF009B91E, 0x5563911D, 0x59DFA6AA,
      0x78C14389, 0xD95A537F, 0x207D5BA2, 0x02E5B9C5, 0x83260376, 0x6295CFA9,
      0x11C81968, 0x4E734A41, 0xB3472DCA, 0x7B14A94A, 0x1B510052, 0x9A532915,
      0xD60F573F, 0xBC9BC6E4, 0x2B60A476, 0x81E67400, 0x08BA6FB5, 0x571BE91F,
      0xF296EC6B, 0x2A0DD915, 0xB6636521, 0xE7B9F9B6, 0xFF34052E, 0xC5855664,
      0x53B02D5D, 0xA99F8FA1, 0x08BA4799, 0x6E85076A },
    
    { 0x4B7A70E9, 0xB5B32944, 0xDB75092E, 0xC4192623, 0xAD6EA6B0, 0x49A7DF7D,
      0x9CEE60B8, 0x8FEDB266, 0xECAA8C71, 0x699A17FF, 0x5664526C, 0xC2B19EE1,
      0x193602A5, 0x75094C29, 0xA0591340, 0xE4183A3E, 0x3F54989A, 0x5B429D65,
      0x6B8FE4D6, 0x99F73FD6, 0xA1D29C07, 0xEFE830F5, 0x4D2D38E6, 0xF0255DC1,
      0x4CDD2086, 0x8470EB26, 0x6382E9C6, 0x021ECC5E, 0x09686B3F, 0x3EBAEFC9,
      0x3C971814, 0x6B6A70A1, 0x687F3584, 0x52A0E286, 0xB79C5305, 0xAA500737,
      0x3E07841C, 0x7FDEAE5C, 0x8E7D44EC, 0x5716F2B8, 0xB03ADA37, 0xF0500C0D,
      0xF01C1F04, 0x0200B3FF, 0xAE0CF51A, 0x3CB574B2, 0x25837A58, 0xDC0921BD,
      0xD19113F9, 0x7CA92FF6, 0x94324773, 0x22F54701, 0x3AE5E581, 0x37C2DADC,
      0xC8B57634, 0x9AF3DDA7, 0xA9446146, 0x0FD0030E, 0xECC8C73E, 0xA4751E41,
      0xE238CD99, 0x3BEA0E2F, 0x3280BBA1, 0x183EB331, 0x4E548B38, 0x4F6DB908,
      0x6F420D03, 0xF60A04BF, 0x2CB81290, 0x24977C79, 0x5679B072, 0xBCAF89AF,
      0xDE9A771F, 0xD9930810, 0xB38BAE12, 0xDCCF3F2E, 0x5512721F, 0x2E6B7124,
      0x501ADDE6, 0x9F84CD87, 0x7A584718, 0x7408DA17, 0xBC9F9ABC, 0xE94B7D8C,
      0xEC7AEC3A, 0xDB851DFA, 0x63094366, 0xC464C3D2, 0xEF1C1847, 0x3215D908,
      0xDD433B37, 0x24C2BA16, 0x12A14D43, 0x2A65C451, 0x50940002, 0x133AE4DD,
      0x71DFF89E, 0x10314E55, 0x81AC77D6, 0x5F11199B, 0x043556F1, 0xD7A3C76B,
      0x3C11183B, 0x5924A509, 0xF28FE6ED, 0x97F1FBFA, 0x9EBABF2C, 0x1E153C6E,
      0x86E34570, 0xEAE96FB1, 0x860E5E0A, 0x5A3E2AB3, 0x771FE71C, 0x4E3D06FA,
      0x2965DCB9, 0x99E71D0F, 0x803E89D6, 0x5266C825, 0x2E4CC978, 0x9C10B36A,
      0xC6150EBA, 0x94E2EA78, 0xA5FC3C53, 0x1E0A2DF4, 0xF2F74EA7, 0x361D2B3D,
      0x1939260F, 0x19C27960, 0x5223A708, 0xF71312B6, 0xEBADFE6E, 0xEAC31F66,
      0xE3BC4595, 0xA67BC883, 0xB17F37D1, 0x018CFF28, 0xC332DDEF, 0xBE6C5AA5,
      0x65582185, 0x68AB9802, 0xEECEA50F, 0xDB2F953B, 0x2AEF7DAD, 0x5B6E2F84,
      0x1521B628, 0x29076170, 0xECDD4775, 0x619F1510, 0x13CCA830, 0xEB61BD96,
      0x0334FE1E, 0xAA0363CF, 0xB5735C90, 0x4C70A239, 0xD59E9E0B, 0xCBAADE14,
      0xEECC86BC, 0x60622CA7, 0x9CAB5CAB, 0xB2F3846E, 0x648B1EAF, 0x19BDF0CA,
      0xA02369B9, 0x655ABB50, 0x40685A32, 0x3C2AB4B3, 0x319EE9D5, 0xC021B8F7,
      0x9B540B19, 0x875FA099, 0x95F7997E, 0x623D7DA8, 0xF837889A, 0x97E32D77,
      0x11ED935F, 0x16681281, 0x0E358829, 0xC7E61FD6, 0x96DEDFA1, 0x7858BA99,
      0x57056F6D, 0xCDE49B9C, 0xED39C197, 0x17460E1E, 0x7A8ACB4F, 0x823C4558,
      0xF3DB5A77, 0x283C7A79, 0x2EB7E493, 0xDC81C9A9, 0x5D4100FA, 0x3D37A8F0,
      0x96403B16, 0x61D809CC, 0xFB21A991, 0x487CAC60, 0x5DEC8032, 0xEF845D5D,
      0xE98575B1, 0xDC262302, 0xEB651B88, 0x23893E81, 0xD396ACC5, 0x0F6D6FF3,
      0x83F44239, 0x2E0B4482, 0xA4842004, 0x69C8F04A, 0x9E1F9B5E, 0x21C66842,
      0xF6E96C9A, 0x670C9C61, 0xABD388F0, 0x6A51A0D2, 0xD8542F68, 0x960FA728,
      0xAB5133A3, 0x6EEF0B6C, 0x137A3BE4, 0xBA3BF050, 0x7EFB2A98, 0xA1F1651D,
      0x39AF0176, 0x66CA593E, 0x82430E88, 0x8CEE8619, 0x456F9FB4, 0x7D84A5C3,
      0x3B8B5EBE, 0xE06F75D8, 0x85C12073, 0x401A449F, 0x56C16AA6, 0x4ED3AA62,
      0x363F7706, 0x1BFEDF72, 0x429B023D, 0x37D0D724, 0xD00A1248, 0xDB0FEAD3 },
    
    { 0x49F1C09B, 0x075372C9, 0x80991B7B, 0x25D479D8, 0xF6E8DEF7, 0xE3FE501A,
      0xB6794C3B, 0x976CE0BD, 0x04C006BA, 0xC1A94FB6, 0x409F60C4, 0x5E5C9EC2,
      0x196A2463, 0x68FB6FAF, 0x3E6C53B5, 0x1339B2EB, 0x3B52EC6F, 0x6DFC511F,
      0x9B30952C, 0xCC814544, 0xAF5EBD09, 0xBEE3D004, 0xDE334AFD, 0x660F2807,
      0x192E4BB3, 0xC0CBA857, 0x45C8740F, 0xD20B5F39, 0xB9D3FBDB, 0x5579C0BD,
      0x1A60320A, 0xD6A100C6, 0x402C7279, 0x679F25FE, 0xFB1FA3CC, 0x8EA5E9F8,
      0xDB3222F8, 0x3C7516DF, 0xFD616B15, 0x2F501EC8, 0xAD0552AB, 0x323DB5FA,
      0xFD238760, 0x53317B48, 0x3E00DF82, 0x9E5C57BB, 0xCA6F8CA0, 0x1A87562E,
      0xDF1769DB, 0xD542A8F6, 0x287EFFC3, 0xAC6732C6, 0x8C4F5573, 0x695B27B0,
      0xBBCA58C8, 0xE1FFA35D, 0xB8F011A0, 0x10FA3D98, 0xFD2183B8, 0x4AFCB56C,
      0x2DD1D35B, 0x9A53E479, 0xB6F84565, 0xD28E49BC, 0x4BFB9790, 0xE1DDF2DA,
      0xA4CB7E33, 0x62FB1341, 0xCEE4C6E8, 0xEF20CADA, 0x36774C01, 0xD07E9EFE,
      0x2BF11FB4, 0x95DBDA4D, 0xAE909198, 0xEAAD8E71, 0x6B93D5A0, 0xD08ED1D0,
      0xAFC725E0, 0x8E3C5B2F, 0x8E7594B7, 0x8FF6E2FB, 0xF2122B64, 0x8888B812,
      0x900DF01C, 0x4FAD5EA0, 0x688FC31C, 0xD1CFF191, 0xB3A8C1AD, 0x2F2F2218,
      0xBE0E1777, 0xEA752DFE, 0x8B021FA1, 0xE5A0CC0F, 0xB56F74E8, 0x18ACF3D6,
      0xCE89E299, 0xB4A84FE0, 0xFD13E0B7, 0x7CC43B81, 0xD2ADA8D9, 0x165FA266,
      0x80957705, 0x93CC7314, 0x211A1477, 0xE6AD2065, 0x77B5FA86, 0xC75442F5,
      0xFB9D35CF, 0xEBCDAF0C, 0x7B3E89A0, 0xD6411BD3, 0xAE1E7E49, 0x00250E2D,
      0x2071B35E, 0x226800BB, 0x57B8E0AF, 0x2464369B, 0xF009B91E, 0x5563911D,
      0x59DFA6AA, 0x78C14389, 0xD95A537F, 0x207D5BA2, 0x02E5B9C5, 0x83260376,
      0x6295CFA9, 0x11C81968, 0x4E734A41, 0xB3472DCA, 0x7B14A94A, 0x1B510052,
      0x9A532915, 0xD60F573F, 0xBC9BC6E4, 0x2B60A476, 0x81E67400, 0x08BA6FB5,
      0x571BE91F, 0xF296EC6B, 0x2A0DD915, 0xB6636521, 0xE7B9F9B6, 0xFF34052E,
      0xC5855664, 0x53B02D5D, 0xA99F8FA1, 0x08BA4799, 0x6E85076A, 0x4B7A70E9,
      0xB5B32944, 0xDB75092E, 0xC4192623, 0xAD6EA6B0, 0x49A7DF7D, 0x9CEE60B8,
      0x8FEDB266, 0xECAA8C71, 0x699A17FF, 0x5664526C, 0xC2B19EE1, 0x193602A5,
      0x75094C29, 0xA0591340, 0xE4183A3E, 0x3F54989A, 0x5B429D65, 0x6B8FE4D6,
      0x99F73FD6, 0xA1D29C07, 0xEFE830F5, 0x4D2D38E6, 0xF0255DC1, 0x4CDD2086,
      0x8470EB26, 0x6382E9C6, 0x021ECC5E, 0x09686B3F, 0x3EBAEFC9, 0x3C971814,
      0x6B6A70A1, 0x687F3584, 0x52A0E286, 0xB79C5305, 0xAA500737, 0x3E07841C,
      0x7FDEAE5C, 0x8E7D44EC, 0x5716F2B8, 0xB03ADA37, 0xF0500C0D, 0xF01C1F04,
      0x0200B3FF, 0xAE0CF51A, 0x3CB574B2, 0x25837A58, 0xDC0921BD, 0xD19113F9,
      0x7CA92FF6, 0x94324773, 0x22F54701, 0x3AE5E581, 0x37C2DADC, 0xC8B57634,
      0x9AF3DDA7, 0xA9446146, 0x0FD0030E, 0xECC8C73E, 0xA4751E41, 0xE238CD99,
      0x3BEA0E2F, 0x3280BBA1, 0x183EB331, 0x4E548B38, 0x4F6DB908, 0x6F420D03,
      0xF60A04BF, 0x2CB81290, 0x24977C79, 0x5679B072, 0xBCAF89AF, 0xDE9A771F,
      0xD9930810, 0xB38BAE12, 0xDCCF3F2E, 0x5512721F, 0x2E6B7124, 0x501ADDE6,
      0x9F84CD87, 0x7A584718, 0x7408DA17, 0xBC9F9ABC, 0xE94B7D8C, 0xEC7AEC3A,
      0xDB851DFA, 0x63094366, 0xC464C3D2, 0xEF1C1847, 0x3215D908, 0xDD433B37 },
    
    { 0x24C2BA16, 0x12A14D43, 0x2A65C451, 0x50940002, 0x133AE4DD, 0x71DFF89E,
      0x10314E55, 0x81AC77D6, 0x5F11199B, 0x043556F1, 0xD7A3C76B, 0x3C11183B,
      0x5924A509, 0xF28FE6ED, 0x97F1FBFA, 0x9EBABF2C, 0x1E153C6E, 0x86E34570,
      0xEAE96FB1, 0x860E5E0A, 0x5A3E2AB3, 0x771FE71C, 0x4E3D06FA, 0x2965DCB9,
      0x99E71D0F, 0x803E89D6, 0x5266C825, 0x2E4CC978, 0x9C10B36A, 0xC6150EBA,
      0x94E2EA78, 0xA5FC3C53, 0x1E0A2DF4, 0xF2F74EA7, 0x361D2B3D, 0x1939260F,
      0x19C27960, 0x5223A708, 0xF71312B6, 0xEBADFE6E, 0xEAC31F66, 0xE3BC4595,
      0xA67BC883, 0xB17F37D1, 0x018CFF28, 0xC332DDEF, 0xBE6C5AA5, 0x65582185,
      0x68AB9802, 0xEECEA50F, 0xDB2F953B, 0x2AEF7DAD, 0x5B6E2F84, 0x1521B628,
      0x29076170, 0xECDD4775, 0x619F1510, 0x13CCA830, 0xEB61BD96, 0x0334FE1E,
      0xAA0363CF, 0xB5735C90, 0x4C70A239, 0xD59E9E0B, 0xCBAADE14, 0xEECC86BC,
      0x60622CA7, 0x9CAB5CAB, 0xB2F3846E, 0x648B1EAF, 0x19BDF0CA, 0xA02369B9,
      0x655ABB50, 0x40685A32, 0x3C2AB4B3, 0x319EE9D5, 0xC021B8F7, 0x9B540B19,
      0x875FA099, 0x95F7997E, 0x623D7DA8, 0xF837889A, 0x97E32D77, 0x11ED935F,
      0x16681281, 0x0E358829, 0xC7E61FD6, 0x96DEDFA1, 0x7858BA99, 0x57056F6D,
      0xCDE49B9C, 0xED39C197, 0x17460E1E, 0x7A8ACB4F, 0x823C4558, 0xF3DB5A77,
      0x283C7A79, 0x2EB7E493, 0xDC81C9A9, 0x5D4100FA, 0x3D37A8F0, 0x96403B16,
      0x61D809CC, 0xFB21A991, 0x487CAC60, 0x5DEC8032, 0xEF845D5D, 0xE98575B1,
      0xDC262302, 0xEB651B88, 0x23893E81, 0xD396ACC5, 0x0F6D6FF3, 0x83F44239,
      0x2E0B4482, 0xA4842004, 0x69C8F04A, 0x9E1F9B5E, 0x21C66842, 0xF6E96C9A,
      0x670C9C61, 0xABD388F0, 0x6A51A0D2, 0xD8542F68, 0x960FA728, 0xAB5133A3,
      0x6EEF0B6C, 0x137A3BE4, 0xBA3BF050, 0x7EFB2A98, 0xA1F1651D, 0x39AF0176,
      0x66CA593E, 0x82430E88, 0x8CEE8619, 0x456F9FB4, 0x7D84A5C3, 0x3B8B5EBE,
      0xE06F75D8, 0x85C12073, 0x401A449F, 0x56C16AA6, 0x4ED3AA62, 0x363F7706,
      0x1BFEDF72, 0x429B023D, 0x37D0D724, 0xD00A1248, 0xDB0FEAD3, 0x49F1C09B,
      0x075372C9, 0x80991B7B, 0x25D479D8, 0xF6E8DEF7, 0xE3FE501A, 0xB6794C3B,
      0x976CE0BD, 0x04C006BA, 0xC1A94FB6, 0x409F60C4, 0x5E5C9EC2, 0x196A2463,
      0x68FB6FAF, 0x3E6C53B5, 0x1339B2EB, 0x3B52EC6F, 0x6DFC511F, 0x9B30952C,
      0xCC814544, 0xAF5EBD09, 0xBEE3D004, 0xDE334AFD, 0x660F2807, 0x192E4BB3,
      0xC0CBA857, 0x45C8740F, 0xD20B5F39, 0xB9D3FBDB, 0x5579C0BD, 0x1A60320A,
      0xD6A100C6, 0x402C7279, 0x679F25FE, 0xFB1FA3CC, 0x8EA5E9F8, 0xDB3222F8,
      0x3C7516DF, 0xFD616B15, 0x2F501EC8, 0xAD0552AB, 0x323DB5FA, 0xFD238760,
      0x53317B48, 0x3E00DF82, 0x9E5C57BB, 0xCA6F8CA0, 0x1A87562E, 0xDF1769DB,
      0xD542A8F6, 0x287EFFC3, 0xAC6732C6, 0x8C4F5573, 0x695B27B0, 0xBBCA58C8,
      0xE1FFA35D, 0xB8F011A0, 0x10FA3D98, 0xFD2183B8, 0x4AFCB56C, 0x2DD1D35B,
      0x9A53E479, 0xB6F84565, 0xD28E49BC, 0x4BFB9790, 0xE1DDF2DA, 0xA4CB7E33,
      0x62FB1341, 0xCEE4C6E8, 0xEF20CADA, 0x36774C01, 0xD07E9EFE, 0x2BF11FB4,
      0x95DBDA4D, 0xAE909198, 0xEAAD8E71, 0x6B93D5A0, 0xD08ED1D0, 0xAFC725E0,
      0x8E3C5B2F, 0x8E7594B7, 0x8FF6E2FB, 0xF2122B64, 0x8888B812, 0x900DF01C,
      0x4FAD5EA0, 0x688FC31C, 0xD1CFF191, 0xB3A8C1AD, 0x2F2F2218, 0xBE0E1777 }
};

// F函数
static uint32_t F(uint32_t x, blowfish_context* ctx) {
    uint8_t a, b, c, d;
    uint32_t y;
    
    d = x & 0xFF;
    x >>= 8;
    c = x & 0xFF;
    x >>= 8;
    b = x & 0xFF;
    x >>= 8;
    a = x & 0xFF;
    
    y = ctx->S[0][a] + ctx->S[1][b];
    y ^= ctx->S[2][c];
    y += ctx->S[3][d];
    
    return y;
}

// 初始化Blowfish上下文
int blowfish_init(blowfish_context* ctx, const uint8_t* key, size_t key_len, int mode, const uint8_t* iv) {
    if (!ctx || !key || key_len == 0 || key_len > 56) {
        return BLOWFISH_INVALID_KEY_LENGTH;
    }
    
    if (mode != BLOWFISH_MODE_ECB && mode != BLOWFISH_MODE_CBC && 
        mode != BLOWFISH_MODE_CFB && mode != BLOWFISH_MODE_OFB) {
        return BLOWFISH_INVALID_MODE;
    }
    
    // 复制原始P数组和S盒
    for (int i = 0; i < 18; i++) {
        ctx->P[i] = ORIG_P[i];
    }
    
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 256; j++) {
            ctx->S[i][j] = ORIG_S[i][j];
        }
    }
    
    // 设置模式
    ctx->mode = mode;
    
    // 设置IV
    if (iv) {
        memcpy(ctx->iv, iv, BLOWFISH_BLOCK_SIZE);
    } else {
        memset(ctx->iv, 0, BLOWFISH_BLOCK_SIZE);
    }
    
    // 密钥调度
    uint32_t data, datal, datar;
    int i, j, k;
    
    j = 0;
    for (i = 0; i < 18; i++) {
        data = 0x00000000;
        for (k = 0; k < 4; k++) {
            data = (data << 8) | key[j];
            j++;
            if (j >= key_len) {
                j = 0;
            }
        }
        ctx->P[i] = ctx->P[i] ^ data;
    }
    
    datal = 0x00000000;
    datar = 0x00000000;
    
    for (i = 0; i < 18; i += 2) {
        blowfish_encrypt_block(ctx, (uint8_t*)&datal, (uint8_t*)&datar);
        ctx->P[i] = datal;
        ctx->P[i + 1] = datar;
    }
    
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 256; j += 2) {
            blowfish_encrypt_block(ctx, (uint8_t*)&datal, (uint8_t*)&datar);
            ctx->S[i][j] = datal;
            ctx->S[i][j + 1] = datar;
        }
    }
    
    return BLOWFISH_SUCCESS;
}

// 加密一个块
void blowfish_encrypt_block(blowfish_context* ctx, const uint8_t* plaintext, uint8_t* ciphertext) {
    // 将明文转换为两个32位块
    uint32_t left  = ((uint32_t)plaintext[0] << 24) |
                     ((uint32_t)plaintext[1] << 16) |
                     ((uint32_t)plaintext[2] <<  8) |
                      (uint32_t)plaintext[3];
                    
    uint32_t right = ((uint32_t)plaintext[4] << 24) |
                     ((uint32_t)plaintext[5] << 16) |
                     ((uint32_t)plaintext[6] <<  8) |
                      (uint32_t)plaintext[7];
    
    // 16轮加密
    for (int i = 0; i < 16; i += 2) {
        // 轮函数作用于左半部分，与右半部分异或
        left ^= ctx->P[i];
        right ^= F(left, ctx);
        
        // 轮函数作用于右半部分，与左半部分异或
        right ^= ctx->P[i + 1];
        left ^= F(right, ctx);
    }
    
    // 最后交换左右两部分，并与P17、P18异或
    uint32_t temp = left;
    left = right ^ ctx->P[16];
    right = temp ^ ctx->P[17];
    
    // 将密文写回输出缓冲区
    ciphertext[0] = (left  >> 24) & 0xFF;
    ciphertext[1] = (left  >> 16) & 0xFF;
    ciphertext[2] = (left  >>  8) & 0xFF;
    ciphertext[3] =  left         & 0xFF;
    
    ciphertext[4] = (right >> 24) & 0xFF;
    ciphertext[5] = (right >> 16) & 0xFF;
    ciphertext[6] = (right >>  8) & 0xFF;
    ciphertext[7] =  right        & 0xFF;
}

void blowfish_decrypt_block(blowfish_context* ctx, const uint8_t* ciphertext, uint8_t* plaintext) {
    // 将密文转换为两个32位块
    uint32_t left  = ((uint32_t)ciphertext[0] << 24) |
                     ((uint32_t)ciphertext[1] << 16) |
                     ((uint32_t)ciphertext[2] <<  8) |
                      (uint32_t)ciphertext[3];
                    
    uint32_t right = ((uint32_t)ciphertext[4] << 24) |
                     ((uint32_t)ciphertext[5] << 16) |
                     ((uint32_t)ciphertext[6] <<  8) |
                      (uint32_t)ciphertext[7];
    
    // 逆向16轮解密
    for (int i = 17; i > 1; i -= 2) {
        // 轮函数作用于左半部分，与右半部分异或
        left ^= ctx->P[i];
        right ^= F(left, ctx);
        
        // 轮函数作用于右半部分，与左半部分异或
        right ^= ctx->P[i - 1];
        left ^= F(right, ctx);
    }
    
    // 最后交换左右两部分，并与P0、P1异或
    uint32_t temp = left;
    left = right ^ ctx->P[1];
    right = temp ^ ctx->P[0];
    
    // 将明文写回输出缓冲区
    plaintext[0] = (left  >> 24) & 0xFF;
    plaintext[1] = (left  >> 16) & 0xFF;
    plaintext[2] = (left  >>  8) & 0xFF;
    plaintext[3] =  left         & 0xFF;
    
    plaintext[4] = (right >> 24) & 0xFF;
    plaintext[5] = (right >> 16) & 0xFF;
    plaintext[6] = (right >>  8) & 0xFF;
    plaintext[7] =  right        & 0xFF;
}

int blowfish_encrypt(blowfish_context* ctx, const uint8_t* plaintext, size_t length, uint8_t* ciphertext) {
    // 检查输入长度是否为块大小的倍数
    if (length % BLOWFISH_BLOCK_SIZE != 0) {
        return BLOWFISH_INVALID_INPUT_LENGTH;
    }
    
    switch (ctx->mode) {
        case BLOWFISH_MODE_ECB:
            for (size_t i = 0; i < length; i += BLOWFISH_BLOCK_SIZE) {
                blowfish_encrypt_block(ctx, plaintext + i, ciphertext + i);
            }
            break;
            
        case BLOWFISH_MODE_CBC: {
            uint8_t temp_block[BLOWFISH_BLOCK_SIZE];
            uint8_t prev_ciphertext[BLOWFISH_BLOCK_SIZE];
            
            // 复制初始IV
            memcpy(prev_ciphertext, ctx->iv, BLOWFISH_BLOCK_SIZE);
            
            for (size_t i = 0; i < length; i += BLOWFISH_BLOCK_SIZE) {
                // 与前一个密文块异或（第一块与IV异或）
                for (int j = 0; j < BLOWFISH_BLOCK_SIZE; j++) {
                    temp_block[j] = plaintext[i + j] ^ prev_ciphertext[j];
                }
                
                // 加密
                blowfish_encrypt_block(ctx, temp_block, ciphertext + i);
                
                // 更新前一个密文块
                memcpy(prev_ciphertext, ciphertext + i, BLOWFISH_BLOCK_SIZE);
            }
            
            // 更新IV为最后一个密文块
            memcpy(ctx->iv, ciphertext + length - BLOWFISH_BLOCK_SIZE, BLOWFISH_BLOCK_SIZE);
            break;
        }
        
        // CFB和OFB模式需要额外实现，此处暂不支持
        case BLOWFISH_MODE_CFB:
        case BLOWFISH_MODE_OFB:
        default:
            return BLOWFISH_INVALID_MODE;
    }
    
    return BLOWFISH_SUCCESS;
}

int blowfish_decrypt(blowfish_context* ctx, const uint8_t* ciphertext, size_t length, uint8_t* plaintext) {
    // 检查输入长度是否为块大小的倍数
    if (length % BLOWFISH_BLOCK_SIZE != 0) {
        return BLOWFISH_INVALID_INPUT_LENGTH;
    }
    
    switch (ctx->mode) {
        case BLOWFISH_MODE_ECB:
            for (size_t i = 0; i < length; i += BLOWFISH_BLOCK_SIZE) {
                blowfish_decrypt_block(ctx, ciphertext + i, plaintext + i);
            }
            break;
            
        case BLOWFISH_MODE_CBC: {
            uint8_t temp_block[BLOWFISH_BLOCK_SIZE];
            uint8_t prev_ciphertext[BLOWFISH_BLOCK_SIZE];
            
            // 复制初始IV
            memcpy(prev_ciphertext, ctx->iv, BLOWFISH_BLOCK_SIZE);
            
            for (size_t i = 0; i < length; i += BLOWFISH_BLOCK_SIZE) {
                // 保存当前密文块用于下一轮
                memcpy(temp_block, ciphertext + i, BLOWFISH_BLOCK_SIZE);
                
                // 解密
                blowfish_decrypt_block(ctx, ciphertext + i, plaintext + i);
                
                // 与前一个密文块异或（第一块与IV异或）
                for (int j = 0; j < BLOWFISH_BLOCK_SIZE; j++) {
                    plaintext[i + j] ^= prev_ciphertext[j];
                }
                
                // 更新前一个密文块
                memcpy(prev_ciphertext, temp_block, BLOWFISH_BLOCK_SIZE);
            }
            
            // 更新IV为最后一个密文块
            memcpy(ctx->iv, ciphertext + length - BLOWFISH_BLOCK_SIZE, BLOWFISH_BLOCK_SIZE);
            break;
        }
        
        // CFB和OFB模式需要额外实现，此处暂不支持
        case BLOWFISH_MODE_CFB:
        case BLOWFISH_MODE_OFB:
        default:
            return BLOWFISH_INVALID_MODE;
    }
    
    return BLOWFISH_SUCCESS;
}

void blowfish_set_iv(blowfish_context* ctx, const uint8_t* iv) {
    if (iv != NULL) {
        memcpy(ctx->iv, iv, BLOWFISH_BLOCK_SIZE);
    } else {
        memset(ctx->iv, 0, BLOWFISH_BLOCK_SIZE);
    }
}
    