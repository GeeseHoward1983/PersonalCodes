import ecdsa
import hashlib

class SHA128:
    """自定义SHA128哈希类，使用SHA256但只取前16字节"""
    def __init__(self):
        self.hasher = hashlib.sha256()
    
    def update(self, data):
        self.hasher.update(data)
    
    def digest(self):
        return self.hasher.digest()[:16]  # 只取前16字节(128位)
    
    def hexdigest(self):
        return self.hasher.hexdigest()[:32]  # 只取前32个十六进制字符

def int_to_32bytes(key_int):
    """将整数转换为32字节的私钥格式"""
    return key_int.to_bytes(32, byteorder='big') % ecdsa.SECP256k1.order

def ecc_sign_to_hex(private_key_int, message):
    """
    使用ECC私钥和SHA128对消息进行签名，返回十六进制格式
    
    Args:
        private_key_int (int): 整数形式的私钥
        message (str): 要签名的消息
    
    Returns:
        str: 十六进制编码的签名
    """
    # 将整数私钥转换为32字节
    private_key_bytes = int_to_32bytes(private_key_int)
    
    # 创建ECC签名密钥（基于SECP256k1曲线）
    signing_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    
    # 使用SHA128哈希函数对消息进行签名
    signature = signing_key.sign(
        message.encode('utf-8'), 
        hashfunc=lambda: SHA128()
    )
    
    # 将签名转换为十六进制格式返回
    return signature.hex()

def ecc_verify_with_public_key(message, signature_hex, qx_bytes, qy_bytes):
    """
    使用指定的公钥和SHA128验证消息签名
    
    Args:
        message (str): 被签名的消息
        signature_hex (str): 十六进制编码的签名
        qx_bytes (list): 公钥x坐标字节列表
        qy_bytes (list): 公钥y坐标字节列表
    
    Returns:
        bool: 验证结果
    """
    # 将公钥坐标转换为字节串
    qx = bytes(qx_bytes)
    qy = bytes(qy_bytes)
    
    # 创建公钥点
    point = ecdsa.ellipticcurve.Point(
        ecdsa.SECP256k1.curve, 
        int.from_bytes(qx, 'big'), 
        int.from_bytes(qy, 'big')
    )
    
    # 创建验证密钥
    verifying_key = ecdsa.VerifyingKey.from_public_point(point, curve=ecdsa.SECP256k1)
    
    # 将十六进制签名转换为字节
    signature = bytes.fromhex(signature_hex)
    
    # 验证签名
    try:
        verifying_key.verify(
            signature, 
            message.encode('utf-8'), 
            hashfunc=lambda: SHA128()
        )
        return True
    except ecdsa.BadSignatureError:
        return False

# 使用示例
if __name__ == "__main__":
    # 使用指定的整数私钥12345
    private_key = 12345
    
    # 要签名的消息
    message = "Hello, ECC World!"
    
    # 生成签名（十六进制格式）
    signature_hex = ecc_sign_to_hex(private_key, message)
    print(f"消息: {message}")
    print(f"使用的私钥(整数): {private_key}")
    print(f"签名(十六进制): {signature_hex}")
    print(f"签名长度: {len(signature_hex)} 字符 ({len(signature_hex)//2} 字节)")
    
    # 指定的公钥坐标
    Qx_bytes = [0x60, 0x85, 0x45, 0x00, 0xB2, 0x7E, 0xDC, 0xD9]  # v36
    Qy_bytes = [0x60, 0x85, 0x45, 0x00, 0xF0, 0xAD, 0x1D, 0x82]  # v25
    
    print(f"公钥Qx: {bytes(Qx_bytes).hex()}")
    print(f"公钥Qy: {bytes(Qy_bytes).hex()}")
    
    # 验证签名
    is_valid = ecc_verify_with_public_key(message, signature_hex, Qx_bytes, Qy_bytes)
    print(f"签名验证结果: {'有效' if is_valid else '无效'}")
    
    # 测试错误情况
    wrong_message = "Wrong message"
    is_valid_wrong = ecc_verify_with_public_key(wrong_message, signature_hex, Qx_bytes, Qy_bytes)
    print(f"错误消息验证结果: {'有效' if is_valid_wrong else '无效'}")
    