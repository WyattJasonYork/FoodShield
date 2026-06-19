"""
国密算法工具模块 (SM2/SM3/SM4)
- SM3 哈希: 替代 SHA-256
- HMAC-SM3: 替代 HMAC-SHA256
- SM4-CBC 加解密: 消息内容加密存储

依赖: gmssl
"""

import os
import secrets
from gmssl.sm3 import sm3_hash, bytes_to_list
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT


# ====================== SM3 哈希 ======================

def sm3_digest(data: bytes) -> bytes:
    """
    计算 SM3 哈希，返回原始字节 (32 bytes)
    """
    hex_str = sm3_hash(bytes_to_list(data))
    return bytes.fromhex(hex_str)


def sm3_hexdigest(data: bytes) -> str:
    """
    计算 SM3 哈希，返回 64 位十六进制字符串
    """
    return sm3_hash(bytes_to_list(data))


def sm3_strhash(data: str) -> str:
    """
    计算字符串的 SM3 哈希，返回 64 位十六进制字符串
    便捷函数，等价于 merkle.py 中 generate_hash 的行为
    """
    return sm3_hash(bytes_to_list(data.encode("utf-8")))


# ====================== SM3 Hashlib 兼容包装器 ======================
# 用于 Python hmac 模块，使 hmac.new(key, msg, SM3Hash) 正常工作


class SM3Hash:
    """
    兼容 hashlib 接口的 SM3 哈希封装，可直接传入 hmac.new()
    """
    digest_size: int = 32
    block_size: int = 64
    name: str = "sm3"

    def __init__(self, data: bytes = b""):
        self._buf: bytearray = bytearray(data) if data else bytearray()

    def update(self, data: bytes) -> None:
        self._buf.extend(data)

    def digest(self) -> bytes:
        return sm3_digest(bytes(self._buf))

    def hexdigest(self) -> str:
        return sm3_hexdigest(bytes(self._buf))

    def copy(self) -> "SM3Hash":
        new = SM3Hash()
        new._buf = bytearray(self._buf)
        return new


# ====================== SM4-CBC 加解密 ======================

# SM4 密钥: 16 字节 (128 bit)，从环境变量读取或使用默认值
_DEFAULT_SM4_KEY = b"FoodShieldSM4Key"


def _get_sm4_key() -> bytes:
    """获取 SM4 密钥，确保 16 字节"""
    key_str = os.getenv("FOODSHIELD_SM4_KEY", "")
    if key_str:
        key = key_str.encode("utf-8")
    else:
        key = _DEFAULT_SM4_KEY
    # 截取或右填充至 16 字节
    if len(key) >= 16:
        return key[:16]
    else:
        return key.ljust(16, b"\x00")


def sm4_encrypt(plaintext: str) -> str:
    """
    使用 SM4-CBC 加密明文
    :param plaintext: 明文字符串
    :return: 十六进制字符串: IV(16B) + 密文，共 32 + N*32 位十六进制
    """
    key = _get_sm4_key()
    iv = secrets.token_bytes(16)  # 随机 IV

    # PKCS7 填充
    data = plaintext.encode("utf-8")
    pad_len = 16 - (len(data) % 16)
    data = data + bytes([pad_len] * pad_len)

    crypt = CryptSM4()
    crypt.set_key(key, SM4_ENCRYPT)
    ciphertext = crypt.crypt_cbc(iv, data)

    # 返回 IV + 密文 的十六进制表示
    return (iv + ciphertext).hex()


def sm4_decrypt(ciphertext_hex: str) -> str:
    """
    使用 SM4-CBC 解密
    :param ciphertext_hex: sm4_encrypt 生成的十六进制字符串
    :return: 明文字符串
    """
    key = _get_sm4_key()
    raw = bytes.fromhex(ciphertext_hex)

    iv = raw[:16]
    ciphertext = raw[16:]

    crypt = CryptSM4()
    crypt.set_key(key, SM4_DECRYPT)
    plaintext_padded = crypt.crypt_cbc(iv, ciphertext)

    # 移除 PKCS7 填充
    pad_len = plaintext_padded[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("SM4 decryption failed: invalid PKCS7 padding")
    plaintext = plaintext_padded[:-pad_len]

    return plaintext.decode("utf-8")


# ====================== 自测 ======================

if __name__ == "__main__":
    print("=" * 50)
    print("SM3 / SM4 自测")
    print("=" * 50)

    # SM3
    h = sm3_strhash("hello world")
    print(f"SM3('hello world') = {h}")
    assert len(h) == 64, "SM3 输出应为 64 位十六进制"

    # HMAC-SM3
    import hmac
    hm = hmac.new(b"mykey", b"mymsg", SM3Hash).hexdigest()
    print(f"HMAC-SM3(key='mykey', msg='mymsg') = {hm}")
    assert len(hm) == 64, "HMAC-SM3 输出应为 64 位十六进制"

    # SM4
    plain = "你好，外卖到了！"
    enc = sm4_encrypt(plain)
    dec = sm4_decrypt(enc)
    print(f"SM4 加密: '{plain}' -> {enc[:32]}...")
    print(f"SM4 解密: -> '{dec}'")
    assert plain == dec, "SM4 加解密往返失败"

    # SM4 空字符串
    empty_enc = sm4_encrypt("")
    empty_dec = sm4_decrypt(empty_enc)
    assert "" == empty_dec, "SM4 空字符串往返失败"

    print("\n✅ 所有自测通过！")
