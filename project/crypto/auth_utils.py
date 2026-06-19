import hmac
from project.crypto.sm_utils import SM3Hash

class HMACAuth:
    """
    统一的HMAC签名与验证逻辑
    使用国密 HMAC-SM3 替代 HMAC-SHA256
    """

    @staticmethod
    def sign(key : str, message : str)->str:
        """
        生成HMAC-SM3签名
        """
        if not key or not message:
            raise ValueError("key and message cannot be empty!")

        byte_key = key.encode('utf-8')
        byte_msg = message.encode('utf-8')
        return hmac.new(byte_key, byte_msg, SM3Hash).hexdigest()


    @staticmethod
    def verify(key : str, message : str, signature : str)->bool:
        """
        验证HMAC签名是否合法
        使用compare_digest防止时序攻击
        """
        expected_sig = HMACAuth.sign(key, message)
        return hmac.compare_digest(expected_sig, signature)
