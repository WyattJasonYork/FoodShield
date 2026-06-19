import hmac
import secrets
import uuid
from project.crypto.sm_utils import SM3Hash


def generate_pid(k_master: str, user_id: str) -> dict:
    """
    生成用户匿名身份标识(PID)
    公式: PID = HMAC-SM3(K_master, userID || r)
    使用国密 SM3 替代 SHA-256
    """
    r = secrets.token_hex(16)

    message = f"{user_id}{r}".encode("utf-8")
    key = k_master.encode("utf-8")

    pid = hmac.new(key, message, SM3Hash).hexdigest()

    return {"pid": pid, "r": r}
if __name__ == "__main__":
    k = "FoodShield"
    user_id = 'user001'
    print(generate_pid(k,user_id))