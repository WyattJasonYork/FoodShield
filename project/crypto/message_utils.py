from project.crypto.sm_utils import sm3_strhash

def calculate_message_hash(order_id, sender_pid, role, content, timestamp):
    """
    计算消息哈希，使用国密 SM3 替代 SHA-256
    """
    raw = f"{order_id}|{sender_pid}|{role}|{content}|{timestamp}"
    return sm3_strhash(raw)