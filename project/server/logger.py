import json

from project.database.db import query_all, query_one, execute
from project.crypto.merkle import hash_message, build_merkle_root
from project.crypto.sm_utils import sm4_decrypt


def get_order_messages(order_id: str):
    """
    获取某个订单下的所有通信消息，按固定顺序返回
    存储的加密内容自动 SM4 解密
    """
    sql = """
        SELECT id, msg_id, order_id, sender_pid, role, content, message_hash, timestamp, created_at
        FROM messages
        WHERE order_id = ?
        ORDER BY timestamp ASC, id ASC
    """
    rows = query_all(sql, (order_id,))
    messages = []
    for row in rows:
        msg = dict(row)
        # SM4 解密消息内容
        try:
            msg["content"] = sm4_decrypt(msg["content"])
        except Exception:
            pass
        messages.append(msg)
    return messages


def create_merkle_snapshot(order_id: str) -> dict:
    """
    根据某订单当前所有消息的 message_hash 生成一次 Merkle Root 快照，
    并写入 audit_logs
    """
    messages = get_order_messages(order_id)

    leaf_hashes = [msg["message_hash"] for msg in messages if msg["message_hash"]]
    merkle_root = build_merkle_root(leaf_hashes)

    latest_msg_id = messages[-1]["msg_id"] if messages else None

    detail = json.dumps(
        {
            "message_count": len(messages),
            "latest_msg_id": latest_msg_id
        },
        ensure_ascii=False
    )

    execute(
        """
        INSERT INTO audit_logs (order_id, action, detail, merkle_root)
        VALUES (?, ?, ?, ?)
        """,
        (order_id, "MERKLE_ROOT_UPDATED", detail, merkle_root)
    )

    return {
        "order_id": order_id,
        "message_count": len(messages),
        "latest_msg_id": latest_msg_id,
        "merkle_root": merkle_root
    }


def verify_order_integrity(order_id: str) -> dict:
    """
    对某个订单的通信记录进行完整性验证：
    1. 重新根据消息内容计算 message_hash
    2. 检查与数据库中的 message_hash 是否一致
    3. 重新生成当前 Merkle Root
    4. 与最近一次 MERKLE_ROOT_UPDATED 快照比较
    5. 将验证结果写入 audit_logs
    """
    messages = get_order_messages(order_id)

    mismatches = []
    recomputed_hashes = []

    for msg in messages:
        expected_hash = hash_message(
            order_id=msg["order_id"],
            sender_pid=msg["sender_pid"],
            role=msg["role"],
            content=msg["content"],
            timestamp=msg["timestamp"]
        )

        recomputed_hashes.append(expected_hash)

        if msg["message_hash"] != expected_hash:
            mismatches.append(
                {
                    "msg_id": msg["msg_id"],
                    "stored_hash": msg["message_hash"],
                    "expected_hash": expected_hash
                }
            )

    current_root = build_merkle_root(recomputed_hashes)

    latest_snapshot = query_one(
        """
        SELECT id, merkle_root, created_at
        FROM audit_logs
        WHERE order_id = ? AND action = 'MERKLE_ROOT_UPDATED'
        ORDER BY id DESC
        LIMIT 1
        """,
        (order_id,)
    )

    snapshot_root = latest_snapshot["merkle_root"] if latest_snapshot else None
    root_match = (snapshot_root == current_root) if snapshot_root else False

    passed = (len(mismatches) == 0) and root_match
    action = "VERIFY_OK" if passed else "VERIFY_FAIL"

    detail = json.dumps(
        {
            "message_count": len(messages),
            "hash_mismatch_count": len(mismatches),
            "root_match": root_match,
            "snapshot_root": snapshot_root,
            "current_root": current_root,
            "mismatches": mismatches
        },
        ensure_ascii=False
    )

    execute(
        """
        INSERT INTO audit_logs (order_id, action, detail, merkle_root)
        VALUES (?, ?, ?, ?)
        """,
        (order_id, action, detail, current_root)
    )

    return {
        "success": passed,
        "order_id": order_id,
        "message_count": len(messages),
        "hash_mismatch_count": len(mismatches),
        "root_match": root_match,
        "snapshot_root": snapshot_root,
        "current_root": current_root,
        "mismatches": mismatches
    }