"""
Database-backed security audit helpers.

This module keeps the old SecurityAuditor import path available, but delegates
to the current SQLite + Merkle implementation.
"""

from __future__ import annotations

from project.database.db import query_all
from project.server.logger import verify_order_integrity


class SecurityAuditor:
    """
    条件溯源前的证据链校验工具。

    当前隐私边界下，管理员端不进行聊天明文关键词扫描；调用方应先完成
    投诉审批，再基于订单号触发后端内部溯源。
    """

    def verify_log_authenticity(self, order_id: str) -> bool:
        result = verify_order_integrity(order_id)
        return bool(result.get("success"))

    def verify_order(self, order_id: str) -> dict:
        return verify_order_integrity(order_id)

    def get_hash_only_messages(self, order_id: str) -> list[dict]:
        rows = query_all(
            """
            SELECT msg_id, order_id, role, message_hash, timestamp
            FROM messages
            WHERE order_id = ?
            ORDER BY id ASC
            """,
            (order_id,),
        )
        return [dict(row) for row in rows]

    def detect_security_violation(self, order_id: str, suspicious_content: str | None = None) -> dict:
        result = verify_order_integrity(order_id)
        if not result.get("success"):
            return {
                "safe_to_trace": False,
                "message": "证据链被污染，系统阻断溯源操作",
                "verify_result": result,
            }

        return {
            "safe_to_trace": True,
            "message": "证据链完整。当前版本不在管理员端执行明文关键词扫描，请走审批式订单号溯源。",
            "verify_result": result,
            "hash_only_messages": self.get_hash_only_messages(order_id),
        }
