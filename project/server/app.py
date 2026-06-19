from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room
from pathlib import Path
from datetime import datetime
from functools import wraps
import uuid
import json
import os

from project.database.db import init_db, execute, query_one, query_all
from project.crypto.pid import generate_pid
from project.crypto.token_utils import generate_token, verify_token
from project.crypto.merkle import hash_message
from project.crypto.sm_utils import sm4_encrypt, sm4_decrypt
from project.server.logger import create_merkle_snapshot, verify_order_integrity


app = Flask(__name__)
app.config["SECRET_KEY"] = "foodshield-secret-key"
app.config["ADMIN_USERNAME"] = os.getenv("FOODSHIELD_ADMIN_USERNAME", "admin")
app.config["ADMIN_PASSWORD"] = os.getenv("FOODSHIELD_ADMIN_PASSWORD", "admin123456")

CORS(app)
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading",
    manage_session=False,
    logger=True,
    engineio_logger=True
)

BASE_DIR = Path(__file__).resolve().parent.parent.parent
FRONTEND_DIR = BASE_DIR / "project" / "frontend"


# ====================== 工具函数 ======================

def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def get_order_by_order_id(order_id: str):
    return query_one("SELECT * FROM orders WHERE order_id = ?", (order_id,))


def save_message(msg_id, order_id, sender_pid, role, content, message_hash, timestamp):
    """
    保存消息到数据库，消息内容使用 SM4 加密存储
    """
    encrypted_content = sm4_encrypt(content)
    execute(
        """
        INSERT INTO messages (msg_id, order_id, sender_pid, role, content, message_hash, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (msg_id, order_id, sender_pid, role, encrypted_content, message_hash, timestamp)
    )


def get_message_history_by_order(order_id: str):
    rows = query_all(
        """
        SELECT msg_id, order_id, sender_pid, role, content, message_hash, timestamp
        FROM messages
        WHERE order_id = ?
        ORDER BY id ASC
        """,
        (order_id,)
    )
    messages = []
    for row in rows:
        msg = dict(row)
        # SM4 解密消息内容
        try:
            msg["content"] = sm4_decrypt(msg["content"])
        except Exception:
            # 兼容旧数据（明文或损坏数据保持原样）
            pass
        messages.append(msg)
    return messages

def get_user_by_pid(pid: str):
    return query_one("SELECT * FROM users WHERE pid = ?", (pid,))


def get_orders_by_user_id(user_id: int):
    rows = query_all(
        """
        SELECT order_id, status, created_at
        FROM orders
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (user_id,)
    )
    return [dict(row) for row in rows]


def log_admin_action(action: str, detail: dict, order_id: str = None):
    execute(
        """
        INSERT INTO audit_logs (order_id, action, detail, merkle_root, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            order_id,
            action,
            json.dumps(detail, ensure_ascii=False),
            None,
            now_iso()
        )
    )


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            try:
                log_admin_action(
                    action="TRACE_DENIED",
                    detail={
                        "path": request.path,
                        "method": request.method,
                        "reason": "not_admin"
                    },
                    order_id=None
                )
            except Exception:
                pass

            return jsonify({
                "success": False,
                "message": "admin permission required"
            }), 403
        return func(*args, **kwargs)
    return wrapper


def trace_pid(pid: str):
    user = get_user_by_pid(pid)
    if not user:
        return None

    user_dict = dict(user)
    orders = get_orders_by_user_id(user_dict["id"])

    return {
        "user_id": user_dict["id"],
        "username": user_dict.get("username"),
        "pid": user_dict.get("pid"),
        "created_at": user_dict.get("created_at"),
        "orders": orders
    }


# ====================== 前端页面路由 ======================

@app.route("/")
def index_page():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/index.html")
def index_html():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/user.html")
def user_page():
    return send_from_directory(FRONTEND_DIR, "user.html")


@app.route("/rider.html")
def rider_page():
    return send_from_directory(FRONTEND_DIR, "rider.html")


@app.route("/admin.html")
def admin_page():
    return send_from_directory(FRONTEND_DIR, "admin.html")


@app.route("/css/<path:filename>")
def css_files(filename):
    return send_from_directory(FRONTEND_DIR / "css", filename)


# ====================== 后端业务 API ======================

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    if not data or "username" not in data:
        return jsonify({"success": False, "message": "username is required"}), 400

    username = data["username"].strip()
    if not username:
        return jsonify({"success": False, "message": "username cannot be empty"}), 400

    existing = query_one("SELECT * FROM users WHERE username = ?", (username,))
    if existing:
        return jsonify({"success": False, "message": "username already exists"}), 400

    try:
        temp_pid = f"temp_{uuid.uuid4()}"
        user_id = execute(
            "INSERT INTO users (username, pid) VALUES (?, ?)",
            (username, temp_pid)
        )

        pid_result = generate_pid("FoodShield", str(user_id))
        pid = pid_result["pid"]

        execute("UPDATE users SET pid = ? WHERE id = ?", (pid, user_id))

        return jsonify({
            "success": True,
            "message": "user registered successfully",
            "data": {
                "user_id": user_id,
                "username": username,
                "pid": pid
            }
        }), 201

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/create_order", methods=["POST"])
def create_order():
    data = request.json
    if not data or "pid" not in data:
        return jsonify({"success": False, "message": "pid is required"}), 400

    pid = data["pid"]

    user = query_one("SELECT * FROM users WHERE pid = ?", (pid,))
    if not user:
        return jsonify({"success": False, "message": "user not found"}), 404

    user_id = user["id"]
    order_id = str(uuid.uuid4())

    token_data = generate_token(order_id, pid)
    token = token_data["token"]
    timestamp = token_data["timestamp"]

    try:
        execute(
            """
            INSERT INTO orders (order_id, user_id, token, token_timestamp, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            (order_id, user_id, token, timestamp, "created")
        )

        return jsonify({
            "success": True,
            "message": "order created successfully",
            "data": {
                "order_id": order_id,
                "pid": pid,
                "token": token,
                "timestamp": timestamp,
                "status": "created"
            }
        }), 201

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/verify_order", methods=["POST"])
def verify_order_api():
    data = request.json
    required = ["order_id", "pid", "timestamp", "token"]

    for field in required:
        if not data or field not in data:
            return jsonify({"success": False, "message": f"{field} is required"}), 400

    is_valid = verify_token(
        data["order_id"],
        data["pid"],
        data["timestamp"],
        data["token"]
    )

    return jsonify({
        "success": True,
        "message": "order verification completed",
        "data": {
            "valid": is_valid
        }
    }), 200


@app.route("/get_pending_orders", methods=["GET"])
def get_pending_orders():
    try:
        rows = query_all(
            """
            SELECT o.order_id, o.status, u.pid
            FROM orders o
            JOIN users u ON o.user_id = u.id
            WHERE o.status = 'created'
            ORDER BY o.id DESC
            """
        )

        orders = []
        for row in rows:
            orders.append({
                "order_id": row["order_id"],
                "status": row["status"],
                "pid": row["pid"]
            })

        return jsonify({
            "success": True,
            "message": "pending orders fetched successfully",
            "data": orders
        }), 200

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/take_order", methods=["POST"])
def take_order():
    data = request.json
    if not data or "order_id" not in data:
        return jsonify({"success": False, "message": "order_id is required"}), 400

    order_id = data["order_id"]

    try:
        order = get_order_by_order_id(order_id)
        if not order:
            return jsonify({"success": False, "message": "order not found"}), 404

        if order["status"] != "created":
            return jsonify({
                "success": False,
                "message": f"order cannot be taken, current status: {order['status']}"
            }), 400

        execute(
            "UPDATE orders SET status = ? WHERE order_id = ?",
            ("taken", order_id)
        )

        return jsonify({
            "success": True,
            "message": "order taken successfully",
            "data": {
                "order_id": order_id,
                "status": "taken"
            }
        }), 200

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/get_message_history/<order_id>", methods=["GET"])
def get_message_history(order_id):
    try:
        order = get_order_by_order_id(order_id)
        if not order:
            return jsonify({"success": False, "message": "order not found"}), 404

        history = get_message_history_by_order(order_id)
        return jsonify({
            "success": True,
            "message": "message history fetched successfully",
            "data": history
        }), 200

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/admin/login", methods=["POST"])
def admin_login():
    try:
        data = request.json or {}
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", "")).strip()

        if not username or not password:
            return jsonify({
                "success": False,
                "message": "username and password are required"
            }), 400

        if (
            username != app.config["ADMIN_USERNAME"]
            or password != app.config["ADMIN_PASSWORD"]
        ):
            log_admin_action(
                action="ADMIN_LOGIN_FAIL",
                detail={
                    "username": username,
                    "reason": "invalid_credentials"
                },
                order_id=None
            )
            return jsonify({
                "success": False,
                "message": "invalid admin credentials"
            }), 401

        session["is_admin"] = True
        session["admin_username"] = username

        log_admin_action(
            action="ADMIN_LOGIN_SUCCESS",
            detail={
                "admin_username": username
            },
            order_id=None
        )

        return jsonify({
            "success": True,
            "message": "admin login successful",
            "data": {
                "is_admin": True,
                "admin_username": username
            }
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    try:
        admin_username = session.get("admin_username")

        if admin_username:
            log_admin_action(
                action="ADMIN_LOGOUT",
                detail={
                    "admin_username": admin_username
                },
                order_id=None
            )

        session.clear()

        return jsonify({
            "success": True,
            "message": "admin logout successful",
            "data": {
                "is_admin": False
            }
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500


@app.route("/admin/session", methods=["GET"])
def admin_session():
    return jsonify({
        "success": True,
        "message": "admin session fetched successfully",
        "data": {
            "is_admin": bool(session.get("is_admin")),
            "admin_username": session.get("admin_username")
        }
    }), 200

# ====================== 管理员 API（第四周） ======================
@app.route("/admin/snapshot/<order_id>", methods=["POST"])
@admin_required
def admin_create_snapshot(order_id):
    try:
        order = get_order_by_order_id(order_id)
        if not order:
            return jsonify({
                "success": False,
                "message": "order not found"
            }), 404

        result = create_merkle_snapshot(order_id)

        return jsonify({
            "success": True,
            "message": "snapshot created successfully",
            "data": result
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500


@app.route("/admin/messages/<order_id>", methods=["GET"])
@admin_required
def admin_get_messages(order_id):
    try:
        order = get_order_by_order_id(order_id)
        if not order:
            return jsonify({
                "success": False,
                "message": "order not found"
            }), 404

        history = get_message_history_by_order(order_id)
        return jsonify({
            "success": True,
            "message": "admin fetched messages successfully",
            "data": history
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500


@app.route("/admin/audit_logs/<order_id>", methods=["GET"])
@admin_required
def admin_get_audit_logs(order_id):
    try:
        order = get_order_by_order_id(order_id)
        if not order:
            return jsonify({
                "success": False,
                "message": "order not found"
            }), 404

        rows = query_all(
            """
            SELECT id, order_id, action, detail, merkle_root, created_at
            FROM audit_logs
            WHERE order_id = ?
            ORDER BY id DESC
            """,
            (order_id,)
        )

        logs = []
        for row in rows:
            item = dict(row)
            try:
                item["detail"] = json.loads(item["detail"]) if item["detail"] else {}
            except Exception:
                pass
            logs.append(item)

        return jsonify({
            "success": True,
            "message": "admin fetched audit logs successfully",
            "data": logs
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500


@app.route("/admin/verify/<order_id>", methods=["POST"])
@admin_required
def admin_verify_order(order_id):
    try:
        order = get_order_by_order_id(order_id)
        if not order:
            return jsonify({
                "success": False,
                "message": "order not found"
            }), 404

        result = verify_order_integrity(order_id)

        return jsonify({
            "success": result["success"],
            "message": "integrity verification completed" if result["success"] else "integrity verification failed",
            "data": result
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500


@app.route("/admin/orders", methods=["GET"])
@admin_required
def admin_get_orders():
    try:
        rows = query_all(
            """
            SELECT o.order_id, o.status, COUNT(m.id) AS message_count
            FROM orders o
            LEFT JOIN messages m ON o.order_id = m.order_id
            GROUP BY o.order_id, o.status
            ORDER BY o.id DESC
            """
        )

        result = []
        for row in rows:
            order_id = row["order_id"]

            latest_log = query_one(
                """
                SELECT action, merkle_root, created_at
                FROM audit_logs
                WHERE order_id = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (order_id,)
            )

            result.append({
                "order_id": order_id,
                "status": row["status"],
                "message_count": row["message_count"],
                "latest_action": latest_log["action"] if latest_log else None,
                "latest_merkle_root": latest_log["merkle_root"] if latest_log else None,
                "latest_audit_time": latest_log["created_at"] if latest_log else None
            })

        return jsonify({
            "success": True,
            "message": "admin fetched orders successfully",
            "data": result
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500

@app.route("/admin/trace", methods=["POST"])
@admin_required
def admin_trace():
    try:
        data = request.json or {}
        pid = str(data.get("pid", "")).strip()
        reason = str(data.get("reason", "")).strip() or "unspecified"

        if not pid:
            return jsonify({
                "success": False,
                "message": "pid is required"
            }), 400

        result = trace_pid(pid)
        admin_username = session.get("admin_username", "unknown")

        if not result:
            log_admin_action(
                action="TRACE_FAIL",
                detail={
                    "pid": pid,
                    "reason": reason,
                    "admin_username": admin_username
                },
                order_id=None
            )
            return jsonify({
                "success": False,
                "message": "pid not found"
            }), 404

        latest_order_id = result["orders"][0]["order_id"] if result["orders"] else None

        log_admin_action(
            action="TRACE_SUCCESS",
            detail={
                "pid": pid,
                "reason": reason,
                "admin_username": admin_username,
                "user_id": result["user_id"],
                "username": result["username"]
            },
            order_id=latest_order_id
        )

        return jsonify({
            "success": True,
            "message": "trace completed successfully",
            "data": result
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500



# ====================== WebSocket 事件 ======================

@socketio.on("connect")
def handle_connect():
    emit("system_message", {
        "type": "system",
        "message": "websocket connected",
        "timestamp": now_iso()
    })


@socketio.on("join_order")
def handle_join_order(data):
    """
    用户侧进入订单聊天房间
    data = {
        "order_id": "...",
        "pid": "...",
        "timestamp": "...",
        "token": "...",
        "role": "user"
    }
    """
    print("=== join_order received ===")
    print("raw data:", data)

    required = ["order_id", "pid", "timestamp", "token", "role"]
    for field in required:
        if not data or field not in data:
            print(f"join_order failed: missing field -> {field}")
            emit("join_result", {
                "success": False,
                "message": f"{field} is required"
            })
            return

    order_id = data["order_id"]
    pid = data["pid"]
    timestamp = data["timestamp"]
    token = data["token"]
    role = data["role"]

    print("order_id =", order_id)
    print("pid =", pid)
    print("timestamp =", timestamp)
    print("role =", role)
    print("token prefix =", token[:16] + "..." if token else "")

    order = get_order_by_order_id(order_id)
    print("order found =", bool(order))

    if not order:
        print("join_order failed: order not found")
        emit("join_result", {
            "success": False,
            "message": "order not found"
        })
        return

    is_valid = verify_token(order_id, pid, timestamp, token)
    print("verify_token result =", is_valid)

    if not is_valid:
        print("join_order failed: order verification failed")
        emit("join_result", {
            "success": False,
            "message": "order verification failed"
        })
        return

    join_room(order_id)
    print("join_order success: joined room", order_id)

    emit("join_result", {
        "success": True,
        "message": f"{role} joined room successfully",
        "order_id": order_id
    })

    emit("system_message", {
        "type": "system",
        "order_id": order_id,
        "message": f"{role} entered the chat room",
        "timestamp": now_iso()
    }, room=order_id)


@socketio.on("join_order_as_rider")
def handle_join_order_as_rider(data):
    """
    骑手侧进入订单聊天房间
    data = {
        "order_id": "...",
        "role": "rider"
    }
    """
    required = ["order_id", "role"]
    for field in required:
        if not data or field not in data:
            emit("join_result", {
                "success": False,
                "message": f"{field} is required"
            })
            return

    order_id = data["order_id"]
    role = data["role"]

    order = get_order_by_order_id(order_id)
    if not order:
        emit("join_result", {
            "success": False,
            "message": "order not found"
        })
        return

    if order["status"] not in ("taken", "delivering", "completed"):
        emit("join_result", {
            "success": False,
            "message": f"rider cannot join, current order status: {order['status']}"
        })
        return

    join_room(order_id)

    emit("join_result", {
        "success": True,
        "message": f"{role} joined room successfully",
        "order_id": order_id
    })

    emit("system_message", {
        "type": "system",
        "order_id": order_id,
        "message": f"{role} entered the chat room",
        "timestamp": now_iso()
    }, room=order_id)


@socketio.on("send_message")
def handle_send_message(data):
    """
    data = {
        "order_id": "...",
        "sender_pid": "...",
        "role": "user" / "rider",
        "content": "..."
    }
    """
    required = ["order_id", "sender_pid", "role", "content"]
    for field in required:
        if not data or field not in data:
            emit("error_message", {
                "type": "error",
                "message": f"{field} is required"
            })
            return

    order_id = data["order_id"]
    sender_pid = data["sender_pid"]
    role = data["role"]
    content = str(data["content"]).strip()

    if not content:
        emit("error_message", {
            "type": "error",
            "message": "content cannot be empty"
        })
        return

    order = get_order_by_order_id(order_id)
    if not order:
        emit("error_message", {
            "type": "error",
            "message": "order not found"
        })
        return

    timestamp = now_iso()
    msg_id = str(uuid.uuid4())

    message_hash = hash_message(
        order_id=order_id,
        sender_pid=sender_pid,
        role=role,
        content=content,
        timestamp=timestamp
    )

    msg = {
        "type": "chat",
        "msg_id": msg_id,
        "order_id": order_id,
        "sender_pid": sender_pid,
        "role": role,
        "content": content,
        "message_hash": message_hash,
        "timestamp": timestamp
    }

    try:
        save_message(
            msg["msg_id"],
            msg["order_id"],
            msg["sender_pid"],
            msg["role"],
            msg["content"],
            msg["message_hash"],
            msg["timestamp"]
        )

        snapshot = create_merkle_snapshot(order_id)

        emit("receive_message", msg, room=order_id)

        emit("system_message", {
            "type": "system",
            "order_id": order_id,
            "message": f"log snapshot updated, root={snapshot['merkle_root'][:12]}...",
            "timestamp": now_iso()
        }, room=order_id)

    except Exception as e:
        print(f"[send_message] error: {e}")
        emit("error_message", {
            "type": "error",
            "message": str(e)
        })

@app.route("/admin/backfill_snapshots", methods=["POST"])
@admin_required
def admin_backfill_snapshots():
    try:
        rows = query_all(
            """
            SELECT DISTINCT o.order_id
            FROM orders o
            LEFT JOIN messages m ON o.order_id = m.order_id
            WHERE m.id IS NOT NULL
            """
        )

        processed = []
        skipped = []

        for row in rows:
            order_id = row["order_id"]

            latest_log = query_one(
                """
                SELECT id
                FROM audit_logs
                WHERE order_id = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (order_id,)
            )

            if latest_log:
                skipped.append(order_id)
                continue

            result = create_merkle_snapshot(order_id)
            processed.append({
                "order_id": order_id,
                "merkle_root": result["merkle_root"],
                "message_count": result["message_count"]
            })

        return jsonify({
            "success": True,
            "message": "snapshot backfill completed",
            "data": {
                "processed": processed,
                "skipped": skipped,
                "processed_count": len(processed),
                "skipped_count": len(skipped)
            }
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500


# ====================== 条件溯源 API 补充 ======================
@app.route("/admin/trace", methods=["POST"])
def admin_trace_violation():
    data = request.json
    order_id = data.get("order_id")
    keyword = data.get("keyword", "").strip()

    if not order_id or not keyword:
        return jsonify({"success": False, "message": "order_id and keyword are required"}), 400

    try:
        # 1. 强制进行完整性校验
        integrity = verify_order_integrity(order_id)
        if not integrity.get("is_valid"):
            return jsonify({
                "success": True,
                "data": {
                    "safe_to_trace": False,
                    "message": "底层日志校验失败，证据链已被污染，系统阻断溯源操作！"
                }
            })

        # 2. 检查关键字是否命中
        messages = get_message_history_by_order(order_id)
        malicious_pids = set()
        for msg in messages:
            # 只要内容包含关键字且存在发送者，就记录 PID
            if keyword in msg.get("content", "") and msg.get("sender_pid"):
                malicious_pids.add(msg.get("sender_pid"))

        if not malicious_pids:
            return jsonify({
                "success": True,
                "data": {
                    "safe_to_trace": False,
                    "message": f"未命中：聊天记录中不存在违规词汇 '{keyword}'。"
                }
            })

        # 3. 命中！解密真实身份
        traced_users = []
        for pid in malicious_pids:
            # 健壮性改进：尝试关联 users 表
            user = query_one("SELECT username FROM users WHERE pid = ?", (pid,))
            if user:
                traced_users.append({
                    "pid": pid,
                    "username": user["username"]
                })
            else:
                # 兜底处理：如果没注册真名，至少把 PID 显示出来
                traced_users.append({
                    "pid": pid,
                    "username": "未在库注册身份 (测试数据)"
                })

        return jsonify({
            "success": True,
            "data": {
                "safe_to_trace": True,
                "message": "检测命中！已锁定涉嫌违规 PID，准许溯源。",
                "traced_users": traced_users
            }
        })

    except Exception as e:
        print(f"溯源出错: {e}")
        return jsonify({"success": False, "message": str(e)}), 500
    
# ====================== 启动 ======================

if __name__ == "__main__":
    init_db()
    socketio.run(app, host="127.0.0.1", port=5000, debug=True)