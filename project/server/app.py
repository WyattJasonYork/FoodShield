from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room
from pathlib import Path
from datetime import datetime
from functools import wraps
import uuid
import json
import os
import hmac
import hashlib
import secrets

from project.database.db import init_db, execute, query_one, query_all
from project.crypto.pid import generate_pid
from project.crypto.token_utils import generate_token, verify_token
from project.crypto.merkle import hash_message
from project.crypto.sm_utils import sm4_encrypt, sm4_decrypt, sm3_strhash
from project.server.logger import create_merkle_snapshot, verify_order_integrity


app = Flask(__name__)
app.config["SECRET_KEY"] = "foodshield-secret-key"
app.config["ADMIN_USERNAME"] = os.getenv("FOODSHIELD_ADMIN_USERNAME", "admin")
app.config["ADMIN_PASSWORD"] = os.getenv("FOODSHIELD_ADMIN_PASSWORD", "admin123456")
app.config["ORDER_ALIAS_SECRET"] = os.getenv("FOODSHIELD_ORDER_ALIAS_SECRET", "foodshield-order-alias-secret")

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


def ensure_schema_migrations():
    """兼容旧版 foodshield.db：补齐导师建议后新增的字段。

    注意：SQLite 的 CREATE TABLE IF NOT EXISTS 不会自动给已有表补字段。
    因此旧数据库存在时，必须显式 ALTER TABLE。
    """
    try:
        user_columns = {row["name"] for row in query_all("PRAGMA table_info(users)")}
        if "password_hash" not in user_columns:
            execute("ALTER TABLE users ADD COLUMN password_hash TEXT NOT NULL DEFAULT ''")
        if "salt" not in user_columns:
            execute("ALTER TABLE users ADD COLUMN salt TEXT NOT NULL DEFAULT ''")
        if "device_fingerprint" not in user_columns:
            execute("ALTER TABLE users ADD COLUMN device_fingerprint TEXT NOT NULL DEFAULT ''")

        order_columns = {row["name"] for row in query_all("PRAGMA table_info(orders)")}
        if "remark" not in order_columns:
            execute("ALTER TABLE orders ADD COLUMN remark TEXT NOT NULL DEFAULT ''")
        if "tag" not in order_columns:
            execute("ALTER TABLE orders ADD COLUMN tag TEXT NOT NULL DEFAULT ''")
        if "delivery_note" not in order_columns:
            execute("ALTER TABLE orders ADD COLUMN delivery_note TEXT NOT NULL DEFAULT ''")

        # 条件溯源申请表：用户端/骑手端按订单号提交申请，管理员审批后溯源。
        execute("""
            CREATE TABLE IF NOT EXISTS trace_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id TEXT NOT NULL,
                requester_role TEXT NOT NULL CHECK (requester_role IN ('user', 'rider')),
                reason TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'approved', 'rejected')),
                admin_note TEXT NOT NULL DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reviewed_at TEXT
            )
        """)
    except Exception as exc:
        print(f"[schema migration skipped] {exc}")


def get_user_by_id(user_id: int):
    return query_one("SELECT * FROM users WHERE id = ?", (user_id,))


def user_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({
                "success": False,
                "message": "请先登录后再操作"
            }), 401
        return func(*args, **kwargs)
    return wrapper


def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return get_user_by_id(user_id)


def public_message(msg: dict):
    """普通用户/骑手视角不暴露 PID；管理员接口仍可看哈希和审计元数据。"""
    item = dict(msg)
    item.pop("sender_pid", None)
    item["sender"] = item.get("role")
    return item


# ====================== 工具函数 ======================

def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def get_order_by_order_id(order_id: str):
    return query_one("SELECT * FROM orders WHERE order_id = ?", (order_id,))


def make_order_alias(order_id: str) -> str:
    """骑手端订单级匿名会话名：同一用户的多个订单也会呈现为不同 alias。"""
    digest = hmac.new(
        app.config["ORDER_ALIAS_SECRET"].encode("utf-8"),
        f"{order_id}|rider_view".encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    return f"Guest-{digest[:6].upper()}"


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


def get_message_history_for_admin(order_id: str):
    """
    管理员视角的消息列表：不含明文内容，只有 SM3 哈希 + 元数据。
    Merkle 完整性验证只需哈希，管理员不需要读明文。
    """
    rows = query_all(
        """
        SELECT msg_id, order_id, role, message_hash, timestamp
        FROM messages
        WHERE order_id = ?
        ORDER BY id ASC
        """,
        (order_id,)
    )
    return [dict(row) for row in rows]


def get_orders_by_user_id(user_id: int):
    rows = query_all(
        """
        SELECT order_id, token, token_timestamp, remark, tag, delivery_note, status, created_at
        FROM orders
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (user_id,)
    )
    return [dict(row) for row in rows]


def get_trace_orders_by_user_id(user_id: int):
    """管理员溯源结果中的订单列表：不返回 token、备注、标签、PID。"""
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
    orders = get_trace_orders_by_user_id(user_dict["id"])

    return {
        "user_id": user_dict["id"],
        "username": user_dict.get("username"),
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
    """用户注册：用户名 + 密码 + 设备指纹 + 验证码 → 后端生成匿名 PID（不直接展示）。"""
    ensure_schema_migrations()
    data = request.json or {}

    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    confirm_password = (data.get("confirm_password") or "").strip()
    captcha_answer = (data.get("captcha_answer") or "").strip()
    machine_fp = (data.get("machine_fp") or data.get("device_fingerprint") or "").strip()

    if not username:
        return jsonify({"success": False, "message": "用户名不能为空"}), 400
    if not password:
        return jsonify({"success": False, "message": "密码不能为空"}), 400
    if len(password) < 6:
        return jsonify({"success": False, "message": "密码长度不能少于 6 位"}), 400
    if password != confirm_password:
        return jsonify({"success": False, "message": "两次密码输入不一致"}), 400
    if not captcha_answer:
        return jsonify({"success": False, "message": "验证码不能为空"}), 400
    if not machine_fp:
        return jsonify({"success": False, "message": "缺少设备识别信息，请刷新页面后重试"}), 400

    session_captcha = session.get("captcha_answer")
    if session_captcha is None:
        return jsonify({"success": False, "message": "验证码已过期，请刷新后重试"}), 400
    try:
        if int(captcha_answer) != int(session_captcha):
            return jsonify({"success": False, "message": "验证码错误"}), 400
    except ValueError:
        return jsonify({"success": False, "message": "验证码格式错误"}), 400
    finally:
        session.pop("captcha_answer", None)

    existing = query_one("SELECT * FROM users WHERE username = ?", (username,))
    if existing:
        return jsonify({"success": False, "message": "用户名已存在"}), 409

    # 简单设备级限流：同一设备最多注册 3 个账号，避免无成本机器注册。
    fp_count = query_one(
        "SELECT COUNT(*) AS cnt FROM users WHERE device_fingerprint = ?",
        (machine_fp,)
    )
    if fp_count and fp_count["cnt"] >= 3:
        return jsonify({
            "success": False,
            "message": "该设备注册次数过多，已触发机器注册限制"
        }), 429

    try:
        salt = secrets.token_hex(16)
        password_hash = sm3_strhash(salt + password)

        temp_pid = f"temp_{uuid.uuid4()}"
        user_id = execute(
            """
            INSERT INTO users (username, pid, password_hash, salt, device_fingerprint)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, temp_pid, password_hash, salt, machine_fp)
        )

        pid_result = generate_pid("FoodShield", str(user_id))
        pid = pid_result["pid"]
        execute("UPDATE users SET pid = ? WHERE id = ?", (pid, user_id))

        # 注册即登录，但返回给前端时不展示 PID；PID 仅在后端参与 Token 校验和条件溯源。
        session["user_id"] = user_id
        session["username"] = username

        return jsonify({
            "success": True,
            "message": "注册成功，请继续创建订单",
            "data": {
                "user_id": user_id,
                "username": username
            }
        }), 201

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# ====================== 验证码 ======================

@app.route("/captcha", methods=["GET"])
def get_captcha():
    """返回数学验证码题目，答案存入 session"""
    import random
    a = random.randint(1, 20)
    b = random.randint(1, 20)
    op = random.choice(["+", "-"])
    if op == "+":
        answer = a + b
    else:
        if a < b:
            a, b = b, a
        answer = a - b
    question = f"{a} {op} {b} = ?"
    session["captcha_answer"] = answer
    return jsonify({
        "success": True,
        "data": {
            "question": question
        }
    })


# ====================== 用户登录/会话 ======================

@app.route("/login", methods=["POST"])
def login():
    """用户登录：用户名 + 密码 + 设备指纹 → 验证 SM3(salt + password)。"""
    ensure_schema_migrations()
    data = request.json or {}

    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    machine_fp = (data.get("machine_fp") or data.get("device_fingerprint") or "").strip()

    if not username or not password:
        return jsonify({"success": False, "message": "用户名和密码不能为空"}), 400
    if not machine_fp:
        return jsonify({"success": False, "message": "缺少设备识别信息，请刷新页面后重试"}), 400

    user = query_one("SELECT * FROM users WHERE username = ?", (username,))
    if not user:
        return jsonify({"success": False, "message": "用户名或密码错误"}), 401

    computed_hash = sm3_strhash(user["salt"] + password)
    if not hmac.compare_digest(computed_hash, user["password_hash"]):
        return jsonify({"success": False, "message": "用户名或密码错误"}), 401

    saved_fp = user["device_fingerprint"] if "device_fingerprint" in user.keys() else ""
    # 兼容旧账号：首次登录时绑定设备指纹；之后必须同设备登录。
    if saved_fp:
        if not hmac.compare_digest(saved_fp, machine_fp):
            return jsonify({
                "success": False,
                "message": "设备识别失败，请使用注册设备登录"
            }), 403
    else:
        execute("UPDATE users SET device_fingerprint = ? WHERE id = ?", (machine_fp, user["id"]))

    session["user_id"] = user["id"]
    session["username"] = user["username"]

    return jsonify({
        "success": True,
        "message": "登录成功",
        "data": {
            "user_id": user["id"],
            "username": user["username"]
        }
    })


@app.route("/user/session", methods=["GET"])
def get_user_session():
    """检查当前用户登录状态；不向前端返回 PID。"""
    ensure_schema_migrations()
    user = get_current_user()
    if user:
        return jsonify({
            "success": True,
            "data": {
                "logged_in": True,
                "user_id": user["id"],
                "username": user["username"]
            }
        })
    return jsonify({
        "success": True,
        "data": {
            "logged_in": False
        }
    })


@app.route("/logout", methods=["POST"])
def logout():
    """用户登出"""
    session.pop("user_id", None)
    session.pop("username", None)
    return jsonify({"success": True, "message": "已登出"})


@app.route("/my_orders", methods=["GET"])
@user_required
def my_orders():
    """仅返回当前登录用户自己的订单历史，不暴露 PID。"""
    ensure_schema_migrations()
    user_id = session["user_id"]
    orders = get_orders_by_user_id(user_id)
    return jsonify({
        "success": True,
        "message": "orders fetched successfully",
        "data": orders
    }), 200


@app.route("/my_orders/search", methods=["GET"])
@user_required
def search_my_orders():
    """用户端订单搜索：只查当前登录用户自己的订单，可按订单号/备注/标签搜索。"""
    ensure_schema_migrations()
    user_id = session["user_id"]
    keyword = (request.args.get("keyword") or "").strip()
    status = (request.args.get("status") or "").strip()

    sql = """
        SELECT order_id, token, token_timestamp, remark, tag, delivery_note, status, created_at
        FROM orders
        WHERE user_id = ?
    """
    params = [user_id]

    if keyword:
        like = f"%{keyword}%"
        sql += " AND (order_id LIKE ? OR remark LIKE ? OR tag LIKE ?)"
        params.extend([like, like, like])

    if status:
        sql += " AND status = ?"
        params.append(status)

    sql += " ORDER BY id DESC"

    rows = query_all(sql, tuple(params))
    return jsonify({
        "success": True,
        "message": "user order search completed",
        "data": [dict(row) for row in rows]
    }), 200


@app.route("/create_order", methods=["POST"])
@user_required
def create_order():
    """
    创建订单必须基于服务端 session。
    关键修复：不再接受/信任前端提交的 PID，避免未登录或伪造 PID 无限创建订单。
    """
    ensure_schema_migrations()
    data = request.json or {}
    user = get_current_user()
    if not user:
        return jsonify({"success": False, "message": "请先登录后再创建订单"}), 401

    user_id = user["id"]
    pid = user["pid"]
    order_id = str(uuid.uuid4())
    remark = str(data.get("remark") or "").strip()[:200]
    tag = str(data.get("tag") or "").strip()[:50]
    delivery_note = str(data.get("delivery_note") or "").strip()[:200]

    token_data = generate_token(order_id, pid)
    token = token_data["token"]
    timestamp = token_data["timestamp"]

    try:
        execute(
            """
            INSERT INTO orders (order_id, user_id, token, token_timestamp, remark, tag, delivery_note, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (order_id, user_id, token, timestamp, remark, tag, delivery_note, "created")
        )

        return jsonify({
            "success": True,
            "message": "order created successfully",
            "data": {
                "order_id": order_id,
                "token": token,
                "timestamp": timestamp,
                "remark": remark,
                "tag": tag,
                "delivery_note": delivery_note,
                "status": "created"
            }
        }), 201

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/verify_order", methods=["POST"])
def verify_order_api():
    """验证订单 Token。优先使用当前登录用户的 PID；PID 不需要前端提交。"""
    data = request.json or {}
    required = ["order_id", "timestamp", "token"]
    for field in required:
        if field not in data:
            return jsonify({"success": False, "message": f"{field} is required"}), 400

    order = get_order_by_order_id(data["order_id"])
    if not order:
        return jsonify({"success": False, "message": "order not found"}), 404

    current_user = get_current_user()
    if not current_user:
        return jsonify({"success": False, "message": "请先登录后再验证订单"}), 401
    if int(current_user["id"]) != int(order["user_id"]):
        return jsonify({"success": False, "message": "只能验证当前登录用户自己的订单"}), 403

    pid = current_user["pid"]

    try:
        is_valid = verify_token(
            data["order_id"],
            pid,
            data["timestamp"],
            data["token"]
        )
    except Exception:
        is_valid = False

    return jsonify({
        "success": True,
        "message": "order verification completed",
        "data": {
            "valid": is_valid
        }
    }), 200


@app.route("/get_pending_orders", methods=["GET"])
def get_pending_orders():
    """骑手端查看待接订单：只展示订单号和状态，不暴露用户 PID。"""
    try:
        ensure_schema_migrations()
        rows = query_all(
            """
            SELECT o.order_id, o.status, o.delivery_note, o.created_at
            FROM orders o
            WHERE o.status = 'created'
            ORDER BY o.id DESC
            """
        )

        orders = []
        for row in rows:
            orders.append({
                "order_id": row["order_id"],
                "order_alias": make_order_alias(row["order_id"]),
                "status": row["status"],
                "delivery_note": row["delivery_note"],
                "created_at": row["created_at"]
            })

        return jsonify({
            "success": True,
            "message": "pending orders fetched successfully",
            "data": orders
        }), 200

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/rider/orders/search", methods=["GET"])
def rider_search_orders():
    """骑手端订单搜索：不返回 PID、user_id、username、token、用户备注/标签。

    仅按订单号、订单状态、配送必要说明检索，并返回订单级匿名 alias，
    避免骑手把同一用户的多个订单关联起来。
    """
    ensure_schema_migrations()
    keyword = (request.args.get("keyword") or "").strip()
    status = (request.args.get("status") or "created").strip()

    sql = """
        SELECT order_id, status, delivery_note, created_at
        FROM orders
        WHERE 1 = 1
    """
    params = []

    if status:
        sql += " AND status = ?"
        params.append(status)

    if keyword:
        like = f"%{keyword}%"
        sql += " AND (order_id LIKE ? OR delivery_note LIKE ?)"
        params.extend([like, like])

    sql += " ORDER BY id DESC"

    rows = query_all(sql, tuple(params))
    result = []
    for row in rows:
        result.append({
            "order_id": row["order_id"],
            "order_alias": make_order_alias(row["order_id"]),
            "status": row["status"],
            "delivery_note": row["delivery_note"],
            "created_at": row["created_at"]
        })

    return jsonify({
        "success": True,
        "message": "rider order search completed",
        "data": result
    }), 200


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

        history = [public_message(msg) for msg in get_message_history_by_order(order_id)]
        return jsonify({
            "success": True,
            "message": "message history fetched successfully",
            "data": history
        }), 200

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500



# ====================== 条件溯源申请 API ======================

@app.route("/trace_requests", methods=["POST"])
def submit_trace_request():
    """用户端/骑手端提交条件溯源申请：只按订单号，不提交 PID。"""
    ensure_schema_migrations()
    data = request.json or {}
    order_id = str(data.get("order_id", "")).strip()
    requester_role = str(data.get("requester_role", "")).strip()
    reason = str(data.get("reason", "")).strip()

    if not order_id:
        return jsonify({"success": False, "message": "order_id is required"}), 400
    if requester_role not in ("user", "rider"):
        return jsonify({"success": False, "message": "requester_role must be user or rider"}), 400
    if not reason:
        return jsonify({"success": False, "message": "reason is required"}), 400

    order = get_order_by_order_id(order_id)
    if not order:
        return jsonify({"success": False, "message": "order not found"}), 404

    # 用户端申请必须是当前登录用户自己的订单；骑手端不需要也不能提交用户身份信息。
    if requester_role == "user":
        session_user_id = session.get("user_id")
        if not session_user_id:
            return jsonify({"success": False, "message": "请先登录后再提交溯源申请"}), 401
        if int(session_user_id) != int(order["user_id"]):
            return jsonify({"success": False, "message": "只能为自己的订单提交溯源申请"}), 403

    request_id = execute(
        """
        INSERT INTO trace_requests (order_id, requester_role, reason, status)
        VALUES (?, ?, ?, 'pending')
        """,
        (order_id, requester_role, reason[:300])
    )

    log_admin_action(
        action="TRACE_REQUEST_SUBMITTED",
        detail={
            "trace_request_id": request_id,
            "requester_role": requester_role,
            "reason": reason[:300],
            "policy": "request_by_order_id_no_pid"
        },
        order_id=order_id
    )

    return jsonify({
        "success": True,
        "message": "trace request submitted successfully",
        "data": {
            "request_id": request_id,
            "order_id": order_id,
            "requester_role": requester_role,
            "status": "pending"
        }
    }), 201


@app.route("/admin/trace_requests", methods=["GET"])
@admin_required
def admin_get_trace_requests():
    """管理员查看溯源申请列表：只展示订单号、申请角色、原因、状态，不展示 PID。"""
    ensure_schema_migrations()
    status = str(request.args.get("status", "pending")).strip()

    sql = """
        SELECT tr.id, tr.order_id, tr.requester_role, tr.reason, tr.status,
               tr.admin_note, tr.created_at, tr.reviewed_at, o.status AS order_status
        FROM trace_requests tr
        LEFT JOIN orders o ON tr.order_id = o.order_id
        WHERE 1 = 1
    """
    params = []
    if status:
        sql += " AND tr.status = ?"
        params.append(status)
    sql += " ORDER BY tr.id DESC LIMIT 100"

    rows = query_all(sql, tuple(params))
    return jsonify({
        "success": True,
        "message": "trace requests fetched successfully",
        "data": [dict(row) for row in rows]
    }), 200


def perform_trace_by_order_id(order_id: str, reason: str, admin_username: str, trace_request_id=None):
    """内部工具：管理员审批后按订单号触发溯源，不要求任何前端提交 PID。"""
    order = get_order_by_order_id(order_id)
    if not order:
        log_admin_action(
            action="TRACE_FAIL",
            detail={
                "order_id": order_id,
                "reason": reason,
                "admin_username": admin_username,
                "trace_request_id": trace_request_id,
                "reason_code": "order_not_found"
            },
            order_id=order_id
        )
        return None, (jsonify({"success": False, "message": "order not found"}), 404)

    user = get_user_by_id(order["user_id"])
    if not user:
        log_admin_action(
            action="TRACE_FAIL",
            detail={
                "order_id": order_id,
                "reason": reason,
                "admin_username": admin_username,
                "trace_request_id": trace_request_id,
                "reason_code": "user_not_found"
            },
            order_id=order_id
        )
        return None, (jsonify({"success": False, "message": "user not found"}), 404)

    result = trace_pid(user["pid"])
    log_admin_action(
        action="TRACE_SUCCESS",
        detail={
            "order_id": order_id,
            "reason": reason,
            "admin_username": admin_username,
            "trace_request_id": trace_request_id,
            "user_id": result["user_id"],
            "username": result["username"],
            "policy": "trace_by_order_id_no_pid_input"
        },
        order_id=order_id
    )
    return result, None


@app.route("/admin/trace_requests/<int:request_id>/approve", methods=["POST"])
@admin_required
def admin_approve_trace_request(request_id):
    """管理员同意用户/骑手的溯源申请，并按订单号执行条件溯源。"""
    ensure_schema_migrations()
    data = request.json or {}
    admin_note = str(data.get("admin_note", "")).strip()
    req = query_one("SELECT * FROM trace_requests WHERE id = ?", (request_id,))
    if not req:
        return jsonify({"success": False, "message": "trace request not found"}), 404
    if req["status"] != "pending":
        return jsonify({"success": False, "message": f"request already {req['status']}"}), 400

    admin_username = session.get("admin_username", "unknown")
    reason = f"申请方：{req['requester_role']}；申请原因：{req['reason']}"
    if admin_note:
        reason += f"；管理员备注：{admin_note}"

    result, error_response = perform_trace_by_order_id(req["order_id"], reason, admin_username, request_id)
    if error_response:
        return error_response

    execute(
        """
        UPDATE trace_requests
        SET status = 'approved', admin_note = ?, reviewed_at = ?
        WHERE id = ?
        """,
        (admin_note[:300], now_iso(), request_id)
    )

    log_admin_action(
        action="TRACE_REQUEST_APPROVED",
        detail={
            "trace_request_id": request_id,
            "requester_role": req["requester_role"],
            "reason": req["reason"],
            "admin_note": admin_note[:300],
            "admin_username": admin_username
        },
        order_id=req["order_id"]
    )

    return jsonify({
        "success": True,
        "message": "trace request approved and trace completed",
        "data": {
            "request_id": request_id,
            "order_id": req["order_id"],
            "requester_role": req["requester_role"],
            "trace_result": result
        }
    }), 200


@app.route("/admin/trace_requests/<int:request_id>/reject", methods=["POST"])
@admin_required
def admin_reject_trace_request(request_id):
    """管理员拒绝溯源申请，只记录审计日志，不执行溯源。"""
    ensure_schema_migrations()
    data = request.json or {}
    admin_note = str(data.get("admin_note", "")).strip() or "管理员拒绝该溯源申请"
    req = query_one("SELECT * FROM trace_requests WHERE id = ?", (request_id,))
    if not req:
        return jsonify({"success": False, "message": "trace request not found"}), 404
    if req["status"] != "pending":
        return jsonify({"success": False, "message": f"request already {req['status']}"}), 400

    execute(
        """
        UPDATE trace_requests
        SET status = 'rejected', admin_note = ?, reviewed_at = ?
        WHERE id = ?
        """,
        (admin_note[:300], now_iso(), request_id)
    )

    log_admin_action(
        action="TRACE_REQUEST_REJECTED",
        detail={
            "trace_request_id": request_id,
            "requester_role": req["requester_role"],
            "reason": req["reason"],
            "admin_note": admin_note[:300],
            "admin_username": session.get("admin_username", "unknown")
        },
        order_id=req["order_id"]
    )

    return jsonify({
        "success": True,
        "message": "trace request rejected",
        "data": {
            "request_id": request_id,
            "order_id": req["order_id"],
            "status": "rejected"
        }
    }), 200


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

        history = get_message_history_for_admin(order_id)
        return jsonify({
            "success": True,
            "message": "admin fetched messages (hash only, no plaintext)",
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

        # 三方 Merkle Root 比对：查询客户端上报的最新 Root
        client_roots = {}
        for role_filter in ("user", "rider"):
            client_log = query_one(
                """
                SELECT merkle_root FROM audit_logs
                WHERE order_id = ? AND action = 'CLIENT_ROOT_REPORTED'
                  AND json_extract(detail, '$.role') = ?
                ORDER BY id DESC LIMIT 1
                """,
                (order_id, role_filter)
            )
            if client_log:
                client_roots[role_filter] = client_log["merkle_root"]

        server_root = result.get("current_root")
        all_match = False
        if server_root and len(client_roots) >= 2:
            all_match = (
                server_root == client_roots.get("user")
                and server_root == client_roots.get("rider")
            )

        result["client_roots"] = client_roots if client_roots else None
        result["all_match"] = all_match

        return jsonify({
            "success": result["success"] and all_match,
            "message": "integrity verification completed" if result["success"] else "integrity verification failed",
            "data": result
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500


@app.route("/admin/orders/search", methods=["GET"])
@admin_required
def admin_search_orders():
    """管理员端审计搜索：只返回审计元数据和消息哈希，不返回备注/标签/PID/Token/明文。"""
    ensure_schema_migrations()
    order_id = (request.args.get("order_id") or "").strip()
    message_hash = (request.args.get("hash") or "").strip()
    action = (request.args.get("action") or "").strip()

    sql = """
        SELECT
            o.order_id,
            o.status,
            o.created_at,
            COUNT(DISTINCT m.id) AS message_count,
            MAX(a.action) AS latest_action,
            MAX(a.created_at) AS latest_audit_time,
            (
                SELECT al.merkle_root
                FROM audit_logs al
                WHERE al.order_id = o.order_id AND al.merkle_root IS NOT NULL
                ORDER BY al.id DESC
                LIMIT 1
            ) AS latest_merkle_root
        FROM orders o
        LEFT JOIN messages m ON o.order_id = m.order_id
        LEFT JOIN audit_logs a ON o.order_id = a.order_id
        WHERE 1 = 1
    """
    params = []

    if order_id:
        sql += " AND o.order_id LIKE ?"
        params.append(f"%{order_id}%")

    if message_hash:
        sql += " AND EXISTS (SELECT 1 FROM messages mh WHERE mh.order_id = o.order_id AND mh.message_hash LIKE ?)"
        params.append(f"%{message_hash}%")

    if action:
        sql += " AND EXISTS (SELECT 1 FROM audit_logs ah WHERE ah.order_id = o.order_id AND ah.action = ?)"
        params.append(action)

    sql += " GROUP BY o.order_id, o.status, o.created_at ORDER BY o.id DESC LIMIT 100"

    rows = query_all(sql, tuple(params))
    result = []
    for row in rows:
        hashes = query_all(
            """
            SELECT message_hash, role, timestamp
            FROM messages
            WHERE order_id = ?
            ORDER BY id ASC
            LIMIT 20
            """,
            (row["order_id"],)
        )
        result.append({
            "order_id": row["order_id"],
            "status": row["status"],
            "created_at": row["created_at"],
            "message_count": row["message_count"],
            "latest_action": row["latest_action"],
            "latest_audit_time": row["latest_audit_time"],
            "latest_merkle_root": row["latest_merkle_root"],
            "message_hashes": [dict(h) for h in hashes]
        })

    return jsonify({
        "success": True,
        "message": "admin audit search completed",
        "data": result
    }), 200


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
    """管理员条件溯源：按订单号触发，不要求管理员手动输入 PID。"""
    try:
        data = request.json or {}
        order_id = str(data.get("order_id", "")).strip()
        reason = str(data.get("reason", "")).strip() or "unspecified"

        if not order_id:
            return jsonify({
                "success": False,
                "message": "order_id is required"
            }), 400

        order = get_order_by_order_id(order_id)
        admin_username = session.get("admin_username", "unknown")
        if not order:
            log_admin_action(
                action="TRACE_FAIL",
                detail={
                    "order_id": order_id,
                    "reason": reason,
                    "admin_username": admin_username,
                    "reason_code": "order_not_found"
                },
                order_id=order_id
            )
            return jsonify({
                "success": False,
                "message": "order not found"
            }), 404

        user = get_user_by_id(order["user_id"])
        if not user:
            log_admin_action(
                action="TRACE_FAIL",
                detail={
                    "order_id": order_id,
                    "reason": reason,
                    "admin_username": admin_username,
                    "reason_code": "user_not_found"
                },
                order_id=order_id
            )
            return jsonify({
                "success": False,
                "message": "user not found"
            }), 404

        result = trace_pid(user["pid"])

        log_admin_action(
            action="TRACE_SUCCESS",
            detail={
                "order_id": order_id,
                "reason": reason,
                "admin_username": admin_username,
                "user_id": result["user_id"],
                "username": result["username"]
            },
            order_id=order_id
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



# ====================== 客户端 Merkle Root 上报 ======================

@app.route("/report_merkle_root", methods=["POST"])
def report_merkle_root():
    """用户端/骑手端上报本地保存的 Merkle Root，存入 audit_logs 供管理员三方比对"""
    data = request.json
    if not data:
        return jsonify({"success": False, "message": "请求体不能为空"}), 400
    order_id = (data.get("order_id") or "").strip()
    merkle_root = (data.get("merkle_root") or "").strip()
    role = (data.get("role") or "").strip()
    if not order_id or not merkle_root or not role:
        return jsonify({"success": False, "message": "order_id, merkle_root, role 均为必填"}), 400
    if role not in ("user", "rider"):
        return jsonify({"success": False, "message": "role 必须为 user 或 rider"}), 400
    try:
        execute(
            "INSERT INTO audit_logs (order_id, action, detail, merkle_root) VALUES (?, ?, ?, ?)",
            (order_id, "CLIENT_ROOT_REPORTED", json.dumps({"role": role}, ensure_ascii=False), merkle_root)
        )
        return jsonify({"success": True, "message": "merkle root reported"}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# ====================== WebSocket 事件 ======================

@socketio.on("connect")
def handle_connect():
    pass  # 静默连接，不发送系统消息到聊天界面


@socketio.on("join_order")
def handle_join_order(data):
    """
    用户侧进入订单聊天房间。
    隐私修复：前端不再提交 PID，后端根据 session 与订单归属关系取 PID 校验 Token。
    """
    required = ["order_id", "timestamp", "token", "role"]
    for field in required:
        if not data or field not in data:
            emit("join_result", {
                "success": False,
                "message": f"{field} is required"
            })
            return

    order_id = data["order_id"]
    timestamp = data["timestamp"]
    token = data["token"]
    role = data["role"]

    if role != "user":
        emit("join_result", {"success": False, "message": "invalid role for user join"})
        return

    order = get_order_by_order_id(order_id)
    if not order:
        emit("join_result", {"success": False, "message": "order not found"})
        return

    session_user_id = session.get("user_id")
    if not session_user_id or int(session_user_id) != int(order["user_id"]):
        emit("join_result", {
            "success": False,
            "message": "please login as the order owner first"
        })
        return

    owner = get_user_by_id(order["user_id"])
    if not owner:
        emit("join_result", {"success": False, "message": "order owner not found"})
        return

    pid = owner["pid"]

    try:
        is_valid = verify_token(order_id, pid, timestamp, token)
    except Exception:
        is_valid = False

    if not is_valid:
        emit("join_result", {
            "success": False,
            "message": "order verification failed"
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
    发送消息。
    修复：用户消息的 sender_pid 由订单归属用户确定，不能完全相信前端提交值；广播给普通端时不暴露 PID。
    """
    required = ["order_id", "role", "content"]
    for field in required:
        if not data or field not in data:
            emit("error_message", {
                "type": "error",
                "message": f"{field} is required"
            })
            return

    order_id = data["order_id"]
    role = data["role"]
    content = str(data["content"]).strip()

    if role not in ("user", "rider"):
        emit("error_message", {"type": "error", "message": "invalid role"})
        return

    if not content:
        emit("error_message", {
            "type": "error",
            "message": "content cannot be empty"
        })
        return

    order = get_order_by_order_id(order_id)
    if not order:
        emit("error_message", {"type": "error", "message": "order not found"})
        return

    owner = get_user_by_id(order["user_id"])
    if role == "user":
        if not owner:
            emit("error_message", {"type": "error", "message": "order owner not found"})
            return
        session_user_id = session.get("user_id")
        if not session_user_id or int(session_user_id) != int(order["user_id"]):
            emit("error_message", {"type": "error", "message": "please login as the order owner first"})
            return
        sender_pid = owner["pid"]
    else:
        sender_pid = "RIDER_DEMO_001"

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
        msg["merkle_root"] = snapshot["merkle_root"]

        emit("receive_message", public_message(msg), room=order_id)

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
@app.route("/admin/trace_violation", methods=["POST"])
@admin_required
def admin_trace_violation():
    """旧版按关键词扫描明文的溯源接口已禁用。

    新版隐私边界：管理员端不读取、不存储、不检索聊天明文；
    管理员只能基于订单号、投诉原因和哈希化审计日志触发条件溯源。
    """
    data = request.json or {}
    order_id = str(data.get("order_id", "")).strip()
    reason = str(data.get("reason", "关键词扫描接口已禁用")).strip()

    if not order_id:
        return jsonify({"success": False, "message": "order_id is required"}), 400

    log_admin_action(
        action="TRACE_KEYWORD_SCAN_BLOCKED",
        detail={
            "order_id": order_id,
            "reason": reason,
            "policy": "admin_hash_only_no_plaintext_scan",
            "admin_username": session.get("admin_username", "unknown")
        },
        order_id=order_id
    )

    return jsonify({
        "success": False,
        "message": "管理员端不读取聊天明文，关键词扫描溯源已禁用；请使用 /admin/trace 按订单号和溯源原因触发条件溯源。"
    }), 403
    

# ====================== 启动 ======================

if __name__ == "__main__":
    init_db()
    ensure_schema_migrations()
    socketio.run(app, host="127.0.0.1", port=5000, debug=True, allow_unsafe_werkzeug=True)