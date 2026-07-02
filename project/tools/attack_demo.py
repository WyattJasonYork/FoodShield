"""
FoodShield attack and defense demo.

The script uses Flask's test client and an isolated SQLite database under /tmp.
It demonstrates common attack attempts and the corresponding server-side
blocking or audit result.
"""

from __future__ import annotations

import argparse
import tempfile
import uuid
from pathlib import Path

from project.database import db


def configure_temp_database(path: str | None) -> Path:
    if path:
        db_path = Path(path).expanduser().resolve()
    else:
        db_path = Path(tempfile.gettempdir()) / f"foodshield_attack_{uuid.uuid4().hex}.db"
    db.DB_PATH = db_path
    db.init_db()
    return db_path


def post_json(client, path: str, payload: dict):
    return client.post(path, json=payload)


def print_case(title: str, expected: str, status_code: int, body: dict):
    success = body.get("success")
    message = body.get("message")
    print(f"\n[{title}]")
    print(f"expected: {expected}")
    print(f"actual:   status={status_code}, success={success}, message={message}")
    detail = {key: value for key, value in body.items() if key not in ("success", "message")}
    if detail:
        print(f"detail:   {detail}")


def register_user(client, username: str, password: str, machine_fp: str):
    captcha = client.get("/captcha").get_json()["data"]["question"]
    answer = str(eval(captcha.replace("=", "").replace("?", "").strip(), {"__builtins__": {}}))
    response = post_json(
        client,
        "/register",
        {
            "username": username,
            "password": password,
            "confirm_password": password,
            "captcha_answer": answer,
            "machine_fp": machine_fp,
        },
    )
    data = response.get_json()
    if not data.get("success"):
        raise RuntimeError(f"register failed: {data}")
    return data["data"]


def register_rider(client, username: str, password: str, machine_fp: str):
    captcha = client.get("/captcha").get_json()["data"]["question"]
    answer = str(eval(captcha.replace("=", "").replace("?", "").strip(), {"__builtins__": {}}))
    response = post_json(
        client,
        "/rider/register",
        {
            "username": username,
            "password": password,
            "confirm_password": password,
            "captcha_answer": answer,
            "machine_fp": machine_fp,
        },
    )
    data = response.get_json()
    if not data.get("success"):
        raise RuntimeError(f"rider register failed: {data}")
    return data["data"]


def run_attack_demo(db_path: str | None):
    db_file = configure_temp_database(db_path)

    from project.server.app import app, ensure_schema_migrations

    app.config.update(TESTING=True)
    with app.app_context():
        ensure_schema_migrations()

    user_client = app.test_client()
    attacker_client = app.test_client()
    rider_client = app.test_client()
    admin_client = app.test_client()

    print("FoodShield attack demo")
    print(f"database: {db_file}")

    register_user(user_client, "alice", "alice123", "device-alice")
    create_resp = post_json(
        user_client,
        "/create_order",
        {
            "remark": "private user remark",
            "tag": "private-tag",
            "delivery_note": "building gate",
        },
    )
    order = create_resp.get_json()["data"]
    order_id = order["order_id"]

    # 1. Unauthenticated order creation.
    resp = post_json(attacker_client, "/create_order", {"remark": "evil"})
    print_case(
        "unauthenticated_create_order",
        "401 because order creation requires a logged-in user session",
        resp.status_code,
        resp.get_json(),
    )

    # 2. Forged token.
    resp = post_json(
        user_client,
        "/verify_order",
        {
            "order_id": order_id,
            "timestamp": order["timestamp"],
            "token": order["token"][:-1] + ("0" if order["token"][-1] != "0" else "1"),
        },
    )
    print_case(
        "forged_token",
        "valid=false because HMAC-SM3 token was modified",
        resp.status_code,
        resp.get_json(),
    )

    # 3. Cross-user order verification.
    register_user(attacker_client, "mallory", "mallory123", "device-mallory")
    resp = post_json(
        attacker_client,
        "/verify_order",
        {
            "order_id": order_id,
            "timestamp": order["timestamp"],
            "token": order["token"],
        },
    )
    print_case(
        "cross_user_verify",
        "403 because another logged-in user cannot verify Alice's order",
        resp.status_code,
        resp.get_json(),
    )

    # 4. Duplicate order taking.
    unauth_take = post_json(rider_client, "/take_order", {"order_id": order_id})
    print_case(
        "unauthenticated_rider_take_order",
        "401 because rider must register/login before taking orders",
        unauth_take.status_code,
        unauth_take.get_json(),
    )

    register_rider(rider_client, "rider_chen", "rider123", "device-rider-chen")
    first_take = post_json(rider_client, "/take_order", {"order_id": order_id})
    second_take = post_json(rider_client, "/take_order", {"order_id": order_id})
    print_case(
        "first_take_order",
        "200 because the logged-in rider takes an unassigned created order",
        first_take.status_code,
        first_take.get_json(),
    )
    print_case(
        "duplicate_take_order",
        "400 because the order has already been taken",
        second_take.status_code,
        second_take.get_json(),
    )

    # 5. Admin API before login.
    resp = admin_client.get(f"/admin/messages/{order_id}")
    print_case(
        "admin_api_without_login",
        "403 because admin session is required",
        resp.status_code,
        resp.get_json(),
    )

    # 6. Admin login and hash-only message view.
    admin_login = post_json(admin_client, "/admin/login", {"username": "admin", "password": "admin123456"})
    print_case(
        "admin_login_default_demo_account",
        "200 in local demo; startup warns if default credentials are still used",
        admin_login.status_code,
        admin_login.get_json(),
    )

    from project.server.app import create_merkle_snapshot, save_message
    from project.crypto.merkle import hash_message
    from project.crypto.sm_utils import sm4_encrypt

    owner = db.query_one("SELECT pid FROM users WHERE username = ?", ("alice",))
    timestamp = "2026-07-02T12:00:00"
    msg_hash = hash_message(order_id, owner["pid"], "user", "normal delivery message", timestamp)
    save_message(str(uuid.uuid4()), order_id, owner["pid"], "user", "normal delivery message", msg_hash, timestamp)
    with app.app_context():
        create_merkle_snapshot(order_id)

    resp = admin_client.get(f"/admin/messages/{order_id}")
    body = resp.get_json()
    has_plaintext = bool(body.get("data") and "content" in body["data"][0])
    print_case(
        "admin_hash_only_messages",
        "200 and no content field because admin sees hash-only audit metadata",
        resp.status_code,
        {"success": body.get("success"), "message": body.get("message"), "contains_content_field": has_plaintext},
    )

    # 7. Database tampering detection: change encrypted content without updating stored hash.
    db.execute(
        "UPDATE messages SET content = ? WHERE order_id = ?",
        (sm4_encrypt("tampered database content"), order_id),
    )
    resp = admin_client.post(f"/admin/verify/{order_id}")
    verify_body = resp.get_json()
    data = verify_body.get("data", {})
    print_case(
        "tamper_detection",
        "VERIFY_FAIL with hash_mismatch_count > 0 after direct DB content modification",
        resp.status_code,
        {
            "success": verify_body.get("success"),
            "message": verify_body.get("message"),
            "hash_mismatch_count": data.get("hash_mismatch_count"),
            "root_match": data.get("root_match"),
        },
    )

    # 8. Plaintext keyword trace is blocked by privacy policy.
    resp = post_json(admin_client, "/admin/trace_violation", {"order_id": order_id, "reason": "keyword scan"})
    print_case(
        "plaintext_keyword_trace_blocked",
        "403 because admin plaintext keyword scanning is disabled",
        resp.status_code,
        resp.get_json(),
    )


def main():
    parser = argparse.ArgumentParser(description="Run FoodShield attack/defense demo.")
    parser.add_argument("--db-path", default=None, help="Optional SQLite path. Defaults to /tmp isolated DB.")
    args = parser.parse_args()
    run_attack_demo(args.db_path)


if __name__ == "__main__":
    main()
