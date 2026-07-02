"""
FoodShield performance benchmark.

Runs against an isolated SQLite database under /tmp by default, so the demo
database in the repository is not modified.
"""

from __future__ import annotations

import argparse
import statistics
import tempfile
import time
import uuid
from pathlib import Path

from project.database import db


def configure_temp_database(path: str | None) -> Path:
    if path:
        db_path = Path(path).expanduser().resolve()
    else:
        db_path = Path(tempfile.gettempdir()) / f"foodshield_perf_{uuid.uuid4().hex}.db"
    db.DB_PATH = db_path
    db.init_db()
    return db_path


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round((pct / 100) * (len(ordered) - 1))))
    return ordered[index]


def timed(fn):
    start = time.perf_counter()
    result = fn()
    return result, time.perf_counter() - start


def run_benchmark(users: int, orders_per_user: int, messages_per_order: int, db_path: str | None):
    db_file = configure_temp_database(db_path)

    # Import app helpers after DB_PATH is redirected.
    from project.server.app import (
        app,
        create_merkle_snapshot,
        ensure_schema_migrations,
        save_message,
        verify_order_integrity,
    )
    from project.crypto.merkle import hash_message
    from project.crypto.pid import generate_pid
    from project.crypto.token_utils import generate_token, verify_token
    from project.crypto.sm_utils import sm4_decrypt, sm4_encrypt

    with app.app_context():
        ensure_schema_migrations()

        user_ids = []
        for idx in range(users):
            pid = generate_pid(app.config["MASTER_KEY"], f"perf-user-{idx}")["pid"]
            user_id = db.execute(
                """
                INSERT INTO users (username, pid, password_hash, salt, device_fingerprint)
                VALUES (?, ?, ?, ?, ?)
                """,
                (f"perf_user_{idx}", pid, "perf_hash", "perf_salt", f"perf_fp_{idx}"),
            )
            user_ids.append((user_id, pid))

        rider_ids = []
        for idx in range(max(1, users)):
            rider_pid = generate_pid(app.config["MASTER_KEY"], f"perf-rider-{idx}")["pid"]
            rider_id = db.execute(
                """
                INSERT INTO riders (username, rider_pid, password_hash, salt, device_fingerprint)
                VALUES (?, ?, ?, ?, ?)
                """,
                (f"perf_rider_{idx}", rider_pid, "perf_hash", "perf_salt", f"perf_rider_fp_{idx}"),
            )
            rider_ids.append((rider_id, rider_pid))

        token_times = []
        token_verify_times = []
        sm4_roundtrip_times = []
        message_write_times = []
        snapshot_times = []
        verify_times = []

        order_count = 0
        message_count = 0

        for user_index, (user_id, pid) in enumerate(user_ids):
            rider_id, rider_pid = rider_ids[user_index % len(rider_ids)]
            for _ in range(orders_per_user):
                order_id = str(uuid.uuid4())
                token_data, token_elapsed = timed(lambda: generate_token(order_id, pid))
                token_times.append(token_elapsed)

                _, token_verify_elapsed = timed(
                    lambda: verify_token(order_id, pid, token_data["timestamp"], token_data["token"])
                )
                token_verify_times.append(token_verify_elapsed)

                db.execute(
                    """
                    INSERT INTO orders (order_id, user_id, rider_id, token, token_timestamp, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (order_id, user_id, rider_id, token_data["token"], token_data["timestamp"], "taken"),
                )
                order_count += 1

                for msg_index in range(messages_per_order):
                    role = "user" if msg_index % 2 == 0 else "rider"
                    sender_pid = pid if role == "user" else rider_pid
                    content = f"benchmark message {msg_index} for {order_id}"
                    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")
                    msg_hash = hash_message(order_id, sender_pid, role, content, timestamp)
                    msg_id = str(uuid.uuid4())

                    _, sm4_elapsed = timed(lambda: sm4_decrypt(sm4_encrypt(content)))
                    sm4_roundtrip_times.append(sm4_elapsed)

                    _, write_elapsed = timed(
                        lambda: save_message(msg_id, order_id, sender_pid, role, content, msg_hash, timestamp)
                    )
                    message_write_times.append(write_elapsed)
                    message_count += 1

                _, snapshot_elapsed = timed(lambda: create_merkle_snapshot(order_id))
                snapshot_times.append(snapshot_elapsed)

                _, verify_elapsed = timed(lambda: verify_order_integrity(order_id))
                verify_times.append(verify_elapsed)

        def stat_line(name: str, values: list[float]) -> str:
            ms = [value * 1000 for value in values]
            return (
                f"{name:<24} count={len(ms):<6} "
                f"avg={statistics.mean(ms):>8.3f}ms "
                f"p95={percentile(ms, 95):>8.3f}ms "
                f"max={max(ms):>8.3f}ms"
            )

        print("FoodShield performance benchmark")
        print(f"database: {db_file}")
        print(f"users={users}, riders={len(rider_ids)}, orders={order_count}, messages={message_count}")
        print(stat_line("token_generate", token_times))
        print(stat_line("token_verify", token_verify_times))
        print(stat_line("sm4_roundtrip", sm4_roundtrip_times))
        print(stat_line("message_write", message_write_times))
        print(stat_line("merkle_snapshot", snapshot_times))
        print(stat_line("integrity_verify", verify_times))


def main():
    parser = argparse.ArgumentParser(description="Run FoodShield local performance benchmark.")
    parser.add_argument("--users", type=int, default=10)
    parser.add_argument("--orders-per-user", type=int, default=5)
    parser.add_argument("--messages-per-order", type=int, default=20)
    parser.add_argument("--db-path", default=None, help="Optional SQLite path. Defaults to /tmp isolated DB.")
    args = parser.parse_args()
    run_benchmark(args.users, args.orders_per_user, args.messages_per_order, args.db_path)


if __name__ == "__main__":
    main()
