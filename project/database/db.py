import sqlite3
import sys
from pathlib import Path


def _get_base_dir():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent.parent


BASE_DIR = _get_base_dir()
DB_PATH = BASE_DIR / "foodshield.db"


def _get_schema_path():
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "project" / "database" / "schema.sql"
    return BASE_DIR / "project" / "database" / "schema.sql"


SCHEMA_PATH = _get_schema_path()


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()
    print("Database initialized successfully.")


def query_all(sql, params=()):
    conn = get_db_connection()
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return rows


def query_one(sql, params=()):
    conn = get_db_connection()
    row = conn.execute(sql, params).fetchone()
    conn.close()
    return row


def execute(sql, params=()):
    conn = get_db_connection()
    cursor = conn.execute(sql, params)
    conn.commit()
    lastrowid = cursor.lastrowid
    conn.close()
    return lastrowid