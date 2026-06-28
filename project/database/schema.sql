CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    pid TEXT NOT NULL UNIQUE,
    pid_r TEXT,
    password_hash TEXT NOT NULL DEFAULT '',
    salt TEXT NOT NULL DEFAULT '',
    device_fingerprint TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL,
    token TEXT,
    token_timestamp TEXT,
    remark TEXT NOT NULL DEFAULT '',
    tag TEXT NOT NULL DEFAULT '',
    delivery_note TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'created'
        CHECK (status IN ('created', 'taken', 'delivering', 'completed', 'cancelled')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    msg_id TEXT NOT NULL UNIQUE,
    order_id TEXT NOT NULL,
    sender_pid TEXT NOT NULL,
    role TEXT NOT NULL
        CHECK (role IN ('user', 'rider', 'admin', 'system')),
    content TEXT NOT NULL,
    message_hash TEXT,
    timestamp TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (order_id) REFERENCES orders(order_id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id TEXT,
    action TEXT NOT NULL,
    detail TEXT,
    merkle_root TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);