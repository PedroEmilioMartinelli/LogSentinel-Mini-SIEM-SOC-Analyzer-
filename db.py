import sqlite3

conn = sqlite3.connect("soc.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert TEXT,
    ip TEXT,
    details TEXT,
    timestamp TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS blocked_ips (
    ip TEXT PRIMARY KEY
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
)
""")

# NOVO: tabela de tentativas falhas
cursor.execute("""
CREATE TABLE IF NOT EXISTS login_failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    ip TEXT NOT NULL,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP
)
""")

conn.commit()


def get_db_connection():
    return sqlite3.connect("soc.db", check_same_thread=False)


# ── Alertas ──────────────────────────────────────────────────────────────────

def insert_alert(alert):
    cursor.execute("""
        INSERT INTO alerts (alert, ip, details, timestamp)
        VALUES (?, ?, ?, ?)
    """, (alert.get("alert"), alert.get("ip"), str(alert), str(alert.get("timestamp"))))
    conn.commit()

def get_alerts():
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC")
    return cursor.fetchall()


# ── Usuários ─────────────────────────────────────────────────────────────────

def create_user(username, hashed_password):
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def get_user(username):
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()

def update_password(username, new_hashed_password):
    cursor.execute("UPDATE users SET password = ? WHERE username = ?", (new_hashed_password, username))
    conn.commit()
    return cursor.rowcount > 0


# ── Tentativas de login falhas ────────────────────────────────────────────────

def insert_login_failure(username, ip):
    """Registra uma tentativa de login falha."""
    cursor.execute("INSERT INTO login_failures (username, ip) VALUES (?, ?)", (username, ip))
    conn.commit()

def get_login_failures():
    """Retorna as últimas 200 tentativas falhas."""
    cursor.execute("SELECT id, username, ip, timestamp FROM login_failures ORDER BY id DESC LIMIT 200")
    return cursor.fetchall()

def count_recent_failures(key_type, key_value, seconds=30):
    """Conta falhas recentes para um IP ou username nos últimos N segundos."""
    if key_type not in ("ip", "username"):
        raise ValueError("key_type deve ser 'ip' ou 'username'")
    cursor.execute(f"""
        SELECT COUNT(*) FROM login_failures
        WHERE {key_type} = ?
          AND datetime(timestamp) >= datetime('now', '-{seconds} seconds')
    """, (key_value,))
    row = cursor.fetchone()
    
    return row[0] if row else 0