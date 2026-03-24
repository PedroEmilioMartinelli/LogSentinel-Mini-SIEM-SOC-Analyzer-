import sqlite3

conn = sqlite3.connect("soc.db", check_same_thread=False)
cursor = conn.cursor()

# Tabela de alertas (já existia)
cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert TEXT,
    ip TEXT,
    details TEXT,
    timestamp TEXT
)
""")

# Tabela de IPs bloqueados (já existia)
cursor.execute("""
CREATE TABLE IF NOT EXISTS blocked_ips (
    ip TEXT PRIMARY KEY
)
""")

# Tabela de usuários — substitui o output/users.json
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
)
""")

conn.commit()


def get_db_connection():
    return sqlite3.connect("soc.db", check_same_thread=False)


# ── Alertas ─────────────────────────────────────────────────────────────────

def insert_alert(alert):
    cursor.execute("""
        INSERT INTO alerts (alert, ip, details, timestamp)
        VALUES (?, ?, ?, ?)
    """, (
        alert.get("alert"),
        alert.get("ip"),
        str(alert),
        str(alert.get("timestamp"))
    ))
    conn.commit()


def get_alerts():
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC")
    return cursor.fetchall()


# ── Usuários ─────────────────────────────────────────────────────────────────

def create_user(username, hashed_password):
    """Cria um novo usuário. Retorna True em sucesso, False se o username já existe."""
    try:
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hashed_password)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # username duplicado


def get_user(username):
    """Retorna a linha do usuário ou None se não existir.
    Formato: (id, username, password, created_at)
    """
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()


def update_password(username, new_hashed_password):
    """Atualiza a senha de um usuário. Retorna True se encontrou e atualizou."""
    cursor.execute(
        "UPDATE users SET password = ? WHERE username = ?",
        (new_hashed_password, username)
    )
    conn.commit()
    return cursor.rowcount > 0