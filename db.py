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

conn.commit()

def get_db_connection():
    return sqlite3.connect("soc.db", check_same_thread=False)

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