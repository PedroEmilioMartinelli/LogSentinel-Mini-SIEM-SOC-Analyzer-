from db import get_db_connection

blocked_ips = set()  # cache em memória, sincronizado com o banco

def block_ip(ip):
    if ip not in blocked_ips:
        blocked_ips.add(ip)
        conn = get_db_connection()
        conn.execute("INSERT OR IGNORE INTO blocked_ips (ip) VALUES (?)", (ip,))
        conn.commit()
        conn.close()
        print(f"[BLOCKED] IP {ip} foi bloqueado")

def is_blocked(ip):
    conn = get_db_connection()
    row = conn.execute("SELECT 1 FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
    conn.close()
    return row is not None  # sempre lê do banco, nunca do set

def unblock_all():
    blocked_ips.clear()
    conn = get_db_connection()
    conn.execute("DELETE FROM blocked_ips")
    conn.commit()
    conn.close()
    print("[BLOCKLIST] Todos os IPs desbloqueados")