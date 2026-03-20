import subprocess
import sys
import os
import sqlite3
import logging
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------

DB_PATH = Path(__file__).parent / "soc.db"

IPTABLES_COMMENT = "LogSentinel"

# "auto" detecta automaticamente iptables ou ufw
BACKEND = "auto"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [OS_BLOCKER] %(levelname)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("os_blocker")

# ---------------------------------------------------------------------------
# Detecção de backend
# ---------------------------------------------------------------------------

def _cmd_exists(cmd: str) -> bool:
    return subprocess.run(["which", cmd], capture_output=True).returncode == 0


def detect_backend() -> str:
    if BACKEND != "auto":
        return BACKEND
    if _cmd_exists("ufw"):
        return "ufw"
    if _cmd_exists("iptables"):
        return "iptables"
    raise EnvironmentError(
        "Nenhum backend de firewall encontrado. "
        "Instale iptables ou ufw e tente novamente."
    )

# ---------------------------------------------------------------------------
# Verificações de ambiente
# ---------------------------------------------------------------------------

def is_root() -> bool:
    """Retorna True se estiver rodando como root."""
    return os.geteuid() == 0


def check_root() -> None:
    """Loga aviso se não for root, mas NÃO encerra o programa."""
    if not is_root():
        log.warning("OS_BLOCKER: sem permissão de root — bloqueio no SO desativado.")


def validate_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False

# ---------------------------------------------------------------------------
# Backend: iptables
# ---------------------------------------------------------------------------

def _iptables_is_blocked(ip: str) -> bool:
    result = subprocess.run(
        ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True
    )
    return result.returncode == 0


def _iptables_block(ip: str) -> bool:
    if _iptables_is_blocked(ip):
        log.warning(f"[iptables] IP {ip} já está bloqueado.")
        return False

    result = subprocess.run(
        [
            "iptables", "-I", "INPUT", "1",
            "-s", ip,
            "-j", "DROP",
            "-m", "comment", "--comment", IPTABLES_COMMENT
        ],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        log.info(f"[iptables] IP {ip} BLOQUEADO com sucesso.")
        return True
    else:
        log.error(f"[iptables] Falha ao bloquear {ip}: {result.stderr.strip()}")
        return False


def _iptables_unblock(ip: str) -> bool:
    if not _iptables_is_blocked(ip):
        log.warning(f"[iptables] IP {ip} não estava bloqueado.")
        return False

    result = subprocess.run(
        ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        log.info(f"[iptables] IP {ip} DESBLOQUEADO.")
        return True
    else:
        log.error(f"[iptables] Falha ao desbloquear {ip}: {result.stderr.strip()}")
        return False


def _iptables_list_blocked() -> list[str]:
    result = subprocess.run(
        ["iptables", "-L", "INPUT", "-n", "--line-numbers"],
        capture_output=True, text=True
    )
    ips = []
    for line in result.stdout.splitlines():
        if IPTABLES_COMMENT in line and "DROP" in line:
            parts = line.split()
            for part in parts:
                if validate_ip(part):
                    ips.append(part)
                    break
    return ips


def _iptables_flush() -> int:
    blocked = _iptables_list_blocked()
    count = 0
    for ip in blocked:
        if _iptables_unblock(ip):
            count += 1
    return count

# ---------------------------------------------------------------------------
# Backend: ufw
# ---------------------------------------------------------------------------

def _ufw_is_blocked(ip: str) -> bool:
    result = subprocess.run(["ufw", "status"], capture_output=True, text=True)
    return ip in result.stdout and "DENY" in result.stdout


def _ufw_block(ip: str) -> bool:
    if _ufw_is_blocked(ip):
        log.warning(f"[ufw] IP {ip} já está bloqueado.")
        return False

    result = subprocess.run(
        ["ufw", "deny", "from", ip, "to", "any"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        log.info(f"[ufw] IP {ip} BLOQUEADO com sucesso.")
        return True
    else:
        log.error(f"[ufw] Falha ao bloquear {ip}: {result.stderr.strip()}")
        return False


def _ufw_unblock(ip: str) -> bool:
    if not _ufw_is_blocked(ip):
        log.warning(f"[ufw] IP {ip} não estava bloqueado.")
        return False

    result = subprocess.run(
        ["ufw", "delete", "deny", "from", ip, "to", "any"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        log.info(f"[ufw] IP {ip} DESBLOQUEADO.")
        return True
    else:
        log.error(f"[ufw] Falha ao desbloquear {ip}: {result.stderr.strip()}")
        return False


def _ufw_list_blocked() -> list[str]:
    result = subprocess.run(["ufw", "status"], capture_output=True, text=True)
    ips = []
    for line in result.stdout.splitlines():
        if "DENY" in line:
            parts = line.split()
            for part in parts:
                if validate_ip(part):
                    ips.append(part)
                    break
    return ips


def _ufw_flush() -> int:
    blocked = _ufw_list_blocked()
    count = 0
    for ip in blocked:
        if _ufw_unblock(ip):
            count += 1
    return count

# ---------------------------------------------------------------------------
# Interface pública (agnóstica de backend)
# ---------------------------------------------------------------------------

def block_ip(ip: str) -> bool:
    """Bloqueia um IP no firewall do SO e registra no banco."""
    if not is_root():
        log.warning(f"Sem root — bloqueio de SO ignorado para {ip}.")
        return False

    if not validate_ip(ip):
        log.error(f"IP inválido: {ip}")
        return False

    try:
        backend = detect_backend()
        log.info(f"Backend detectado: {backend}")

        if backend == "iptables":
            success = _iptables_block(ip)
        else:
            success = _ufw_block(ip)

        if success:
            _db_register_block(ip, backend, action="block")

        return success
    except Exception as e:
        log.warning(f"Erro ao bloquear IP {ip} no SO: {e}")
        return False


def unblock_ip(ip: str) -> bool:
    """Remove o bloqueio de um IP e atualiza o banco."""
    if not is_root():
        log.warning(f"Sem root — desbloqueio de SO ignorado para {ip}.")
        return False

    if not validate_ip(ip):
        log.error(f"IP inválido: {ip}")
        return False

    try:
        backend = detect_backend()

        if backend == "iptables":
            success = _iptables_unblock(ip)
        else:
            success = _ufw_unblock(ip)

        if success:
            _db_register_block(ip, backend, action="unblock")

        return success
    except Exception as e:
        log.warning(f"Erro ao desbloquear IP {ip} no SO: {e}")
        return False


def list_blocked() -> list[str]:
    """Retorna lista de IPs bloqueados. Retorna [] se não tiver permissão."""
    if not is_root():
        return []

    try:
        backend = detect_backend()
        if backend == "iptables":
            return _iptables_list_blocked()
        return _ufw_list_blocked()
    except Exception as e:
        log.warning(f"Erro ao listar IPs bloqueados: {e}")
        return []


def flush_all() -> int:
    """Remove TODOS os bloqueios aplicados pelo LogSentinel."""
    if not is_root():
        log.warning("Sem root — flush ignorado.")
        return 0

    try:
        backend = detect_backend()
        log.warning("Removendo TODOS os bloqueios do LogSentinel...")
        if backend == "iptables":
            count = _iptables_flush()
        else:
            count = _ufw_flush()
        log.info(f"{count} IP(s) desbloqueado(s).")
        return count
    except Exception as e:
        log.warning(f"Erro ao fazer flush: {e}")
        return 0


def sync_from_db() -> int:
    """Re-aplica todos os bloqueios registrados no banco (útil após reboot)."""
    if not is_root():
        log.warning("Sem root — sync ignorado.")
        return 0

    try:
        ips = _db_get_blocked_ips()
        count = 0
        for ip in ips:
            if block_ip(ip):
                count += 1
        log.info(f"Sync concluído: {count} IP(s) re-bloqueado(s).")
        return count
    except Exception as e:
        log.warning(f"Erro ao sincronizar banco: {e}")
        return 0

# ---------------------------------------------------------------------------
# Integração com banco SQLite
# ---------------------------------------------------------------------------

def _get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    _ensure_table(conn)
    return conn


def _ensure_table(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS os_blocks (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ip        TEXT    NOT NULL,
            backend   TEXT    NOT NULL,
            action    TEXT    NOT NULL CHECK(action IN ('block', 'unblock')),
            timestamp TEXT    NOT NULL
        )
    """)
    conn.commit()


def _db_register_block(ip: str, backend: str, action: str) -> None:
    try:
        conn = _get_db()
        conn.execute(
            "INSERT INTO os_blocks (ip, backend, action, timestamp) VALUES (?, ?, ?, ?)",
            (ip, backend, action, datetime.utcnow().isoformat())
        )
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning(f"Não foi possível registrar no banco: {e}")


def _db_get_blocked_ips() -> list[str]:
    try:
        conn = _get_db()
        rows = conn.execute("""
            SELECT ip, action
            FROM os_blocks
            WHERE id IN (
                SELECT MAX(id) FROM os_blocks GROUP BY ip
            )
            AND action = 'block'
        """).fetchall()
        conn.close()
        return [row["ip"] for row in rows]
    except Exception as e:
        log.warning(f"Erro ao consultar banco: {e}")
        return []