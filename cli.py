"""
cli.py — LogSentinel Mini SIEM
================================
Interface de linha de comando do projeto.

Uso:
  python cli.py                    # analisa logs e gera alertas (comportamento original)
  sudo python cli.py block   <ip>  # bloqueia IP no firewall do SO
  sudo python cli.py unblock <ip>  # remove bloqueio do IP
  sudo python cli.py list          # lista IPs bloqueados
  sudo python cli.py sync          # re-aplica bloqueios após reboot
  sudo python cli.py flush         # remove TODOS os bloqueios do LogSentinel
"""

import sys

from core.parser import LogParser
from core.detector import Detector
from core.correlator import Correlator
from utils.helpers import save_alerts
from os_blocker import block_ip, unblock_ip, list_blocked, flush_all, sync_from_db

# ---------------------------------------------------------------------------
# Comandos de bloqueio OS
# ---------------------------------------------------------------------------

def cmd_block(ip: str) -> None:
    success = block_ip(ip)
    if success:
        print(f"[+] IP {ip} bloqueado no firewall do SO.")
    else:
        print(f"[-] Não foi possível bloquear {ip}. Verifique os logs.")


def cmd_unblock(ip: str) -> None:
    success = unblock_ip(ip)
    if success:
        print(f"[+] IP {ip} desbloqueado.")
    else:
        print(f"[-] Não foi possível desbloquear {ip}. Verifique os logs.")


def cmd_list() -> None:
    ips = list_blocked()
    if ips:
        print(f"\n{'IP':<20} Status")
        print("-" * 32)
        for ip in ips:
            print(f"{ip:<20} BLOQUEADO")
        print(f"\nTotal: {len(ips)} IP(s) bloqueado(s).")
    else:
        print("[*] Nenhum IP bloqueado pelo LogSentinel no momento.")


def cmd_sync() -> None:
    count = sync_from_db()
    print(f"[+] Sync concluído: {count} IP(s) re-bloqueado(s) a partir do banco.")


def cmd_flush() -> None:
    confirm = input("[!] Tem certeza que deseja remover TODOS os bloqueios? [s/N] ")
    if confirm.lower() == "s":
        count = flush_all()
        print(f"[+] {count} IP(s) desbloqueado(s).")
    else:
        print("[*] Operação cancelada.")

# ---------------------------------------------------------------------------
# Análise de logs (comportamento original)
# ---------------------------------------------------------------------------

def cmd_analyze() -> None:
    print("[+] Iniciando análise...")

    parser = LogParser()
    detector = Detector()
    correlator = Correlator()

    alerts = []

    with open("logs/auth.log") as f:
        for line in f:
            event = parser.parse_auth(line) or parser.parse_web(line)
            if event:
                alerts += detector.process(event)
                alerts += correlator.correlate(event)

    save_alerts(alerts)
    print(f"[+] Finalizado. Alertas gerados: {len(alerts)}")

# ---------------------------------------------------------------------------
# Roteador de comandos
# ---------------------------------------------------------------------------

def print_help() -> None:
    print("""
Uso: python cli.py [comando] [args]

Comandos disponíveis:
  (sem argumento)      Analisa logs/auth.log e gera alertas
  block   <ip>         Bloqueia IP no firewall do SO  (requer sudo)
  unblock <ip>         Remove bloqueio do IP          (requer sudo)
  list                 Lista IPs bloqueados            (requer sudo)
  sync                 Re-aplica bloqueios do banco    (requer sudo)
  flush                Remove todos os bloqueios       (requer sudo)
  help                 Exibe esta mensagem
""")


if __name__ == "__main__":
    args = sys.argv[1:]

    if not args:
        cmd_analyze()

    elif args[0] in ("help", "--help", "-h"):
        print_help()

    elif args[0] == "block":
        if len(args) < 2:
            print("Erro: informe o IP. Ex: sudo python cli.py block 192.168.1.5")
            sys.exit(1)
        cmd_block(args[1])

    elif args[0] == "unblock":
        if len(args) < 2:
            print("Erro: informe o IP. Ex: sudo python cli.py unblock 192.168.1.5")
            sys.exit(1)
        cmd_unblock(args[1])

    elif args[0] == "list":
        cmd_list()

    elif args[0] == "sync":
        cmd_sync()

    elif args[0] == "flush":
        cmd_flush()

    else:
        print(f"Comando desconhecido: '{args[0]}'")
        print_help()
        sys.exit(1)