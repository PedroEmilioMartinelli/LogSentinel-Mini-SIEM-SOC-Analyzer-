blocked_ips = set()

def block_ip(ip):
    if ip not in blocked_ips:
        blocked_ips.add(ip)
        print(f"[BLOCKED] IP {ip} foi bloqueado")

def is_blocked(ip):
    return ip in blocked_ips
