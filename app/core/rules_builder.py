"""
Genera el archivo iptables-restore desde la configuración JSON.
Produce un archivo .v4 listo para: iptables-restore < project_m.rules.v4
"""

from datetime import datetime
from app.constants import (
    IPTABLES_CHAIN_REJECT, IPTABLES_LOG_PREFIX, IPTABLES_LOG_LIMIT,
    IPTABLES_LOG_LEVEL, CHAIN_WEBBLOCK, CHAIN_MACBLOCK,
    CHAIN_CONNLIMIT, CHAIN_CLISRV, APP_NAME, APP_VERSION,
    WEB_BLOCK_PORTS, WEB_BLOCK_UDP_PORTS,
)


def build_rules(config: dict, resolved_ips: dict[str, list[str]]) -> str:
    """
    config: dict de configuración
    resolved_ips: {"facebook": ["157.240.0.1", ...], "youtube": [...], "hotmail": [...]}
    Retorna el contenido del archivo .rules.v4
    """
    lines = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines += [
        f"# {APP_NAME} v{APP_VERSION} — Archivo de reglas personalizado",
        f"# Generado: {now}",
        f"# NO EDITAR MANUALMENTE — generado por la aplicación",
        f"# Cargar con: iptables-restore < project_m.rules.v4",
        "",
        "*filter",
        f":{CHAIN_WEBBLOCK} - [0:0]",
        f":{CHAIN_MACBLOCK} - [0:0]",
        f":{CHAIN_CONNLIMIT} - [0:0]",
        f":{CHAIN_CLISRV} - [0:0]",
        f":{IPTABLES_CHAIN_REJECT} - [0:0]",
        ":INPUT ACCEPT [0:0]",
        ":FORWARD ACCEPT [0:0]",
        ":OUTPUT ACCEPT [0:0]",
        "",
    ]

    # === Cadena PM_REJECT: LOG + DROP ===
    lines += [
        f"# --- Cadena {IPTABLES_CHAIN_REJECT}: registra y rechaza ---",
        f"-A {IPTABLES_CHAIN_REJECT} -m limit --limit {IPTABLES_LOG_LIMIT} --limit-burst 10 "
        f"-j LOG --log-prefix \"{IPTABLES_LOG_PREFIX}\" --log-level {IPTABLES_LOG_LEVEL}",
        f"-A {IPTABLES_CHAIN_REJECT} -j {config.get('default_action', 'DROP')}",
        "",
    ]

    # === Bloqueo MAC ===
    mac_rules = config.get("mac_rules", [])
    if mac_rules:
        lines.append(f"# --- Cadena {CHAIN_MACBLOCK}: bloqueo por MAC ---")
        for rule in mac_rules:
            if not rule.get("enabled", False):
                continue
            mac = rule.get("mac", "")
            iface = rule.get("interface", "")
            name = rule.get("name", "desconocido")
            if not mac:
                continue
            iface_flag = f"-i {iface} " if iface else ""
            lines.append(f"# MAC: {name}")
            lines.append(
                f"-A {CHAIN_MACBLOCK} {iface_flag}-m mac --mac-source {mac} "
                f"-j {IPTABLES_CHAIN_REJECT}"
            )
        lines.append("")

    # === connlimit ===
    conn_profiles = config.get("conn_profiles", [])
    if conn_profiles:
        lines.append(f"# --- Cadena {CHAIN_CONNLIMIT}: límite de conexiones ---")
        for p in conn_profiles:
            if not p.get("enabled", False):
                continue
            port = p.get("port", 0)
            proto = p.get("proto", "tcp")
            max_conn = p.get("max", 10)
            action = p.get("action", "REJECT")
            name = p.get("name", "")
            if port <= 0:
                continue
            reject_flag = "--reject-with tcp-reset" if action == "REJECT" and proto == "tcp" else ""
            target = f"REJECT {reject_flag}".strip() if action == "REJECT" else "DROP"
            lines.append(f"# connlimit: {name}")
            lines.append(
                f"-A {CHAIN_CONNLIMIT} -p {proto} --dport {port} "
                f"-m connlimit --connlimit-above {max_conn} --connlimit-mask 32 "
                f"-j {target}"
            )
        lines.append("")

    # === Cliente → Servidor (bloqueo unidireccional) ===
    clisrv = config.get("clisrv", {})
    if clisrv.get("enabled", False):
        srv = clisrv.get("server_ip", "")
        cli = clisrv.get("client_ip", "")
        iface = clisrv.get("interface", "")
        action = clisrv.get("action", "DROP")
        protocols = clisrv.get("protocols", ["tcp", "udp", "icmp"])
        if srv and cli:
            lines.append(f"# --- Cadena {CHAIN_CLISRV}: bloqueo cliente→servidor ---")
            iface_flag = f"-i {iface} " if iface else ""
            # Permitir ESTABLISHED/RELATED primero (respuestas del cliente al servidor sí)
            lines.append(
                f"-A {CHAIN_CLISRV} {iface_flag}-s {cli} -d {srv} "
                f"-m state --state ESTABLISHED,RELATED -j ACCEPT"
            )
            for proto in protocols:
                proto_flag = f"-p {proto} " if proto != "all" else ""
                lines.append(
                    f"-A {CHAIN_CLISRV} {iface_flag}{proto_flag}-s {cli} -d {srv} "
                    f"-m state --state NEW -j {IPTABLES_CHAIN_REJECT}"
                )
            lines.append("")

    # === Bloqueo sitios web ===
    blocked_domains = config.get("blocked_domains", {})
    if blocked_domains and resolved_ips:
        lines.append(f"# --- Cadena {CHAIN_WEBBLOCK}: bloqueo por IP de dominios ---")
        for key, domain_cfg in blocked_domains.items():
            if not domain_cfg.get("enabled", False):
                continue
            label = domain_cfg.get("label", key)
            ips = resolved_ips.get(key, [])
            if not ips:
                continue
            lines.append(f"# {label} ({len(ips)} IPs resueltas)")
            for ip in ips:
                for port in WEB_BLOCK_PORTS:
                    lines.append(
                        f"-A {CHAIN_WEBBLOCK} -p tcp -d {ip} --dport {port} "
                        f"-j {IPTABLES_CHAIN_REJECT}"
                    )
                for port in WEB_BLOCK_UDP_PORTS:
                    lines.append(
                        f"-A {CHAIN_WEBBLOCK} -p udp -d {ip} --dport {port} "
                        f"-j {IPTABLES_CHAIN_REJECT}"
                    )
        lines.append("")

    # === Saltos desde FORWARD hacia las cadenas personalizadas ===
    lan = config.get("interfaces", {}).get("lan", "")
    iface_in = f"-i {lan} " if lan else ""
    iface_out = f"-o {lan} " if lan else ""

    lines += [
        "# --- Saltos FORWARD → cadenas personalizadas ---",
        f"-A FORWARD {iface_in}-j {CHAIN_MACBLOCK}",
        f"-A FORWARD {iface_in}-j {CHAIN_CONNLIMIT}",
        f"-A FORWARD {iface_in}-j {CHAIN_CLISRV}",
        f"-A FORWARD {iface_in}-j {CHAIN_WEBBLOCK}",
        "",
        "COMMIT",
        "",
    ]

    return "\n".join(lines)


def get_rule_count(rules_content: str) -> int:
    """Cuenta reglas activas (líneas -A)."""
    return sum(1 for line in rules_content.splitlines() if line.strip().startswith("-A"))
