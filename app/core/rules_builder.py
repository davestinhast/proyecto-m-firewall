"""
Genera el archivo iptables-restore desde la configuración JSON.
Produce un archivo .v4 listo para: iptables-restore < project_m.rules.v4

Estrategia de bloqueo de sitios web:
  - Se usan ipset sets (PM_FACEBOOK, PM_YOUTUBE, PM_HOTMAIL) para IPs iniciales.
  - Se usa DNS Proxy local para retornar NXDOMAIN y bloquear resolución.
  - Se usa inspección de paquetes (SNI - Server Name Indication) en el puerto TCP 443
    para bloquear el inicio de la conexión HTTPS sin importar qué IP use el CDN.
"""

from datetime import datetime
from app.constants import (
    IPTABLES_CHAIN_REJECT, IPTABLES_LOG_PREFIX, IPTABLES_LOG_LIMIT,
    IPTABLES_LOG_LEVEL, CHAIN_WEBBLOCK, CHAIN_MACBLOCK,
    CHAIN_CONNLIMIT, CHAIN_CLISRV, APP_NAME, APP_VERSION,
    WEB_BLOCK_PORTS, IPSET_SET_PREFIX,
)


SNI_KEYWORDS = {
    "facebook": ["facebook.com", "fbcdn.net", "fb.com", "messenger.com", "fbsbx.com"],
    "youtube": [
        "youtube.com",
        "youtu.be",
        "googlevideo.com",
        "ytimg.com",
        "ggpht.com",
        "youtube-nocookie.com",
        "youtubei.googleapis.com",
        "youtube.googleapis.com",
        "youtube.l.google.com",
        "youtube-ui.l.google.com",
        "ytstatic.l.google.com",
    ],
    "hotmail": ["hotmail.com", "outlook.com", "live.com", "microsoftonline.com"],
}

DNS_KEYWORDS = {
    "facebook": ["facebook", "fbcdn", "fb.com", "messenger", "fbsbx"],
    "youtube": [
        "youtube",
        "youtu",
        "googlevideo",
        "ytimg",
        "ggpht",
        "youtube-nocookie",
        "youtubei",
        "ytstatic",
    ],
    "hotmail": ["hotmail", "outlook", "live.com", "microsoftonline"],
}


def build_rules(config: dict, resolved_ips: dict[str, list[str]]) -> str:
    """
    config: dict de configuración
    resolved_ips: {"facebook": ["157.240.0.1", ...], "youtube": [...], "hotmail": [...]}
    Retorna el contenido del archivo .rules.v4

    NOTA: Los sets de ipset (PM_FACEBOOK, PM_YOUTUBE, PM_HOTMAIL) deben haber sido
    cargados antes con: ipset restore < project_m.ipset
    Las reglas iptables de este archivo solo referencian los sets, no las IPs directamente.
    """
    lines = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    wan = config.get("interfaces", {}).get("wan", "")
    lan = config.get("interfaces", {}).get("lan", "")

    lines += [
        f"# {APP_NAME} v{APP_VERSION} — Archivo de reglas PERSONALIZADO",
        f"# Generado: {now}",
        f"# Guardado en: /opt/proyecto-m/rules/project_m.rules.v4",
        f"# (NO se usa /etc/sysconfig/iptables — rúbrica requiere archivo personalizado)",
        f"# Cargar con: iptables-restore < project_m.rules.v4",
        f"# IPs bloqueadas via ipset: ipset restore < project_m.ipset",
        "",
    ]

    # === Verificar si hay bloqueos de sitios activos ===
    blocked_domains = config.get("blocked_domains", {})
    has_webblock = any(v.get("enabled", False) for v in blocked_domains.values())

    # ── Tabla NAT: MASQUERADE y Redirección DNS ──────────────────────────────
    lines += [
        "*nat",
        ":PREROUTING ACCEPT [0:0]",
        ":INPUT ACCEPT [0:0]",
        ":OUTPUT ACCEPT [0:0]",
        ":POSTROUTING ACCEPT [0:0]",
    ]
    
    server_ip = config.get("server_ip", "")
    if has_webblock and server_ip:
        # Redirigir tráfico DNS (UDP/TCP 53) de clientes al proxy local en el puerto 10053
        lines.append(f"-A PREROUTING -p udp --dport 53 -j DNAT --to-destination {server_ip}:10053")
        lines.append(f"-A PREROUTING -p tcp --dport 53 -j DNAT --to-destination {server_ip}:10053")
        # Redirigir tráfico DNS de la propia máquina de Kali (excepto usuario root/la app)
        lines.append(f"-A OUTPUT -p udp --dport 53 -m owner ! --uid-owner 0 -j DNAT --to-destination 127.0.0.1:10053")
        lines.append(f"-A OUTPUT -p tcp --dport 53 -m owner ! --uid-owner 0 -j DNAT --to-destination 127.0.0.1:10053")

    if wan:
        lines.append(f"-A POSTROUTING -o {wan} -j MASQUERADE")
    else:
        lines.append("-A POSTROUTING -j MASQUERADE")
    lines += ["COMMIT", ""]

    # ── Tabla filter ────────────────────────────────────────────────────────────
    lines += [
        "*filter",
        f":{CHAIN_WEBBLOCK} - [0:0]",
        f":{CHAIN_MACBLOCK} - [0:0]",
        f":{CHAIN_CONNLIMIT} - [0:0]",
        f":{CHAIN_CLISRV} - [0:0]",
        ":PM_DNSBLOCK - [0:0]",
        f":{IPTABLES_CHAIN_REJECT} - [0:0]",
        ":INPUT ACCEPT [0:0]",
        ":FORWARD ACCEPT [0:0]",
        ":OUTPUT ACCEPT [0:0]",
        "",
    ]

    # === Cadena PM_REJECT: LOG + DROP ===
    lines += [
        f"# [Cadena {IPTABLES_CHAIN_REJECT}: registra y rechaza]",
        f"-A {IPTABLES_CHAIN_REJECT} -m limit --limit {IPTABLES_LOG_LIMIT} --limit-burst 10 "
        f"-j LOG --log-prefix \"{IPTABLES_LOG_PREFIX}\" --log-level {IPTABLES_LOG_LEVEL}",
        f"-A {IPTABLES_CHAIN_REJECT} -j {config.get('default_action', 'DROP')}",
        "",
    ]

    # === Bloqueo MAC ===
    mac_rules = config.get("mac_rules", [])
    if mac_rules:
        lines.append(f"# [Cadena {CHAIN_MACBLOCK}: bloqueo por MAC]")
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

    # === connlimit: límite de conexiones simultáneas ===
    conn_profiles = config.get("conn_profiles", [])
    if conn_profiles:
        lines.append(f"# [Cadena {CHAIN_CONNLIMIT}: límite de conexiones simultáneas]")
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
            lines.append(f"# connlimit: {name} (max {max_conn} conexiones en puerto {port}/{proto})")
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
            lines.append(f"# [Cadena {CHAIN_CLISRV}: bloqueo cliente-servidor]")
            iface_flag = f"-i {iface} " if iface else ""
            # Permitir respuestas ESTABLISHED del servidor hacia el cliente
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
    has_webblock = any(v.get("enabled", False) for v in blocked_domains.values())
    keywords = []  # inicializar aquí para evitar NameError si has_webblock es False
    if has_webblock:
        lines.append(f"# [Cadena {CHAIN_WEBBLOCK}: bloqueo por ipset]")
        lines.append("# Los sets PM_FACEBOOK, PM_YOUTUBE, PM_HOTMAIL se cargan con:")
        lines.append("# ipset restore < /opt/proyecto-m/rules/project_m.ipset")
        lines.append("")
        for key, domain_cfg in blocked_domains.items():
            if not domain_cfg.get("enabled", False):
                continue
            label = domain_cfg.get("label", key)
            set_name = f"{IPSET_SET_PREFIX}{key.upper()}"
            ip_count = len(resolved_ips.get(key, []))
            lines.append(f"# {label}: set {set_name} ({ip_count} IPs cargadas)")
            for port in WEB_BLOCK_PORTS:
                # Bloquear TCP
                lines.append(
                    f"-A {CHAIN_WEBBLOCK} -p tcp --dport {port} "
                    f"-m set --match-set {set_name} dst "
                    f"-j {IPTABLES_CHAIN_REJECT}"
                )
                # Bloquear UDP (Evita bypass con HTTP/3 / QUIC)
                lines.append(
                    f"-A {CHAIN_WEBBLOCK} -p udp --dport {port} "
                    f"-m set --match-set {set_name} dst "
                    f"-j {IPTABLES_CHAIN_REJECT}"
                )

            # BLOQUEO SNI (Server Name Indication) PARA HTTPS (TLS 1.2/1.3)
            # Esto bloquea la conexión incluso si el cliente tiene la IP cacheadada o usa DoH, 
            # ya que lee el dominio en texto plano durante el 'Client Hello' del protocolo TLS.
            sni_keywords = SNI_KEYWORDS.get(key, [])
            
            for kw in sni_keywords:
                lines.append(
                    f"-A {CHAIN_WEBBLOCK} -p tcp --dport 443 "
                    f"-m string --string \"{kw}\" --algo bm --to 65535 "
                    f"-j {IPTABLES_CHAIN_REJECT}"
                )

        # El bloqueo DNS inteligente se activa de forma AUTOMÁTICA para cualquier dominio que esté habilitado.
        # Así el usuario no tiene que activar casillas avanzadas complejas.
        if has_webblock:
            # Siempre bloquear servidores DNS seguros (DoH) y el dominio canario de Firefox (use-application-dns.net)
            # para forzar fallback a DNS estándar (puerto 53)
            keywords += ["dns.google", "cloudflare-dns", "dns.quad9", "use-application-dns.net"]
            
            # Agregar palabras clave según el sitio activado
            for key, domain_cfg in blocked_domains.items():
                if domain_cfg.get("enabled", False):
                    keywords += DNS_KEYWORDS.get(key, [])

        if keywords:
            lines.append("")
            lines.append("# [Reglas de Bloqueo DNS Agresivo (Filtro de Contenido)]")
            
            # Bloquear servidores DoH conocidos por IP para forzar fallback a DNS estándar en puerto 53
            # Bloqueamos IPs principales de Google, Cloudflare y Quad9 en el puerto 443 de salida
            doh_ips = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"]
            for ip in doh_ips:
                lines.append(f"-A {CHAIN_WEBBLOCK} -p tcp -d {ip} --dport 443 -j {IPTABLES_CHAIN_REJECT}")
            
            # Bloquear DNS-over-TLS (DoT) en el puerto 853 (TCP/UDP) para forzar fallback a DNS normal
            lines.append("# Bloqueo global de DoT (puerto 853) para forzar fallback a DNS normal")
            lines.append(f"-A {CHAIN_WEBBLOCK} -p tcp --dport 853 -j {IPTABLES_CHAIN_REJECT}")
            lines.append(f"-A {CHAIN_WEBBLOCK} -p udp --dport 853 -j {IPTABLES_CHAIN_REJECT}")

            # BLOQUEO DE QUIC (UDP 443): Obliga al navegador a usar TCP 443 (donde las reglas de IP actúan sí o sí)
            # Esto evita que YouTube se salte las reglas usando protocolos UDP rápidos de Google
            lines.append("# Bloqueo global de QUIC para forzar fallback a TCP")
            lines.append(f"-A {CHAIN_WEBBLOCK} -p udp --dport 443 -j {IPTABLES_CHAIN_REJECT}")
            
            # Eliminar duplicados
            keywords = list(set(keywords))
            for kw in keywords:
                # Bloquear consultas (dport 53) y respuestas (sport 53) en UDP en la cadena PM_DNSBLOCK
                # Duplicamos con algoritmo BM y KMP por compatibilidad según el kernel de Linux
                for algo in ["bm", "kmp"]:
                    lines.append(
                        f"-A PM_DNSBLOCK -p udp --dport 53 "
                        f"-m string --string \"{kw}\" --algo {algo} "
                        f"-j {IPTABLES_CHAIN_REJECT}"
                    )
                    lines.append(
                        f"-A PM_DNSBLOCK -p udp --sport 53 "
                        f"-m string --string \"{kw}\" --algo {algo} "
                        f"-j {IPTABLES_CHAIN_REJECT}"
                    )
                    # Bloquear en TCP
                    lines.append(
                        f"-A PM_DNSBLOCK -p tcp --dport 53 "
                        f"-m string --string \"{kw}\" --algo {algo} "
                        f"-j {IPTABLES_CHAIN_REJECT}"
                    )
                    lines.append(
                        f"-A PM_DNSBLOCK -p tcp --sport 53 "
                        f"-m string --string \"{kw}\" --algo {algo} "
                        f"-j {IPTABLES_CHAIN_REJECT}"
                    )
        lines.append("")

    # === Saltos desde INPUT, FORWARD y OUTPUT hacia las cadenas personalizadas ===
    iface_in = f"-i {lan} " if lan else ""

    lines += [
        "# [Saltos INPUT a cadenas personalizadas]",
        # Aceptar tráfico hacia el DNS Proxy local en el puerto 10053
        f"-A INPUT -p udp --dport 10053 -j ACCEPT",
        f"-A INPUT -p tcp --dport 10053 -j ACCEPT",
        f"-A INPUT -j {CHAIN_WEBBLOCK}",
    ]

    if keywords:
        lines += [
            f"-A INPUT -p udp --dport 53 -j PM_DNSBLOCK",
            f"-A INPUT -p tcp --dport 53 -j PM_DNSBLOCK",
        ]

    lines += [
        "",
        "# [Saltos FORWARD a cadenas personalizadas]",
        f"-A FORWARD {iface_in}-j {CHAIN_MACBLOCK}",
        f"-A FORWARD {iface_in}-j {CHAIN_CONNLIMIT}",
        f"-A FORWARD {iface_in}-j {CHAIN_CLISRV}",
        f"-A FORWARD {iface_in}-j {CHAIN_WEBBLOCK}",
    ]

    if keywords:
        lines += [
            f"-A FORWARD -p udp --dport 53 -j PM_DNSBLOCK",
            f"-A FORWARD -p tcp --dport 53 -j PM_DNSBLOCK",
        ]

    lines += [
        "",
        "# [Saltos OUTPUT a PM_WEBBLOCK para bloqueo local]",
        f"-A OUTPUT -j {CHAIN_WEBBLOCK}",
    ]

    if keywords:
        # En OUTPUT excluimos al usuario root (UID 0) para que la propia app pueda resolver
        lines += [
            f"-A OUTPUT -p udp --dport 53 -m owner ! --uid-owner 0 -j PM_DNSBLOCK",
            f"-A OUTPUT -p tcp --dport 53 -m owner ! --uid-owner 0 -j PM_DNSBLOCK",
        ]

    lines += [
        "",
        "COMMIT",
        "",
    ]

    return "\n".join(lines)


def get_rule_count(rules_content: str) -> int:
    """Cuenta reglas activas (líneas -A)."""
    return sum(1 for line in rules_content.splitlines() if line.strip().startswith("-A"))
