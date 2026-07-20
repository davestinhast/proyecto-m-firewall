"""
M-FIREWALL — Constantes globales
Proyecto M — Quezada / Espinola / Sanchez
"""

APP_NAME = "M-FIREWALL"
APP_VERSION = "1.0.0"
APP_AUTHORS = ["Quezada Juarez Fabrizio", "Espinola Figueroa Manuel", "Sanchez Bonifaz Lucero"]

# Rutas Linux — reglas en archivo PERSONALIZADO (no /etc/sysconfig/iptables)
LINUX_BASE_DIR = "/opt/proyecto-m"
LINUX_RULES_FILE = "/opt/proyecto-m/rules/project_m.rules.v4"
LINUX_IPSET_FILE = "/opt/proyecto-m/rules/project_m.ipset"
LINUX_RULES_BACKUP_DIR = "/opt/proyecto-m/rules/backups"
LINUX_LOG_DIR = "/var/log/proyecto-m"
LINUX_LOG_FILE = "/var/log/proyecto-m/iptables-rejected.log"
LINUX_CONFIG_FILE = "/opt/proyecto-m/config/project_m.json"

# Rutas del repositorio
REPO_RULES_FILE = "rules/project_m.rules.v4"
REPO_IPSET_FILE = "rules/project_m.ipset"
REPO_CONFIG_EXAMPLE = "config/project_m.example.json"

# systemd
SYSTEMD_SERVICE = "proyecto-m-firewall.service"
SYSTEMD_DOMAINS_SERVICE = "proyecto-m-domains.service"
SYSTEMD_DOMAINS_TIMER = "proyecto-m-domains.timer"

# iptables
IPTABLES_CHAIN_REJECT = "PM_REJECT"
IPTABLES_LOG_PREFIX = "PM-DROP "
IPTABLES_LOG_LIMIT = "5/min"
IPTABLES_LOG_LEVEL = "4"

# Cadenas personalizadas
CHAIN_WEBBLOCK = "PM_WEBBLOCK"
CHAIN_MACBLOCK = "PM_MACBLOCK"
CHAIN_CONNLIMIT = "PM_CONNLIMIT"
CHAIN_CLISRV = "PM_CLISRV"

# Prefijo de los ipset sets (PM_FACEBOOK, PM_YOUTUBE, PM_HOTMAIL)
IPSET_SET_PREFIX = "PM_"

# Puerto para el DNS proxy server en user-space
DNS_PROXY_PORT = 10053

# Colores UI (sincronizados con main.qss)
COLOR_BG = "#0a0a0f"
COLOR_SIDEBAR = "#111118"
COLOR_CARD = "#16161f"
COLOR_BORDER = "#252535"
COLOR_TEXT = "#F1F3F5"
COLOR_TEXT_SECONDARY = "#8892a4"
COLOR_BLUE = "#3b82f6"
COLOR_GREEN = "#22c55e"
COLOR_YELLOW = "#f59e0b"
COLOR_RED = "#ef4444"

# Dimensiones ventana
WINDOW_WIDTH = 1280
WINDOW_HEIGHT = 860
WINDOW_MIN_WIDTH = 1000
WINDOW_MIN_HEIGHT = 680
SIDEBAR_WIDTH = 240
HEADER_HEIGHT = 60
FOOTER_HEIGHT = 56

# Dominios bloqueados por defecto
BLOCKED_DOMAINS = {
    "facebook": {
        "label": "Facebook",
        "description": "Facebook, Messenger y CDN asociado",
        "domains": [
            "facebook.com",
            "www.facebook.com",
            "m.facebook.com",
            "fb.com",
            "www.fb.com",
            "fbcdn.net",
            "www.fbcdn.net",
            "fbsbx.com",
            "www.fbsbx.com",
            "messenger.com",
            "www.messenger.com",
            "static.xx.fbcdn.net",
            "connect.facebook.net",
            "fb.me",
            "instagram.com",
            "www.instagram.com",
        ],
        "enabled": False,
    },
    "youtube": {
        "label": "YouTube",
        "description": "YouTube y Google Video CDN",
        "domains": [
            # Solo dominios con IPs EXCLUSIVAS de YouTube.
            # ggpht.com, googleapis.com, *.l.google.com → IPs compartidas con Google Search → NO incluir en ipset
            # El DNS Proxy bloquea esos dominios via keyword "youtube"/"ggpht"/"ytimg" sin tocar IPs de Google
            "youtube.com",
            "www.youtube.com",
            "m.youtube.com",
            "youtu.be",
            "googlevideo.com",
            "www.googlevideo.com",
            "ytimg.com",
            "www.ytimg.com",
            "youtube-nocookie.com",
            "www.youtube-nocookie.com",
        ],
        "enabled": False,
    },
    "hotmail": {
        "label": "Hotmail / Outlook",
        "description": "Microsoft Hotmail, Outlook y Live",
        "domains": [
            "hotmail.com",
            "www.hotmail.com",
            "outlook.live.com",
            "login.live.com",
            "live.com",
            "www.live.com",
            "outlook.com",
            "www.outlook.com",
            "office365.com",
            "www.office365.com",
            "microsoftonline.com",
            "login.microsoftonline.com",
            "msftconnecttest.com",
            "microsoft.com",
            "www.microsoft.com",
        ],
        "enabled": False,
    },
}

# Perfiles connlimit por defecto
DEFAULT_CONN_PROFILES = [
    {"name": "SSH",          "proto": "tcp", "port": 22,  "max": 3,  "action": "REJECT", "enabled": False},
    {"name": "HTTP",         "proto": "tcp", "port": 80,  "max": 50, "action": "REJECT", "enabled": False},
    {"name": "HTTPS",        "proto": "tcp", "port": 443, "max": 50, "action": "REJECT", "enabled": False},
    {"name": "Personalizado","proto": "tcp", "port": 0,   "max": 5,  "action": "REJECT", "enabled": False},
]

# Puertos bloqueados para sitios web (TCP únicamente — HTTPS cifra, UDP/QUIC no aplica con string match)
WEB_BLOCK_PORTS = [80, 443]

# Navegación lateral
NAV_ITEMS = [
    {"id": "websites",    "label": "Sitios Web"},
    {"id": "clisrv",      "label": "Cliente / Servidor"},
    {"id": "mac",         "label": "Bloqueo MAC"},
    {"id": "connections", "label": "Conexiones"},
    {"id": "logs",        "label": "Registros"},
    {"id": "settings",    "label": "Configuracion"},
]
