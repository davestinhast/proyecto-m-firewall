"""
M-FIREWALL — Constantes globales
Proyecto M — Quezada / Espinola / Sanchez
"""

APP_NAME = "M-FIREWALL"
APP_VERSION = "1.0.0"
APP_AUTHORS = ["Quezada Juarez Fabrizio", "Espinola Figueroa Manuel", "Sanchez Bonifaz Lucero"]

# Rutas Linux
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

# Colores UI (sincronizados con main.qss)
COLOR_BG = "#101216"
COLOR_SIDEBAR = "#15181E"
COLOR_CARD = "#1B1F27"
COLOR_BORDER = "#2A303B"
COLOR_TEXT = "#F1F3F5"
COLOR_TEXT_SECONDARY = "#989FAB"
COLOR_BLUE = "#4F7DF3"
COLOR_GREEN = "#3CB371"
COLOR_YELLOW = "#D6A343"
COLOR_RED = "#D95C5C"

# Dimensiones ventana
WINDOW_WIDTH = 1440
WINDOW_HEIGHT = 900
WINDOW_MIN_WIDTH = 1100
WINDOW_MIN_HEIGHT = 700
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
            "fbcdn.net",
            "fbsbx.com",
            "messenger.com",
            "static.xx.fbcdn.net",
        ],
        "enabled": True,
    },
    "youtube": {
        "label": "YouTube",
        "description": "YouTube y Google Video CDN",
        "domains": [
            "youtube.com",
            "www.youtube.com",
            "youtu.be",
            "googlevideo.com",
            "ytimg.com",
            "yt3.ggpht.com",
            "youtube-nocookie.com",
        ],
        "enabled": True,
    },
    "hotmail": {
        "label": "Hotmail / Outlook",
        "description": "Microsoft Hotmail, Outlook y Live",
        "domains": [
            "hotmail.com",
            "outlook.live.com",
            "login.live.com",
            "live.com",
            "outlook.com",
            "office365.com",
        ],
        "enabled": True,
    },
}

# Perfiles connlimit por defecto
DEFAULT_CONN_PROFILES = [
    {"name": "SSH",         "proto": "tcp", "port": 22,  "max": 3,  "action": "REJECT", "enabled": True},
    {"name": "HTTP",        "proto": "tcp", "port": 80,  "max": 10, "action": "REJECT", "enabled": True},
    {"name": "HTTPS",       "proto": "tcp", "port": 443, "max": 10, "action": "REJECT", "enabled": True},
    {"name": "Personalizado","proto": "tcp", "port": 0,   "max": 5,  "action": "REJECT", "enabled": False},
]

# Puertos bloqueados para sitios web
WEB_BLOCK_PORTS = [80, 443]   # TCP
WEB_BLOCK_UDP_PORTS = [443]   # UDP/QUIC

# Navegación lateral
NAV_ITEMS = [
    {"id": "dashboard",    "label": "Inicio",            "icon": "🏠"},
    {"id": "websites",     "label": "Sitios Web",        "icon": "🌐"},
    {"id": "clisrv",       "label": "Cliente / Servidor","icon": "🔁"},
    {"id": "mac",          "label": "Bloqueo MAC",       "icon": "📛"},
    {"id": "connections",  "label": "Conexiones",        "icon": "🔗"},
    {"id": "logs",         "label": "Registros",         "icon": "📋"},
    {"id": "backups",      "label": "Copias",            "icon": "💾"},
    {"id": "settings",     "label": "Configuración",     "icon": "⚙️"},
]
