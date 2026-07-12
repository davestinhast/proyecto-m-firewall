#!/bin/bash
# M-FIREWALL — Lanzador principal
# Uso: ./run.sh  (auto-eleva a root en Linux)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT_ABS="$SCRIPT_DIR/run.sh"
VENV="$SCRIPT_DIR/.venv"

# ── Linux: necesita root para iptables + preservar display para Qt ──────────
if [[ "$(uname -s 2>/dev/null)" == "Linux" ]]; then
    if [[ $EUID -ne 0 ]]; then
        echo "[M-FIREWALL] Se necesita root para iptables. Elevando permisos..."
        chmod +x "$SCRIPT_ABS" 2>/dev/null || true

        # sudo preservando entorno gráfico (DISPLAY, Wayland, etc.)
        exec sudo -E \
            DISPLAY="${DISPLAY:-:0}" \
            XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
            WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-}" \
            XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}" \
            DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-}" \
            HOME="$HOME" \
            PATH="$PATH" \
            bash "$SCRIPT_ABS" "$@"
    fi

    # Crear directorios necesarios (ya somos root)
    mkdir -p /opt/proyecto-m/config
    mkdir -p /opt/proyecto-m/rules/backups
    mkdir -p /var/log/proyecto-m
    touch /var/log/proyecto-m/iptables-rejected.log 2>/dev/null || true
    chmod 644 /var/log/proyecto-m/iptables-rejected.log 2>/dev/null || true
fi

# ── Activar entorno virtual si existe ───────────────────────────────────────
if [[ -d "$VENV" ]]; then
    source "$VENV/bin/activate"
fi

cd "$SCRIPT_DIR"

# Asegurar que el directorio del proyecto esté en PYTHONPATH
# (sys.path.insert en run.py no siempre funciona bajo sudo)
export PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}"

# Lanzar (python3 primero, python como fallback)
if command -v python3 &>/dev/null; then
    python3 run.py
else
    python run.py
fi
