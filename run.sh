#!/bin/bash
# M-FIREWALL — Lanzador principal
# Uso: ./run.sh  (auto-eleva a root en Linux)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$SCRIPT_DIR/.venv"

# ── Linux: necesita root para iptables + preservar display para Qt ──────────
if [[ "$(uname -s 2>/dev/null)" == "Linux" ]]; then
    if [[ $EUID -ne 0 ]]; then
        echo "[M-FIREWALL] Se necesita root para iptables. Elevando permisos..."

        # Intentar pkexec primero (muestra ventana gráfica de autenticación)
        if command -v pkexec &>/dev/null; then
            exec pkexec env \
                DISPLAY="${DISPLAY:-}" \
                XAUTHORITY="${XAUTHORITY:-}" \
                WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-}" \
                XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-}" \
                DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-}" \
                HOME="$HOME" \
                PATH="$PATH" \
                "$0" "$@"
        else
            # Fallback: sudo preservando entorno gráfico
            exec sudo -E \
                DISPLAY="${DISPLAY:-:0}" \
                XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
                WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-}" \
                XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}" \
                "$0" "$@"
        fi
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

# Lanzar (python3 primero, python como fallback)
if command -v python3 &>/dev/null; then
    python3 run.py
else
    python run.py
fi
