#!/bin/bash
# M-FIREWALL — Lanzador principal
# Uso: ./run.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$SCRIPT_DIR/.venv"

if [[ -d "$VENV" ]]; then
    source "$VENV/bin/activate"
fi

cd "$SCRIPT_DIR"
python run.py
