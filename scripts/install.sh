#!/bin/bash
# M-FIREWALL — Script de instalación para Kali Linux / Debian
# Uso: sudo ./scripts/install.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

INSTALL_DIR="/opt/proyecto-m"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}  M-FIREWALL — Instalador v1.0        ${NC}"
echo -e "${BLUE}  Proyecto M — Kali Linux             ${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# 1. Verificar Linux
if [[ "$(uname -s)" != "Linux" ]]; then
    echo -e "${RED}Error: este script requiere Linux.${NC}"
    exit 1
fi

# 2. Verificar root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: ejecutar como root (sudo ./scripts/install.sh).${NC}"
    exit 1
fi

echo -e "${YELLOW}[1/12] Actualizando paquetes...${NC}"
apt-get update -qq

echo -e "${YELLOW}[2/12] Instalando iptables e ipset...${NC}"
apt-get install -y iptables ipset iptables-persistent

echo -e "${YELLOW}[3/12] Instalando rsyslog...${NC}"
apt-get install -y rsyslog

echo -e "${YELLOW}[4/12] Instalando Python y dependencias del sistema...${NC}"
apt-get install -y python3 python3-venv python3-pip

echo -e "${YELLOW}[5/12] Instalando arp-scan para escaneo de red...${NC}"
apt-get install -y arp-scan || true

echo -e "${YELLOW}[6/12] Creando entorno virtual Python...${NC}"
python3 -m venv "$REPO_DIR/.venv"
source "$REPO_DIR/.venv/bin/activate"

echo -e "${YELLOW}[7/12] Instalando dependencias Python...${NC}"
pip install --quiet --upgrade pip
pip install --quiet -r "$REPO_DIR/requirements.txt"

echo -e "${YELLOW}[8/12] Creando directorio de instalación...${NC}"
mkdir -p "$INSTALL_DIR/rules/backups"
mkdir -p "$INSTALL_DIR/config"

echo -e "${YELLOW}[9/12] Copiando archivos de configuración y reglas...${NC}"
cp "$REPO_DIR/rules/project_m.rules.v4" "$INSTALL_DIR/rules/" 2>/dev/null || true
if [[ ! -f "$INSTALL_DIR/config/project_m.json" ]]; then
    cp "$REPO_DIR/config/project_m.example.json" "$INSTALL_DIR/config/project_m.json" 2>/dev/null || true
fi

echo -e "${YELLOW}[10/12] Creando directorio de logs...${NC}"
mkdir -p /var/log/proyecto-m
touch /var/log/proyecto-m/iptables-rejected.log
chmod 644 /var/log/proyecto-m/iptables-rejected.log

echo -e "${YELLOW}[11/12] Configurando rsyslog...${NC}"
cp "$REPO_DIR/rsyslog/30-proyecto-m.conf" /etc/rsyslog.d/ 2>/dev/null || true
systemctl restart rsyslog 2>/dev/null || true

echo -e "${YELLOW}[12/12] Instalando servicio systemd...${NC}"
cp "$REPO_DIR/systemd/proyecto-m-firewall.service" /etc/systemd/system/ 2>/dev/null || true
systemctl daemon-reload 2>/dev/null || true

echo ""
echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}  Instalación completada.             ${NC}"
echo -e "${GREEN}======================================${NC}"
echo ""
echo -e "Ejecutar la aplicación:"
echo -e "  ${BLUE}./run.sh${NC}"
echo ""
