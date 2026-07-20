#!/bin/bash
# Diagnostico rapido para el bloqueo de YouTube en M-FIREWALL.
# Uso: sudo bash scripts/diagnose_youtube.sh

echo "=== M-FIREWALL / Diagnostico YouTube ==="
date
echo

echo "[1] Identidad de red"
ip -br addr 2>/dev/null || true
echo
ip route 2>/dev/null || true
echo

echo "[2] Configuracion guardada"
CONFIG="/opt/proyecto-m/config/project_m.json"
if [[ ! -f "$CONFIG" ]]; then
  CONFIG="config/project_m.example.json"
fi
echo "CONFIG=$CONFIG"
python3 - <<'PY' "$CONFIG"
import json, sys
path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    cfg = json.load(f)
yt = cfg.get("blocked_domains", {}).get("youtube", {})
print("schema:", cfg.get("_schema_version", "(sin version)"))
print("server_ip:", cfg.get("server_ip"))
print("interfaces:", cfg.get("interfaces"))
print("youtube.enabled:", yt.get("enabled"))
print("youtube.domains:", ", ".join(yt.get("domains", [])))
PY
echo

echo "[3] Servicios y puertos"
systemctl is-active rsyslog 2>/dev/null || true
ss -lunpt 2>/dev/null | grep -E '(:10053|:53)' || true
echo

echo "[4] IP sets"
for set_name in PM_FACEBOOK PM_HOTMAIL PM_YOUTUBE; do
  echo "--- $set_name ---"
  ipset list "$set_name" -terse 2>&1 || true
done
echo

echo "[5] Cadenas iptables principales"
for chain in INPUT OUTPUT FORWARD PM_WEBBLOCK PM_DNSBLOCK PM_REJECT; do
  echo "--- filter/$chain ---"
  iptables -L "$chain" -n -v --line-numbers 2>&1 || true
done
echo

echo "[6] NAT DNS"
iptables -t nat -L PREROUTING -n -v --line-numbers 2>&1 || true
echo
iptables -t nat -L OUTPUT -n -v --line-numbers 2>&1 || true
echo

echo "[7] Pruebas DNS locales"
for domain in youtube.com www.youtube.com youtubei.googleapis.com r3---sn.googlevideo.com yt3.ggpht.com; do
  echo "--- $domain ---"
  getent ahostsv4 "$domain" 2>&1 | head -10 || true
done
echo

echo "[8] Logs recientes PM-DROP"
tail -80 /var/log/proyecto-m/iptables-rejected.log 2>/dev/null || true

echo
echo "=== Fin diagnostico ==="
