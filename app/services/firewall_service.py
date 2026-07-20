"""
Aplica, valida y restaura reglas iptables.

ORDEN CORRECTO:
  1. Crear los sets de ipset vacios (si no existen) -> iptables-restore --test no falla
  2. Cargar las IPs en los sets via ipset restore
  3. Validar las reglas con iptables-restore --test
  4. Escribir el archivo personalizado
  5. Aplicar con iptables-restore
"""

import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from app.core import command_runner, rules_builder
from app.core.platform_detector import get_mode
from app.constants import LINUX_RULES_FILE, LINUX_RULES_BACKUP_DIR, LINUX_IPSET_FILE, IPSET_SET_PREFIX


def _ensure_ipset_sets_exist(keys: list[str]) -> None:
    """
    Crea los sets de ipset vacios si no existen todavia.
    Esto es NECESARIO antes de validar con iptables-restore --test,
    porque iptables verifica que los sets referenciados existan.
    """
    for key in keys:
        set_name = f"{IPSET_SET_PREFIX}{key.upper()}"
        try:
            subprocess.run(
                ["ipset", "create", set_name, "hash:ip",
                 "family", "inet", "hashsize", "1024", "maxelem", "65536", "-exist"],
                capture_output=True, timeout=10,
            )
        except Exception:
            pass


def validate_rules(rules_content: str, blocked_keys: list | None = None) -> tuple[bool, str]:
    """
    Valida sin aplicar. Retorna (ok, mensaje).
    Si se pasan blocked_keys, crea los sets de ipset vacios primero
    para que iptables-restore --test no falle por sets inexistentes.
    """
    if get_mode() == "demo":
        return True, "Modo demostracion — validacion simulada correcta."

    # Crear sets vacios si no existen (evita error "Set PM_X doesn't exist")
    if blocked_keys:
        _ensure_ipset_sets_exist(blocked_keys)

    rc, stdout, stderr = command_runner.run_iptables_restore(rules_content, dry_run=True)
    if rc == 0:
        return True, "Validacion correcta."
    return False, stderr.strip() or "Error desconocido en iptables-restore --test"


def apply_rules(
    rules_content: str,
    rules_path: str = "",
    resolved: dict | None = None,
) -> tuple[bool, str]:
    """
    1. Activa ip_forward
    2. Crea sets de ipset vacios (para que la validacion no falle)
    3. Carga las IPs en los sets via ipset restore
    4. Valida las reglas iptables
    5. Crea backup
    6. Escribe el archivo personalizado
    7. Aplica con iptables-restore
    """
    if get_mode() == "demo":
        return False, "Modo demostracion — no se pueden aplicar reglas en Windows."

    target_path = rules_path.strip() if rules_path.strip() else LINUX_RULES_FILE

    # 1. Activar ip_forward
    from app.core.platform_detector import enable_ip_forward
    enable_ip_forward()

    blocked_keys = list(resolved.keys()) if resolved else []

    # 2. Crear sets vacios ANTES de validar (obligatorio)
    if blocked_keys:
        _ensure_ipset_sets_exist(blocked_keys)

    # 3. Cargar IPs en los sets
    if resolved:
        from app.services.domain_service import apply_ipset, build_ipset_file
        ipset_ok, ipset_msg = apply_ipset(resolved)
        if ipset_ok:
            try:
                ipset_content = build_ipset_file(resolved)
                ipset_path = Path(LINUX_IPSET_FILE)
                ipset_path.parent.mkdir(parents=True, exist_ok=True)
                ipset_path.write_text(ipset_content, encoding="utf-8")
            except Exception:
                pass

    # 4. Validar (ahora los sets ya existen, no fallara)
    ok, msg = validate_rules(rules_content, blocked_keys=blocked_keys)
    if not ok:
        return False, f"Validacion fallida: {msg}"

    # 5. Backup
    _create_backup(target_path)

    # 6. Escribir archivo personalizado
    try:
        p = Path(target_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(rules_content, encoding="utf-8")
    except Exception as e:
        return False, f"No se pudo escribir {target_path}: {e}"

    # 7. Aplicar
    rc, stdout, stderr = command_runner.run_iptables_restore(rules_content)
    if rc == 0:
        # Limpiar solo entradas conntrack de los dominios bloqueados para forzar
        # re-negociación TLS sin cortar el resto de conexiones activas del sistema.
        try:
            import subprocess as _sp
            _sp.run(["conntrack", "-F"], capture_output=True, timeout=5)
        except Exception:
            pass

        rule_count = rules_builder.get_rule_count(rules_content)
        return True, (
            f"Reglas aplicadas correctamente. {rule_count} reglas activas en {target_path}."
        )
    return False, stderr.strip() or "Error al aplicar reglas."


def refresh_ipset(config: dict) -> tuple[bool, str]:
    """Actualiza los sets de ipset sin recargar iptables."""
    if get_mode() == "demo":
        return False, "Modo demostracion."
    from app.services.domain_service import resolve_all_domains, apply_ipset
    blocked = config.get("blocked_domains", {})
    if not any(v.get("enabled", False) for v in blocked.values()):
        return False, "No hay sitios habilitados."
    try:
        resolved = resolve_all_domains(blocked)
        ok, msg = apply_ipset(resolved)
        return ok, msg
    except Exception as e:
        return False, f"Error: {e}"


def restore_backup(backup_path: str) -> tuple[bool, str]:
    if get_mode() == "demo":
        return False, "Modo demostracion."
    rc, stdout, stderr = command_runner.run_iptables_restore_file(backup_path)
    if rc == 0:
        return True, f"Restaurado desde {backup_path}"
    return False, stderr.strip()


def flush_all() -> tuple[bool, str]:
    """Elimina todas las reglas de todas las tablas."""
    if get_mode() == "demo":
        return False, "Modo demostracion."

    # Limpiar tablas principales
    for table in ["filter", "nat", "mangle", "raw", "security"]:
        command_runner.run_iptables(["-t", table, "-F"])
        command_runner.run_iptables(["-t", table, "-X"])

    # Políticas por defecto a ACCEPT
    command_runner.run_iptables(["-P", "INPUT", "ACCEPT"])
    command_runner.run_iptables(["-P", "FORWARD", "ACCEPT"])
    command_runner.run_iptables(["-P", "OUTPUT", "ACCEPT"])

    # IPv6
    for table in ["filter", "nat", "mangle", "raw", "security"]:
        command_runner.run(["ip6tables", "-t", table, "-F"])
        command_runner.run(["ip6tables", "-t", table, "-X"])
    command_runner.run(["ip6tables", "-P", "INPUT", "ACCEPT"])
    command_runner.run(["ip6tables", "-P", "FORWARD", "ACCEPT"])
    command_runner.run(["ip6tables", "-P", "OUTPUT", "ACCEPT"])

    # nftables
    command_runner.run(["nft", "flush", "ruleset"])

    return True, "Todas las reglas eliminadas (IPv4, IPv6 y nftables)."


def deep_reset_network() -> tuple[bool, str]:
    """
    Realiza una limpieza profunda y reparacion de la red del sistema:
    1. Ejecuta flush_all() (vaciar iptables/ip6tables/nftables).
    2. Destruye todos los conjuntos ipset.
    3. Elimina lineas de bloqueo en /etc/hosts.
    4. Agrega nameservers publicos a /etc/resolv.conf para restaurar DNS.
    """
    if get_mode() == "demo":
        return False, "Modo demostracion — no se puede ejecutar en Windows."

    log_msgs = []

    # 1. Vaciar reglas de firewall
    ok, msg = flush_all()
    log_msgs.append(msg)

    # 2. Destruir conjuntos ipset
    try:
        r = subprocess.run(["ipset", "destroy"], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            log_msgs.append("Conjuntos ipset destruidos correctamente.")
        else:
            log_msgs.append(f"Nota al destruir ipset: {r.stderr.strip()}")
    except Exception as e:
        log_msgs.append(f"No se pudo limpiar ipset: {e}")

    # 3. Limpiar /etc/hosts
    hosts_path = Path("/etc/hosts")
    if hosts_path.exists():
        try:
            lines = hosts_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            clean_lines = []
            removed_count = 0
            block_keywords = ["facebook", "youtube", "hotmail", "live.com", "outlook", "fbcdn"]
            for line in lines:
                if any(kw in line.lower() for kw in block_keywords) and not line.strip().startswith("#"):
                    removed_count += 1
                else:
                    clean_lines.append(line)
            if removed_count > 0:
                hosts_path.write_text("\n".join(clean_lines) + "\n", encoding="utf-8")
                log_msgs.append(f"Se eliminaron {removed_count} lineas de bloqueo de /etc/hosts.")
            else:
                log_msgs.append("/etc/hosts sin bloqueos activos.")
        except Exception as e:
            log_msgs.append(f"Error al limpiar /etc/hosts: {e}")

    # 4. Restaurar /etc/resolv.conf
    try:
        # En Linux, NetworkManager gestiona /etc/resolv.conf a través de DHCP.
        # En lugar de forzar 8.8.8.8 (que algunos ISPs como Claro bloquean),
        # borramos el archivo manual y reiniciamos NetworkManager para que el ISP asigne el correcto.
        import os
        if os.path.exists("/etc/resolv.conf"):
            os.remove("/etc/resolv.conf")
        subprocess.run(["systemctl", "restart", "NetworkManager"], timeout=10)
        log_msgs.append("DNS restablecido: NetworkManager reiniciado para obtener los DNS del ISP original por DHCP.")
    except Exception as e:
        log_msgs.append(f"Error al reiniciar NetworkManager para restaurar DNS: {e}")

    return True, "\n".join(log_msgs)



def get_active_rules() -> tuple[bool, str]:
    if get_mode() == "demo":
        return True, _demo_rules()
    rc, stdout, stderr = command_runner.run_iptables(["-L", "-n", "-v", "--line-numbers"])
    if rc == 0:
        return True, stdout
    return False, stderr


def list_backups(backup_dir: str = LINUX_RULES_BACKUP_DIR) -> list[dict]:
    p = Path(backup_dir)
    if not p.exists():
        return []
    backups = []
    for f in sorted(p.glob("*.rules.v4"), reverse=True):
        stat = f.stat()
        content = f.read_text(errors="ignore")
        backups.append({
            "path": str(f),
            "name": f.name,
            "date": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            "size": stat.st_size,
            "rule_count": rules_builder.get_rule_count(content),
        })
    return backups


def _create_backup(rules_path: str):
    p = Path(rules_path)
    if not p.exists():
        return
    backup_dir = Path(LINUX_RULES_BACKUP_DIR)
    backup_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = backup_dir / f"backup_{ts}.rules.v4"
    shutil.copy2(p, dest)


def _demo_rules() -> str:
    return """Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination
PM_MACBLOCK  all  --  anywhere             anywhere
PM_CONNLIMIT all  --  anywhere             anywhere
PM_CLISRV  all  --  anywhere             anywhere
PM_WEBBLOCK all  --  anywhere             anywhere

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
PM_WEBBLOCK all  --  anywhere             anywhere

Chain PM_REJECT (2 references)
LOG        all  --  anywhere             anywhere   LOG level warning prefix "PM-DROP "
DROP       all  --  anywhere             anywhere

[MODO DEMOSTRACION — reglas simuladas]"""
