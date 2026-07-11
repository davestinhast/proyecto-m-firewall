"""
Aplica, valida y restaura reglas iptables.
"""

import shutil
from datetime import datetime
from pathlib import Path
from app.core import command_runner, rules_builder
from app.core.platform_detector import get_mode
from app.constants import LINUX_RULES_FILE, LINUX_RULES_BACKUP_DIR


def validate_rules(rules_content: str) -> tuple[bool, str]:
    """Valida sin aplicar. Retorna (ok, mensaje)."""
    if get_mode() == "demo":
        return True, "Modo demostración — validación simulada correcta."
    rc, stdout, stderr = command_runner.run_iptables_restore(rules_content, dry_run=True)
    if rc == 0:
        return True, "Validación correcta."
    return False, stderr.strip() or "Error desconocido en iptables-restore --test"


def apply_rules(rules_content: str, rules_path: str = LINUX_RULES_FILE) -> tuple[bool, str]:
    """
    1. Valida
    2. Crea backup
    3. Escribe archivo
    4. Aplica
    5. Retorna (ok, mensaje)
    """
    if get_mode() == "demo":
        return False, "Modo demostración — no se pueden aplicar reglas en Windows."

    ok, msg = validate_rules(rules_content)
    if not ok:
        return False, f"Validación fallida: {msg}"

    # Backup
    _create_backup(rules_path)

    # Escribir archivo
    try:
        p = Path(rules_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(rules_content, encoding="utf-8")
    except Exception as e:
        return False, f"No se pudo escribir {rules_path}: {e}"

    # Aplicar
    rc, stdout, stderr = command_runner.run_iptables_restore(rules_content)
    if rc == 0:
        return True, f"Reglas aplicadas correctamente. ({rules_builder.get_rule_count(rules_content)} reglas)"
    return False, stderr.strip() or "Error al aplicar reglas."


def restore_backup(backup_path: str) -> tuple[bool, str]:
    """Restaura un archivo de backup."""
    if get_mode() == "demo":
        return False, "Modo demostración."
    rc, stdout, stderr = command_runner.run_iptables_restore_file(backup_path)
    if rc == 0:
        return True, f"Restaurado desde {backup_path}"
    return False, stderr.strip()


def flush_all() -> tuple[bool, str]:
    """Elimina todas las reglas iptables."""
    if get_mode() == "demo":
        return False, "Modo demostración."
    rc, _, err = command_runner.run_iptables(["-F"])
    if rc != 0:
        return False, err
    command_runner.run_iptables(["-X"])
    command_runner.run_iptables(["-P", "INPUT", "ACCEPT"])
    command_runner.run_iptables(["-P", "FORWARD", "ACCEPT"])
    command_runner.run_iptables(["-P", "OUTPUT", "ACCEPT"])
    return True, "Reglas eliminadas. Tráfico abierto."


def get_active_rules() -> tuple[bool, str]:
    """Retorna el listado actual de reglas iptables."""
    if get_mode() == "demo":
        return True, _demo_rules()
    rc, stdout, stderr = command_runner.run_iptables(["-L", "-n", "-v", "--line-numbers"])
    if rc == 0:
        return True, stdout
    return False, stderr


def list_backups(backup_dir: str = LINUX_RULES_BACKUP_DIR) -> list[dict]:
    """Lista copias de seguridad disponibles."""
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

Chain PM_REJECT (2 references)
LOG        all  --  anywhere             anywhere   LOG level warning prefix "PM-DROP "
DROP       all  --  anywhere             anywhere

[MODO DEMOSTRACIÓN — reglas simuladas]"""
