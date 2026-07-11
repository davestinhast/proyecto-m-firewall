"""
Ejecuta comandos del sistema de forma segura.
- Sin shell=True.
- Sin concatenación de strings de usuario.
- Retorna (returncode, stdout, stderr).
"""

import subprocess
import shlex
from typing import Optional


def run(args: list[str], timeout: int = 30, input_data: Optional[str] = None) -> tuple[int, str, str]:
    """
    Ejecuta un comando como lista de argumentos.
    Retorna (returncode, stdout, stderr).
    """
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_data,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Tiempo agotado ({timeout}s): {args[0]}"
    except FileNotFoundError:
        return -2, "", f"Comando no encontrado: {args[0]}"
    except PermissionError:
        return -3, "", f"Sin permisos para ejecutar: {args[0]}"
    except Exception as e:
        return -99, "", str(e)


def run_iptables(args: list[str]) -> tuple[int, str, str]:
    return run(["iptables"] + args)


def run_iptables_restore(rules_content: str, dry_run: bool = False) -> tuple[int, str, str]:
    cmd = ["iptables-restore"]
    if dry_run:
        cmd.append("--test")
    return run(cmd, input_data=rules_content, timeout=15)


def run_iptables_restore_file(path: str, dry_run: bool = False) -> tuple[int, str, str]:
    try:
        with open(path, "r") as f:
            content = f.read()
    except Exception as e:
        return -1, "", str(e)
    return run_iptables_restore(content, dry_run=dry_run)


def run_ipset(args: list[str]) -> tuple[int, str, str]:
    return run(["ipset"] + args)


def run_iptables_save() -> tuple[int, str, str]:
    return run(["iptables-save"])


def get_interfaces() -> list[str]:
    """Lista interfaces de red disponibles."""
    try:
        import os
        net_path = "/sys/class/net"
        if os.path.exists(net_path):
            return sorted(os.listdir(net_path))
    except Exception:
        pass
    return []


def check_root() -> bool:
    import os
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False
