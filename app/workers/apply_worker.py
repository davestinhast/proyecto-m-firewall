"""
Worker para aplicar reglas en hilo separado (no bloquea la GUI).
"""

from PySide6.QtCore import QThread, Signal
from app.services import firewall_service, domain_service
from app.core import rules_builder, configuration


class ApplyWorker(QThread):
    progress = Signal(int, str)       # porcentaje, mensaje
    finished = Signal(bool, str)      # ok, mensaje final
    rule_count = Signal(int)

    def __init__(self, config: dict):
        super().__init__()
        self._config = config

    def run(self):
        try:
            self.progress.emit(10, "Resolviendo dominios...")
            resolved = domain_service.resolve_all_domains(
                self._config.get("blocked_domains", {}),
                progress_cb=lambda cur, tot, key, n: self.progress.emit(
                    10 + int(40 * cur / max(tot, 1)),
                    f"Resolviendo {key}... {n} IPs"
                )
            )

            self.progress.emit(55, "Generando reglas...")
            rules_content = rules_builder.build_rules(self._config, resolved)
            count = rules_builder.get_rule_count(rules_content)
            self.rule_count.emit(count)

            self.progress.emit(70, "Validando con iptables-restore --test...")
            ok, msg = firewall_service.validate_rules(rules_content)
            if not ok:
                self.finished.emit(False, f"Validación fallida: {msg}")
                return

            self.progress.emit(85, "Aplicando reglas...")
            ok, msg = firewall_service.apply_rules(rules_content, self._config.get("rules_file", ""))
            self.progress.emit(100, msg)
            self.finished.emit(ok, msg)

        except Exception as e:
            self.finished.emit(False, f"Error inesperado: {e}")


class ValidateWorker(QThread):
    finished = Signal(bool, str)

    def __init__(self, config: dict):
        super().__init__()
        self._config = config

    def run(self):
        try:
            resolved = domain_service.resolve_all_domains(
                self._config.get("blocked_domains", {}),
            )
            rules_content = rules_builder.build_rules(self._config, resolved)
            ok, msg = firewall_service.validate_rules(rules_content)
            self.finished.emit(ok, msg)
        except Exception as e:
            self.finished.emit(False, str(e))


class ScanNetworkWorker(QThread):
    finished = Signal(list)
    error = Signal(str)

    def __init__(self, subnet: str):
        super().__init__()
        self._subnet = subnet

    def run(self):
        from app.services import network_service
        try:
            devices = network_service.scan_network_arp(self._subnet)
            self.finished.emit(devices)
        except Exception as e:
            self.error.emit(str(e))
            self.finished.emit([])


class LogWatcherWorker(QThread):
    new_entries = Signal(list)

    def __init__(self, log_file: str, interval_ms: int = 3000):
        super().__init__()
        self._log_file = log_file
        self._interval = interval_ms
        self._running = True

    def run(self):
        from app.services import logging_service
        import time
        last_size = 0
        while self._running:
            try:
                import os
                size = os.path.getsize(self._log_file) if os.path.exists(self._log_file) else 0
                if size != last_size:
                    entries = logging_service.read_log_tail(50, self._log_file)
                    self.new_entries.emit(entries)
                    last_size = size
            except Exception:
                pass
            time.sleep(self._interval / 1000)

    def stop(self):
        self._running = False
