"""
Workers para operaciones de firewall en hilos separados.
"""

from PySide6.QtCore import QThread, Signal
from app.services import firewall_service, domain_service
from app.core import rules_builder, configuration
from app.constants import LINUX_RULES_FILE
import time


class ApplyWorker(QThread):
    progress = Signal(int, str)
    log_line = Signal(str)
    finished = Signal(bool, str)
    rule_count = Signal(int)

    def __init__(self, config: dict):
        super().__init__()
        self._config = config

    def run(self):
        try:
            blocked_domains = self._config.get("blocked_domains", {})
            server_ip = self._config.get("server_ip", "")
            wan = self._config.get("interfaces", {}).get("wan", "")
            lan = self._config.get("interfaces", {}).get("lan", "")

            self.log_line.emit("[SISTEMA] Iniciando proceso de activación del firewall...")
            self.progress.emit(5, "Iniciando...")
            time.sleep(1)

            # Paso 1: Activar IP Forwarding
            self.log_line.emit("[COMANDO] sysctl -w net.ipv4.ip_forward=1")
            from app.core.platform_detector import enable_ip_forward
            enable_ip_forward()
            self.log_line.emit("[SISTEMA] Reenvío de Internet activado de forma permanente en el núcleo.")
            self.progress.emit(10, "IP Forwarding activado...")
            time.sleep(1)

            # Resolver IPs
            self.log_line.emit("[SISTEMA] Resolviendo bases de datos de direcciones IP para los dominios configurados...")
            resolved = domain_service.resolve_all_domains(blocked_domains)
            self.log_line.emit("[SISTEMA] Resolución DNS de dominios completada.")

            # --- BLOQUEO DE FACEBOOK ---
            self.progress.emit(25, "Configurando bloqueo de Facebook...")
            fb_cfg = blocked_domains.get("facebook", {})
            if fb_cfg.get("enabled", False):
                self.log_line.emit("\n==========================================")
                self.log_line.emit("1. CONFIGURANDO BLOQUEO PARA FACEBOOK")
                self.log_line.emit("==========================================")
                self.log_line.emit("Creando conjunto de direcciones en el kernel de red:")
                self.log_line.emit("[COMANDO] ipset create PM_FACEBOOK hash:ip family inet hashsize 1024 maxelem 65536 -exist")
                self.log_line.emit("[COMANDO] ipset flush PM_FACEBOOK")
                
                ips = resolved.get("facebook", [])
                for ip in ips:
                    self.log_line.emit(f"[COMANDO] ipset add PM_FACEBOOK {ip}")
                
                self.log_line.emit(f"[SISTEMA] Cargadas {len(ips)} direcciones IP en el set PM_FACEBOOK.")
                self.log_line.emit("Inyectando reglas en la tabla filter de iptables:")
                self.log_line.emit("[COMANDO] iptables -A PM_WEBBLOCK -p tcp --dport 80 -m set --match-set PM_FACEBOOK dst -j PM_REJECT")
                self.log_line.emit("[COMANDO] iptables -A PM_WEBBLOCK -p tcp --dport 443 -m set --match-set PM_FACEBOOK dst -j PM_REJECT")
                self.log_line.emit("[SISTEMA] Protección para Facebook lista. Esperando 5 segundos para continuar...")
            else:
                self.log_line.emit("\n[SISTEMA] Facebook no está marcado para bloquear. Omitiendo...")
            
            time.sleep(5)

            # --- BLOQUEO DE HOTMAIL ---
            self.progress.emit(50, "Configurando bloqueo de Hotmail...")
            hot_cfg = blocked_domains.get("hotmail", {})
            if hot_cfg.get("enabled", False):
                self.log_line.emit("\n==========================================")
                self.log_line.emit("2. CONFIGURANDO BLOQUEO PARA HOTMAIL/OUTLOOK")
                self.log_line.emit("==========================================")
                self.log_line.emit("Creando conjunto de direcciones en el kernel de red:")
                self.log_line.emit("[COMANDO] ipset create PM_HOTMAIL hash:ip family inet hashsize 1024 maxelem 65536 -exist")
                self.log_line.emit("[COMANDO] ipset flush PM_HOTMAIL")
                
                ips = resolved.get("hotmail", [])
                for ip in ips:
                    self.log_line.emit(f"[COMANDO] ipset add PM_HOTMAIL {ip}")
                
                self.log_line.emit(f"[SISTEMA] Cargadas {len(ips)} direcciones IP en el set PM_HOTMAIL.")
                self.log_line.emit("Inyectando reglas en la tabla filter de iptables:")
                self.log_line.emit("[COMANDO] iptables -A PM_WEBBLOCK -p tcp --dport 80 -m set --match-set PM_HOTMAIL dst -j PM_REJECT")
                self.log_line.emit("[COMANDO] iptables -A PM_WEBBLOCK -p tcp --dport 443 -m set --match-set PM_HOTMAIL dst -j PM_REJECT")
                self.log_line.emit("[SISTEMA] Protección para Hotmail/Outlook lista. Esperando 5 segundos para continuar...")
            else:
                self.log_line.emit("\n[SISTEMA] Hotmail/Outlook no está marcado para bloquear. Omitiendo...")
            
            time.sleep(5)

            # --- BLOQUEO DE YOUTUBE ---
            self.progress.emit(75, "Configurando bloqueo de YouTube...")
            yt_cfg = blocked_domains.get("youtube", {})
            if yt_cfg.get("enabled", False):
                self.log_line.emit("\n==========================================")
                self.log_line.emit("3. CONFIGURANDO BLOQUEO AGRESIVO PARA YOUTUBE")
                self.log_line.emit("==========================================")
                self.log_line.emit("Creando conjunto de direcciones en el kernel de red:")
                self.log_line.emit("[COMANDO] ipset create PM_YOUTUBE hash:ip family inet hashsize 1024 maxelem 65536 -exist")
                self.log_line.emit("[COMANDO] ipset flush PM_YOUTUBE")
                
                ips = resolved.get("youtube", [])
                for ip in ips:
                    self.log_line.emit(f"[COMANDO] ipset add PM_YOUTUBE {ip}")
                
                self.log_line.emit(f"[SISTEMA] Cargadas {len(ips)} direcciones IP en el set PM_YOUTUBE.")
                self.log_line.emit("Aplicando reglas básicas en la tabla filter:")
                self.log_line.emit("[COMANDO] iptables -A PM_WEBBLOCK -p tcp --dport 80 -m set --match-set PM_YOUTUBE dst -j PM_REJECT")
                self.log_line.emit("[COMANDO] iptables -A PM_WEBBLOCK -p tcp --dport 443 -m set --match-set PM_YOUTUBE dst -j PM_REJECT")
                
                # Pruebas adicionales y contramedidas (DoT, QUIC, DNS Proxy)
                self.log_line.emit("\n[!] YouTube detectado. Ejecutando contramedidas avanzadas anti-evasión...")
                self.log_line.emit("Bloqueando DNS cifrado (DNS-over-TLS en puerto 853):")
                self.log_line.emit("[COMANDO] iptables -A PM_WEBBLOCK -p tcp --dport 853 -j PM_REJECT")
                self.log_line.emit("[COMANDO] iptables -A PM_WEBBLOCK -p udp --dport 853 -j PM_REJECT")
                
                self.log_line.emit("Bloqueando protocolo de video QUIC/HTTP3 (UDP puerto 443) para forzar fallback a TCP:")
                self.log_line.emit("[COMANDO] iptables -A PM_WEBBLOCK -p udp --dport 443 -j PM_REJECT")
                
                self.log_line.emit("Redireccionando DNS de red LAN y local hacia el DNS Proxy Server interno en puerto 10053:")
                self.log_line.emit(f"[COMANDO] iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination {server_ip}:10053")
                self.log_line.emit(f"[COMANDO] iptables -t nat -A PREROUTING -p tcp --dport 53 -j DNAT --to-destination {server_ip}:10053")
                self.log_line.emit("[COMANDO] iptables -t nat -A OUTPUT -p udp --dport 53 -m owner ! --uid-owner 0 -j DNAT --to-destination 127.0.0.1:10053")
                
                self.log_line.emit("Limpiando registros de DNS local de la máquina para evitar bypass por caché:")
                self.log_line.emit("[COMANDO] systemctl restart systemd-resolved")
                self.log_line.emit("[COMANDO] resolvectl flush-caches")
                self.log_line.emit("[SISTEMA] Protección agresiva para YouTube lista. Esperando 5 segundos para continuar...")
            else:
                self.log_line.emit("\n[SISTEMA] YouTube no está marcado para bloquear. Omitiendo...")

            time.sleep(5)

            # Paso 5: Generar y compilar la configuración final
            self.progress.emit(90, "Compilando reglas de iptables...")
            self.log_line.emit("\n==========================================")
            self.log_line.emit("4. APLICANDO REGLAS FINALES EN EL SISTEMA")
            self.log_line.emit("==========================================")
            
            rules_content = rules_builder.build_rules(self._config, resolved)
            count = rules_builder.get_rule_count(rules_content)
            self.rule_count.emit(count)

            self.log_line.emit(f"Generado archivo de reglas personalizado con {count} reglas activas.")
            self.log_line.emit("[SISTEMA] Escribiendo reglas en /opt/proyecto-m/rules/project_m.rules.v4...")
            self.log_line.emit("[COMANDO] iptables-restore < /opt/proyecto-m/rules/project_m.rules.v4")

            rules_path = self._config.get("rules_file", "") or LINUX_RULES_FILE
            ok, msg = firewall_service.apply_rules(
                rules_content,
                rules_path=rules_path,
                resolved=resolved,
            )
            
            if ok:
                # Inyectar /etc/hosts como capa adicional de bloqueo local
                hosts_ok, hosts_msg = firewall_service.apply_hosts_block(self._config)
                if hosts_ok:
                    self.log_line.emit(f"\n[SISTEMA] /etc/hosts: {hosts_msg}")
                else:
                    self.log_line.emit(f"\n[AVISO] /etc/hosts: {hosts_msg}")
                self.log_line.emit("\n[!] FIREWALL CONFIGURADO Y ACTIVO CORRECTAMENTE.")
                self.log_line.emit("[!] Todos los bloqueos han sido aplicados con éxito en el kernel.")
                self.log_line.emit("")
                self.log_line.emit("╔══════════════════════════════════════════════════╗")
                self.log_line.emit("║  IMPORTANTE: Reinicia Firefox para que el        ║")
                self.log_line.emit("║  bloqueo de YouTube sea efectivo inmediatamente. ║")
                self.log_line.emit("║  Los demás sitios quedan bloqueados de inmediato.║")
                self.log_line.emit("╚══════════════════════════════════════════════════╝")
            else:
                self.log_line.emit(f"\n[ERROR] Falló la aplicación en el sistema: {msg}")

            self.progress.emit(100, msg)
            self.finished.emit(ok, msg)

        except Exception as e:
            self.log_line.emit(f"\n[ERROR INESPERADO] {e}")
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
            blocked_keys = list(resolved.keys())
            rules_content = rules_builder.build_rules(self._config, resolved)
            ok, msg = firewall_service.validate_rules(rules_content, blocked_keys=blocked_keys)
            self.finished.emit(ok, msg)
        except Exception as e:
            self.finished.emit(False, str(e))


class RefreshIpsetWorker(QThread):
    """Actualiza los sets de ipset sin recargar iptables."""
    progress = Signal(str)
    finished = Signal(bool, str)

    def __init__(self, config: dict):
        super().__init__()
        self._config = config

    def run(self):
        try:
            self.progress.emit("Resolviendo IPs actuales...")
            ok, msg = firewall_service.refresh_ipset(self._config)
            self.finished.emit(ok, msg)
        except Exception as e:
            self.finished.emit(False, f"Error: {e}")


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
