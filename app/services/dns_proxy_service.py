"""
Servidor DNS Proxy en segundo plano.
Intercepta peticiones de DNS redireccionadas y devuelve NXDOMAIN para dominios bloqueados.
Permite bloquear de forma 100% inmune a la aleatorización de mayúsculas (0x20 DNS casing).
"""

import socket
import threading
import logging
from pathlib import Path
from app.constants import DNS_PROXY_PORT

logger = logging.getLogger("dns_proxy")
logging.basicConfig(level=logging.INFO)

_server_instance = None
_server_lock = threading.Lock()

def detect_upstream_dns() -> str:
    """Detecta dinámicamente el servidor DNS configurado en el sistema (evita loopbacks)."""
    try:
        resolv = Path("/etc/resolv.conf")
        if resolv.exists():
            for line in resolv.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line.startswith("nameserver "):
                    ns = line.split()[1].strip()
                    # Ignorar direcciones loopback locales para no causar bucles infinitos
                    if ns not in ["127.0.0.1", "127.0.0.53", "127.0.1.1", "::1"]:
                        logger.info(f"DNS Proxy: Detectado DNS del sistema activo: {ns}")
                        return ns
    except Exception as e:
        logger.error(f"Error al leer /etc/resolv.conf: {e}")
    # Fallback predeterminado a Google DNS si no hay DNS local
    return "8.8.8.8"

class DNSProxyServer:
    def __init__(self, ip="0.0.0.0", port=DNS_PROXY_PORT):
        self.ip = ip
        self.port = port
        self.upstream = "8.8.8.8"
        self.sock = None
        self.running = False
        self.thread = None
        self.config = {}

    def start(self, config: dict):
        with _server_lock:
            self.config = config
            if self.running:
                return
            
            # Detectar el DNS activo de la red del usuario
            self.upstream = detect_upstream_dns()
            
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # Permitir reusar la dirección/puerto
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.sock.bind((self.ip, self.port))
                self.running = True
                self.thread = threading.Thread(target=self._listen, daemon=True)
                self.thread.start()
                logger.info(f"Servidor DNS Proxy iniciado en {self.ip}:{self.port} (Upstream redirigido a: {self.upstream})")
            except Exception as e:
                logger.error(f"Error al iniciar DNS Proxy: {e}")

    def update_config(self, config: dict):
        self.config = config
        # Refrescar el upstream por si cambió la interfaz de red
        self.upstream = detect_upstream_dns()

    def stop(self):
        with _server_lock:
            self.running = False
            if self.sock:
                try:
                    self.sock.close()
                except Exception:
                    pass
                self.sock = None
            logger.info("Servidor DNS Proxy detenido.")

    def _listen(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(2048)
                if not data:
                    continue
                # Ejecutar el manejo de cada query en un hilo ligero para no bloquear
                threading.Thread(target=self._handle_query, args=(data, addr), daemon=True).start()
            except Exception:
                break

    def _decode_dns_name(self, data: bytes, offset: int = 12) -> str:
        """Extrae el nombre de dominio codificado de un paquete DNS."""
        try:
            labels = []
            while offset < len(data):
                length = data[offset]
                if length == 0:
                    break
                # Si es un puntero comprimido (0xc0)
                if (length & 0xc0) == 0xc0:
                    break
                offset += 1
                label = data[offset:offset+length].decode("utf-8", errors="ignore")
                labels.append(label)
                offset += length
            return ".".join(labels)
        except Exception:
            return "desconocido"

    def _write_to_rejected_log(self, client_ip: str, domain: str, action: str):
        """Escribe una línea de log personalizada en el archivo oficial de logs."""
        from datetime import datetime
        import os
        from app.constants import LINUX_LOG_FILE
        ts = datetime.now().strftime("%b %d %H:%M:%S")
        # El formato contiene PM-DROP para que la interfaz lo filtre automáticamente
        log_line = f"{ts} kali PM-DROP: [DNS-PROXY] SRC={client_ip} DOMAIN={domain} ACTION={action}\n"
        try:
            os.makedirs(os.path.dirname(LINUX_LOG_FILE), exist_ok=True)
            with open(LINUX_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(log_line)
        except Exception:
            pass

    def _handle_query(self, data, addr):
        if len(data) < 12:
            return

        client_ip = addr[0]
        domain = self._decode_dns_name(data)

        # Palabras clave a bloquear basadas en la configuración cargada
        blocked_domains = self.config.get("blocked_domains", {})
        keywords = []
        has_blocked = False

        for key, cfg in blocked_domains.items():
            if cfg.get("enabled", False):
                has_blocked = True
                if key == "facebook":
                    keywords += ["facebook", "fbcdn"]
                elif key == "youtube":
                    keywords += ["youtu", "googlevideo", "ytimg"]
                elif key == "hotmail":
                    keywords += ["hotmail", "outlook", "live.com"]

        # Si hay al menos un sitio bloqueado, siempre cegar servidores DoH y DNS alternativos
        if has_blocked:
            keywords += ["dns.google", "cloudflare-dns", "dns.quad9", "use-application-dns.net"]

        # Realizar coincidencia case-insensitive sobre el nombre decodificado
        domain_lower = domain.lower()
        should_block = False
        for kw in keywords:
            if kw in domain_lower:
                should_block = True
                break

        if should_block:
            # Responder con un paquete DNS tipo NXDOMAIN (Código de error de nombre: RCODE = 3)
            # Transaction ID: bytes 0-1
            # Flags para Respuesta NXDOMAIN: 0x8183 (Response, standard query, recursion desired, recursion available, NXDOMAIN)
            # Questions Count: bytes 4-5
            # Answer Count: 0 (0x0000)
            # Authority Count: 0 (0x0000)
            # Additional Count: 0 (0x0000)
            tx_id = data[:2]
            qd_count = data[4:6]
            # Cabecera DNS NXDOMAIN + la pregunta original (data[12:])
            response = tx_id + b"\x81\x83" + qd_count + b"\x00\x00\x00\x00\x00\x00" + data[12:]
            try:
                self.sock.sendto(response, addr)
                logger.info(f"DNS Proxy: Interceptado y bloqueado {domain} para {client_ip}")
                self._write_to_rejected_log(client_ip, domain, "BLOQUEADO (NXDOMAIN)")
            except Exception:
                pass
        else:
            # Reenviar al DNS de la red real detectado dinámicamente
            try:
                # Obtener el DNS original en tiempo real para NUNCA romper el internet si la red cambia
                current_upstream = detect_upstream_dns()
                up_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                up_sock.settimeout(2.0)
                up_sock.sendto(data, (current_upstream, 53))
                resp, _ = up_sock.recvfrom(2048)
                self.sock.sendto(resp, addr)
                up_sock.close()
            except Exception:
                # Si falla el DNS real, simplemente ignorar
                pass

def get_dns_proxy() -> DNSProxyServer:
    global _server_instance
    with _server_lock:
        if _server_instance is None:
            _server_instance = DNSProxyServer()
        return _server_instance
