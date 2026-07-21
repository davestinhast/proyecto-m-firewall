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
logger.setLevel(logging.INFO)
logger.propagate = False  # No mandar logs al root handler (stdout)

def _setup_file_logging():
    """Redirige logs del DNS proxy a archivo, nunca a consola."""
    if logger.handlers:
        return
    try:
        log_dir = Path("/var/log/proyecto-m")
        log_dir.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(str(log_dir / "dns-proxy.log"), encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
    except Exception:
        # Si no se puede escribir el archivo (ej. Windows / sin permisos),
        # agregar NullHandler para silenciar completamente
        logger.addHandler(logging.NullHandler())

_server_instance = None
_server_lock = threading.Lock()

# Servidores DNS de respaldo en orden de prioridad (se usan si el upstream principal falla)
_FALLBACK_DNS_SERVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

DNS_BLOCK_KEYWORDS = {
    "facebook": ["facebook", "fbcdn", "fb.com", "messenger", "fbsbx"],
    "youtube": [
        "youtube",
        "youtu",
        "googlevideo",
        "ytimg",
        "ggpht",
        "youtube-nocookie",
        "youtubei",
        "ytstatic",
    ],
    "hotmail": ["hotmail", "outlook", "live.com", "microsoftonline"],
}

def detect_upstream_dns() -> str:
    """
    Detecta el servidor DNS upstream REAL del sistema.

    Estrategia para Kali Linux con systemd-resolved:
      - /etc/resolv.conf es un symlink a stub-resolv.conf → solo tiene 127.0.0.53 (loopback)
      - /run/systemd/resolve/resolv.conf tiene el DNS REAL del DHCP (ej: 192.168.1.1, 10.0.2.3)

    Por eso leemos /run/systemd/resolve/resolv.conf PRIMERO.
    Si usamos 8.8.8.8 como fallback y la red del laboratorio lo bloquea,
    TODAS las queries no-bloqueadas fallan silenciosamente → todo parece bloqueado.
    """
    loopbacks = {"127.0.0.1", "127.0.0.53", "127.0.1.1", "::1"}

    # Orden: DNS real de systemd-resolved → /etc/resolv.conf → fallback
    for resolv_path in [
        Path("/run/systemd/resolve/resolv.conf"),  # DNS real upstream (desde DHCP/config)
        Path("/etc/resolv.conf"),                   # Puede ser stub o DNS directo
    ]:
        try:
            if not resolv_path.exists():
                continue
            for line in resolv_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line.startswith("nameserver "):
                    ns = line.split()[1].strip()
                    if ns not in loopbacks:
                        logger.info(f"DNS Proxy: usando upstream DNS: {ns} (desde {resolv_path})")
                        return ns
        except Exception as e:
            logger.error(f"DNS Proxy: error leyendo {resolv_path}: {e}")

    logger.warning("DNS Proxy: no se detectó DNS del sistema, usando 8.8.8.8 como último recurso")
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
        _setup_file_logging()
        with _server_lock:
            self.config = config
            if self.running:
                return

            # Detectar el DNS real de la red (no el stub de systemd-resolved)
            self.upstream = detect_upstream_dns()

            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # SO_REUSEPORT permite hacer bind aunque haya otro socket en el mismo puerto
                # (útil si el proceso anterior no cerró limpiamente)
                try:
                    self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except OSError:
                    pass  # No disponible en todos los kernels/SO
                self.sock.bind((self.ip, self.port))
                self.running = True
                self.thread = threading.Thread(target=self._listen, daemon=True)
                self.thread.start()
                logger.info(
                    f"Servidor DNS Proxy iniciado en {self.ip}:{self.port} "
                    f"(upstream: {self.upstream})"
                )
            except Exception as e:
                logger.error(f"Error al iniciar DNS Proxy en puerto {self.port}: {e}")

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
        # Buffer de 4096 bytes — suficiente para respuestas DNS grandes (DNSSEC, etc.)
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
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

    def _get_question_end_offset(self, data: bytes, offset: int = 12) -> int:
        """Calcula el final de la seccion de pregunta DNS para poder truncar metadatos EDNS0."""
        try:
            while offset < len(data):
                length = data[offset]
                if length == 0:
                    offset += 1
                    break
                if (length & 0xc0) == 0xc0:
                    offset += 2
                    break
                offset += length + 1
            # Agregar 4 bytes para incluir QTYPE (2 bytes) y QCLASS (2 bytes)
            return offset + 4
        except Exception:
            return len(data)

    # Marca de socket (fwmark) para que iptables excluya las queries upstream del DNAT.
    # El proxy marca sus sockets con SO_MARK=100 y la regla iptables usa
    # "-m mark ! --mark 100" para excluirlos, evitando el bucle infinito.
    # SO_MARK = 36 en Linux (socket.h SOL_SOCKET), siempre disponible en Kali.
    _UPSTREAM_FWMARK = 100
    _SO_MARK = 36  # socket.SO_MARK no siempre está definido en Python, usar valor numérico

    def _forward_query(self, data: bytes) -> bytes | None:
        """
        Reenvía la query DNS al upstream con fallback en cascada.

        Los sockets upstream se marcan con SO_MARK=100 (fwmark).
        La regla iptables OUTPUT DNAT usa "-m mark ! --mark 100" para excluirlos,
        así el proxy puede consultar DNS directamente sin ser DNAT'ado a sí mismo.
        Esto reemplaza el frágil "! --uid-owner 0" que falla en Kali con iptables-nft.
        """
        servers_to_try = [self.upstream] + [
            s for s in _FALLBACK_DNS_SERVERS if s != self.upstream
        ]
        for server in servers_to_try:
            # Saltar loopbacks (evita cualquier bucle residual)
            if server in ("127.0.0.1", "127.0.0.53", "0.0.0.0", "::1"):
                logger.warning(f"DNS Proxy: upstream {server} es loopback — omitiendo")
                continue
            up_sock = None
            try:
                up_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                up_sock.settimeout(2.0)
                # Marcar el socket para que iptables lo excluya del OUTPUT DNAT
                try:
                    up_sock.setsockopt(socket.SOL_SOCKET, self._SO_MARK, self._UPSTREAM_FWMARK)
                except OSError:
                    pass  # No disponible en Windows o VMs sin CONFIG_FWMARKS
                up_sock.sendto(data, (server, 53))
                resp, resp_addr = up_sock.recvfrom(4096)
                # Detección de bucle residual: si la respuesta viene del propio proxy, abortar
                if resp_addr[0] in ("127.0.0.1", "::1") and resp_addr[1] == self.port:
                    logger.error(
                        f"DNS Proxy: ¡BUCLE DETECTADO desde {resp_addr}! "
                        "SO_MARK no funcionó — verifica que el kernel tenga CONFIG_FWMARKS."
                    )
                    return None
                return resp
            except Exception:
                continue
            finally:
                if up_sock:
                    try:
                        up_sock.close()
                    except Exception:
                        pass
        return None

    def _make_servfail(self, data: bytes) -> bytes:
        """
        Genera respuesta SERVFAIL (RCODE=2) para cuando todos los upstream DNS fallan.
        SERVFAIL da un error inmediato al cliente en lugar de dejarlo esperando timeout.
        Flags: 0x8182 = Response(1) OPCODE(0000) AA(0) TC(0) RD(1) RA(1) RCODE(2=SERVFAIL)
        """
        if len(data) < 12:
            return data
        tx_id = data[:2]
        qd_count = data[4:6]
        question_end = self._get_question_end_offset(data)
        return (
            tx_id
            + b"\x81\x82"                          # Flags SERVFAIL
            + qd_count                              # QDCOUNT (misma pregunta)
            + b"\x00\x00"                          # ANCOUNT = 0
            + b"\x00\x00"                          # NSCOUNT = 0
            + b"\x00\x00"                          # ARCOUNT = 0
            + data[12:question_end]                 # Sección Question original
        )

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
                keywords += DNS_BLOCK_KEYWORDS.get(key, [])

        # Si hay al menos un sitio bloqueado, siempre cegar servidores DoH y DNS alternativos
        if has_blocked:
            keywords += ["dns.google", "cloudflare-dns", "dns.quad9", "use-application-dns.net"]

        # Realizar coincidencia case-insensitive sobre el nombre decodificado
        domain_lower = domain.lower()
        should_block = any(kw in domain_lower for kw in keywords)

        if should_block:
            # Responder con NXDOMAIN (RCODE=3)
            # Flags 0x8183: Response, standard query, RD=1, RA=1, NXDOMAIN
            tx_id = data[:2]
            qd_count = data[4:6]
            question_end = self._get_question_end_offset(data)
            response = (
                tx_id
                + b"\x81\x83"                      # Flags NXDOMAIN
                + qd_count
                + b"\x00\x00\x00\x00\x00\x00"
                + data[12:question_end]
            )
            try:
                self.sock.sendto(response, addr)
                logger.info(f"DNS Proxy: BLOQUEADO {domain} para {client_ip}")
                self._write_to_rejected_log(client_ip, domain, "BLOQUEADO (NXDOMAIN)")
            except Exception:
                pass
        else:
            # Reenviar al DNS upstream con cascada de fallback
            resp = self._forward_query(data)
            if resp is not None:
                try:
                    self.sock.sendto(resp, addr)
                except Exception:
                    pass
            else:
                # Todos los servidores DNS fallaron — SERVFAIL inmediato en lugar de silencio
                # Silencio causaría timeout de 30s en el browser para CADA dominio
                try:
                    servfail = self._make_servfail(data)
                    self.sock.sendto(servfail, addr)
                    logger.warning(
                        f"DNS Proxy: SERVFAIL para '{domain}' "
                        f"(upstream {self.upstream} y fallbacks no respondieron)"
                    )
                except Exception:
                    pass


def get_dns_proxy() -> DNSProxyServer:
    global _server_instance
    with _server_lock:
        if _server_instance is None:
            _server_instance = DNSProxyServer()
        return _server_instance
