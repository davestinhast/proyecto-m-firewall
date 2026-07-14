"""
Pantalla — Bloqueo de sitios web
Bloquea acceso a Facebook, YouTube y Hotmail mediante ipset + iptables.
"""

import subprocess
import socket
from datetime import datetime
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea, QPushButton, QApplication, QTextEdit,
    QSizePolicy,
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtWidgets import QCheckBox
from app.constants import BLOCKED_DOMAINS, LINUX_RULES_FILE, IPSET_SET_PREFIX


# ─── WORKERS ─────────────────────────────────────────────────────────────────

class _EnableIPForwardWorker(QThread):
    finished = Signal(bool)

    def run(self):
        from app.core.platform_detector import enable_ip_forward
        ok = enable_ip_forward()
        self.finished.emit(ok)


class _CheckSiteWorker(QThread):
    """Verifica cuantas IPs tiene el ipset set y si el sitio es accesible."""
    finished = Signal(str, int, bool)  # key, ip_count_in_set, reachable

    def __init__(self, key: str, domain: str):
        super().__init__()
        self._key = key
        self._domain = domain

    def run(self):
        set_name = f"{IPSET_SET_PREFIX}{self._key.upper()}"

        ip_count = 0
        try:
            result = subprocess.run(
                ["ipset", "list", set_name, "-terse"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.startswith("Number of entries:"):
                        ip_count = int(line.split(":")[1].strip())
                        break
            else:
                # El set no existe aun
                ip_count = 0
        except FileNotFoundError:
            ip_count = -1  # ipset no instalado
        except Exception:
            ip_count = -1

        reachable = False
        if self._domain:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((self._domain, 443))
                s.close()
                reachable = True
            except Exception:
                reachable = False

        self.finished.emit(self._key, ip_count, reachable)


class _RefreshIpsetWorker(QThread):
    progress = Signal(str)
    finished = Signal(bool, str)

    def __init__(self, config: dict):
        super().__init__()
        self._config = config

    def run(self):
        from app.services import firewall_service
        self.progress.emit("Resolviendo IPs actuales...")
        ok, msg = firewall_service.refresh_ipset(self._config)
        self.finished.emit(ok, msg)


class _DiagWorker(QThread):
    """Ejecuta comandos de diagnostico y devuelve el output completo."""
    finished = Signal(str)

    def run(self):
        lines = []
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines.append(f"=== Diagnostico M-FIREWALL [{ts}] ===\n")

        # 1. ipset instalado?
        lines.append("--- ipset ---")
        try:
            r = subprocess.run(["ipset", "version"], capture_output=True, text=True, timeout=5)
            lines.append(r.stdout.strip() or "ipset disponible")
        except FileNotFoundError:
            lines.append("[ERROR] ipset NO esta instalado. Ejecuta: sudo apt install ipset")
        except Exception as e:
            lines.append(f"[ERROR] {e}")

        # 2. Sets de ipset activos
        lines.append("\n--- Sets ipset activos (PM_*) ---")
        for key in ["FACEBOOK", "YOUTUBE", "HOTMAIL"]:
            set_name = f"PM_{key}"
            try:
                r = subprocess.run(
                    ["ipset", "list", set_name, "-terse"],
                    capture_output=True, text=True, timeout=5,
                )
                if r.returncode == 0:
                    for line in r.stdout.splitlines():
                        if "Number of entries" in line:
                            lines.append(f"  {set_name}: {line.strip()}")
                else:
                    lines.append(f"  {set_name}: NO EXISTE (aplica las reglas primero)")
            except FileNotFoundError:
                lines.append(f"  {set_name}: ipset no disponible")
            except Exception as e:
                lines.append(f"  {set_name}: {e}")

        # 3. iptables chains PM_*
        lines.append("\n--- iptables chain PM_WEBBLOCK ---")
        try:
            r = subprocess.run(
                ["iptables", "-L", "PM_WEBBLOCK", "-n", "-v"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0:
                lines.append(r.stdout.strip() or "(vacio)")
            else:
                lines.append(f"Chain no existe: {r.stderr.strip()}")
        except FileNotFoundError:
            lines.append("[ERROR] iptables no disponible")
        except Exception as e:
            lines.append(f"[ERROR] {e}")

        # 4. iptables OUTPUT hacia PM_WEBBLOCK
        lines.append("\n--- iptables OUTPUT (bloqueo desde Kali) ---")
        try:
            r = subprocess.run(
                ["iptables", "-L", "OUTPUT", "-n", "-v"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0:
                relevant = [l for l in r.stdout.splitlines() if "WEBBLOCK" in l or "Chain OUTPUT" in l]
                lines.append("\n".join(relevant) if relevant else "  (sin reglas OUTPUT hacia PM_WEBBLOCK)")
            else:
                lines.append(r.stderr.strip())
        except Exception as e:
            lines.append(f"[ERROR] {e}")

        # 5. iptables FORWARD
        lines.append("\n--- iptables FORWARD (bloqueo para clientes) ---")
        try:
            r = subprocess.run(
                ["iptables", "-L", "FORWARD", "-n", "-v"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0:
                relevant = [l for l in r.stdout.splitlines() if "WEBBLOCK" in l or "Chain FORWARD" in l]
                lines.append("\n".join(relevant) if relevant else "  (sin reglas FORWARD hacia PM_WEBBLOCK)")
            else:
                lines.append(r.stderr.strip())
        except Exception as e:
            lines.append(f"[ERROR] {e}")

        # 6. nftables (puede interferir)
        lines.append("\n--- nftables (puede interferir con iptables) ---")
        try:
            r = subprocess.run(
                ["nft", "list", "ruleset"],
                capture_output=True, text=True, timeout=5,
            )
            out = r.stdout.strip()
            if out:
                lines.append("[!] nftables tiene reglas activas:")
                lines.append(out[:800] + ("..." if len(out) > 800 else ""))
            else:
                lines.append("  nftables: sin reglas (OK)")
        except FileNotFoundError:
            lines.append("  nft no disponible")
        except Exception as e:
            lines.append(f"  {e}")

        # 7. IP Forward
        lines.append("\n--- IP Forward ---")
        try:
            r = subprocess.run(
                ["sysctl", "net.ipv4.ip_forward"],
                capture_output=True, text=True, timeout=5,
            )
            lines.append(f"  {r.stdout.strip()}")
        except Exception as e:
            lines.append(f"  {e}")

        # 8. Conectividad a los sitios
        lines.append("\n--- Conectividad TCP:443 desde Kali ---")
        for domain, key in [("facebook.com", "FB"), ("youtube.com", "YT"), ("hotmail.com", "Hotmail")]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((domain, 443))
                s.close()
                lines.append(f"  {key} ({domain}): ACCESIBLE - el bloqueo en OUTPUT no esta activo")
            except Exception:
                lines.append(f"  {key} ({domain}): bloqueado o sin respuesta")

        lines.append("\n=== Fin del diagnostico ===")
        self.finished.emit("\n".join(lines))


# ─── STATUS BAR MEJORADA ─────────────────────────────────────────────────────

class _StatusBar(QFrame):
    """Barra de estado: IP Forward, ruta archivo y gateway para clientes."""

    def __init__(self, config: dict, parent=None):
        super().__init__(parent)
        self._config = config
        self._worker = None
        self.setObjectName("card")
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        # Fila 1: IP Forward + boton activar
        row1 = QHBoxLayout()
        row1.setSpacing(12)

        ip_icon = QLabel("IP Forward:")
        ip_icon.setObjectName("label_hint")
        ip_icon.setFixedWidth(72)
        row1.addWidget(ip_icon)

        self._ipfwd_lbl = QLabel("Verificando...")
        self._ipfwd_lbl.setObjectName("label_secondary")
        row1.addWidget(self._ipfwd_lbl, stretch=1)

        self._btn_enable_ipfwd = QPushButton("Activar IP Forward")
        self._btn_enable_ipfwd.setObjectName("btn_success")
        self._btn_enable_ipfwd.setVisible(False)
        self._btn_enable_ipfwd.clicked.connect(self._on_enable)
        row1.addWidget(self._btn_enable_ipfwd)

        layout.addLayout(row1)

        # Fila 2: Gateway para clientes + ruta archivo
        row2 = QHBoxLayout()
        row2.setSpacing(12)

        gw_icon = QLabel("Gateway:")
        gw_icon.setObjectName("label_hint")
        gw_icon.setFixedWidth(72)
        row2.addWidget(gw_icon)

        srv_ip = self._config.get("server_ip", "") or "X.X.X.X"
        self._gw_cmd = f"sudo ip route add default via {srv_ip}"
        self._gw_lbl = QLabel(self._gw_cmd)
        self._gw_lbl.setStyleSheet(
            "font-family: 'Consolas','Courier New',monospace; font-size: 11px; "
            "color: #7080a0; background: transparent;"
        )
        self._gw_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        row2.addWidget(self._gw_lbl, stretch=1)

        btn_copy = QPushButton("Copiar")
        btn_copy.setObjectName("btn_small")
        btn_copy.setToolTip("Ejecutar en el PC cliente para configurar gateway")
        btn_copy.clicked.connect(lambda: QApplication.clipboard().setText(self._gw_cmd))
        row2.addWidget(btn_copy)

        rules_path = self._config.get("rules_file", "") or LINUX_RULES_FILE
        path_lbl = QLabel(f"Reglas: {rules_path}")
        path_lbl.setStyleSheet(
            "font-family: 'Consolas','Courier New',monospace; font-size: 10px; "
            "color: #3a4050; background: transparent;"
        )
        row2.addWidget(path_lbl)

        layout.addLayout(row2)

        self.refresh()

    def refresh(self):
        from app.core.platform_detector import is_linux, has_ip_forward
        if is_linux():
            if has_ip_forward():
                self._ipfwd_lbl.setText("ACTIVO — Kali esta reenviando paquetes correctamente")
                self._ipfwd_lbl.setStyleSheet("color: #22c55e; font-size: 12px; background: transparent;")
                self._btn_enable_ipfwd.setVisible(False)
            else:
                self._ipfwd_lbl.setText("INACTIVO — los clientes no podran ser bloqueados sin esto")
                self._ipfwd_lbl.setStyleSheet("color: #ef4444; font-size: 12px; font-weight: 600; background: transparent;")
                self._btn_enable_ipfwd.setVisible(True)
        else:
            self._ipfwd_lbl.setText("Modo demo — no aplica")
            self._ipfwd_lbl.setStyleSheet("color: #4a5060; font-size: 12px; background: transparent;")

    def _on_enable(self):
        self._btn_enable_ipfwd.setEnabled(False)
        self._btn_enable_ipfwd.setText("Activando...")
        self._worker = _EnableIPForwardWorker()
        self._worker.finished.connect(self._on_done)
        self._worker.start()

    def _on_done(self, ok: bool):
        self._btn_enable_ipfwd.setEnabled(True)
        self._btn_enable_ipfwd.setText("Activar IP Forward")
        self.refresh()

    def update_config(self, config: dict):
        self._config = config
        srv_ip = config.get("server_ip", "") or "X.X.X.X"
        self._gw_cmd = f"sudo ip route add default via {srv_ip}"
        self._gw_lbl.setText(self._gw_cmd)


# ─── PANEL DE DIAGNOSTICO ────────────────────────────────────────────────────

class _DiagPanel(QFrame):
    """Panel colapsable que muestra el estado real del sistema."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self._expanded = False
        self._worker = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 10, 16, 10)
        layout.setSpacing(8)

        # Header del panel (siempre visible)
        header_row = QHBoxLayout()

        title = QLabel("Diagnostico del sistema")
        title.setObjectName("label_subtitle")
        header_row.addWidget(title)

        header_row.addStretch()

        info = QLabel("Que hace falta para que el bloqueo funcione")
        info.setObjectName("label_secondary")
        header_row.addWidget(info)

        self._btn_run = QPushButton("Ejecutar diagnostico")
        self._btn_run.setObjectName("btn_secondary")
        self._btn_run.clicked.connect(self._run_diag)
        header_row.addWidget(self._btn_run)

        self._btn_toggle = QPushButton("Mostrar")
        self._btn_toggle.setObjectName("btn_small")
        self._btn_toggle.clicked.connect(self._toggle)
        header_row.addWidget(self._btn_toggle)

        layout.addLayout(header_row)

        # Resumen de estado rapido (siempre visible)
        self._summary_row = QHBoxLayout()
        self._summary_row.setSpacing(20)

        self._lbl_ipset    = self._make_status_lbl("ipset")
        self._lbl_webblock = self._make_status_lbl("PM_WEBBLOCK")
        self._lbl_ipfwd    = self._make_status_lbl("IP Forward")
        self._lbl_nft      = self._make_status_lbl("nftables")

        for lbl in [self._lbl_ipset, self._lbl_webblock, self._lbl_ipfwd, self._lbl_nft]:
            self._summary_row.addWidget(lbl)
        self._summary_row.addStretch()
        layout.addLayout(self._summary_row)

        # Area de texto colapsable (output completo)
        self._text_area = QTextEdit()
        self._text_area.setReadOnly(True)
        self._text_area.setMinimumHeight(280)
        self._text_area.setMaximumHeight(400)
        self._text_area.setPlaceholderText(
            "Presiona 'Ejecutar diagnostico' para ver el estado real del sistema.\n\n"
            "Esto mostrara:\n"
            "  - Si ipset esta instalado y cuantas IPs tiene cargadas\n"
            "  - Si iptables tiene activas las cadenas PM_WEBBLOCK\n"
            "  - Si nftables esta interfiriendo con el bloqueo\n"
            "  - Si los sitios son accesibles desde Kali"
        )
        self._text_area.setVisible(False)
        layout.addWidget(self._text_area)

    def _make_status_lbl(self, name: str) -> QLabel:
        lbl = QLabel(f"{name}: —")
        lbl.setObjectName("label_mono")
        lbl.setStyleSheet("color: #4a5060; font-size: 11px; background: transparent;")
        return lbl

    def _toggle(self):
        self._expanded = not self._expanded
        self._text_area.setVisible(self._expanded)
        self._btn_toggle.setText("Ocultar" if self._expanded else "Mostrar")

    def _run_diag(self):
        if self._worker and self._worker.isRunning():
            return
        self._btn_run.setEnabled(False)
        self._btn_run.setText("Ejecutando...")
        self._text_area.setPlainText("Ejecutando diagnostico del sistema...")
        if not self._expanded:
            self._text_area.setVisible(True)
            self._expanded = True
            self._btn_toggle.setText("Ocultar")

        self._worker = _DiagWorker()
        self._worker.finished.connect(self._on_diag_done)
        self._worker.start()

    def _on_diag_done(self, output: str):
        self._btn_run.setEnabled(True)
        self._btn_run.setText("Ejecutar diagnostico")
        self._text_area.setPlainText(output)
        self._text_area.verticalScrollBar().setValue(0)

        # Actualizar resumen de estado rapido
        self._update_summary(output)

    def _update_summary(self, output: str):
        # ipset
        if "ipset NO esta instalado" in output:
            self._set_lbl(self._lbl_ipset, "ipset: NO INSTALADO", "err")
        elif "Number of entries: 0" in output:
            self._set_lbl(self._lbl_ipset, "ipset: sin IPs", "warn")
        elif "Number of entries:" in output:
            self._set_lbl(self._lbl_ipset, "ipset: IPs cargadas", "ok")
        else:
            self._set_lbl(self._lbl_ipset, "ipset: sets vacios", "warn")

        # PM_WEBBLOCK
        if "Chain no existe" in output or "does not exist" in output:
            self._set_lbl(self._lbl_webblock, "PM_WEBBLOCK: no existe", "err")
        elif "match-set" in output or "PM_REJECT" in output:
            self._set_lbl(self._lbl_webblock, "PM_WEBBLOCK: activo", "ok")
        else:
            self._set_lbl(self._lbl_webblock, "PM_WEBBLOCK: vacio", "warn")

        # IP Forward
        if "= 1" in output or "= 1\n" in output:
            self._set_lbl(self._lbl_ipfwd, "IP Forward: activo", "ok")
        else:
            self._set_lbl(self._lbl_ipfwd, "IP Forward: inactivo", "err")

        # nftables
        if "nftables tiene reglas activas" in output:
            self._set_lbl(self._lbl_nft, "nftables: ACTIVO (puede interferir)", "warn")
        else:
            self._set_lbl(self._lbl_nft, "nftables: sin reglas", "ok")

    def _set_lbl(self, lbl: QLabel, text: str, state: str):
        colors = {"ok": "#22c55e", "warn": "#f59e0b", "err": "#ef4444"}
        color = colors.get(state, "#6b7585")
        lbl.setText(text)
        lbl.setStyleSheet(
            f"color: {color}; font-size: 11px; font-weight: 600; background: transparent;"
        )


# ─── SITE CARD ───────────────────────────────────────────────────────────────

class SiteCard(QFrame):
    toggled         = Signal(str, bool)
    check_requested = Signal(str)

    def __init__(self, key: str, cfg: dict, parent=None):
        super().__init__(parent)
        self._key = key
        self._cfg = cfg
        self.setObjectName("card")
        self._setup_ui()

    def _setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 14, 20, 14)
        main_layout.setSpacing(10)

        # Fila superior: nombre + toggle + boton verificar
        top_row = QHBoxLayout()
        top_row.setSpacing(16)

        label_name = QLabel(self._cfg["label"])
        label_name.setStyleSheet(
            "font-size: 15px; font-weight: 700; color: #e8eaf0; background: transparent;"
        )
        top_row.addWidget(label_name)

        desc = QLabel(self._cfg.get("description", ""))
        desc.setObjectName("label_secondary")
        top_row.addWidget(desc, stretch=1)

        self._toggle = QCheckBox("Habilitar bloqueo")
        self._toggle.setChecked(self._cfg.get("enabled", False))
        self._toggle.toggled.connect(lambda checked: self.toggled.emit(self._key, checked))
        self._toggle.setStyleSheet("font-weight: 600; color: #c0c8d8; background: transparent;")
        top_row.addWidget(self._toggle)

        self._btn_check = QPushButton("Verificar")
        self._btn_check.setObjectName("btn_small")
        self._btn_check.clicked.connect(lambda: self.check_requested.emit(self._key))
        top_row.addWidget(self._btn_check)

        main_layout.addLayout(top_row)

        # Separador
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        main_layout.addWidget(sep)

        # Fila inferior: estado
        status_row = QHBoxLayout()
        status_row.setSpacing(20)

        self._badge = QLabel("Sin verificar")
        self._badge.setStyleSheet(
            "color: #4a5060; font-size: 12px; font-weight: 600; background: transparent;"
        )
        status_row.addWidget(self._badge)

        self._ipset_label = QLabel("ipset: —")
        self._ipset_label.setObjectName("label_mono")
        status_row.addWidget(self._ipset_label)

        self._reach_label = QLabel("")
        self._reach_label.setObjectName("label_secondary")
        status_row.addWidget(self._reach_label)

        status_row.addStretch()

        domains_text = "  ·  ".join(self._cfg.get("domains", [])[:4])
        if len(self._cfg.get("domains", [])) > 4:
            domains_text += "  ..."
        domains_lbl = QLabel(domains_text)
        domains_lbl.setStyleSheet(
            "color: #2a3040; font-size: 10px; font-family: monospace; background: transparent;"
        )
        status_row.addWidget(domains_lbl)

        main_layout.addLayout(status_row)

    def set_checking(self, checking: bool):
        self._btn_check.setEnabled(not checking)
        if checking:
            self._badge.setText("Verificando...")
            self._badge.setStyleSheet(
                "color: #f59e0b; font-size: 12px; font-weight: 600; background: transparent;"
            )

    def set_check_result(self, ip_count: int, reachable: bool):
        ts = datetime.now().strftime("%H:%M")

        if ip_count == -1:
            self._badge.setText("ipset no disponible (instala: sudo apt install ipset)")
            self._badge.setStyleSheet(
                "color: #ef4444; font-size: 11px; font-weight: 600; background: transparent;"
            )
            self._ipset_label.setText(f"ipset: no instalado ({ts})")
            self._ipset_label.setStyleSheet("color: #ef4444; font-size: 11px; background: transparent;")
            self._reach_label.setText("")
        elif ip_count == 0:
            self._badge.setText("INACTIVO — aplica las reglas primero")
            self._badge.setStyleSheet(
                "color: #f59e0b; font-size: 12px; font-weight: 600; background: transparent;"
            )
            self._ipset_label.setText(f"ipset: 0 IPs ({ts})")
            self._ipset_label.setStyleSheet("color: #f59e0b; font-size: 11px; background: transparent;")
            if reachable:
                self._reach_label.setStyleSheet("color: #ef4444; font-size: 11px; background: transparent;")
                self._reach_label.setText("accesible desde Kali")
            else:
                self._reach_label.setText("")
        else:
            if reachable:
                self._badge.setText("PARCIAL — IPs cargadas pero sitio responde desde Kali")
                self._badge.setStyleSheet(
                    "color: #f97316; font-size: 11px; font-weight: 600; background: transparent;"
                )
                self._reach_label.setStyleSheet("color: #f97316; font-size: 11px; background: transparent;")
                self._reach_label.setText("Kali puede acceder (OUTPUT activo bloquea esto)")
            else:
                self._badge.setText("BLOQUEADO")
                self._badge.setStyleSheet(
                    "color: #ef4444; font-size: 12px; font-weight: 700; background: transparent;"
                )
                self._reach_label.setStyleSheet("color: #22c55e; font-size: 11px; background: transparent;")
                self._reach_label.setText("TCP 443: sin respuesta")

            self._ipset_label.setText(f"ipset: {ip_count} IPs ({ts})")
            self._ipset_label.setStyleSheet("color: #22c55e; font-size: 11px; background: transparent;")

        self._btn_check.setEnabled(True)

    def set_enabled(self, enabled: bool):
        self._toggle.blockSignals(True)
        self._toggle.setChecked(enabled)
        self._toggle.blockSignals(False)


# ─── PAGE ────────────────────────────────────────────────────────────────────

class WebsitesPage(QWidget):
    config_changed = Signal(dict)

    def __init__(self, config: dict, parent=None):
        super().__init__(parent)
        self._config = config
        self._workers: list   = []
        self._checking: set   = set()
        self._refresh_worker  = None

        self._auto_timer = QTimer(self)
        self._auto_timer.setInterval(30_000)
        self._auto_timer.timeout.connect(self._verify_all)

        self._setup_ui()

    def _setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(12)

        # Titulo y acciones
        title_row = QHBoxLayout()
        title = QLabel("Bloqueo de Sitios Web")
        title.setObjectName("label_title")
        title_row.addWidget(title)
        title_row.addStretch()

        btn_refresh_ips = QPushButton("Actualizar IPs bloqueadas")
        btn_refresh_ips.setObjectName("btn_secondary")
        btn_refresh_ips.setToolTip(
            "Resuelve los dominios de nuevo y actualiza los sets de ipset.\n"
            "No necesita recargar las reglas iptables."
        )
        btn_refresh_ips.clicked.connect(self._on_refresh_ips)
        title_row.addWidget(btn_refresh_ips)
        self._btn_refresh_ips = btn_refresh_ips

        btn_verify_all = QPushButton("Verificar todos")
        btn_verify_all.setObjectName("btn_secondary")
        btn_verify_all.clicked.connect(self._verify_all)
        title_row.addWidget(btn_verify_all)

        btn_flush = QPushButton("Limpiar todas las reglas")
        btn_flush.setObjectName("btn_danger")
        btn_flush.setToolTip("Elimina TODAS las reglas iptables activas. Restaura conectividad.")
        btn_flush.clicked.connect(self._flush_rules)
        title_row.addWidget(btn_flush)

        layout.addLayout(title_row)

        # Barra de estado mejorada
        self._status_bar = _StatusBar(self._config)
        layout.addWidget(self._status_bar)

        # Panel de diagnostico
        self._diag_panel = _DiagPanel()
        layout.addWidget(self._diag_panel)

        # Estado de actualizacion de IPs
        self._refresh_status = QLabel("")
        self._refresh_status.setObjectName("label_secondary")
        self._refresh_status.setVisible(False)
        layout.addWidget(self._refresh_status)

        # Site cards
        blocked = self._config.get("blocked_domains", BLOCKED_DOMAINS)
        self._site_cards: dict = {}
        for key, cfg in blocked.items():
            card = SiteCard(key, cfg)
            card.toggled.connect(self._on_toggle)
            card.check_requested.connect(self._on_check_requested)
            layout.addWidget(card)
            self._site_cards[key] = card

        layout.addStretch()
        scroll.setWidget(container)
        main_layout.addWidget(scroll)

    def showEvent(self, event):
        super().showEvent(event)
        self._status_bar.refresh()
        self._verify_all()
        if not self._auto_timer.isActive():
            self._auto_timer.start()

    def hideEvent(self, event):
        super().hideEvent(event)
        self._auto_timer.stop()

    def _verify_all(self):
        for key in self._site_cards:
            self._on_check_requested(key)

    def _on_toggle(self, key: str, enabled: bool):
        if "blocked_domains" not in self._config:
            self._config["blocked_domains"] = {}
        if key not in self._config["blocked_domains"]:
            self._config["blocked_domains"][key] = BLOCKED_DOMAINS.get(key, {})
        self._config["blocked_domains"][key]["enabled"] = enabled
        self.config_changed.emit(self._config)

    def _on_check_requested(self, key: str):
        if key in self._checking:
            return
        card = self._site_cards.get(key)
        if not card:
            return
        self._checking.add(key)
        card.set_checking(True)
        domains = (
            self._config.get("blocked_domains", BLOCKED_DOMAINS)
            .get(key, {})
            .get("domains", [])
        )
        primary_domain = domains[0] if domains else ""
        worker = _CheckSiteWorker(key, primary_domain)
        worker.finished.connect(self._on_check_done)
        self._workers.append(worker)
        worker.start()

    def _on_check_done(self, key: str, ip_count: int, reachable: bool):
        self._checking.discard(key)
        self._workers = [w for w in self._workers if w.isRunning()]
        card = self._site_cards.get(key)
        if card:
            card.set_check_result(ip_count, reachable)

    def _on_refresh_ips(self):
        if self._refresh_worker and self._refresh_worker.isRunning():
            return
        self._btn_refresh_ips.setEnabled(False)
        self._btn_refresh_ips.setText("Actualizando...")
        self._refresh_status.setText("Resolviendo IPs...")
        self._refresh_status.setStyleSheet("color: #f59e0b; background: transparent;")
        self._refresh_status.setVisible(True)

        self._refresh_worker = _RefreshIpsetWorker(self._config)
        self._refresh_worker.progress.connect(lambda m: self._refresh_status.setText(m))
        self._refresh_worker.finished.connect(self._on_refresh_done)
        self._refresh_worker.start()

    def _on_refresh_done(self, ok: bool, msg: str):
        self._btn_refresh_ips.setEnabled(True)
        self._btn_refresh_ips.setText("Actualizar IPs bloqueadas")
        if ok:
            self._refresh_status.setText(f"[OK]  {msg}")
            self._refresh_status.setStyleSheet("color: #22c55e; background: transparent;")
        else:
            self._refresh_status.setText(f"[!]  {msg}")
            self._refresh_status.setStyleSheet("color: #ef4444; background: transparent;")
        self._verify_all()

    def _flush_rules(self):
        from app.services import firewall_service
        from PySide6.QtWidgets import QMessageBox
        reply = QMessageBox.warning(
            self, "Limpiar todas las reglas",
            "Esto eliminara TODAS las reglas iptables activas.\n"
            "Los sitios bloqueados volverin a ser accesibles.\n\n¿Continuar?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        ok, msg = firewall_service.flush_all()
        if ok:
            QMessageBox.information(self, "Reglas eliminadas", msg)
            self._verify_all()
        else:
            QMessageBox.warning(self, "Error", f"No se pudo limpiar: {msg}")

    def update_config(self, config: dict):
        self._config = config
        self._status_bar.update_config(config)
        blocked = config.get("blocked_domains", {})
        for key, card in self._site_cards.items():
            if key in blocked:
                card.set_enabled(blocked[key].get("enabled", False))
