# M-FIREWALL

Administrador de seguridad iptables con interfaz gráfica.

**Integrantes:**
- Quezada Juarez Fabrizio
- Espinola Figueroa Manuel
- Sanchez Bonifaz Lucero

## Instalación (Kali Linux)

```bash
git clone https://github.com/USUARIO/proyecto-m-firewall.git
cd proyecto-m-firewall
chmod +x scripts/*.sh run.sh
sudo ./scripts/install.sh
./run.sh
```

## Uso en Windows (modo demostración)

```bash
pip install -r requirements.txt
python run.py
```

## Funciones

- Bloqueo de Facebook, YouTube y Hotmail por IP
- Bloqueo cliente → servidor (estados NEW/ESTABLISHED)
- Bloqueo por dirección MAC con escáner de red
- Límite de conexiones simultáneas (connlimit)
- Registro de paquetes rechazados en tiempo real
- Archivo personalizado: `/opt/proyecto-m/rules/project_m.rules.v4`
- Copias de seguridad automáticas
- Modo demostración en Windows
