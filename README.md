# CenterPark - Herramienta de Análisis y Auditoría de Redes

![CenterPark v1.3](https://img.shields.io/badge/CenterPark-v1.3-green)
![Python 3.6+](https://img.shields.io/badge/Python-3.6%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey)
![License](https://img.shields.io/badge/License-EUPL%20v1.2-blue)

## Descripción

**CenterPark v1.3** es una aplicación completa de **análisis y auditoría de redes WiFi/LAN** escrita en Python. Permite escanear dispositivos, capturar tráfico mediante ARP spoofing, interrumpir la conectividad de un objetivo (modo DoS), ejecutar escaneos agresivos y auditorías de vulnerabilidades con nmap, y exportar todos los resultados.

Este proyecto está pensado exclusivamente para **auditores de seguridad**, administradores de red y estudiantes que necesiten analizar sus propias redes o redes sobre las que tengan **autorización explícita por escrito**.

> ⚠️ **ADVERTENCIA ÉTICA Y LEGAL**
>
> El uso de esta herramienta en redes ajenas **sin autorización es ilegal** y puede constituir un delito. El autor no se hace responsable del mal uso de este software. Usted es el único responsable de cumplir con todas las leyes locales, nacionales e internacionales aplicables.

## Características

- 🔍 **Detección dinámica de la red**: ya **no usa IP fija**; detecta el rango real (CIDR) mediante Scapy, funcionando en redes `/16`, `/24`, etc., incluso **sin acceso a Internet**.
- 🛡️ **Restauración correcta de tablas ARP**: obtiene las **MAC reales antes de iniciar cualquier ataque** (ARP request directo con Scapy, sin depender de la caché ARP) y las usa para restaurar la red al finalizar.
- ⏳ **Spinners animados**: indicador de progreso durante operaciones largas (escaneo de red, escaneo agresivo y auditoría de vulnerabilidades).
- 🧱 Escaneo de red con `arp-scan` y fallback a `nmap` (`-sn`).
- 📋 Tabla de dispositivos con vendor MAC (base OUI local, sin Internet).
- 🌐 Detección del gateway mediante la tabla de rutas de Scapy.
- 🧪 Escaneo agresivo con nmap (`-A -T4 -O -sV -sC`).
- 🔓 Auditoría de vulnerabilidades con nmap (`--script=vuln`).
- 📤 Exportación de resultados a **JSON y TXT**.
- 🎨 Interfaz de colores ANSI, menú interactivo y manejo de `Ctrl+C`.

## Requisitos

### Sistema
- **Sistema Operativo**: Linux (Debian/Ubuntu recomendado)
- **Permisos**: root/sudo (necesario para Scapy y ARP)
- **Arquitectura**: 32/64 bits

### Dependencias del sistema
- `python3` (3.6+) y `python3-pip`
- `nmap`
- `arp-scan`
- `net-tools` (opcional, para `ip`/`ifconfig`)

### Módulos Python
- `scapy`
- `python-nmap`

## Instalación

### Opción 1: instalación automática (recomendada)

Clona el repositorio y ejecuta el instalador:

```bash
git clone https://github.com/Kblake/centerpark.git
cd centerpark
chmod +x install.sh
sudo ./install.sh
```

El script instalará todos los paquetes del sistema, las dependencias Python y verificará que todo esté listo.

### Opción 2: instalación manual

```bash
# Paquetes del sistema
sudo apt update
sudo apt install -y python3 python3-pip nmap arp-scan net-tools \
                   python3-nmap aircrack-ng iw wireless-tools build-essential \
                   libssl-dev libffi-dev

# Dependencias Python
pip3 install -r requirements.txt
```

## Uso

```bash
sudo python3 centerpark_v1.3.py
```

Al iniciar, la herramienta:
1. Verifica permisos y dependencias.
2. Escanea la red (con spinner de progreso) y muestra los dispositivos encontrados.
3. Muestra el menú principal.

### Menú principal

| Opción | Acción |
|--------|--------|
| **1** | Escaneo agresivo del objetivo (nmap `-A -T4 -O -sV -sC`) |
| **2** | Modo monitor: ARP spoofing + captura de tráfico |
| **3** | Denied Service: ARP flooding para cortar Internet al objetivo |
| **4** | Auditoría de vulnerabilidades (nmap `--script=vuln`) |
| **5** | Exportar resultados a JSON/TXT |
| **6** | Cambiar de dispositivo objetivo |
| **7** | Salir (restaura la red) |

> 💡 Tanto en el modo monitor como en el DoS, las **MAC reales se capturan antes del ataque** y se restauran automáticamente al salir (con `Ctrl+C` o desde el menú).

## Notas de la versión 1.3

### Detección dinámica de red

El script ya no asume `192.168.1.0/24`. Ahora obtiene el rango real mediante `get_network_range()`:

1. Lee IP y máscara de la interfaz por defecto de Scapy.
2. Si falla, obtiene la IP local por socket (asumiendo `/24`).
3. Si todo falla, usa `192.168.1.0/24` como último recurso.

Del mismo modo, el router se detecta con la tabla de rutas de Scapy (`conf.route.route`) y solo como fallback se deduce de la red local.

### Restauración fiable de ARP

Durante ARP spoofing/DoS la caché ARP del sistema queda envenenada, por lo que **no se puede confiar en `arp -a`** para restaurar. Por eso:

1. Antes del ataque se obtienen las MAC reales con `_get_real_mac()` (ARP request directo).
2. Se almacenan en `self.router_mac` y `self.target_mac`.
3. Al restaurar, se envían paquetes ARP correctivos con `hwsrc` explícito usando esas MAC reales.

## Estructura del proyecto

```
centerpark/
├── centerpark_v1.3.py    # Script principal
├── install.sh            # Instalación automática
├── README.md             # Esta documentación
├── CHANGELOG.md          # Registro de cambios
├── LICENSE.txt           # Licencia EUPL v1.2
├── requirements.txt      # Dependencias Python
├── config.ini.example    # Plantilla de configuración
├── example_output.txt    # Ejemplo de salida
└── .gitignore            # Exclusión de archivos para Git
```

## Exportación de resultados

Desde el menú, la opción **5** guarda una sesión en `~/centerpark_reports/`:

- `centerpark_session_YYYYMMDD_HHMMSS.json`
- `centerpark_session_YYYYMMDD_HHMMSS.txt`

## Solución de problemas

| Error | Solución |
|-------|----------|
| `No module named 'scapy'` | `pip3 install scapy` o `sudo ./install.sh` |
| `ModuleNotFoundError: nmap` | `pip3 install python-nmap` |
| `Permission denied` | Ejecute con `sudo` |
| `nmap: command not found` | `sudo apt install nmap` |
| La red no se restaura | Vuelva a ejecutar el script; usa `_get_real_mac` para restaurar |

## Licencia

Este proyecto se distribuye bajo la **European Union Public Licence (EUPL) v1.2**. Consulte [LICENSE.txt](LICENSE.txt) para más información.

## Contribuciones

Las contribuciones son bienvenidas:
- Abra un *Issue* para reportar errores o sugerir mejoras.
- Envíe un *Pull Request* con sus cambios y una descripción clara.
- Actualice el `CHANGELOG.md` y la documentación cuando corresponda.

## Contacto

**Autor**: Kblake
**Fecha**: 2026

---

*Versión: 1.3*
*Fecha: 2026*

### Aviso Legal

El autor de este script **no se hace responsable** del uso que terceros puedan darle. El usuario **asume toda la responsabilidad** por el uso de este software. Utilícelo únicamente en redes que posea o para las que cuente con autorización explícita por escrito.
