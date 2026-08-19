# Center Park - Registro de Cambios

## [1.3.2] - 2026-08-18

### Mejorado

- **Informe completo y visual de `rob_info.py`** (módulo 2 del launcher):
  - **Resumen ejecutivo** al inicio con estado general del sistema y conteo de alertas.
  - **Detalle por archivo**: primer/último evento, conteos por categoría con su último evento, IPs y usuarios más frecuentes.
  - **Análisis y tendencias**: alertas contextuales (fuerza bruta, escaneo de puertos, comandos sudo sospechosos), estado del sistema y actividad por hora con gráfico ASCII.
  - **Formato visual**: tabla de categorías con bordes, barras de progreso por categoría, top de IPs/usuarios con contexto, últimos N eventos de cada categoría, primeros eventos del día y eventos más frecuentes.
  - **Estadísticas avanzadas**: salud del sistema (CPU, RAM, disco, servicios críticos, uptime).
  - **JSON mejorado**: secciones `metadata` (hostname, kernel, uptime, OS, usuarios activos), `alertas`, `analisis` (estado general, conteos y recomendaciones) y `detalles` por fase (eventos recientes/frecuentes, IPs y usuarios analizados).

## [1.3.1] - 2026-08-18

### Añadido

- **Launcher de módulos**: CenterPark ahora inicia como un launcher que muestra un menú de módulos **sin escanear la red automáticamente**.
  - Módulo **`[1] Auditoría de Red`**: contiene toda la funcionalidad original (escaneo de red, selección de objetivo, escaneo agresivo, modo monitor/ARP spoofing, DoS, auditoría de vulnerabilidades y exportación). Al salir (opción 7 del menú original) **vuelve al menú de módulos**, no cierra el script.
  - Módulo **`[2] Robar información del sistema`**: ejecuta el módulo externo `rob_info.py`, que analiza los logs del sistema (aplicaciones y sistema) en paralelo por fases y permite guardar un informe JSON.
  - Opción **`[0]`** para salir de CenterPark.
- Nuevos métodos `modulo_launcher()` y `modulo_auditoria_red()`.
- Añadido módulo externo `rob_info.py` (recolector/análisis de logs del sistema).

### Cambiado

- `run()` ya **no escanea la red** al inicio: tras verificar permisos y dependencias muestra el menú de módulos.
- `main_menu()`: la opción 7 ahora devuelve al launcher en lugar de `sys.exit`; se eliminó la opción 8 (rob_info) redundante, ya que es el módulo `[2]` del launcher.
- Banner actualizado a "LAUNCHER DE MÓDULOS".

## [1.3.0] - 2026-08-14

### Corregido

- **Problema crítico de restauración de tablas ARP**: la caché ARP quedaba envenenada durante los ataques y `restore_network()` obtenía direcciones MAC falsas de `arp -a`. Ahora las MAC reales se obtienen **antes del ataque** mediante `_get_real_mac()` (ARP request directo con Scapy, sin depender de la caché) y se almacenan en `self.router_mac` / `self.target_mac`.
- `restore_network()` ahora envía paquetes ARP correctivos con el campo `hwsrc` (MAC origen) explícito para garantizar que los dispositivos acepten la restauración.
- `_arp_spoof()` ahora especifica `hwdst` (MAC destino) explícito para mayor efectividad del spoofing.
- El método `cleanup()` detiene correctamente los spinners activos al recibir `Ctrl+C`.
- Eliminado código muerto (`self.dos_attack = False`) dentro de `get_network_range()`.
- Corregido el orden de `self.spinner_stop = None` para que se ejecute tras `stop_event.set()` y `spinner_thread.join()`.
- Añadido `spinner_thread.join()` faltante en bloques `except` de `scan_network()`.
- Eliminada importación redundante de `get_if_addr` / `get_if_mask` dentro de `get_network_range()` (ya importado por `from scapy.all import *`).

### Añadido

- **Método `_get_real_mac(ip)`**: obtiene la MAC real de una IP mediante un ARP request directo en la red (`srp(Ether/ARP)`), sin depender de la caché ARP del sistema.
- **Spinners animados** durante operaciones largas: escaneo de red (arp-scan / nmap), escaneo agresivo y auditoría de vulnerabilidades. Usan un hilo `daemon` con los caracteres `|/-\` y se detienen correctamente al finalizar o al recibir `Ctrl+C`.
- **Método `get_network_range()`**: detección dinámica del rango de red en formato CIDR (ej. `192.168.1.0/24`) usando la interfaz por defecto de Scapy, con fallback a socket y último recurso fijo.
- **Referencia `self.spinner_stop`** en `__init__()`, `cleanup()` y en todos los métodos que inician spinners, para permitir la detención global desde el manejador de señales.
- **Importación `import ipaddress`** para manipulación de redes CIDR.

### Cambiado

- **`scan_network()`**: la IP fija `'192.168.1.0/24'` ha sido sustituida por `self.get_network_range()` para el fallback con nmap.
- **`_get_router_ip()`**: ahora usa la tabla de rutas de Scapy (`conf.route.route("0.0.0.0")`) en lugar de `ip route`, con fallback a deducción desde la red local.
- **`arp_spoof_monitor()`** y **`arp_spoof_dos()`**: ahora obtienen las MAC reales del router y el objetivo antes de iniciar el ataque, y abortan si no se pueden obtener.
- **`restore_network()`**: ya no consulta `_get_mac()` (que leía la caché ARP envenenada); usa `self.router_mac` y `self.target_mac` con fallback a `_get_real_mac()`.
- **Versión**: actualizada de 1.2 a 1.3 en el banner, docstring, reportes y scripts de instalación.

## [1.0.0] - 2026-05-22

### Añadido

#### Funcionalidades Principales
- Implementación del módulo de captura y análisis de tráfico WiFi
  - Detección automática de interfaces WiFi disponibles
  - Activación de modo monitor mediante airmon-ng
  - Escaneo de red para identificación de dispositivos
  - Captura de paquetes en tiempo real utilizando Scapy
  - Filtrado por dirección IP específica
  - Visualización de datos en tiempo real con formato estructurado
  - Manejo de señales del sistema para finalización controlada
  - Restauración automática de configuración de red
  - Sistema de logging en archivo de texto
  - Interfaz de línea de comandos interactiva

#### Documentación
- Guía completa de instalación y configuración (README.md)
- Especificaciones de requisitos del sistema
- Procedimientos de instalación detallados
- Manual de uso y operación
- Guía de resolución de problemas
- Información de licencia

#### Scripts de Despliegue
- Script de instalación automatizada (install.sh)
  - Verificación de privilegios de ejecución
  - Instalación de paquetes del sistema
  - Instalación de dependencias Python
  - Validación de instalación

#### Configuración
- Archivo de configuración personalizable (config.ini)
  - Parámetros de visualización
  - Filtros de red configurables
  - Opciones de rendimiento

#### Utilidades
- Archivo de ejemplo de salida (example_output.txt)
- Gestión de dependencias (requirements.txt)
- Configuración de exclusión de archivos (.gitignore)

### Características Técnicas
- Detección automática de interfaces WiFi
- Gestión de modo monitor
- Escaneo de red multi-método (arp-scan, ping sweep, cache ARP)
- Captura de paquetes con filtrado
- Visualización en tiempo real con interfaz de colores
- Gestión de señales del sistema
- Restauración de configuración de red
- Sistema de logging
- Interfaz CLI interactiva
- Exportación de resultados (JSON/TXT)
- Análisis de vulnerabilidades con nmap
- Escaneo agresivo de puertos y servicios
- Base de datos de vendors MAC

### Requisitos del Sistema
- Sistema Operativo: Linux
- Arquitectura: 32/64 bits
- Python: 3.6+
- Dependencias: scapy, aircrack-ng, iw, wireless-tools, nmap, arp-scan
- Privilegios: sudo

### Notas de la Versión
- Primer lanzamiento estable
- Captura pasiva de tráfico de red
- Requiere tarjeta WiFi con soporte de modo monitor

---

## [Unreleased]

### Mejoras Planificadas
- Soporte para múltiples interfaces WiFi simultáneas
- Análisis estadístico avanzado de tráfico
- Detección y clasificación de protocolos específicos
- Exportación de datos en múltiples formatos (JSON, CSV, XML)
- Interfaz web opcional para visualización remota
- Sistema de notificaciones de eventos
- Soporte completo para IPv6
- Mejora en el manejo de errores de red
- Optimización de rendimiento en captura de paquetes
- Sistema de plugins extensible

