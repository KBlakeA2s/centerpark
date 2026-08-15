#!/bin/bash

# ================================
# Center Park v1.3 - Script de Instalación
# ================================
# Este script instala automáticamente todas las dependencias
# necesarias para ejecutar centerpark_v1.3.py

# Colores para la terminal
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
BLUE='\033[94m'
CYAN='\033[96m'
NC='\033[0m' # No Color

# Función para imprimir mensajes
print_message() {
    echo -e "${CYAN}[Center Park]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[ADVERTENCIA]${NC} $1"
}

# Verificar si se ejecuta como root
if [ "$EUID" -ne 0 ]; then
    print_error "Este script debe ejecutarse como root (sudo)"
    echo "Ejecute con: sudo ./install.sh"
    exit 1
fi

# Mostrar encabezado
clear
print_message "=========================================="
print_message "  CENTER PARK v1.3 - Instalación Automática"
print_message "=========================================="
echo

# Actualizar sistema
print_message "Actualizando lista de paquetes..."
if apt update -qq; then
    print_success "Lista de paquetes actualizada"
else
    print_error "No se pudo actualizar la lista de paquetes"
    exit 1
fi
echo

# Instalar dependencias del sistema
print_message "Instalando dependencias del sistema..."
PACKAGES=(
    "python3"
    "python3-pip"
    "python3-dev"
    "python3-nmap"
    "nmap"
    "arp-scan"
    "net-tools"
    "aircrack-ng"
    "iw"
    "wireless-tools"
    "build-essential"
    "libssl-dev"
    "libffi-dev"
)

for pkg in "${PACKAGES[@]}"; do
    if apt install -y -qq "$pkg" > /dev/null 2>&1; then
        print_success "Instalado: $pkg"
    else
        print_warning "No se pudo instalar: $pkg"
    fi
done
echo

# Instalar Scapy
print_message "Instalando Scapy..."
if pip3 install scapy --quiet; then
    print_success "Scapy instalado"
else
    print_error "No se pudo instalar Scapy"
    print_warning "Intentando instalar con --user..."
    pip3 install scapy --user --quiet
    if [ $? -eq 0 ]; then
        print_success "Scapy instalado con --user"
    else
        print_error "No se pudo instalar Scapy. Intente manualmente: pip3 install scapy"
    fi
fi

# Instalar python-nmap (módulo Python)
print_message "Verificando python-nmap..."
if python3 -c "import nmap; print('python-nmap disponible')" 2>/dev/null; then
    print_success "python-nmap ya estaba instalado"
else
    print_message "Instalando python-nmap..."
    if pip3 install python-nmap --quiet 2>/dev/null; then
        print_success "python-nmap instalado"
    else
        print_warning "No se pudo instalar python-nmap, verifique con: pip3 install python-nmap"
    fi
fi
echo

# Verificar instalación
print_message "Verificando instalación..."

# Verificar Python 3
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1)
    print_success "Python 3: $PYTHON_VERSION"
else
    print_error "Python 3 no está instalado"
fi

# Verificar Scapy
if python3 -c "import scapy; print('Scapy', scapy.__version__)" 2>/dev/null; then
    SCAPY_VERSION=$(python3 -c "import scapy; print(scapy.__version__)" 2>/dev/null)
    print_success "Scapy: $SCAPY_VERSION"
else
    print_error "Scapy no está instalado correctamente"
fi

# Verificar python-nmap
if python3 -c "import nmap" 2>/dev/null; then
    print_success "python-nmap: instalado"
else
    print_error "python-nmap no está instalado"
fi

# Verificar nmap
if command -v nmap &> /dev/null; then
    print_success "nmap: $(which nmap)"
else
    print_error "nmap no está instalado"
fi

# Verificar arp-scan
if command -v arp-scan &> /dev/null; then
    print_success "arp-scan: $(which arp-scan)"
else
    print_error "arp-scan no está instalado"
fi

# Verificar airmon-ng
if command -v airmon-ng &> /dev/null; then
    print_success "airmon-ng: $(which airmon-ng)"
else
    print_error "airmon-ng no está instalado"
fi
echo

# Dar permisos de ejecución al script
print_message "Configurando permisos..."
if [ -f "centerpark_v1.3.py" ]; then
    chmod +x centerpark_v1.3.py
    print_success "Permisos configurados para centerpark_v1.3.py"
else
    print_error "No se encontró centerpark_v1.3.py en el directorio actual"
fi
echo

# Mostrar instrucciones finales
print_message "=========================================="
print_message "  INSTALACIÓN COMPLETADA"
print_message "=========================================="
echo
print_message "Para ejecutar Center Park v1.3:"
print_success "  1. Conéctese a una red WiFi o LAN"
print_success "  2. Ejecute: sudo python3 centerpark_v1.3.py"
print_success "  3. Siga las instrucciones en pantalla"
echo
print_warning "ADVERTENCIA: Esta herramienta solo debe usarse en"
print_warning "redes propias o con autorización explícita por escrito."
echo
print_message "Directorio de instalación: $(pwd)"
print_message "=========================================="
