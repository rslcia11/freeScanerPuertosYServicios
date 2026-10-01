#!/bin/bash
# Kali bloquea pip a nivel de sistema (PEP 668), así que las librerías se instalan con apt.
echo "[*] Instalando Nmap, Nikto y las librerías de Python..."
sudo apt update
sudo apt install -y nmap nikto python3-nmap python3-requests python3-dnspython python3-colorama

echo "[+] Todo listo. Ejecuta el escáner con: sudo python3 vuln_scanner.py"
