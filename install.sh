#!/bin/bash
echo "[*] Instalando dependencias del sistema..."
sudo apt update
sudo apt install -y nmap nikto python3-pip

echo "[*] Instalando librerías de Python..."
pip3 install -r requirements.txt

echo "[+] Todo listo. Ejecuta el escáner con: python3 vuln_scanner.py"
