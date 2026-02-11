# 🛡️ Free Scanner: Puertos, Servicios y Vulnerabilidades (v3.0)

Este proyecto es un escáner de seguridad automatizado desarrollado para **Kali Linux**. Combina la potencia de Nmap y Nikto con la inteligencia de la base de datos de vulnerabilidades (CVE) de la NVD.

---

## 🚀 Funcionalidades Principales

* **Escaneo de Red:** Identificación de puertos abiertos y detección de servicios/versiones mediante Nmap.
* **Detección de CVEs:** Consulta automática a la API de la NVD para encontrar vulnerabilidades conocidas basadas en las versiones de los servicios detectados.
* **Auditoría Web:** Integración con Nikto para escaneos de vulnerabilidades en servidores HTTP/HTTPS.
* **Reportes Multiformato:** Genera reportes detallados en **JSON** (para análisis de datos) y **HTML Profesional** (para lectura humana).

---

## 🛠️ Instalación y Uso rápido

Para desplegar esta herramienta en un entorno Kali Linux, sigue estos pasos:

### 1. Clonar el repositorio
```bash
git clone [https://github.com/rslcia11/freeScanerPuertosYServicios.git](https://github.com/rslcia11/freeScanerPuertosYServicios.git)
cd freeScanerPuertosYServicios
```
### 2. Instalar dependencias
```bash
El script install.sh configurará automáticamente Nmap, Nikto y las librerías de Python:
chmod +x install.sh
sudo ./install.sh
```
### 3. Ejecutar el escáner
Para que la detección de versiones y OS funcione correctamente, lanza el script con privilegios de superusuario:
```bash
sudo python3 vuln_scanner.py
```
