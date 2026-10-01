# Free Scanner: puertos, servicios y vulnerabilidades

Escáner de seguridad para Kali Linux. A partir de un dominio o una IP, encuentra los puertos abiertos y las versiones de cada servicio, busca vulnerabilidades conocidas (CVE) en la base de datos oficial NVD, audita los servidores web con Nikto y entrega un reporte en JSON y otro en HTML.

Proyecto en equipo para la UIDE, por Wilson Martínez y Fabian Campoverde.

> **Uso responsable.** Escanea solo sistemas propios o con autorización por escrito. El programa pide confirmar esa autorización antes de empezar.

## Qué hace

| Paso | Herramienta | Resultado |
| :-- | :-- | :-- |
| 1. Resolución | dnspython | IP del dominio, registros A y MX |
| 2. Puertos y servicios | Nmap `-A -T4 --top-ports 1000 -Pn` | Puertos abiertos, servicio, versión y sistema operativo probable |
| 3. Riesgo por puerto | Reglas propias | Nivel de riesgo, recomendaciones y categoría OWASP Top 10 para FTP, SSH, Telnet, SMTP, HTTP, HTTPS, MySQL, RDP y HTTP alternativo |
| 4. CVE | API 2.0 de la NVD | Vulnerabilidades publicadas para cada servicio y versión, con sus referencias |
| 5. Auditoría web | Nikto | Hallazgos del primer servicio HTTP o HTTPS, con un límite de 120 s |
| 6. Reporte | JSON y HTML | Resumen con puertos, riesgos críticos y altos, y CVE encontrados |

## Instalación

En Kali Linux:

```bash
git clone https://github.com/rslcia11/freeScanerPuertosYServicios.git
cd freeScanerPuertosYServicios
chmod +x install.sh
./install.sh
```

`install.sh` instala Nmap, Nikto y las librerías de Python con `apt`. En otra distribución, instala Nmap y Nikto con su gestor de paquetes y las librerías en un entorno virtual con `pip install -r requirements.txt`.

## Uso

```bash
sudo python3 vuln_scanner.py
```

Hace falta `sudo` para que Nmap pueda detectar el sistema operativo. El programa pide el objetivo y la confirmación de autorización, y al terminar deja en la carpeta actual:

- `report_<fecha>.json`: todos los datos del escaneo.
- `report_<fecha>.html`: el mismo reporte para leer en el navegador.
- `nikto_<fecha>.txt`: la salida completa de Nikto, si había un servicio web.

La API pública de la NVD acepta 5 consultas cada 30 segundos, así que el escáner espera 6 segundos entre consultas. Con muchos servicios, la búsqueda de CVE tarda un poco.

## Estructura

```
vuln_scanner.py   Flujo principal: DNS, Nmap, reglas de riesgo, Nikto y reportes
vuln_lookup.py    Consulta de CVE en la API de la NVD
install.sh        Instalación de dependencias en Kali
requirements.txt  Librerías de Python para instalar con pip
```

## Stack

Python · Nmap · Nikto · NVD API 2.0 · Kali Linux
