#!/usr/bin/env python3
"""
Security Vulnerability Scanner v3.0
Proyecto: Análisis de vulnerabilidades en aplicativos web
Autores: Wilson Martinez, Fabian Campoverde
Universidad Internacional del Ecuador
"""

import nmap
import socket
import dns.resolver
import subprocess
import json
import os
from datetime import datetime
from colorama import Fore, Style, init
from vuln_lookup import buscar_vulnerabilidades

init(autoreset=True)

SECURITY_RECOMMENDATIONS = {
    21: {
        'service': 'FTP',
        'risk': 'ALTO',
        'description': 'FTP transmite credenciales en texto plano',
        'recommendations': [
            'Migrar a SFTP o FTPS',
            'Deshabilitar login anónimo',
            'Implementar autenticación de dos factores',
            'Restringir acceso por IP',
            'Monitorear logs regularmente'
        ],
        'owasp': 'A02:2021 - Cryptographic Failures'
    },
    22: {
        'service': 'SSH',
        'risk': 'MEDIO',
        'description': 'Puerto SSH expuesto a ataques de fuerza bruta',
        'recommendations': [
            'Usar solo claves SSH, deshabilitar contraseñas',
            'Cambiar puerto por defecto',
            'Implementar fail2ban',
            'Deshabilitar login root',
            'Usar 2FA',
            'Mantener SSH actualizado'
        ],
        'owasp': 'A07:2021 - Authentication Failures'
    },
    23: {
        'service': 'Telnet',
        'risk': 'CRITICO',
        'description': 'Telnet transmite todo en texto plano',
        'recommendations': [
            'DESHABILITAR Telnet inmediatamente',
            'Migrar a SSH',
            'Bloquear puerto 23',
            'Auditar sistemas'
        ],
        'owasp': 'A02:2021 - Cryptographic Failures'
    },
    25: {
        'service': 'SMTP',
        'risk': 'MEDIO',
        'description': 'Servidor de correo vulnerable a spam',
        'recommendations': [
            'Configurar SMTP AUTH',
            'Deshabilitar relay abierto',
            'Implementar SPF, DKIM y DMARC',
            'Usar TLS/SSL',
            'Filtros anti-spam'
        ],
        'owasp': 'A05:2021 - Security Misconfiguration'
    },
    80: {
        'service': 'HTTP',
        'risk': 'ALTO',
        'description': 'Tráfico web sin cifrar',
        'recommendations': [
            'Migrar a HTTPS',
            'Implementar redirección HTTP a HTTPS',
            'Configurar HSTS',
            'Certificados SSL válidos',
            'Headers de seguridad'
        ],
        'owasp': 'A02:2021 - Cryptographic Failures'
    },
    443: {
        'service': 'HTTPS',
        'risk': 'BAJO',
        'description': 'HTTPS requiere configuración segura',
        'recommendations': [
            'Usar TLS 1.2 o superior',
            'Cipher suites seguros',
            'Implementar HSTS',
            'Renovar certificados',
            'OCSP Stapling'
        ],
        'owasp': 'A02:2021 - Cryptographic Failures'
    },
    3306: {
        'service': 'MySQL',
        'risk': 'CRITICO',
        'description': 'Base de datos expuesta es riesgo crítico',
        'recommendations': [
            'NO exponer MySQL a Internet',
            'bind-address = 127.0.0.1',
            'Firewall restrictivo',
            'Cambiar puerto',
            'Autenticación fuerte',
            'Cifrar conexiones SSL/TLS'
        ],
        'owasp': 'A05:2021 - Security Misconfiguration'
    },
    3389: {
        'service': 'RDP',
        'risk': 'CRITICO',
        'description': 'RDP objetivo de ransomware',
        'recommendations': [
            'NO exponer RDP a Internet',
            'Usar VPN',
            'Implementar MFA',
            'Cambiar puerto',
            'Network Level Authentication',
            'Monitorear accesos'
        ],
        'owasp': 'A07:2021 - Authentication Failures'
    },
    8080: {
        'service': 'HTTP-ALT',
        'risk': 'ALTO',
        'description': 'Puerto HTTP alternativo',
        'recommendations': [
            'Migrar a HTTPS (8443)',
            'Autenticación robusta',
            'Verificar que no sea desarrollo en producción',
            'Headers de seguridad'
        ],
        'owasp': 'A02:2021 - Cryptographic Failures'
    }
}

class VulnScanner:
    def __init__(self, target):
        self.target = target
        self.ip_address = None
        self.scan_results = {
            'target': target,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'ip_address': None,
            'dns_info': {},
            'ports': [],
            'web_vulnerabilities': [],
            'security_recommendations': [],
            'cve_vulnerabilities': [],
            'risk_summary': {'CRITICO': 0, 'ALTO': 0, 'MEDIO': 0, 'BAJO': 0},
            'summary': {}
        }
    
    def print_banner(self):
        banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════╗
║     SECURITY VULNERABILITY SCANNER v3.0              ║
║     UIDE - Seguridad Informática 2025                ║
║     Con integración NVD/CVE Database                 ║
╚═══════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)
    
    def is_valid_ip(self, address):
        try:
            socket.inet_aton(address)
            return True
        except socket.error:
            return False
    
    def resolve_domain(self):
        print(f"\n{Fore.YELLOW}[*] Resolviendo dominio: {self.target}{Style.RESET_ALL}")
        
        if self.is_valid_ip(self.target):
            print(f"{Fore.GREEN}[+] IP detectada: {self.target}{Style.RESET_ALL}")
            self.ip_address = self.target
            self.scan_results['ip_address'] = self.target
            return True
        
        try:
            answers = dns.resolver.resolve(self.target, 'A')
            self.ip_address = str(answers[0])
            self.scan_results['ip_address'] = self.ip_address
            self.scan_results['dns_info']['A_records'] = [str(rdata) for rdata in answers]
            
            print(f"{Fore.GREEN}[+] Dominio resuelto: {self.target} → {self.ip_address}{Style.RESET_ALL}")
            
            try:
                mx_records = dns.resolver.resolve(self.target, 'MX')
                self.scan_results['dns_info']['MX_records'] = [str(rdata.exchange) for rdata in mx_records]
            except:
                pass
            
            return True
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error al resolver dominio: {e}{Style.RESET_ALL}")
            return False
    
    def aggressive_port_scan(self):
        print(f"\n{Fore.YELLOW}[*] Escaneo AGRESIVO en {self.ip_address}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Top 1000 puertos + detección de servicios{Style.RESET_ALL}")
        
        try:
            nm = nmap.PortScanner()
            print(f"{Fore.YELLOW}[*] Ejecutando: nmap -A -T4 --top-ports 1000 -Pn{Style.RESET_ALL}")
            nm.scan(self.ip_address, arguments='-A -T4 --top-ports 1000 -Pn')
            
            if self.ip_address in nm.all_hosts():
                host_info = nm[self.ip_address]
                
                print(f"{Fore.GREEN}[+] Host detectado{Style.RESET_ALL}")
                
                if 'osmatch' in host_info and host_info['osmatch']:
                    os_matches = host_info['osmatch']
                    if os_matches:
                        best_match = os_matches[0]
                        print(f"{Fore.CYAN}[*] OS: {best_match['name']} ({best_match['accuracy']}%){Style.RESET_ALL}")
                        self.scan_results['os_detection'] = {
                            'name': best_match['name'],
                            'accuracy': best_match['accuracy']
                        }
                
                ports_found = 0
                for proto in host_info.all_protocols():
                    ports = host_info[proto].keys()
                    
                    for port in sorted(ports):
                        port_info = host_info[proto][port]
                        state = port_info['state']
                        
                        if state == 'open':
                            ports_found += 1
                            service = port_info.get('name', 'unknown')
                            version = port_info.get('version', '')
                            product = port_info.get('product', '')
                            
                            port_data = {
                                'port': port,
                                'protocol': proto,
                                'state': state,
                                'service': service,
                                'version': version,
                                'product': product
                            }
                            
                            if port in SECURITY_RECOMMENDATIONS:
                                rec = SECURITY_RECOMMENDATIONS[port]
                                port_data['security_info'] = rec
                                
                                risk_level = rec['risk']
                                self.scan_results['risk_summary'][risk_level] += 1
                                
                                self.scan_results['security_recommendations'].append({
                                    'port': port,
                                    'service': service,
                                    'risk': rec['risk'],
                                    'description': rec['description'],
                                    'recommendations': rec['recommendations'],
                                    'owasp': rec['owasp']
                                })
                                
                                risk_color = Fore.RED if risk_level in ['CRITICO', 'ALTO'] else Fore.YELLOW
                                print(f"{Fore.GREEN}[+] Puerto {port}/{proto} - {service} {product} {version}{Style.RESET_ALL}")
                                print(f"    {risk_color}⚠ RIESGO {risk_level}: {rec['description']}{Style.RESET_ALL}")
                            else:
                                print(f"{Fore.GREEN}[+] Puerto {port}/{proto} - {service} {product} {version}{Style.RESET_ALL}")
                            
                            self.scan_results['ports'].append(port_data)
                            
                            # 🔥 NUEVA FUNCIONALIDAD: Buscar CVEs reales desde NVD
                            if product and version:
                                print(f"{Fore.CYAN}    [🔍] Buscando CVEs para {product} {version}...{Style.RESET_ALL}")
                                cves = buscar_vulnerabilidades(product, version, max_resultados=2)
                                if cves:
                                    port_data['cves'] = cves
                                    for cve in cves:
                                        # Mostrar CVE encontrado
                                        cve_color = Fore.RED if cve['severidad'] in ['CRITICAL', 'HIGH'] else Fore.YELLOW
                                        print(f"    {cve_color}🔴 {cve['cve_id']} - {cve['severidad']} ({cve['cvss_score']}/10){Style.RESET_ALL}")
                                        
                                        self.scan_results['cve_vulnerabilities'].append({
                                            'port': port,
                                            'service': service,
                                            'product': product,
                                            'version': version,
                                            'cve': cve
                                        })
                
                print(f"{Fore.GREEN}[+] Puertos abiertos: {ports_found}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[+] CVEs encontrados: {len(self.scan_results['cve_vulnerabilities'])}{Style.RESET_ALL}")
                return True
            else:
                print(f"{Fore.RED}[!] Host no alcanzable{Style.RESET_ALL}")
                return False
                
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
            return False
    
    def check_web_services(self):
        print(f"\n{Fore.YELLOW}[*] Verificando servicios web...{Style.RESET_ALL}")
        
        web_ports = []
        for port_info in self.scan_results['ports']:
            service = port_info['service'].lower()
            if 'http' in service or port_info['port'] in [80, 443, 8080, 8443]:
                web_ports.append(port_info)
        
        if not web_ports:
            print(f"{Fore.YELLOW}[!] No hay servicios web{Style.RESET_ALL}")
            return False
        
        print(f"{Fore.GREEN}[+] Servicios web en: {[p['port'] for p in web_ports]}{Style.RESET_ALL}")
        
        target_port = web_ports[0]['port']
        protocol = 'https' if target_port == 443 else 'http'
        
        print(f"{Fore.YELLOW}[*] Nikto en {protocol}://{self.ip_address}:{target_port}{Style.RESET_ALL}")
        
        try:
            nikto_output = f"nikto_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            
            cmd = [
                'nikto',
                '-h', f"{protocol}://{self.ip_address}:{target_port}",
                '-output', nikto_output,
                '-Format', 'txt',
                '-maxtime', '120s'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=150)
            
            if os.path.exists(nikto_output) and os.path.getsize(nikto_output) > 0:
                print(f"{Fore.GREEN}[+] Nikto completado: {nikto_output}{Style.RESET_ALL}")
                self.scan_results['web_vulnerabilities'].append({
                    'tool': 'nikto',
                    'output_file': nikto_output,
                    'target': f"{protocol}://{self.ip_address}:{target_port}"
                })
                return True
            else:
                print(f"{Fore.YELLOW}[!] Sin resultados Nikto{Style.RESET_ALL}")
                return False
                
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error Nikto: {e}{Style.RESET_ALL}")
            return False
    
    def generate_html_report(self, json_file):
        """Generar reporte HTML profesional sin emojis"""
        html_file = json_file.replace('.json', '.html')
        
        total_critical = self.scan_results['risk_summary']['CRITICO']
        total_high = self.scan_results['risk_summary']['ALTO']
        total_cves = len(self.scan_results['cve_vulnerabilities'])
        
        # Contar CVEs por severidad
        cves_critical = sum(1 for cve in self.scan_results['cve_vulnerabilities'] 
                           if cve['cve']['severidad'] == 'CRITICAL')
        cves_high = sum(1 for cve in self.scan_results['cve_vulnerabilities'] 
                       if cve['cve']['severidad'] == 'HIGH')
        cves_medium = sum(1 for cve in self.scan_results['cve_vulnerabilities'] 
                         if cve['cve']['severidad'] == 'MEDIUM')
        cves_low = sum(1 for cve in self.scan_results['cve_vulnerabilities'] 
                      if cve['cve']['severidad'] == 'LOW')
        
        # Determinar riesgo general
        if total_critical > 0 or cves_critical > 2:
            overall_risk = 'CRÍTICO'
            overall_color = '#c0392b'
        elif total_high > 2 or cves_critical > 0 or cves_high > 3:
            overall_risk = 'ALTO'
            overall_color = '#d35400'
        elif total_high > 0 or cves_high > 0:
            overall_risk = 'MEDIO'
            overall_color = '#f39c12'
        else:
            overall_risk = 'BAJO'
            overall_color = '#27ae60'
        
        html = f'''<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Análisis de Seguridad - {self.target}</title>
<style>
* {{
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}}

body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    background: #ecf0f1;
    color: #2c3e50;
    line-height: 1.6;
    padding: 20px;
}}

.report-container {{
    max-width: 1200px;
    margin: 0 auto;
    background: white;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}}

.report-header {{
    background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
    color: white;
    padding: 40px;
    border-bottom: 4px solid {overall_color};
}}

.report-header h1 {{
    font-size: 28px;
    font-weight: 600;
    margin-bottom: 8px;
    letter-spacing: -0.5px;
}}

.report-header .institution {{
    font-size: 15px;
    opacity: 0.9;
    margin-bottom: 4px;
}}

.report-header .authors {{
    font-size: 14px;
    opacity: 0.8;
}}

.report-header .nvd-notice {{
    margin-top: 15px;
    padding: 10px 15px;
    background: rgba(255,255,255,0.1);
    border-radius: 4px;
    font-size: 13px;
    border-left: 3px solid #3498db;
}}

.alert-banner {{
    background: {overall_color};
    color: white;
    padding: 20px 40px;
    font-size: 18px;
    font-weight: 600;
    text-align: center;
    letter-spacing: 1px;
}}

.content {{
    padding: 40px;
}}

.section {{
    margin-bottom: 40px;
}}

.section-title {{
    font-size: 20px;
    font-weight: 600;
    color: #2c3e50;
    margin-bottom: 20px;
    padding-bottom: 10px;
    border-bottom: 2px solid #ecf0f1;
}}

.info-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}}

.info-item {{
    background: #f8f9fa;
    padding: 15px;
    border-left: 3px solid #3498db;
    border-radius: 3px;
}}

.info-item .label {{
    font-size: 12px;
    text-transform: uppercase;
    color: #7f8c8d;
    margin-bottom: 5px;
    font-weight: 600;
    letter-spacing: 0.5px;
}}

.info-item .value {{
    font-size: 16px;
    color: #2c3e50;
    font-weight: 500;
}}

.stats-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 15px;
    margin-bottom: 30px;
}}

.stat-card {{
    background: white;
    border: 2px solid #ecf0f1;
    border-radius: 4px;
    padding: 20px;
    text-align: center;
    transition: transform 0.2s;
}}

.stat-card:hover {{
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
}}

.stat-card.critical {{
    border-color: #c0392b;
    background: #fadbd8;
}}

.stat-card.high {{
    border-color: #d35400;
    background: #fdebd0;
}}

.stat-card.medium {{
    border-color: #f39c12;
    background: #fcf3cf;
}}

.stat-card.low {{
    border-color: #27ae60;
    background: #d5f4e6;
}}

.stat-number {{
    font-size: 36px;
    font-weight: 700;
    margin-bottom: 5px;
}}

.stat-card.critical .stat-number {{ color: #c0392b; }}
.stat-card.high .stat-number {{ color: #d35400; }}
.stat-card.medium .stat-number {{ color: #f39c12; }}
.stat-card.low .stat-number {{ color: #27ae60; }}

.stat-label {{
    font-size: 13px;
    text-transform: uppercase;
    color: #7f8c8d;
    font-weight: 600;
    letter-spacing: 0.5px;
}}

.data-table {{
    width: 100%;
    border-collapse: collapse;
    background: white;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    margin-bottom: 20px;
}}

.data-table thead {{
    background: #34495e;
    color: white;
}}

.data-table th {{
    padding: 12px 15px;
    text-align: left;
    font-weight: 600;
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}

.data-table td {{
    padding: 12px 15px;
    border-bottom: 1px solid #ecf0f1;
    font-size: 14px;
}}

.data-table tbody tr:hover {{
    background: #f8f9fa;
}}

.badge {{
    display: inline-block;
    padding: 4px 10px;
    border-radius: 3px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}

.badge-critical {{
    background: #c0392b;
    color: white;
}}

.badge-high {{
    background: #d35400;
    color: white;
}}

.badge-medium {{
    background: #f39c12;
    color: white;
}}

.badge-low {{
    background: #27ae60;
    color: white;
}}

.badge-info {{
    background: #95a5a6;
    color: white;
}}

.badge-nvd {{
    background: #3498db;
    color: white;
}}

.vulnerability-card {{
    background: white;
    border: 1px solid #ecf0f1;
    border-radius: 4px;
    margin-bottom: 20px;
    overflow: hidden;
}}

.vulnerability-card.severity-CRITICAL {{
    border-left: 4px solid #c0392b;
}}

.vulnerability-card.severity-HIGH {{
    border-left: 4px solid #d35400;
}}

.vulnerability-card.severity-MEDIUM {{
    border-left: 4px solid #f39c12;
}}

.vulnerability-card.severity-LOW {{
    border-left: 4px solid #27ae60;
}}

.vulnerability-header {{
    padding: 15px 20px;
    background: #f8f9fa;
    border-bottom: 1px solid #ecf0f1;
}}

.vulnerability-header h3 {{
    font-size: 16px;
    color: #2c3e50;
    margin-bottom: 5px;
}}

.vulnerability-body {{
    padding: 20px;
}}

.vulnerability-meta {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
    margin-bottom: 15px;
}}

.meta-item {{
    font-size: 13px;
}}

.meta-item strong {{
    display: block;
    color: #7f8c8d;
    font-size: 11px;
    text-transform: uppercase;
    margin-bottom: 3px;
}}

.vulnerability-description {{
    background: #f8f9fa;
    padding: 15px;
    border-radius: 3px;
    margin-bottom: 15px;
    font-size: 14px;
    line-height: 1.6;
}}

.references-list {{
    list-style: none;
    margin-top: 10px;
}}

.references-list li {{
    margin-bottom: 8px;
    font-size: 13px;
}}

.references-list a {{
    color: #3498db;
    text-decoration: none;
    word-break: break-all;
}}

.references-list a:hover {{
    text-decoration: underline;
}}

.recommendation-box {{
    background: white;
    border: 1px solid #ecf0f1;
    border-radius: 4px;
    margin-bottom: 20px;
    overflow: hidden;
}}

.recommendation-header {{
    padding: 15px 20px;
    background: #f39c12;
    color: white;
}}

.recommendation-header h3 {{
    font-size: 15px;
}}

.recommendation-body {{
    padding: 20px;
}}

.recommendation-body p {{
    margin-bottom: 10px;
    font-size: 14px;
}}

.recommendation-list {{
    background: #fffbf0;
    padding: 15px;
    border-radius: 3px;
    margin-top: 15px;
}}

.recommendation-list h4 {{
    font-size: 14px;
    margin-bottom: 10px;
    color: #2c3e50;
}}

.recommendation-list ul {{
    margin-left: 20px;
}}

.recommendation-list li {{
    margin-bottom: 8px;
    font-size: 14px;
    color: #555;
}}

.report-footer {{
    background: #2c3e50;
    color: white;
    padding: 30px 40px;
    text-align: center;
}}

.report-footer h3 {{
    font-size: 18px;
    margin-bottom: 10px;
}}

.report-footer p {{
    font-size: 14px;
    opacity: 0.9;
    margin-bottom: 5px;
}}

.report-footer .disclaimer {{
    margin-top: 15px;
    padding-top: 15px;
    border-top: 1px solid rgba(255,255,255,0.2);
    font-size: 12px;
    opacity: 0.7;
}}

@media print {{
    body {{ background: white; padding: 0; }}
    .report-container {{ box-shadow: none; }}
    .vulnerability-card, .recommendation-box {{ page-break-inside: avoid; }}
}}
</style>
</head>
<body>
<div class="report-container">

<div class="report-header">
<h1>ANÁLISIS DE SEGURIDAD INFORMÁTICA</h1>
<div class="institution">Universidad Internacional del Ecuador</div>
<div class="institution">Facultad de Ingeniería en Sistemas</div>
<div class="authors">Wilson Martinez | Fabian Campoverde</div>
<div class="nvd-notice">
Reporte generado con datos verificables de NVD (National Vulnerability Database)
</div>
</div>

<div class="alert-banner">
NIVEL DE RIESGO IDENTIFICADO: {overall_risk}
</div>

<div class="content">

<div class="section">
<div class="section-title">Información del Análisis</div>
<div class="info-grid">
<div class="info-item">
<div class="label">Target Analizado</div>
<div class="value">{self.target}</div>
</div>
<div class="info-item">
<div class="label">Dirección IP</div>
<div class="value">{self.ip_address}</div>
</div>
<div class="info-item">
<div class="label">Fecha de Escaneo</div>
<div class="value">{self.scan_results['timestamp']}</div>
</div>
<div class="info-item">
<div class="label">CVEs Identificados</div>
<div class="value">{total_cves} <span class="badge badge-nvd">NVD</span></div>
</div>
</div>
</div>

<div class="section">
<div class="section-title">Distribución de Riesgos</div>
<div class="stats-grid">
<div class="stat-card critical">
<div class="stat-number">{total_critical}</div>
<div class="stat-label">Crítico</div>
</div>
<div class="stat-card high">
<div class="stat-number">{total_high}</div>
<div class="stat-label">Alto</div>
</div>
<div class="stat-card medium">
<div class="stat-number">{self.scan_results['risk_summary']['MEDIO']}</div>
<div class="stat-label">Medio</div>
</div>
<div class="stat-card low">
<div class="stat-number">{self.scan_results['risk_summary']['BAJO']}</div>
<div class="stat-label">Bajo</div>
</div>
</div>
</div>

<div class="section">
<div class="section-title">Puertos y Servicios Detectados</div>
<table class="data-table">
<thead>
<tr>
<th>Puerto</th>
<th>Protocolo</th>
<th>Servicio</th>
<th>Producto</th>
<th>Versión</th>
<th>Nivel de Riesgo</th>
<th>CVEs</th>
</tr>
</thead>
<tbody>'''
        
        for port in self.scan_results['ports']:
            risk_badge = ''
            if 'security_info' in port:
                risk = port['security_info']['risk']
                badge_class = 'badge-' + risk.lower().replace('í', 'i')
                risk_badge = f'<span class="badge {badge_class}">{risk}</span>'
            else:
                risk_badge = '<span class="badge badge-info">Información</span>'
            
            cve_count = len(port.get('cves', []))
            cve_badge = f'<span class="badge badge-critical">{cve_count}</span>' if cve_count > 0 else '-'
            
            html += f'''
<tr>
<td><strong>{port['port']}</strong></td>
<td>{port['protocol'].upper()}</td>
<td>{port['service']}</td>
<td>{port['product'] if port['product'] else '-'}</td>
<td>{port['version'] if port['version'] else '-'}</td>
<td>{risk_badge}</td>
<td>{cve_badge}</td>
</tr>'''
        
        html += '''
</tbody>
</table>
</div>'''
        
        # Sección de CVEs
        if self.scan_results['cve_vulnerabilities']:
            html += '''
<div class="section">
<div class="section-title">Vulnerabilidades CVE Identificadas</div>
<p style="color:#7f8c8d; margin-bottom:20px; font-size:14px;">
Vulnerabilidades verificadas en la base de datos oficial NVD del gobierno de Estados Unidos. 
Cada CVE incluye referencias oficiales y puntuación CVSS estándar de la industria.
</p>'''
            
            for cve_vuln in self.scan_results['cve_vulnerabilities']:
                cve = cve_vuln['cve']
                
                html += f'''
<div class="vulnerability-card severity-{cve['severidad']}">
<div class="vulnerability-header">
<h3>{cve['cve_id']} <span class="badge badge-{cve['severidad'].lower()}">{cve['severidad']} {cve['cvss_score']}/10</span></h3>
</div>
<div class="vulnerability-body">
<div class="vulnerability-meta">
<div class="meta-item">
<strong>Servicio Afectado</strong>
{cve_vuln['product']} {cve_vuln['version']}
</div>
<div class="meta-item">
<strong>Puerto</strong>
{cve_vuln['port']}/{cve_vuln['service']}
</div>
<div class="meta-item">
<strong>Fecha de Publicación</strong>
{cve['fecha']}
</div>
<div class="meta-item">
<strong>Score CVSS</strong>
{cve['cvss_score']}/10.0
</div>
</div>

<div class="vulnerability-description">
<strong>Descripción:</strong><br>
{cve['descripcion']}
</div>

<div class="meta-item">
<strong>Solución Recomendada</strong>
{cve['solucion']}
</div>

<div class="meta-item" style="margin-top:15px;">
<strong>Referencias Oficiales</strong>
<ul class="references-list">'''
                
                for ref in cve['referencias'][:5]:
                    html += f'<li><a href="{ref}" target="_blank">{ref}</a></li>'
                
                html += '''
</ul>
</div>
</div>
</div>'''
            
            html += '</div>'
        
        # Recomendaciones de seguridad
        if self.scan_results['security_recommendations']:
            html += '''
<div class="section">
<div class="section-title">Recomendaciones de Seguridad</div>'''
            
            for rec in self.scan_results['security_recommendations']:
                html += f'''
<div class="recommendation-box">
<div class="recommendation-header">
<h3>Puerto {rec['port']} - {rec['service']} <span class="badge badge-{rec['risk'].lower().replace('í','i')}" style="background:rgba(255,255,255,0.3);">{rec['risk']}</span></h3>
</div>
<div class="recommendation-body">
<p><strong>Riesgo Identificado:</strong> {rec['description']}</p>
<p><strong>Clasificación OWASP:</strong> {rec['owasp']}</p>

<div class="recommendation-list">
<h4>Acciones Correctivas Recomendadas</h4>
<ul>'''
                
                for r in rec['recommendations']:
                    html += f'<li>{r}</li>'
                
                html += '''
</ul>
</div>
</div>
</div>'''
            
            html += '</div>'
        
        html += '''
</div>

<div class="report-footer">
<h3>Security Vulnerability Scanner</h3>
<p>Versión 3.0 - Universidad Internacional del Ecuador</p>
<p>Desarrollado por Wilson Martinez y Fabian Campoverde</p>
<p>Proyecto de Seguridad Informática - 2025</p>
<div class="disclaimer">
Este análisis se realizó con fines académicos y de investigación en seguridad informática.
Los datos de vulnerabilidades provienen de fuentes oficiales verificables (NVD).
Solo debe realizarse en sistemas con autorización explícita.
</div>
</div>

</div>
</body>
</html>'''
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"{Fore.GREEN}[+] HTML profesional generado: {html_file}{Style.RESET_ALL}")
        return html_file
    
    def generate_report(self):
        print(f"\n{Fore.YELLOW}[*] Generando reportes...{Style.RESET_ALL}")
        
        self.scan_results['summary'] = {
            'total_ports_open': len(self.scan_results['ports']),
            'web_services_found': len([p for p in self.scan_results['ports'] if 'http' in p['service'].lower()]),
            'critical_risks': self.scan_results['risk_summary']['CRITICO'],
            'high_risks': self.scan_results['risk_summary']['ALTO'],
            'total_cves': len(self.scan_results['cve_vulnerabilities'])
        }
        
        report_file = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(self.scan_results, f, indent=4, ensure_ascii=False)
        
        print(f"{Fore.GREEN}[+] JSON: {report_file}{Style.RESET_ALL}")
        
        self.generate_html_report(report_file)
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}RESUMEN{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"Target: {self.target}")
        print(f"Puertos: {self.scan_results['summary']['total_ports_open']}")
        print(f"{Fore.RED}CRÍTICO: {self.scan_results['risk_summary']['CRITICO']}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}ALTO: {self.scan_results['risk_summary']['ALTO']}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}CVEs encontrados: {self.scan_results['summary']['total_cves']} (NVD){Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        return report_file
    
    def run(self):
        self.print_banner()
        
        if not self.resolve_domain():
            return False
        
        self.aggressive_port_scan()
        
        if len(self.scan_results['ports']) > 0:
            self.check_web_services()
        
        self.generate_report()
        
        print(f"\n{Fore.GREEN}[✓] Completado{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Revisa el HTML para ver CVEs oficiales con referencias verificables{Style.RESET_ALL}\n")
        return True

def main():
    print(f"{Fore.CYAN}Security Vulnerability Scanner v3.0 - UIDE 2025{Style.RESET_ALL}\n")
    
    target = input(f"{Fore.YELLOW}Ingrese dominio o IP: {Style.RESET_ALL}").strip()
    
    if not target:
        print(f"{Fore.RED}[!] Target inválido{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.RED}⚠️  ADVERTENCIA: Solo escanee sistemas autorizados{Style.RESET_ALL}\n")
    
    confirm = input(f"{Fore.YELLOW}¿Tiene autorización para escanear {target}? (s/n): {Style.RESET_ALL}").lower()
    
    if confirm != 's':
        print(f"{Fore.RED}[!] Cancelado{Style.RESET_ALL}")
        return
    
    scanner = VulnScanner(target)
    scanner.run()

if __name__ == "__main__":
    main()
