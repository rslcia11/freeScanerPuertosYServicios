#!/usr/bin/env python3
"""
Módulo de consulta de vulnerabilidades reales desde NVD
National Vulnerability Database - Oficial de EEUU
"""

import requests
import time
from colorama import Fore, Style

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def buscar_vulnerabilidades(servicio, version=None, max_resultados=3):
    """
    Busca vulnerabilidades reales en la base de datos NVD
    
    Args:
        servicio: Nombre del servicio (ej: 'OpenSSH', 'Apache')
        version: Versión específica (ej: '8.2', '2.4.7')
        max_resultados: Cantidad máxima de CVEs a retornar
        
    Returns:
        Lista de diccionarios con CVEs encontrados
    """
    print(f"{Fore.CYAN}    [*] Consultando NVD para {servicio} {version or ''}...{Style.RESET_ALL}")
    
    # Construir query de búsqueda
    query = servicio
    if version:
        query += f" {version}"
    
    params = {
        "keywordSearch": query,
        "resultsPerPage": max_resultados
    }
    
    try:
        # Hacer request a la API
        response = requests.get(NVD_API_URL, params=params, timeout=10)
        
        # Verificar respuesta
        if response.status_code == 200:
            data = response.json()
            
            vulnerabilidades = []
            cves_encontrados = data.get("vulnerabilities", [])
            
            if not cves_encontrados:
                print(f"{Fore.YELLOW}    [!] No se encontraron CVEs para {servicio}{Style.RESET_ALL}")
                return []
            
            for item in cves_encontrados:
                cve_data = item.get("cve", {})
                
                # ID del CVE
                cve_id = cve_data.get("id", "N/A")
                
                # Descripción
                descriptions = cve_data.get("descriptions", [])
                descripcion = descriptions[0].get("value", "Sin descripción") if descriptions else "Sin descripción"
                
                # Severidad y Score CVSS
                severidad = "DESCONOCIDA"
                cvss_score = 0.0
                
                metricas = cve_data.get("metrics", {})
                
                # Intentar obtener CVSS v3.1 (más reciente)
                if "cvssMetricV31" in metricas and metricas["cvssMetricV31"]:
                    cvss_data = metricas["cvssMetricV31"][0]["cvssData"]
                    severidad = cvss_data.get("baseSeverity", "DESCONOCIDA")
                    cvss_score = cvss_data.get("baseScore", 0.0)
                # Si no, intentar CVSS v3.0
                elif "cvssMetricV30" in metricas and metricas["cvssMetricV30"]:
                    cvss_data = metricas["cvssMetricV30"][0]["cvssData"]
                    severidad = cvss_data.get("baseSeverity", "DESCONOCIDA")
                    cvss_score = cvss_data.get("baseScore", 0.0)
                # Si no, intentar CVSS v2
                elif "cvssMetricV2" in metricas and metricas["cvssMetricV2"]:
                    cvss_score = metricas["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", 0.0)
                    # Convertir score v2 a severidad
                    if cvss_score >= 7.0:
                        severidad = "HIGH"
                    elif cvss_score >= 4.0:
                        severidad = "MEDIUM"
                    else:
                        severidad = "LOW"
                
                # Referencias
                referencias = []
                refs = cve_data.get("references", [])
                for ref in refs[:3]:  # Máximo 3 referencias
                    referencias.append(ref.get("url", ""))
                
                # Fecha de publicación
                fecha_publicacion = cve_data.get("published", "Desconocida")
                
                vulnerabilidad = {
                    "cve_id": cve_id,
                    "descripcion": descripcion[:200] + "..." if len(descripcion) > 200 else descripcion,
                    "severidad": severidad,
                    "cvss_score": cvss_score,
                    "fecha": fecha_publicacion.split("T")[0] if "T" in fecha_publicacion else fecha_publicacion,
                    "solucion": "Actualizar el servicio a la versión más reciente con parches de seguridad aplicados",
                    "referencias": referencias
                }
                
                vulnerabilidades.append(vulnerabilidad)
            
            if vulnerabilidades:
                print(f"{Fore.GREEN}    [+] Encontrados {len(vulnerabilidades)} CVE(s){Style.RESET_ALL}")
            
            return vulnerabilidades
            
        elif response.status_code == 403:
            print(f"{Fore.YELLOW}    [!] API rate limit alcanzado, esperando...{Style.RESET_ALL}")
            time.sleep(6)  # NVD tiene límite de 5 requests/30 seg
            return []
        else:
            print(f"{Fore.YELLOW}    [!] Error API: Status {response.status_code}{Style.RESET_ALL}")
            return []
            
    except requests.exceptions.Timeout:
        print(f"{Fore.YELLOW}    [!] Timeout consultando NVD{Style.RESET_ALL}")
        return []
    except requests.exceptions.RequestException as e:
        print(f"{Fore.YELLOW}    [!] Error de conexión: {str(e)[:50]}{Style.RESET_ALL}")
        return []
    except Exception as e:
        print(f"{Fore.RED}    [!] Error inesperado: {str(e)[:50]}{Style.RESET_ALL}")
        return []


def test_modulo():
    """
    Función de prueba del módulo
    """
    print("\n🔍 Probando módulo vuln_lookup.py\n")
    
    # Test 1: OpenSSH
    print("=" * 60)
    print("TEST 1: Buscando vulnerabilidades de OpenSSH 8.2")
    print("=" * 60)
    vulns = buscar_vulnerabilidades("OpenSSH", "8.2", max_resultados=2)
    
    for v in vulns:
        print(f"\n🔴 {v['cve_id']} - {v['severidad']} ({v['cvss_score']}/10)")
        print(f"   Fecha: {v['fecha']}")
        print(f"   Descripción: {v['descripcion']}")
        print(f"   Solución: {v['solucion']}")
        if v['referencias']:
            print(f"   Referencias:")
            for ref in v['referencias']:
                print(f"     - {ref}")
    
    print("\n" + "=" * 60)
    print("TEST 2: Buscando vulnerabilidades de Apache")
    print("=" * 60)
    vulns = buscar_vulnerabilidades("Apache httpd", "2.4", max_resultados=2)
    
    for v in vulns:
        print(f"\n🔴 {v['cve_id']} - {v['severidad']} ({v['cvss_score']}/10)")
        print(f"   Descripción: {v['descripcion']}")


if __name__ == "__main__":
    # Si ejecutas este archivo directamente, corre las pruebas
    test_modulo()
