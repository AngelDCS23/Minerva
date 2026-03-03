import nmap
import socket
import re
import subprocess
import requests 
import time  
import os
from dotenv import load_dotenv

load_dotenv()

class MinervaScanner:
    def __init__(self):
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            print("Error: No se encontró Nmap instalado en el sistema.")
            exit(1)

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip

    def discover_ips(self, target=None):
        if target:
            network_range = target
        else:
            local_ip = self.get_local_ip()
            network_range = ".".join(local_ip.split('.')[:-1]) + ".0/24"
        
        print(f"[*] Minerva iniciando descubrimiento en: {network_range}")
        self.nm.scan(hosts=network_range, arguments='-sn')
        
        hosts_list = []
        for host in self.nm.all_hosts():
            hosts_list.append({
                "ip": host,
                "hostname": self.nm[host].hostname() if self.nm[host].hostname() else "Desconocido",
                "status": self.nm[host].state()
            })
        return hosts_list

    def get_nvd_description(self, cve_id):
        """Consulta la API de NVD para obtener la descripción real del CVE."""
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        try:
            api_key = os.getenv("NVD_API_KEY")
            
            headers = {"User-Agent": "Minerva-Security-Scanner"}
            
            if api_key:
                headers["apiKey"] = api_key
                time.sleep(0.1)
            else:
                time.sleep(0.6)
            
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if "vulnerabilities" in data and len(data["vulnerabilities"]) > 0:
                    descriptions = data["vulnerabilities"][0]["cve"]["descriptions"]
                    for desc in descriptions:
                        if desc["lang"] == "en":
                            return desc["value"]
                            
            elif response.status_code == 403:
                return "Descripción temporalmente no disponible (Límite de API NVD alcanzado)."
                
        except Exception as e:
            print(f"[-] Error conectando a NVD para {cve_id}: {e}")
            
        return "Vulnerabilidad detectada. Detalles específicos no disponibles."

    def scan_host_details(self, ip, mode="deep"):
        if mode == "vuln":
            print(f"[*] Minerva iniciando VULN Scan RÁPIDO en: {ip}")
            scan_args = '-sV -O -T4 -Pn --script vulners'
        else:
            print(f"[*] Minerva iniciando Deep Scan en: {ip}")
            scan_args = '-sV -O -T4 -Pn'

        self.nm.scan(ip, arguments=scan_args)
        
        port_info = []
        os_info = "Unknown OS"
        vendor_info = "Unknown Vendor"
        
        if ip in self.nm.all_hosts():
            if 'osmatch' in self.nm[ip] and len(self.nm[ip]['osmatch']) > 0:
                os_info = self.nm[ip]['osmatch'][0]['name']
            if 'vendor' in self.nm[ip] and len(self.nm[ip]['vendor']) > 0:
                vendor_info = list(self.nm[ip]['vendor'].values())[0]

            if self.nm[ip].all_protocols():
                for proto in self.nm[ip].all_protocols():
                    ports = self.nm[ip][proto].keys()
                    for port in ports:
                        info = self.nm[ip][proto][port]
                        vulns_found = {} 
                        
                        if 'script' in info and 'vulners' in info['script']:
                            lines = info['script']['vulners'].split('\n')
                            for line in lines:
                                if 'CVE-' in line:
                                    parts = [p.strip() for p in line.split('\t') if p.strip()]
                                    if len(parts) >= 2:
                                        raw_cve = parts[0]
                                        cvss = parts[1] if len(parts) > 1 else "0.0"
                                        
                                        match = re.search(r'(CVE-\d{4}-\d+)', raw_cve)
                                        clean_cve = match.group(1) if match else raw_cve
                                        
                                        if clean_cve not in vulns_found:
                                            try:
                                                score = float(cvss)
                                                severity = "High" if score >= 7.0 else "Medium" if score >= 4.0 else "Low"
                                            except:
                                                severity = "Unknown"
                                            
                                            print(f"  [+] Descargando datos del NIST para {clean_cve}...")
                                            real_desc = self.get_nvd_description(clean_cve)
                                                
                                            vulns_found[clean_cve] = {
                                                "cve_id": clean_cve, "cvss": cvss, "severity": severity, 
                                                "desc": real_desc
                                            }

                        port_info.append({
                            "port_number": int(port),
                            "protocol": proto,
                            "service_name": info.get('name', 'unknown'),
                            "state": info.get('state', 'unknown'),
                            "version_info": f"{info.get('product', '')} {info.get('version', '')}".strip(),
                            "vulns": list(vulns_found.values()) 
                        })
                        
        return port_info, os_info, vendor_info

    def get_network_context(self):
        print("[*] Minerva buscando configuración de red (DHCP Discover)...")
        try:
            result = subprocess.run(
                ['nmap', '--script', 'broadcast-dhcp-discover'], 
                capture_output=True, text=True, timeout=20
            )
            output = result.stdout
            router_match = re.search(r"Router:\s*([0-9\.]+)", output)
            subnet_match = re.search(r"Subnet Mask:\s*([0-9\.]+)", output)
            
            gateway = router_match.group(1) if router_match else "Desconocido"
            subnet = subnet_match.group(1) if subnet_match else "Desconocido"
            
            return gateway, subnet
        except Exception as e:
            return "192.168.1.1", "255.255.255.0"

if __name__ == "__main__":
    minerva = MinervaScanner()
    print("Test IP:", minerva.get_local_ip())