import nmap
import socket
import re
import subprocess

class MinervaScanner:
    def __init__(self):
        # Inicializamos el objeto PortScanner de nmap
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            print("Error: No se encontró Nmap instalado en el sistema.")
            print("Instálalo con: sudo apt install nmap")
            exit(1)

    def get_local_ip(self):
        """
        Detecta la IP privada actual de tu ThinkPad en la red local.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # No envía datos reales, solo sirve para identificar la interfaz de red activa
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip

    def discover_ips(self):
        """
        Realiza un 'Ping Sweep' rápido en el segmento /24 de la red local
        para encontrar qué dispositivos están encendidos.
        """
        local_ip = self.get_local_ip()
        # Construimos el rango de red (ej: de 192.168.1.15 a 192.168.1.0/24)
        network_range = ".".join(local_ip.split('.')[:-1]) + ".0/24"
        
        print(f"[*] Minerva iniciando descubrimiento en: {network_range}")
        
        # -sn: Escaneo de tipo ping (no escanea puertos todavía, es mucho más rápido)
        # Se recomienda ejecutar como sudo para obtener mejores resultados (MACs, hostnames)
        self.nm.scan(hosts=network_range, arguments='-sn')
        
        hosts_list = []
        for host in self.nm.all_hosts():
            hosts_list.append({
                "ip": host,
                "hostname": self.nm[host].hostname() if self.nm[host].hostname() else "Desconocido",
                "status": self.nm[host].state()
            })
        return hosts_list

    def scan_host_details(self, ip):
        """
        Escaneo profundo de un host para encontrar puertos, servicios y versiones.
        """
        print(f"[*] Minerva iniciando escaneo profundo (Deep Scan) en: {ip}")
        # -sV: Detección de versiones, -T4: Agresivo/Rápido, -Pn: Omitir ping previo
        self.nm.scan(ip, arguments='-sV -T4 -Pn')
        
        port_info = []
        if ip in self.nm.all_hosts():
            for proto in self.nm[ip].all_protocols():
                ports = self.nm[ip][proto].keys()
                for port in ports:
                    info = self.nm[ip][proto][port]
                    port_info.append({
                        "port_number": int(port),
                        "protocol": proto,
                        "service_name": info.get('name', 'unknown'),
                        "state": info.get('state', 'unknown'),
                        "version_info": f"{info.get('product', '')} {info.get('version', '')}".strip()
                    })
        return port_info

    def get_network_context(self):
        """
        Lanza un script de broadcast para encontrar el router real y la subred.
        """
        print("[*] Minerva buscando configuración de red (DHCP Discover)...")
        try:
            # Lanzamos el comando nativo de Nmap directamente al sistema
            result = subprocess.run(
                ['nmap', '--script', 'broadcast-dhcp-discover'], 
                capture_output=True, text=True, timeout=20
            )
            output = result.stdout
            
            # Usamos expresiones regulares (Regex) para pescar los datos exactos
            router_match = re.search(r"Router:\s*([0-9\.]+)", output)
            subnet_match = re.search(r"Subnet Mask:\s*([0-9\.]+)", output)
            
            # Si los encuentra los guarda, si no, usa valores por defecto
            gateway = router_match.group(1) if router_match else "Desconocido"
            subnet = subnet_match.group(1) if subnet_match else "Desconocido"
            
            print(f"[+] Red detectada -> Gateway: {gateway} | Máscara: {subnet}")
            return gateway, subnet
            
        except Exception as e:
            print(f"[-] Fallo al obtener DHCP: {e}")
            return "Desconocido", "Desconocido"

# --- BLOQUE DE PRUEBA LOCAL ---
if __name__ == "__main__":
    # Instanciamos el escáner
    minerva = MinervaScanner()
    
    print("=== Minerva Network Scanner - Test de Consola ===")
    mi_ip = minerva.get_local_ip()
    print(f"Tu IP local es: {mi_ip}")
    print("Buscando dispositivos... (esto puede tardar unos segundos)")
    
    try:
        dispositivos = minerva.discover_ips()
        
        print(f"\n[+] Se han encontrado {len(dispositivos)} dispositivos activos:")
        print("-" * 60)
        for d in dispositivos:
            print(f"IP: {d['ip']:<15} | Host: {d['hostname']:<20} | Estado: {d['status']}")
        print("-" * 60)
        
    except Exception as e:
        print(f"\n[!] Error durante el escaneo: {e}")
        print("Tip: Intenta ejecutarlo con 'sudo' para dar permisos a Nmap.")

