import nmap
import socket

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
        Escaneo profundo de un host específico para encontrar puertos y versiones.
        """
        print(f"[*] Minerva analizando a fondo la IP: {ip}")
        # -sV: Detección de versiones
        # -T4: Acelera un poco el proceso
        self.nm.scan(ip, arguments='-sV -T4')
        
        port_info = []
        if ip in self.nm.all_hosts():
            for proto in self.nm[ip].all_protocols():
                ports = self.nm[ip][proto].keys()
                for port in ports:
                    info = self.nm[ip][proto][port]
                    port_info.append({
                        "port": port,
                        "name": info['name'],
                        "product": info['product'],
                        "version": info['version'],
                        "state": info['state']
                    })
        return port_info

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