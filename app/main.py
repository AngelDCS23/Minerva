from fastapi import FastAPI, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.scanner import MinervaScanner
from app.database import engine, get_db
from app import models

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

scanner = MinervaScanner()

@app.get("/", response_class=HTMLResponse)
async def read_item(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/scan")
async def start_scan(target: str = None, scan_mode: str = "quick", db: Session = Depends(get_db)):
    project = db.query(models.Project).filter(models.Project.name == "Default Workspace").first()
    if not project:
        project = models.Project(name="Default Workspace", description="Automático")
        db.add(project)
        db.commit()
        db.refresh(project)

    gateway_ip, subnet_mask = scanner.get_network_context()
    
    scan_name = "Quick Discovery"
    if scan_mode == "deep": scan_name = "Deep Network Scan"
    if scan_mode == "vuln": scan_name = "Vulnerability Scan"

    new_scan = models.Scan(project_id=project.id, scan_type=scan_name, gateway_ip=gateway_ip, subnet_mask=subnet_mask)
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    results = scanner.discover_ips(target=target)
    discovered_ips = []

    for device in results:
        mac_temporal = f"MAC-{device['ip']}"
        host = db.query(models.Host).filter(models.Host.mac_address == mac_temporal).first()
        
        if not host:
            host = models.Host(mac_address=mac_temporal, hostname=device.get("hostname", "Desconocido"))
            db.add(host)
        else:
            host.hostname = device.get("hostname", host.hostname)
        db.commit()

        db_result = models.ScanResult(scan_id=new_scan.id, host_mac=host.mac_address, ip_address=device["ip"], status=device["status"])
        db.add(db_result)
        db.commit()

        if device["status"] == "up":
            discovered_ips.append(device["ip"])

    return {"message": "Descubrimiento completado", "ips": discovered_ips}

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    latest_scan = db.query(models.Scan).order_by(models.Scan.timestamp.desc()).first()
    hosts_data = []
    total_hosts = 0
    online_hosts = 0
    total_vulns = 0 # <-- NUEVO CONTADOR REAL

    if latest_scan:
        results = db.query(models.ScanResult).filter(models.ScanResult.scan_id == latest_scan.id).all()
        total_hosts = len(results)
        online_hosts = sum(1 for r in results if r.status == "up")
        for r in results:
            hosts_data.append({"ip": r.ip_address, "hostname": r.host.hostname if r.host else "Desconocido", "status": r.status})
            # Sumamos las vulnerabilidades reales de este host
            for p in r.ports:
                total_vulns += len(p.vulnerabilities)
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request, "hosts": hosts_data, "total_hosts": total_hosts, 
        "online_hosts": online_hosts, "total_vulns": total_vulns # <-- Lo enviamos al HTML
    })

@app.get("/deep_scan/{ip}")
async def run_deep_scan(ip: str, mode: str = "deep", db: Session = Depends(get_db)):
    latest_result = db.query(models.ScanResult).filter(models.ScanResult.ip_address == ip).order_by(models.ScanResult.id.desc()).first()
    if not latest_result: return {"error": "IP no encontrada"}

    db.query(models.Port).filter(models.Port.scan_result_id == latest_result.id).delete()
    db.commit()

    port_info, os_info, vendor_info = scanner.scan_host_details(ip, mode=mode)

    if latest_result.host:
        latest_result.host.os_name = os_info
        latest_result.host.vendor = vendor_info
        db.commit()

    if len(port_info) == 0:
        dummy_port = models.Port(scan_result_id=latest_result.id, port_number=0, protocol="tcp", service_name="firewall", state="filtered", version_info="Stealth Mode")
        db.add(dummy_port)
        db.commit()
        return {"ports": [{"port_number": 0, "service_name": "firewall", "version_info": "Stealth Mode", "state": "filtered"}], "os": os_info, "vendor": vendor_info}

    saved_ports = []
    for p in port_info:
        new_port = models.Port(
            scan_result_id=latest_result.id, 
            port_number=p["port_number"], 
            protocol=p["protocol"], 
            service_name=p["service_name"], 
            state=p["state"], 
            version_info=p.get("version_info", "")
        )
        db.add(new_port)
        
        db.flush() 
        
        for v in p.get("vulns", []):
            new_vuln = models.Vulnerability(
                port_id=new_port.id, 
                cve_id=v["cve_id"], 
                cvss_score=str(v["cvss"]), 
                severity=v["severity"], 
                description=v["desc"]
            )
            db.add(new_vuln)
            
        saved_ports.append(p)
    
    db.commit()
    return {"ports": saved_ports, "os": os_info, "vendor": vendor_info}

@app.get("/report", response_class=HTMLResponse)
async def generate_report(request: Request, db: Session = Depends(get_db)):
    latest_scan = db.query(models.Scan).order_by(models.Scan.timestamp.desc()).first()
    if not latest_scan:
        return HTMLResponse(content="<h1>No hay escaneos previos para generar un informe.</h1>", status_code=404)

    results = db.query(models.ScanResult).filter(models.ScanResult.scan_id == latest_scan.id, models.ScanResult.status == "up").all()
    
    high_vulns = 0
    med_vulns = 0
    low_vulns = 0
    
    report_hosts = []
    
    for r in results:
        open_ports = [p for p in r.ports if p.port_number != 0 and p.state != 'filtered']
        
        host_vulns = []
        host_high = 0
        
        for port in open_ports:
            host_vulns.extend(port.vulnerabilities)
            for v in port.vulnerabilities:
                if v.severity == "High": 
                    high_vulns += 1
                    host_high += 1
                elif v.severity == "Medium": 
                    med_vulns += 1
                else: 
                    low_vulns += 1
                    
        risk = "Low"
        if host_high > 0: risk = "High"
        elif len(host_vulns) > 0 or len(open_ports) > 5: risk = "Medium"
        
        report_hosts.append({
            "ip": r.ip_address,
            "mac": r.host.mac_address.replace('MAC-', '') if r.host else "Unknown",
            "hostname": r.host.hostname if r.host and r.host.hostname != 'Desconocido' else f"ip-{r.ip_address.replace('.','-')}",
            "os": r.host.os_name if r.host else "Unknown",
            "vendor": r.host.vendor if r.host else "Unknown",
            "ports": open_ports,
            "vulns": host_vulns,
            "risk": risk
        })

    return templates.TemplateResponse("report.html", {
        "request": request,
        "scan": latest_scan,
        "hosts": report_hosts,
        "total_hosts": len(report_hosts),
        "total_vulns": high_vulns + med_vulns + low_vulns,
        "high_vulns": high_vulns,
        "med_vulns": med_vulns,
        "low_vulns": low_vulns,
        "date": latest_scan.timestamp.strftime('%Y-%m-%d %H:%M')
    })

@app.get("/report/{ip}", response_class=HTMLResponse)
async def generate_single_report(ip: str, request: Request, db: Session = Depends(get_db)):
    # Buscamos el último escaneo solo de esta IP
    scan_result = db.query(models.ScanResult).filter(models.ScanResult.ip_address == ip).order_by(models.ScanResult.id.desc()).first()
    
    if not scan_result:
        return HTMLResponse(content="<h1>Host no encontrado para generar informe.</h1>", status_code=404)

    open_ports = [p for p in scan_result.ports if p.port_number != 0 and p.state != 'filtered']
    
    all_vulns = []
    for port in open_ports:
        all_vulns.extend(port.vulnerabilities)
        
    high_count = sum(1 for v in all_vulns if v.severity == "High")
    med_count = sum(1 for v in all_vulns if v.severity == "Medium")
    low_count = sum(1 for v in all_vulns if v.severity == "Low")
    
    risk_score = "Low"
    if high_count > 0: risk_score = "High"
    elif med_count > 0: risk_score = "Medium"
    elif len(open_ports) > 5: risk_score = "Medium"

    return templates.TemplateResponse("single_report.html", {
        "request": request,
        "ip": ip,
        "host": scan_result.host,
        "scan_result": scan_result,
        "ports": open_ports,
        "vulns": all_vulns,
        "risk_score": risk_score,
        "high_count": high_count,
        "med_count": med_count,
        "low_count": low_count,
        "date": scan_result.scan.timestamp.strftime('%Y-%m-%d %H:%M') if scan_result.scan else "N/A"
    })

@app.get("/api/topology")
async def get_topology(db: Session = Depends(get_db)):
    latest_scan = db.query(models.Scan).order_by(models.Scan.timestamp.desc()).first()
    if not latest_scan or not latest_scan.results: return {"nodes": [], "edges": []}

    gw_ip = latest_scan.gateway_ip if latest_scan.gateway_ip else "192.168.1.1"
    nodes = [{"id": "gateway", "label": f"<b>Gateway</b>\n<span style='color:#64748b; font-size:10px;'>{gw_ip}</span>", "type": "gateway"}]
    edges = []

    for result in latest_scan.results:
        hostname = result.host.hostname if result.host and result.host.hostname != "Desconocido" else "Unknown"
        node_id = result.ip_address
        
        # LÓGICA REAL: ¿Tiene alguna vulnerabilidad en algún puerto?
        has_vuln = any(len(port.vulnerabilities) > 0 for port in result.ports)
        
        device_type = "desktop"
        vendor = result.host.vendor if result.host and result.host.vendor else ""
        
        if "Xiaomi" in vendor or "Espressif" in vendor or "Amazon" in vendor: device_type = "iot"
        elif "server" in hostname.lower(): device_type = "server"
        elif "print" in hostname.lower(): device_type = "printer"
        elif "cam" in hostname.lower(): device_type = "camera"

        nodes.append({"id": node_id, "label": f"<b>{hostname}</b>\n<span style='color:#64748b; font-size:10px;'>{node_id}</span>", "type": device_type, "has_vuln": has_vuln})
        edges.append({"from": "gateway", "to": node_id, "color": "#334155"})

    return {"nodes": nodes, "edges": edges}

    return {"nodes": nodes, "edges": edges}
    latest_scan = db.query(models.Scan).order_by(models.Scan.timestamp.desc()).first()
    if not latest_scan or not latest_scan.results:
        return {"nodes": [], "edges": []}

    # Nodo Central
    nodes = [{
        "id": "gateway",
        "label": "<b>Gateway</b>\n<span style='color:#64748b; font-size:10px;'>192.168.1.1</span>",
        "type": "gateway"
    }]
    edges = []

    for result in latest_scan.results:
        hostname = result.host.hostname if result.host and result.host.hostname != "Desconocido" else "Unknown"
        node_id = result.ip_address

        # Lógica visual temporal: Simular vulnerabilidad si la IP termina en .104
        has_vuln = True if node_id.endswith(".108") else False

        # Inferir icono según el nombre del host
        device_type = "desktop"
        hl = hostname.lower()
        if "server" in hl: device_type = "server"
        elif "print" in hl: device_type = "printer"
        elif "cam" in hl: device_type = "camera"
        elif "sales" in hl: device_type = "building"

        nodes.append({
            "id": node_id,
            "label": f"<b>{hostname}</b>\n<span style='color:#64748b; font-size:10px;'>{node_id}</span>",
            "type": device_type,
            "has_vuln": has_vuln
        })
        
        edges.append({"from": "gateway", "to": node_id, "color": "#334155"})

    return {"nodes": nodes, "edges": edges}

@app.get("/api/node/{ip}")
async def get_node_details(ip: str, db: Session = Depends(get_db)):
    scan_result = db.query(models.ScanResult).filter(models.ScanResult.ip_address == ip).order_by(models.ScanResult.id.desc()).first()
    if not scan_result: return {"error": "Nodo no encontrado"}

    hostname = scan_result.host.hostname if scan_result.host else "Unknown"
    os_name = scan_result.host.os_name if scan_result.host and scan_result.host.os_name else "Unknown OS"
    vendor = scan_result.host.vendor if scan_result.host and scan_result.host.vendor else "Unknown Vendor"
    
    device_type = "desktop"
    if "Xiaomi" in vendor or "Espressif" in vendor or "Amazon" in vendor: device_type = "iot"
    elif "server" in hostname.lower(): device_type = "server"
    elif "print" in hostname.lower(): device_type = "printer"
    elif "cam" in hostname.lower(): device_type = "camera"

    ports_data = []
    total_node_vulns = 0
    for port in scan_result.ports:
        total_node_vulns += len(port.vulnerabilities)
        ports_data.append({"port_number": port.port_number, "service_name": port.service_name, "version_info": port.version_info, "state": port.state})

    return {
        "ip": ip, "hostname": hostname, "status": scan_result.status,
        "type": device_type, "os_name": os_name, "vendor": vendor, "ports": ports_data,
        "vuln_count": total_node_vulns 
    }

@app.get("/host/{ip}", response_class=HTMLResponse)
async def host_details(ip: str, request: Request, db: Session = Depends(get_db)):
    scan_result = db.query(models.ScanResult).filter(models.ScanResult.ip_address == ip).order_by(models.ScanResult.id.desc()).first()
    
    if not scan_result:
        return HTMLResponse(content="<h1>Host no encontrado</h1>", status_code=404)

    open_ports = [p for p in scan_result.ports if p.port_number != 0 and p.state != 'filtered']
    
    all_vulns = []
    for port in open_ports:
        all_vulns.extend(port.vulnerabilities)
        
    high_count = sum(1 for v in all_vulns if v.severity == "High")
    med_count = sum(1 for v in all_vulns if v.severity == "Medium")
    low_count = sum(1 for v in all_vulns if v.severity == "Low")
    
    risk_score = "Low"
    if high_count > 0: risk_score = "High"
    elif med_count > 0: risk_score = "Medium"
    elif len(open_ports) > 5: risk_score = "Medium"

    return templates.TemplateResponse("host_details.html", {
        "request": request,
        "ip": ip,
        "host": scan_result.host,
        "scan_result": scan_result,
        "ports": open_ports,
        "vulns": all_vulns,
        "risk_score": risk_score,
        "high_count": high_count,  
        "med_count": med_count,  
        "low_count": low_count  
    })

@app.get("/host/{ip}/history", response_class=HTMLResponse)
async def host_history(ip: str, request: Request, db: Session = Depends(get_db)):
    history_results = db.query(models.ScanResult).filter(models.ScanResult.ip_address == ip).order_by(models.ScanResult.id.desc()).all()
    
    if not history_results:
        return HTMLResponse(content="<h1>No hay historial para este host.</h1>", status_code=404)
        
    host_info = history_results[0].host
    
    timeline = []
    for r in history_results:
        open_ports = [p for p in r.ports if p.port_number != 0 and p.state != 'filtered']
        
        vulns_count = sum(len(p.vulnerabilities) for p in open_ports)
        
        timeline.append({
            "scan_id": r.scan_id,
            "date": r.scan.timestamp.strftime('%Y-%m-%d %H:%M') if r.scan else "Desconocida",
            "status": r.status,
            "ports_count": len(open_ports),
            "vulns_count": vulns_count,
            "scan_type": r.scan.scan_type if r.scan else "Desconocido"
        })
        
    return templates.TemplateResponse("host_history.html", {
        "request": request,
        "ip": ip,
        "host": host_info,
        "timeline": timeline
    })