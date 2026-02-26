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
async def start_scan(db: Session = Depends(get_db)):
    project = db.query(models.Project).filter(models.Project.name == "Default Workspace").first()
    if not project:
        project = models.Project(name="Default Workspace", description="Proyecto creado automáticamente")
        db.add(project)
        db.commit()
        db.refresh(project)

    # 1. ¡NUEVO! Averiguamos el contexto de la red antes de guardar el escaneo
    gateway_ip, subnet_mask = scanner.get_network_context()

    # 2. Guardamos el escaneo inyectando la IP del router y la máscara
    new_scan = models.Scan(
        project_id=project.id, 
        scan_type="Quick Discovery",
        gateway_ip=gateway_ip,
        subnet_mask=subnet_mask
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    # 3. El escaneo de siempre
    results = scanner.discover_ips()

    for device in results:
        mac_temporal = f"MAC-{device['ip']}"
        
        host = db.query(models.Host).filter(models.Host.mac_address == mac_temporal).first()
        
        if not host:
            host = models.Host(
                mac_address=mac_temporal,
                hostname=device.get("hostname", "Desconocido")
            )
            db.add(host)
            db.commit()
        else:
            host.hostname = device.get("hostname", host.hostname)
            db.commit()

        db_result = models.ScanResult(
            scan_id=new_scan.id,
            host_mac=host.mac_address,
            ip_address=device["ip"],
            status=device["status"]
        )
        db.add(db_result)
    
    db.commit()
    return {"message": "Escaneo completado y guardado en la BD con contexto de red"}

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    latest_scan = db.query(models.Scan).order_by(models.Scan.timestamp.desc()).first()
    
    hosts_para_html = []
    total_hosts = 0
    online_hosts = 0

    if latest_scan:
        total_hosts = len(latest_scan.results)
        online_hosts = sum(1 for r in latest_scan.results if r.status == "up")
        
        # 2. Preparamos los datos tal y como los espera la plantilla HTML
        for result in latest_scan.results:
            # Sacamos el nombre del host usando la relación que creamos en models.py
            hostname = result.host.hostname if result.host else "Desconocido"
            
            hosts_para_html.append({
                "ip": result.ip_address,
                "hostname": hostname,
                "status": result.status
            })

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "total_hosts": total_hosts,
        "online_hosts": online_hosts,
        "hosts": hosts_para_html
    })

@app.get("/deep_scan/{ip}")
async def deep_scan_host(ip: str, db: Session = Depends(get_db)):
    scan_result = db.query(models.ScanResult).filter(models.ScanResult.ip_address == ip).order_by(models.ScanResult.id.desc()).first()
    
    if not scan_result:
        return {"error": "IP no encontrada en escaneos previos."}

    discovered_ports = scanner.scan_host_details(ip)
    
    db.query(models.Port).filter(models.Port.scan_result_id == scan_result.id).delete()
    
    saved_ports = []
    for p_data in discovered_ports:
        new_port = models.Port(
            scan_result_id=scan_result.id,
            port_number=p_data["port_number"],
            protocol=p_data["protocol"],
            service_name=p_data["service_name"],
            state=p_data["state"],
            version_info=p_data["version_info"]
        )
        db.add(new_port)
        saved_ports.append(p_data)
        
    db.commit()
    
    return {
        "ip": ip,
        "status": "completed",
        "ports": saved_ports
    }

@app.get("/api/topology")
async def get_topology(db: Session = Depends(get_db)):
    latest_scan = db.query(models.Scan).order_by(models.Scan.timestamp.desc()).first()
    if not latest_scan or not latest_scan.results:
        return {"nodes": [], "edges": []}

    gw_ip = latest_scan.gateway_ip if latest_scan.gateway_ip else "192.168.1.1"

    # Nodo Central
    nodes = [{
        "id": "gateway",
        "label": f"<b>Gateway</b>\n<span style='color:#64748b; font-size:10px;'>{gw_ip}</span>",
        "type": "gateway"
    }]
    edges = []

    for result in latest_scan.results:
        # CORRECCIÓN: Manejo seguro de nombres nulos
        hostname = "Unknown"
        if result.host and result.host.hostname and result.host.hostname != "Desconocido":
            hostname = result.host.hostname
            
        node_id = result.ip_address

        # Lógica visual: Simular vulnerabilidad si la IP termina en .104 (luego lo haremos real)
        has_vuln = True if node_id.endswith(".104") else False

        # Inferir icono de forma segura
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

