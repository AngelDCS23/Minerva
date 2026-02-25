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

    new_scan = models.Scan(project_id=project.id, scan_type="Quick Discovery")
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    # 3. Lanzar Nmap
    results = scanner.discover_ips()

    # 4. Guardar los resultados en la Base de Datos
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
    return {"message": "Escaneo completado y guardado en la BD"}

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