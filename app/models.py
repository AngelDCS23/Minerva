from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
import datetime

from app.database import Base

class Project(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    scans = relationship("Scan", back_populates="project")

class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    scan_type = Column(String)
    
    gateway_ip = Column(String, nullable=True)
    subnet_mask = Column(String, nullable=True)
    
    project = relationship("Project", back_populates="scans")
    results = relationship("ScanResult", back_populates="scan", cascade="all, delete-orphan")

class Host(Base):
    """
    Representa un dispositivo físico único (MAC).
    """
    __tablename__ = "hosts"
    mac_address = Column(String, primary_key=True, index=True)
    hostname = Column(String)
    first_seen = Column(DateTime, default=datetime.datetime.utcnow)

    os_name = Column(String, nullable=True, default="Unknown")
    vendor = Column(String, nullable=True, default="Unknown")
    
    results = relationship("ScanResult", back_populates="host")

class ScanResult(Base):
    """
    Lo que Minerva vió en un host durante un escaneo específico.
    """
    __tablename__ = "scan_results"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    host_mac = Column(String, ForeignKey("hosts.mac_address"))
    ip_address = Column(String)
    status = Column(String)
    
    scan = relationship("Scan", back_populates="results")
    host = relationship("Host")

    ports = relationship("Port", back_populates="scan_result", cascade="all, delete-orphan")

class Port(Base):
    """
    Puertos y servicios descubiertos en una ip específica.
    """
    __tablename__ = "ports"
    id = Column(Integer, primary_key=True, index=True)
    scan_result_id = Column(Integer, ForeignKey("scan_results.id"))
    port_number = Column(Integer)
    protocol = Column(String)
    service_name = Column(String)
    state = Column(String)
    version_info = Column(String, nullable=True)

    scan_result = relationship("ScanResult", back_populates="ports")
    vulnerabilities = relationship("Vulnerability", back_populates="port", cascade="all, delete-orphan")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True, index=True)
    port_id = Column(Integer, ForeignKey("ports.id"))
    cve_id = Column(String, index=True)
    severity = Column(String) # High, Medium, Low
    cvss_score = Column(String)
    description = Column(String, nullable=True)
    
    port = relationship("Port", back_populates="vulnerabilities")
