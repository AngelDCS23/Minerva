<p align="center">
  <img src="static/img/minerva.svg" alt="Minerva Logo" width="150"/>
</p>

<h1 align="center">Minerva Network Vulnerability Scanner</h1>

<p align="center">
  <strong>Automated Network Auditing and Vulnerability Assessment Platform</strong>
</p>

---

## Overview

Minerva is a comprehensive network security tool designed to automate the reconnaissance and vulnerability assessment phases of a penetration test or security audit. By wrapping the core capabilities of Nmap within a modern, asynchronous FastAPI backend, Minerva provides real-time network mapping, service fingerprinting, and automatic correlation of discovered services with the National Vulnerability Database (NVD) for CVE identification.

## Core Features

* **Automated Discovery & Fingerprinting:** Utilizes Nmap to identify live hosts, open ports, running services, and operating systems.
* **CVE Correlation:** Automatically maps discovered services and their specific versions against known vulnerabilities (CVEs) using the NIST NVD API.
* **Interactive Topology Mapping:** Generates dynamic, visual network graphs in real-time, allowing security analysts to intuitively explore the network architecture.
* **Project Management:** Isolates scan results, timelines, and analyst notes into distinct projects or client workspaces.
* **Executive Reporting:** Exports comprehensive, formatted PDF reports detailing the network topology, discovered hosts, and severity-scored vulnerabilities.

## System Requirements

The pre-compiled Debian package automatically resolves and installs all necessary system dependencies. However, the target system must be based on a Debian architecture:
* Debian, Ubuntu, Kali Linux, Parrot OS, or similar.
* System architectures: `amd64`.

## Installation

Minerva is distributed as a `.deb` package for streamlined deployment. The package manager will automatically handle the installation of underlying dependencies such as Python 3, virtual environments, and Nmap.

1. Download the latest release from the repository:
   ```bash
   wget https://github.com/AngelDCS23/minerva/releases/download/v1.0.0/minerva_1.0_amd64.deb
   ```

2. Install the package using `apt` (requires root privileges):
   ```bash
   sudo apt install ./minerva_1.0_amd64.deb
   ```

*Note: The installation process automatically creates an isolated Python virtual environment within `/opt/minerva` and registers the `minerva` command globally.*

## Usage

Once installed, you can start the Minerva application from any directory using the global command:

```bash
minerva
```

The terminal will output the server status. Open your preferred web browser and navigate to:
**http://localhost:8000**

To stop the server, simply press `Ctrl + C` in the terminal.

## Configuration (NVD API Key)

To prevent rate-limiting when querying the National Vulnerability Database for CVEs, it is highly recommended to configure an NVD API Key.

1. Request a free API key from the [NIST Developers Portal](https://nvd.nist.gov/developers/request-an-api-key).
2. Create or edit the environment file located in the installation directory:
   ```bash
   sudo nano /opt/minerva/.env
   ```
3. Add your key to the file:
   ```env
   NVD_API_KEY=your_api_key_here
   ```
4. Restart the Minerva service.

## Uninstallation

To completely remove Minerva and its dependencies from your system, run:

```bash
sudo apt remove --purge minerva-scanner -y
sudo rm -rf /opt/minerva
```

## Legal Disclaimer

Minerva is developed strictly for educational purposes and authorized security auditing. Using this tool to scan networks or infrastructure without explicit, prior, and mutual consent is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this software.

## License

[MIT License](LICENSE)