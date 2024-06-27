**Name**: Rishabh Tiwari

**Company**: CODTECH IT SOLUTIONS

**ID**: CT08DS1430

**Domain**: CYBER SECURITY & ETHICAL HACKING

**Mentor**: SRAVANI GOUNI
#### Network Vulnerability Scanner

This Python script is designed to scan a website for open ports and potential vulnerabilities due to outdated software versions. It utilizes various network and web APIs to gather information and produce a vulnerability report.

#### Features:
- **Port Scanning**: Scans specified ports on the target website to check for open ports.
- **Service Detection**: Uses Nmap to detect the service running on open ports.
- **Version Checking**: Verifies if the detected service is running an outdated software version.
- **Vulnerability Report**: Generates a detailed report listing discovered vulnerabilities.

#### Requirements:
- Python 3.x
- `requests` library (for fetching IP address from URL)
- `nmap` command-line tool (for service detection and version checking)

#### Usage:
1. Run the script.
2. Enter the URL of the website you want to scan when prompted.
3. The script will conduct a port scan, detect services, check versions, and compile a vulnerability report.
