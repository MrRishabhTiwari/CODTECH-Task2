import socket
import subprocess
import re
from datetime import datetime
import requests

def get_ip_address(url):
    try:
        response = requests.get(url)
        host = response.url.split("//")[-1].split("/")[0]
        ip_address = socket.gethostbyname(host)
        return ip_address
    except:
        return None

def scan_port(ip_address, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip_address, port))
        print(f"Port {port} is open on {ip_address}")
        return True
    except socket.error:
        print(f"Port {port} is closed on {ip_address}")
        return False

def scan_ports(ip_address, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        if scan_port(ip_address, port):
            open_ports.append(port)
    return open_ports

def get_service(ip_address, port):
    try:
        output = subprocess.check_output(["nmap", "-sV", "-p", str(port), ip_address])
        service = re.search(r"open\s+tcp\s+(\w+)", output.decode()).group(1)
        return service
    except:
        return "Unknown"

def check_software_version(ip_address, port, service):
    try:
        output = subprocess.check_output(["nmap", "-sV", "--version-light", "-p", str(port), ip_address])
        version = re.search(rf"{service}\/(\d+(?:\.\d+)+)", output.decode()).group(1)
        return version
    except:
        return "Unknown"

def scan_website(url):
    ip_address = get_ip_address(url)
    if ip_address:
        open_ports = scan_ports(ip_address, 1, 10)
        vulnerabilities = []
        for port in open_ports:
            service = get_service(ip_address, port)
            version = check_software_version(ip_address, port, service)
            vulnerabilities.append({
                "ip_address": ip_address,
                "port": port,
                "service": service,
                "version": version,
                "vulnerability": "Outdated software version" if version!= "Unknown" else "Unknown"
            })
        return vulnerabilities
    else:
        return None

def generate_report(vulnerabilities):
    report = "Vulnerability Report\n"
    report += "=====================\n"
    report += f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    report += "---------------------\n"
    for vulnerability in vulnerabilities:
        report += f"IP Address: {vulnerability['ip_address']}\n"
        report += f"Port: {vulnerability['port']}\n"
        report += f"Service: {vulnerability['service']}\n"
        report += f"Version: {vulnerability['version']}\n"
        report += f"Vulnerability: {vulnerability['vulnerability']}\n"
        report += "---------------------\n"
    return report

url = input("Enter the website URL: ")
vulnerabilities = scan_website(url)

if vulnerabilities:
    report = generate_report(vulnerabilities)
    print(report)
else:
    print("Failed to scan the website")
