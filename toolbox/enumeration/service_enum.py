#!/usr/bin/env python3
"""
Service Detector pour CyberSec Pro
Module de détection et d'analyse des services réseau
"""

import socket
import subprocess
import re
import threading
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Optional
import json
import logging

class ServiceDetector:
    """Détecteur de services réseau avec identification de versions"""
    
    def __init__(self):
        self.common_ports = {
            21: 'FTP',
            22: 'SSH', 
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            27017: 'MongoDB'
        }
        
        self.service_banners = {}
        self.version_patterns = self.load_version_patterns()
        self.timeout = 5
        self.max_threads = 50
        
        self.setup_logging()
    
    def setup_logging(self):
        """Configuration du logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - ServiceDetector - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def load_version_patterns(self):
        """Charger les patterns de détection de versions"""
        return {
            'SSH': [
                (r'SSH-(\d+\.\d+)-OpenSSH_(\d+\.\d+)', 'OpenSSH {1}'),
                (r'SSH-(\d+\.\d+)-OpenSSH_(\d+\.\d+)(\w+)', 'OpenSSH {1}{2}'),
                (r'SSH-(\d+\.\d+)', 'SSH version {0}')
            ],
            'HTTP': [
                (r'Server:\s*Apache/(\d+\.\d+\.\d+)', 'Apache {0}'),
                (r'Server:\s*nginx/(\d+\.\d+\.\d+)', 'Nginx {0}'),
                (r'Server:\s*Microsoft-IIS/(\d+\.\d+)', 'IIS {0}'),
                (r'Server:\s*([^\r\n]+)', '{0}')
            ],
            'FTP': [
                (r'220.*?(\w+)\s*FTP.*?(\d+\.\d+)', '{0} FTP {1}'),
                (r'220\s+(.+?)\s+FTP', '{0} FTP'),
                (r'220.*?vsftpd\s+(\d+\.\d+\.\d+)', 'vsftpd {0}')
            ],
            'SMTP': [
                (r'220.*?(\w+)\s*SMTP.*?(\d+\.\d+)', '{0} SMTP {1}'),
                (r'220\s+(.+?)\s+ESMTP', '{0} ESMTP'),
                (r'220.*?Postfix', 'Postfix SMTP')
            ],
            'MySQL': [
                (r'(\d+\.\d+\.\d+)-MySQL', 'MySQL {0}'),
                (r'(\d+\.\d+\.\d+)', 'MySQL {0}')
            ],
            'PostgreSQL': [
                (r'PostgreSQL\s+(\d+\.\d+)', 'PostgreSQL {0}')
            ]
        }
    
    def detect_services(self, target_ip, port_range="1-1000", deep_scan=True):
        """Détecter les services sur une cible"""
        self.logger.info(f"Début de la détection de services sur {target_ip}")
        
        # Parser la plage de ports
        start_port, end_port = self.parse_port_range(port_range)
        
        # Scanner les ports ouverts
        open_ports = self.scan_ports(target_ip, start_port, end_port)
        
        if not open_ports:
            return f"Aucun port ouvert trouvé sur {target_ip} dans la plage {port_range}"
        
        # Identifier les services
        services = self.identify_services(target_ip, open_ports, deep_scan)
        
        # Générer le rapport
        return self.generate_report(target_ip, services)
    
    def parse_port_range(self, port_range):
        """Parser une plage de ports (ex: "1-1000", "80,443,8080")"""
        if '-' in port_range:
            start, end = port_range.split('-', 1)
            return int(start), int(end)
        elif ',' in port_range:
            ports = [int(p.strip()) for p in port_range.split(',')]
            return min(ports), max(ports)
        else:
            port = int(port_range)
            return port, port
    
    def scan_ports(self, target_ip, start_port, end_port):
        """Scanner les ports ouverts"""
        self.logger.info(f"Scan des ports {start_port}-{end_port} sur {target_ip}")
        
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self.check_port, target_ip, port): port 
                for port in range(start_port, end_port + 1)
            }
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append(port)
                        self.logger.info(f"Port {port} ouvert")
                except Exception as e:
                    self.logger.debug(f"Erreur sur port {port}: {e}")
        
        return sorted(open_ports)
    
    def check_port(self, ip, port):
        """Vérifier si un port est ouvert"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def identify_services(self, target_ip, ports, deep_scan=True):
        """Identifier les services sur les ports ouverts"""
        services = {}
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self.analyze_service, target_ip, port, deep_scan): port 
                for port in ports
            }
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    service_info = future.result()
                    if service_info:
                        services[port] = service_info
                except Exception as e:
                    self.logger.error(f"Erreur analyse port {port}: {e}")
                    services[port] = {
                        'service': self.common_ports.get(port, 'Unknown'),
                        'version': 'Unknown',
                        'banner': '',
                        'error': str(e)
                    }
        
        return services
    
    def analyze_service(self, ip, port, deep_scan=True):
        """Analyser un service spécifique"""
        service_info = {
            'service': self.common_ports.get(port, 'Unknown'),
            'version': 'Unknown',
            'banner': '',
            'details': {},
            'vulnerabilities': []
        }
        
        try:
            # Capture du banner
            banner = self.grab_banner(ip, port)
            service_info['banner'] = banner
            
            # Identification du service
            if banner:
                detected_service = self.identify_service_from_banner(banner, port)
                if detected_service:
                    service_info.update(detected_service)
            
            # Analyse approfondie si demandée
            if deep_scan:
                detailed_info = self.deep_analyze_service(ip, port, service_info['service'])
                service_info['details'].update(detailed_info)
            
            # Vérification des vulnérabilités courantes
            vulns = self.check_common_vulnerabilities(service_info)
            service_info['vulnerabilities'] = vulns
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse du service {ip}:{port}: {e}")
            service_info['error'] = str(e)
        
        return service_info
    
    def grab_banner(self, ip, port, timeout=5):
        """Capturer le banner d'un service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            # Envoyer une requête appropriée selon le port
            if port == 80:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            elif port == 443:
                # Pour HTTPS, on ne peut pas facilement capturer sans SSL
                sock.close()
                return self.get_https_info(ip, port)
            elif port in [21, 22, 25]:
                # Ces services envoient automatiquement un banner
                pass
            else:
                # Tentative générique
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
            
        except Exception as e:
            self.logger.debug(f"Erreur capture banner {ip}:{port}: {e}")
            return ""
    
    def get_https_info(self, ip, port):
        """Obtenir des informations HTTPS via SSL"""
        try:
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((ip, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    return f"SSL/TLS Certificate: {cert.get('subject', 'Unknown')}, Cipher: {cipher[0] if cipher else 'Unknown'}"
        except Exception:
            return "HTTPS (SSL/TLS)"
    
    def identify_service_from_banner(self, banner, port):
        """Identifier un service à partir de son banner"""
        service_name = self.common_ports.get(port, 'Unknown')
        
        # Patterns spécifiques par service
        if port == 22 or 'SSH' in banner.upper():
            service_name = 'SSH'
        elif port in [80, 443] or 'HTTP' in banner.upper():
            service_name = 'HTTP' if port == 80 else 'HTTPS'
        elif port == 21 or 'FTP' in banner.upper():
            service_name = 'FTP'
        elif port == 25 or 'SMTP' in banner.upper():
            service_name = 'SMTP'
        
        # Extraction de version
        version = self.extract_version(banner, service_name)
        
        return {
            'service': service_name,
            'version': version,
            'confidence': 'high' if version != 'Unknown' else 'medium'
        }
    
    def extract_version(self, banner, service_name):
        """Extraire la version d'un service depuis son banner"""
        if service_name not in self.version_patterns:
            return 'Unknown'
        
        for pattern, version_format in self.version_patterns[service_name]:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                try:
                    return version_format.format(*match.groups())
                except:
                    return match.group(1) if match.groups() else 'Unknown'
        
        return 'Unknown'
    
    def deep_analyze_service(self, ip, port, service_name):
        """Analyse approfondie d'un service"""
        details = {}
        
        try:
            if service_name == 'HTTP' or service_name == 'HTTPS':
                details.update(self.analyze_web_service(ip, port))
            elif service_name == 'SSH':
                details.update(self.analyze_ssh_service(ip, port))
            elif service_name == 'FTP':
                details.update(self.analyze_ftp_service(ip, port))
            elif service_name == 'SMTP':
                details.update(self.analyze_smtp_service(ip, port))
            elif service_name == 'MySQL':
                details.update(self.analyze_mysql_service(ip, port))
        except Exception as e:
            details['analysis_error'] = str(e)
        
        return details
    
    def analyze_web_service(self, ip, port):
        """Analyser un service web"""
        details = {}
        
        try:
            import requests
            
            protocol = 'https' if port == 443 else 'http'
            url = f"{protocol}://{ip}:{port}"
            
            response = requests.get(url, timeout=5, verify=False)
            
            details['status_code'] = response.status_code
            details['server'] = response.headers.get('Server', 'Unknown')
            details['powered_by'] = response.headers.get('X-Powered-By', 'Unknown')
            details['content_length'] = len(response.content)
            
            # Détection de technologies
            content = response.text.lower()
            if 'wordpress' in content:
                details['cms'] = 'WordPress'
            elif 'joomla' in content:
                details['cms'] = 'Joomla'
            elif 'drupal' in content:
                details['cms'] = 'Drupal'
            
        except Exception as e:
            details['error'] = str(e)
        
        return details
    
    def analyze_ssh_service(self, ip, port):
        """Analyser un service SSH"""
        details = {}
        
        try:
            # Vérifier les algorithmes supportés
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            
            # Négociation SSH simplifiée
            sock.send(b"SSH-2.0-TestClient\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            details['ssh_version'] = response.strip()
            details['key_exchange'] = 'Available'  # Simplifié
            
            sock.close()
            
        except Exception as e:
            details['error'] = str(e)
        
        return details
    
    def analyze_ftp_service(self, ip, port):
        """Analyser un service FTP"""
        details = {}
        
        try:
            import ftplib
            
            # Test de connexion anonyme
            try:
                ftp = ftplib.FTP()
                ftp.connect(ip, port, timeout=5)
                ftp.login('anonymous', 'anonymous@test.com')
                details['anonymous_login'] = 'Allowed'
                ftp.quit()
            except:
                details['anonymous_login'] = 'Denied'
                
        except Exception as e:
            details['error'] = str(e)
        
        return details
    
    def analyze_smtp_service(self, ip, port):
        """Analyser un service SMTP"""
        details = {}
        
        try:
            import smtplib
            
            smtp = smtplib.SMTP()
            smtp.connect(ip, port)
            
            # Obtenir les capacités
            response = smtp.ehlo()
            details['capabilities'] = str(response)
            
            smtp.quit()
            
        except Exception as e:
            details['error'] = str(e)
        
        return details
    
    def analyze_mysql_service(self, ip, port):
        """Analyser un service MySQL"""
        details = {}
        
        try:
            # Test de connexion simple (sans authentification)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            
            # Recevoir le packet de greeting MySQL
            greeting = sock.recv(1024)
            
            if len(greeting) > 5:
                # Parser le packet MySQL (simplifié)
                details['protocol_version'] = greeting[4]
                details['mysql_detected'] = True
            
            sock.close()
            
        except Exception as e:
            details['error'] = str(e)
        
        return details
    
    def check_common_vulnerabilities(self, service_info):
        """Vérifier les vulnérabilités communes"""
        vulnerabilities = []
        
        service = service_info.get('service', '').upper()
        version = service_info.get('version', '')
        
        # Base de données simplifiée de vulnérabilités
        vuln_db = {
            'SSH': {
                'OpenSSH 7.4': ['CVE-2018-15473 - User enumeration'],
                'OpenSSH 6.6': ['CVE-2016-0777 - Information disclosure']
            },
            'HTTP': {
                'Apache 2.4.29': ['CVE-2017-15710 - Out of bounds write'],
                'nginx 1.0': ['CVE-2013-2028 - Stack buffer overflow']
            },
            'FTP': {
                'vsftpd 2.3.4': ['CVE-2011-2523 - Backdoor command execution']
            }
        }
        
        if service in vuln_db:
            for vuln_version, vulns in vuln_db[service].items():
                if vuln_version in version:
                    vulnerabilities.extend(vulns)
        
        # Vérifications génériques
        if service_info.get('details', {}).get('anonymous_login') == 'Allowed':
            vulnerabilities.append('Anonymous FTP access enabled')
        
        return vulnerabilities
    
    def generate_report(self, target_ip, services):
        """Générer le rapport de détection de services"""
        report = []
        report.append("=" * 60)
        report.append("SERVICE DETECTION REPORT")
        report.append("=" * 60)
        report.append(f"Target: {target_ip}")
        report.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Services Found: {len(services)}")
        report.append("")
        
        for port, service_info in sorted(services.items()):
            report.append(f"PORT {port}/TCP")
            report.append("-" * 20)
            report.append(f"Service: {service_info.get('service', 'Unknown')}")
            report.append(f"Version: {service_info.get('version', 'Unknown')}")
            
            if service_info.get('banner'):
                report.append(f"Banner: {service_info['banner'][:100]}...")
            
            # Détails supplémentaires
            details = service_info.get('details', {})
            if details:
                report.append("Details:")
                for key, value in details.items():
                    if key != 'error':
                        report.append(f"  {key}: {value}")
            
            # Vulnérabilités
            vulns = service_info.get('vulnerabilities', [])
            if vulns:
                report.append("Potential Vulnerabilities:")
                for vuln in vulns:
                    report.append(f"  - {vuln}")
            
            report.append("")
        
        return "\n".join(report)
    
    def export_to_json(self, target_ip, services, filename=None):
        """Exporter les résultats en JSON"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"service_scan_{target_ip}_{timestamp}.json"
        
        data = {
            'target': target_ip,
            'scan_date': datetime.now().isoformat(),
            'services': services
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        return filename

def main():
    """Fonction principale pour tests"""
    detector = ServiceDetector()
    
    target = input("Entrez l'IP cible: ").strip()
    if not target:
        target = "127.0.0.1"
    
    print(f"Détection de services sur {target}...")
    result = detector.detect_services(target, "1-1000", deep_scan=True)
    print(result)

if __name__ == "__main__":
    main()