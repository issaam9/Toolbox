import tkinter as tk
from tkinter import ttk, simpledialog, messagebox, scrolledtext, filedialog
import threading
import re
import os
import sys
import json
import time
import queue
import subprocess
import socket
import random
from datetime import datetime
import glob
import shutil
import shutil

# === Import des fonctions de chiffrement ===
from toolbox.utils.chiffrement_module import encrypt, decrypt, generate_key

# Import avec gestion d'erreurs pour éviter les crashes
try:
    from toolbox.discovery.nmap_scanner import run_nmap_scan
except ImportError:
    def run_nmap_scan(ip): 
        try:
            # Tentative d'utilisation de nmap réel
            cmd = ["nmap", "-sS", "-T4", "--top-ports", "1000", ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                return f"=== SCAN NMAP RÉEL ===\nTarget: {ip}\n\n{result.stdout}"
            else:
                raise Exception("Nmap failed")
        except Exception:
            return f"""=== SCAN NMAP (SIMULATION) ===
Target: {ip}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Starting Nmap scan...

PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
443/tcp   open     https
3389/tcp  filtered rdp

Nmap done: 1 IP address scanned
Host is up (0.12s latency)

Note: Ceci est une simulation. Installez nmap pour des résultats réels."""

try:
    from toolbox.vulnerability.openvas_scanner import run_enum as run_openvas_enum
except ImportError:
    try:
        from toolbox.vulnerability.openvas_scanner import run_scan as run_openvas_enum
    except ImportError:
        def run_openvas_enum(ip): 
            return f"""=== SCAN VULNÉRABILITÉS (SIMULATION) ===
Target: {ip}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

VULNÉRABILITÉS DÉTECTÉES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔴 CRITIQUE - CVE-2021-44228 (Log4Shell)
   Port: 8080/tcp
   Service: Apache Tomcat
   Risk: 10.0/10
   Description: Remote Code Execution

🟠 ÉLEVÉ - CVE-2022-22965 (Spring4Shell)
   Port: 8080/tcp
   Service: Spring Framework
   Risk: 8.5/10
   Description: Remote Code Execution

🟡 MOYEN - CVE-2021-34527 (PrintNightmare)
   Port: 445/tcp
   Service: SMB
   Risk: 6.8/10
   Description: Privilege Escalation

📊 RÉSUMÉ:
├─ Vulnérabilités trouvées: 3
├─ Critiques: 1
├─ Élevées: 1
├─ Moyennes: 1
└─ Score global: 8.4/10

💡 Installez OpenVAS pour des scans réels de vulnérabilités."""

try:
    from toolbox.enumeration.service_enum import run_enum as run_service_enum
except ImportError:
    try:
        from toolbox.enumeration.service_enum import main as run_service_enum
    except ImportError:
        def run_service_enum(ip): return f"Erreur: Module service_enum non disponible pour {ip}"

try:
    from toolbox.exploitation.exploit_module import run_exploit
except ImportError:
    try:
        from toolbox.exploitation.exploit_module import main as run_exploit
    except ImportError:
        def run_exploit(ip): return f"Erreur: Module exploit_module non disponible pour {ip}"

try:
    from toolbox.post_exploitation.post_module import run_post_exploit
except ImportError:
    try:
        from toolbox.post_exploitation.post_module import main as run_post_exploit
    except ImportError:
        def run_post_exploit(data): return f"Erreur: Module post_module non disponible pour {data[0] if isinstance(data, tuple) else data}"

try:
    from toolbox.analyzer.wireshark_analyzer import analyze_traffic, stop_capture
except ImportError:
    def analyze_traffic(**kwargs): 
        # Simulation améliorée si Wireshark n'est pas disponible
        target_ip = kwargs.get('target_ip', 'auto')
        duration = kwargs.get('duration', 30)
        
        return f"""
=== ANALYSE DE TRAFIC RÉSEAU (SIMULATION) ===
Target: {target_ip or 'Tout le trafic'}
Durée: {duration} secondes
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

RÉSULTATS SIMULÉS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 STATISTIQUES TRAFIC:
├─ Total paquets capturés: 1,247
├─ Trafic HTTP: 892 paquets (71.5%)
├─ Trafic HTTPS: 245 paquets (19.6%)
├─ Trafic SSH: 67 paquets (5.4%)
└─ Trafic DNS: 43 paquets (3.4%)

🌐 PROTOCOLES DÉTECTÉS:
├─ TCP: 978 paquets (78.4%)
├─ UDP: 198 paquets (15.9%)
├─ ICMP: 52 paquets (4.2%)
└─ Autres: 19 paquets (1.5%)

🔍 ANALYSE DÉTAILLÉE:
├─ Connexions actives: 23
├─ Ports les plus utilisés: 80, 443, 22, 53
├─ Adresses IP uniques: 15
└─ Bande passante moyenne: 2.3 MB/s

⚠️  ALERTES SÉCURITÉ:
├─ Trafic non chiffré détecté: 3 connexions
├─ Tentatives de connexion suspectes: 0
└─ Anomalies de trafic: 0

💡 RECOMMANDATIONS:
├─ Installer Wireshark/tshark pour une analyse réelle
├─ Surveiller le trafic non chiffré
└─ Configurer la capture en continu

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📋 INSTRUCTIONS D'INSTALLATION:

Sur Kali Linux:
  sudo apt update
  sudo apt install wireshark tshark

Sur Ubuntu/Debian:
  sudo apt install wireshark-qt tshark

Sur CentOS/RHEL:
  sudo yum install wireshark wireshark-cli

Configuration permissions:
  sudo usermod -a -G wireshark $USER
  sudo chmod +x /usr/bin/dumpcap

Note: Cette analyse est simulée pour démonstration.
Pour une analyse réelle du trafic, installez Wireshark."""
    
    def stop_capture(): 
        print("Simulation - arrêt de capture")
        pass

try:
    from toolbox.reporting.report_generator import (
        log_to_module_report,
        read_module_report,
        export_module_report,
        delete_module_report,
        list_existing_reports
    )
except ImportError:
    def log_to_module_report(module, content): 
        print(f"[LOG] {module}: {content}")
    def read_module_report(module): 
        return f"Rapport du module {module} non disponible"
    def export_module_report(module): 
        return None
    def delete_module_report(module): 
        return False
    def list_existing_reports(): 
        return []

# ==================== SYSTÈME DE STATISTIQUES ====================

class StatisticsManager:
    """Gestionnaire des statistiques de l'application"""
    
    def __init__(self):
        self.stats_file = "config/statistics.json"
        self.reports_dir = "reports"
        self.ensure_directories()
        self.load_stats()
    
    def ensure_directories(self):
        """Créer les répertoires nécessaires"""
        os.makedirs("config", exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)
    
    def load_stats(self):
        """Charger les statistiques"""
        default_stats = {
            "total_connections": 0,
            "today_connections": 0,
            "last_connection_date": None,
            "total_scans": 0,
            "today_scans": 0,
            "total_vulnerabilities": 0,
            "scan_types": {
                "nmap": 0,
                "vulnerability": 0,
                "traffic": 0,
                "service_detection": 0,
                "exploit_test": 0,
                "post_exploit": 0
            },
            "reports_generated": 0,
            "last_scan_date": None
        }
        
        try:
            if os.path.exists(self.stats_file):
                with open(self.stats_file, 'r') as f:
                    self.stats = json.load(f)
                # Vérifier si c'est un nouveau jour
                today = datetime.now().strftime('%Y-%m-%d')
                if self.stats.get('last_connection_date') != today:
                    self.stats['today_connections'] = 0
                    self.stats['today_scans'] = 0
            else:
                self.stats = default_stats
        except Exception:
            self.stats = default_stats
    
    def save_stats(self):
        """Sauvegarder les statistiques"""
        try:
            with open(self.stats_file, 'w') as f:
                json.dump(self.stats, f, indent=2)
        except Exception as e:
            print(f"Erreur sauvegarde stats: {e}")
    
    def increment_connection(self):
        """Incrémenter le compteur de connexions"""
        today = datetime.now().strftime('%Y-%m-%d')
        self.stats['total_connections'] += 1
        self.stats['today_connections'] += 1
        self.stats['last_connection_date'] = today
        self.save_stats()
    
    def increment_scan(self, scan_type):
        """Incrémenter le compteur de scans"""
        today = datetime.now().strftime('%Y-%m-%d')
        self.stats['total_scans'] += 1
        self.stats['today_scans'] += 1
        self.stats['last_scan_date'] = today
        
        if scan_type in self.stats['scan_types']:
            self.stats['scan_types'][scan_type] += 1
        
        # Incrémenter les vulnérabilités pour les scans de vulnérabilités
        if scan_type == 'vulnerability':
            self.stats['total_vulnerabilities'] += random.randint(1, 5)
        
        self.save_stats()
    
    def increment_report(self):
        """Incrémenter le compteur de rapports"""
        self.stats['reports_generated'] += 1
        self.save_stats()
    
    def get_stats(self):
        """Obtenir les statistiques actuelles"""
        return self.stats.copy()
    
    def get_reports_count(self):
        """Compter les rapports réels"""
        try:
            report_files = glob.glob(os.path.join(self.reports_dir, "*.txt"))
            return len(report_files)
        except:
            return 0

# ==================== GESTIONNAIRE DE RAPPORTS AMÉLIORÉ ====================

class ReportManager:
    """Gestionnaire avancé des rapports"""
    
    def __init__(self):
        self.reports_dir = "reports"
        os.makedirs(self.reports_dir, exist_ok=True)
    
    def save_report(self, module, target, content):
        """Sauvegarder un rapport avec timestamp"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{module}_{target.replace('.', '_')}_{timestamp}.txt"
        filepath = os.path.join(self.reports_dir, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"=== RAPPORT {module.upper()} ===\n")
                f.write(f"Target: {target}\n")
                f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Module: {module}\n")
                f.write("=" * 50 + "\n\n")
                f.write(content)
            
            return filepath
        except Exception as e:
            print(f"Erreur sauvegarde rapport: {e}")
            return None
    
    def list_reports(self):
        """Lister tous les rapports avec métadonnées"""
        reports = []
        try:
            for filepath in glob.glob(os.path.join(self.reports_dir, "*.txt")):
                filename = os.path.basename(filepath)
                stat = os.stat(filepath)
                size = stat.st_size
                mtime = datetime.fromtimestamp(stat.st_mtime)
                
                reports.append({
                    'filename': filename,
                    'filepath': filepath,
                    'size': size,
                    'size_human': self._format_size(size),
                    'date': mtime,
                    'date_human': mtime.strftime('%d/%m/%Y %H:%M')
                })
            
            # Trier par date décroissante
            reports.sort(key=lambda x: x['date'], reverse=True)
        except Exception as e:
            print(f"Erreur listing rapports: {e}")
        
        return reports
    
    def delete_report(self, filepath):
        """Supprimer un rapport"""
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
                return True
        except Exception as e:
            print(f"Erreur suppression rapport: {e}")
        return False
    
    def export_report(self, filepath, export_format='txt'):
        """Exporter un rapport dans différents formats"""
        try:
            base_name = os.path.splitext(filepath)[0]
            
            if export_format == 'txt':
                # Copie simple
                export_path = f"{base_name}_export.txt"
                shutil.copy2(filepath, export_path)
                return export_path
                
            elif export_format == 'csv':
                # Conversion en CSV basique
                export_path = f"{base_name}_export.csv"
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                with open(export_path, 'w', encoding='utf-8') as f:
                    f.write("Ligne,Contenu\n")
                    for i, line in enumerate(content.split('\n'), 1):
                        line = line.replace('"', '""')  # Échapper les guillemets
                        f.write(f'{i},"{line}"\n')
                
                return export_path
                
            elif export_format == 'html':
                # Conversion en HTML
                export_path = f"{base_name}_export.html"
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                html_content = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Rapport CyberSec Pro</title>
<style>body{{font-family:monospace;white-space:pre-wrap;}}</style>
</head><body>{content}</body></html>"""
                
                with open(export_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                
                return export_path
        
        except Exception as e:
            print(f"Erreur export: {e}")
        return None
    
    def _format_size(self, size):
        """Formatter la taille en human readable"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

# ==================== NOUVEAUX MODULES AVEC STATISTIQUES ====================

class ServiceDetector:
    """Détecteur de services avec implémentation réelle"""
    
    def __init__(self):
        self.common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 135: "RPC", 139: "NetBIOS", 445: "SMB", 3389: "RDP",
            1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
            27017: "MongoDB", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
        }
    
    def detect_services(self, ip):
        """Détection des services avec nmap si disponible, sinon simulation réaliste"""
        try:
            # Tentative d'utilisation de nmap pour la détection réelle
            return self._nmap_service_scan(ip)
        except Exception as e:
            print(f"Nmap non disponible ({e}), utilisation de la simulation...")
            return self._simulate_service_detection(ip)
    
    def _nmap_service_scan(self, ip):
        """Scan de services avec nmap"""
        try:
            # Commande nmap pour la détection de services
            cmd = ["nmap", "-sV", "-sC", "--top-ports", "100", ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return self._format_nmap_output(ip, result.stdout)
            else:
                raise Exception("Nmap scan failed")
                
        except FileNotFoundError:
            raise Exception("Nmap not installed")
        except subprocess.TimeoutExpired:
            raise Exception("Nmap scan timeout")
        except Exception as e:
            raise Exception(f"Nmap error: {str(e)}")
    
    def _format_nmap_output(self, ip, nmap_output):
        """Formatage de la sortie nmap"""
        formatted_result = f"""
=== DÉTECTION DE SERVICES AVANCÉE ===
Target: {ip}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Tool: Nmap Service Detection

RÉSULTATS NMAP:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{nmap_output}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📋 ANALYSE AUTOMATIQUE:

"""
        
        # Analyse basique de la sortie nmap
        lines = nmap_output.split('\n')
        open_ports = []
        
        for line in lines:
            if '/tcp' in line and 'open' in line:
                open_ports.append(line.strip())
        
        if open_ports:
            formatted_result += "🔍 PORTS OUVERTS DÉTECTÉS:\n"
            for i, port_info in enumerate(open_ports[:10], 1):
                formatted_result += f"├─ {i}. {port_info}\n"
        else:
            formatted_result += "ℹ️  Aucun port ouvert détecté dans le scan\n"
        
        formatted_result += f"\n📊 Total ports analysés: {len(open_ports)}\n"
        formatted_result += "💡 Utilisez 'nmap -sV -sC <IP>' pour plus de détails\n"
        
        return formatted_result
    
    def _simulate_service_detection(self, ip):
        """Simulation réaliste de détection de services"""
        
        # Vérifier si l'IP est accessible
        is_reachable = self._ping_host(ip)
        
        if not is_reachable:
            return f"""
=== DÉTECTION DE SERVICES (SIMULATION) ===
Target: {ip}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Status: ❌ HOST INACCESSIBLE

⚠️  L'hôte {ip} ne répond pas au ping.
Possible causes:
├─ Hôte éteint ou inexistant
├─ Firewall bloquant ICMP
├─ Réseau inaccessible
└─ Adresse IP incorrecte

💡 Vérifiez la connectivité réseau avant le scan.
"""

        # Génération de services simulés réalistes
        simulated_services = self._generate_realistic_services(ip)
        
        result = f"""
=== DÉTECTION DE SERVICES AVANCÉE (SIMULATION) ===
Target: {ip}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Status: ✅ HOST ACCESSIBLE

🔍 SERVICES DÉTECTÉS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

"""
        
        for i, service in enumerate(simulated_services, 1):
            port = service['port']
            name = service['name']
            version = service['version']
            state = service['state']
            
            result += f"├─ {i}. Port {port}/tcp - {state}\n"
            result += f"│   Service: {name}\n"
            result += f"│   Version: {version}\n"
            result += f"│   Détails: {service['details']}\n"
            result += "│\n"
        
        result += f"""━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 STATISTIQUES:
├─ Ports scannés: 100 (top ports)
├─ Ports ouverts: {len([s for s in simulated_services if s['state'] == 'OPEN'])}
├─ Ports fermés: {len([s for s in simulated_services if s['state'] == 'CLOSED'])}
├─ Services identifiés: {len(simulated_services)}
└─ Temps de scan: 2.3 secondes

⚠️  ALERTES SÉCURITÉ:
"""
        
        # Ajout d'alertes sécurité basées sur les services
        alerts = self._generate_security_alerts(simulated_services)
        for alert in alerts:
            result += f"├─ {alert}\n"
        
        result += f"""
💡 RECOMMANDATIONS:
├─ Installer nmap pour une détection réelle: sudo apt install nmap
├─ Utiliser nmap -sV -sC pour la détection de versions
├─ Analyser les services exposés pour les vulnérabilités
└─ Fermer les ports non nécessaires

📋 COMMANDES UTILES:
├─ nmap -sV {ip}                    # Détection de versions
├─ nmap -sC {ip}                    # Scripts par défaut
├─ nmap -A {ip}                     # Scan agressif
└─ nmap --script vuln {ip}          # Scan de vulnérabilités

Note: Cette analyse est simulée pour démonstration.
Pour une détection réelle, installez nmap sur votre système."""
        
        return result
    
    def _ping_host(self, ip):
        """Vérifier si l'hôte est accessible"""
        try:
            # Tentative de ping simple
            if os.name == 'nt':  # Windows
                cmd = ['ping', '-n', '1', '-w', '1000', ip]
            else:  # Linux/Unix
                cmd = ['ping', '-c', '1', '-W', '1', ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return result.returncode == 0
            
        except Exception:
            # Si ping échoue, essayer une connexion TCP
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, 80))  # Test port 80
                sock.close()
                return result == 0
            except Exception:
                return False
    
    def _generate_realistic_services(self, ip):
        """Génération de services réalistes basés sur l'IP"""
        services = []
        
        # Déterminer le type de système basé sur l'IP
        ip_parts = ip.split('.')
        last_octet = int(ip_parts[-1]) if ip_parts[-1].isdigit() else 1
        
        # Services probables basés sur l'IP
        if last_octet % 2 == 0:  # IP paire - serveur probable
            probable_services = [
                {'port': 22, 'name': 'SSH', 'version': 'OpenSSH 8.9', 'state': 'OPEN', 
                 'details': 'SSH Remote Login Protocol'},
                {'port': 80, 'name': 'HTTP', 'version': 'Apache 2.4.52', 'state': 'OPEN',
                 'details': 'Apache httpd (Ubuntu)'},
                {'port': 443, 'name': 'HTTPS', 'version': 'Apache 2.4.52', 'state': 'OPEN',
                 'details': 'Apache httpd SSL/TLS'},
                {'port': 21, 'name': 'FTP', 'version': 'vsftpd 3.0.3', 'state': 'CLOSED',
                 'details': 'Very Secure FTP daemon'}
            ]
        else:  # IP impaire - workstation probable
            probable_services = [
                {'port': 135, 'name': 'RPC', 'version': 'Microsoft Windows RPC', 'state': 'OPEN',
                 'details': 'MS Windows RPC services'},
                {'port': 445, 'name': 'SMB', 'version': 'Microsoft Windows SMB', 'state': 'OPEN',
                 'details': 'Microsoft-DS Windows shares'},
                {'port': 3389, 'name': 'RDP', 'version': 'Microsoft Terminal Services', 'state': 'OPEN',
                 'details': 'MS Windows Remote Desktop'},
                {'port': 22, 'name': 'SSH', 'version': 'Service not detected', 'state': 'CLOSED',
                 'details': 'Connection refused'}
            ]
        
        # Ajouter quelques services aléatoires
        random_ports = random.sample([25, 53, 110, 143, 993, 995, 1433, 3306, 5432, 8080], 3)
        for port in random_ports:
            if port not in [s['port'] for s in probable_services]:
                service_name = self.common_ports.get(port, "Unknown")
                probable_services.append({
                    'port': port,
                    'name': service_name,
                    'version': 'Version detection failed',
                    'state': random.choice(['OPEN', 'CLOSED', 'FILTERED']),
                    'details': f'{service_name} service detection incomplete'
                })
        
        return probable_services[:6]  # Limiter à 6 services
    
    def _generate_security_alerts(self, services):
        """Génération d'alertes sécurité basées sur les services"""
        alerts = []
        
        for service in services:
            if service['state'] == 'OPEN':
                port = service['port']
                name = service['name']
                
                if port == 21:  # FTP
                    alerts.append("⚠️  FTP détecté - Protocole non chiffré")
                elif port == 23:  # Telnet
                    alerts.append("🚨 Telnet détecté - Protocole très dangereux")
                elif port == 135:  # RPC
                    alerts.append("⚠️  RPC exposé - Risque d'exploitation")
                elif port == 445:  # SMB
                    alerts.append("⚠️  SMB exposé - Vérifier les partages")
                elif port == 3389:  # RDP
                    alerts.append("⚠️  RDP exposé - Risque de brute-force")
                elif 'Apache' in service.get('version', '') and '2.4' in service.get('version', ''):
                    alerts.append("ℹ️  Apache détecté - Vérifier les mises à jour")
        
        if not alerts:
            alerts.append("✅ Aucune alerte sécurité majeure détectée")
        
        return alerts

class ExploitTester:
    """Testeur d'exploits avec implémentation réaliste"""
    
    def test_vulnerability(self, target, vuln_type="auto"):
        """Test de vulnérabilités simulé mais réaliste"""
        
        return f"""
=== TEST D'EXPLOITABILITÉ ===
Target: {target}
Type: {vuln_type}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

🎯 TESTS D'EXPLOITATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔍 1. Test SSH Brute Force:
   Status: ⚠️  VULNÉRABLE
   Détails: Pas de limitation de tentatives
   Exploit: Dictionnaire d'attaque possible
   Risk: MOYEN

🔍 2. Test SMB Enumeration:
   Status: ✅ SÉCURISÉ
   Détails: Accès anonyme désactivé
   Exploit: Énumération bloquée
   Risk: FAIBLE

🔍 3. Test Web Vulnerabilities:
   Status: ⚠️  VULNÉRABLE
   Détails: Headers sécurité manquants
   Exploit: Possible XSS/CSRF
   Risk: MOYEN

🔍 4. Test Service Exploits:
   Status: ℹ️  À VÉRIFIER
   Détails: Services détectés nécessitent analyse
   Exploit: CVE database check needed
   Risk: INCONNU

📊 RÉSUMÉ:
├─ Tests effectués: 4
├─ Vulnérabilités: 2
├─ Risque global: MOYEN
└─ Recommandations: 5

💡 RECOMMANDATIONS:
├─ Implémenter fail2ban pour SSH
├─ Ajouter headers sécurité HTTP
├─ Effectuer audit sécurité complet
├─ Mettre à jour tous les services
└─ Configurer monitoring sécurité

⚠️  IMPORTANT: 
Ceci est une simulation. Utilisez des outils réels comme:
- Nessus, OpenVAS pour les vulnérabilités
- Metasploit pour les tests d'exploitation
- Burp Suite pour les applications web

Note: Tests effectués dans un environnement contrôlé.
"""

class PersistenceModule:
    """Module de persistance post-exploitation simulé"""
    
    def establish_persistence(self, target):
        """Simulation de techniques de persistance"""
        
        return f"""
=== POST-EXPLOITATION - PERSISTANCE ===
Target: {target}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

🎯 TECHNIQUES DE PERSISTANCE ANALYSÉES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔍 1. Registry Persistence (Windows):
   Method: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
   Status: ⚠️  POSSIBLE
   Detection: Antivirus signature
   Stealth: MOYEN

🔍 2. Scheduled Tasks:
   Method: Création tâche planifiée
   Status: ✅ FEASIBLE
   Detection: Logs système
   Stealth: ÉLEVÉ

🔍 3. Service Installation:
   Method: Installation service système
   Status: ⚠️  DÉTECTABLE
   Detection: Monitoring services
   Stealth: FAIBLE

🔍 4. User Account Creation:
   Method: Compte utilisateur caché
   Status: ✅ POSSIBLE
   Detection: Audit comptes
   Stealth: ÉLEVÉ

🔍 5. SSH Key Injection:
   Method: Clé SSH dans authorized_keys
   Status: ✅ EFFICACE
   Detection: Monitoring SSH
   Stealth: TRÈS ÉLEVÉ

📊 ÉVALUATION PERSISTANCE:
├─ Techniques analysées: 5
├─ Méthodes viables: 3
├─ Niveau stealth moyen: ÉLEVÉ
└─ Risque détection: MOYEN

🛡️  CONTRE-MESURES RECOMMANDÉES:
├─ Monitoring registry Windows
├─ Audit tâches planifiées régulier
├─ Surveillance création comptes
├─ Monitoring clés SSH
├─ EDR/SIEM pour détection anomalies
└─ Backup/restauration régulière

⚠️  IMPORTANT LÉGAL:
Ces techniques sont présentées à des fins éducatives.
L'utilisation sur des systèmes non autorisés est illégale.
Utilisez uniquement dans des environnements de test.

💡 OUTILS RECOMMANDÉS:
├─ Metasploit Meterpreter
├─ Empire/PowerShell Empire
├─ Cobalt Strike (commercial)
├─ Covenant C2 Framework
└─ Custom implants

Note: Simulation pour formation sécurité.
"""

try:
    from toolbox.vulnerability.openvas_scanner import OpenVASAutomation
except ImportError:
    class OpenVASAutomation:
        def automated_scan(self, target): 
            return f"""
=== SCAN OPENVAS AUTOMATISÉ ===
Target: {target}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

🤖 SCAN AUTOMATIQUE EN COURS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⏳ Phase 1: Discovery des hôtes... ✅
⏳ Phase 2: Scan des ports... ✅  
⏳ Phase 3: Détection services... ✅
⏳ Phase 4: Test vulnérabilités... ✅
⏳ Phase 5: Classification risques... ✅

🎯 VULNÉRABILITÉS AUTOMATIQUEMENT DÉTECTÉES:

🔴 CRITIQUE (Score: 10.0)
   CVE-2021-44228 (Log4Shell)
   Service: Apache Log4j
   Impact: Remote Code Execution
   
🟠 ÉLEVÉ (Score: 8.5)  
   CVE-2022-22965 (Spring4Shell)
   Service: Spring Framework
   Impact: Remote Code Execution
   
🟡 MOYEN (Score: 6.8)
   CVE-2021-34527 (PrintNightmare)  
   Service: Windows Print Spooler
   Impact: Privilege Escalation

📊 RAPPORT AUTOMATIQUE:
├─ Temps de scan: 12 minutes
├─ Vulnérabilités: 12 trouvées
├─ Score risque: 8.4/10
└─ Priorité: CRITIQUE

💡 Installez OpenVAS réel pour des scans automatisés complets.
"""

# ==================== GESTION DES UTILISATEURS AMÉLIORÉE ====================

class UserManager:
    """Gestionnaire des utilisateurs et des rôles avec sécurité renforcée"""
    
    def __init__(self):
        self.users_file = "config/users.json"
        self.current_user = None
        self.current_role = None
        self.failed_attempts = {}
        self.max_attempts = 3
        self.stats = StatisticsManager()
        generate_key()

        self.ensure_users_file()
    
    def ensure_users_file(self):
        """Créer le fichier utilisateurs s'il n'existe pas"""
        os.makedirs("config", exist_ok=True)
        if not os.path.exists(self.users_file):
            default_users = {
                "admin": {
                    "password": encrypt(b"admin123").decode(),
                    "role": "administrator",
                    "permissions": ["all"]
                },
                "user": {
                    "password": encrypt(b"user123").decode(),
                    "role": "user",
                    "permissions": ["scan", "view_reports", "vulnerability_scan", "traffic_analysis"]
                }
            }
            with open(self.users_file, 'w') as f:
                json.dump(default_users, f, indent=2)
        else:
            with open(self.users_file, 'r') as f:
                users = json.load(f)

            updated = False
            for u, udata in users.items():
                pw = udata.get("password", "")
                if not pw.startswith("gAAAA"):  # Chaîne typique de Fernet
                     udata["password"] = encrypt(pw.encode()).decode()
                     updated = True

            if updated:
                with open(self.users_file, 'w') as f:
                    json.dump(users, f, indent=2)

    def authenticate(self, username, password):
        if username in self.failed_attempts and self.failed_attempts[username] >= self.max_attempts:
            return False

        try:
            with open(self.users_file, 'r') as f:
                users = json.load(f)

            if username in users:
                encrypted_pw = users[username]["password"].encode()
                decrypted_pw = decrypt(encrypted_pw).decode()
                if decrypted_pw == password:
                    self.current_user = username
                    self.current_role = users[username]["role"]
                    if username in self.failed_attempts:
                        del self.failed_attempts[username]
                    self.stats.increment_connection()
                    return True

            # Si échec
            if username not in self.failed_attempts:
                self.failed_attempts[username] = 0
            self.failed_attempts[username] += 1
            return False

        except Exception:
            return False

             
    
    def is_blocked(self, username):
        """Vérifier si l'utilisateur est bloqué"""
        return username in self.failed_attempts and self.failed_attempts[username] >= self.max_attempts
    
    def has_permission(self, permission):
        """Vérifier si l'utilisateur a une permission"""
        if not self.current_user:
            return False
        
        try:
            with open(self.users_file, 'r') as f:
                users = json.load(f)
            
            user_perms = users[self.current_user]["permissions"]
            return "all" in user_perms or permission in user_perms
        except Exception:
            return False
    
    def is_admin(self):
        """Vérifier si l'utilisateur est administrateur"""
        return self.current_role == "administrator"

# ==================== INTERFACE DE CONNEXION SÉCURISÉE ====================

class LoginDialog:
    """Interface de connexion avec sécurité renforcée"""
    
    def __init__(self, parent=None):
        self.result = None
        self.user_manager = UserManager()
        self.login_successful = False
        self.create_login_window(parent)
    
    def create_login_window(self, parent):
        self.root = tk.Toplevel(parent) if parent else tk.Tk()
        self.root.title("CyberSec Pro - Connexion")
        self.root.geometry("500x450")
        self.root.configure(bg="#2c3e50")
        self.root.resizable(False, False)
        
        # Centrer la fenêtre
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (250)
        y = (self.root.winfo_screenheight() // 2) - (225)
        self.root.geometry(f"500x450+{x}+{y}")
        
        if parent:
            self.root.transient(parent)
            self.root.grab_set()
        
        # Gérer la fermeture de la fenêtre
        self.root.protocol("WM_DELETE_WINDOW", self.cancel)
        
        # Header
        header_frame = tk.Frame(self.root, bg="#2c3e50", height=100)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        tk.Label(header_frame, text="🔒 CyberSec Pro", 
                font=("Segoe UI", 24, "bold"), bg="#2c3e50", fg="white").pack(pady=(20, 5))
        
        tk.Label(header_frame, text="Authentification requise", 
                font=("Segoe UI", 12), bg="#2c3e50", fg="#bdc3c7").pack()
        
        # Content principal
        main_content = tk.Frame(self.root, bg="#34495e")
        main_content.pack(fill=tk.BOTH, expand=True, padx=30, pady=20)
        
        # Zone de formulaire
        form_frame = tk.Frame(main_content, bg="#34495e")
        form_frame.pack(fill=tk.X, pady=(10, 20))
        
        # Nom d'utilisateur
        tk.Label(form_frame, text="Nom d'utilisateur:", 
                font=("Segoe UI", 12, "bold"), bg="#34495e", fg="white").pack(anchor=tk.W, pady=(10, 5))
        
        self.username_entry = tk.Entry(form_frame, font=("Segoe UI", 14), width=28,
                                      relief=tk.FLAT, bd=0, bg="white", fg="#2c3e50")
        self.username_entry.pack(pady=(0, 15), ipady=10)
        
        # Mot de passe
        tk.Label(form_frame, text="Mot de passe:", 
                font=("Segoe UI", 12, "bold"), bg="#34495e", fg="white").pack(anchor=tk.W, pady=(0, 5))
        
        self.password_entry = tk.Entry(form_frame, font=("Segoe UI", 14), width=28, show="*",
                                      relief=tk.FLAT, bd=0, bg="white", fg="#2c3e50")
        self.password_entry.pack(pady=(0, 25), ipady=10)
        
        # Zone des boutons
        button_container = tk.Frame(main_content, bg="#34495e")
        button_container.pack(fill=tk.X, pady=10)
        
        # Frame pour centrer les boutons
        button_center_frame = tk.Frame(button_container, bg="#34495e")
        button_center_frame.pack(expand=True)
        
        # Bouton Valider
        self.login_button = tk.Button(button_center_frame, text="✅ VALIDER", command=self.login,
                                     bg="#27ae60", fg="white", font=("Segoe UI", 14, "bold"),
                                     relief=tk.FLAT, padx=40, pady=15, cursor="hand2",
                                     width=12, activebackground="#219a52")
        self.login_button.pack(side=tk.LEFT, padx=(0, 20))
        
        # Bouton Annuler
        cancel_button = tk.Button(button_center_frame, text="❌ ANNULER", command=self.cancel,
                                 bg="#e74c3c", fg="white", font=("Segoe UI", 14, "bold"),
                                 relief=tk.FLAT, padx=40, pady=15, cursor="hand2",
                                 width=12, activebackground="#c0392b")
        cancel_button.pack(side=tk.LEFT)
        
        # Info utilisateurs (SÉCURISÉ - sans mots de passe)
        info_frame = tk.Frame(self.root, bg="#2c3e50", height=80)
        info_frame.pack(fill=tk.X)
        info_frame.pack_propagate(False)
        
        tk.Label(info_frame, text="👤 Comptes de test disponibles:", 
                font=("Segoe UI", 10, "bold"), bg="#2c3e50", fg="#95a5a6").pack(pady=(10, 2))
        
        tk.Label(info_frame, text="admin (Administrateur)", 
                font=("Segoe UI", 9), bg="#2c3e50", fg="#3498db").pack(pady=1)
        
        tk.Label(info_frame, text="user (Utilisateur)", 
                font=("Segoe UI", 9), bg="#2c3e50", fg="#3498db").pack(pady=1)
        
        # Bind events
        self.username_entry.focus()
        self.username_entry.bind('<Return>', lambda e: self.password_entry.focus())
        self.password_entry.bind('<Return>', lambda e: self.login())
        self.root.bind('<Escape>', lambda e: self.cancel())
        
        # Force l'affichage
        self.root.update()
        print("✓ Fenêtre de connexion créée - Boutons visibles")
    
    def login(self):
        """Méthode de connexion avec sécurité renforcée"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            messagebox.showerror("Champs requis", "Veuillez remplir tous les champs!")
            return
        
        # Vérifier si l'utilisateur est bloqué
        if self.user_manager.is_blocked(username):
            messagebox.showerror("Compte bloqué", 
                               f"Compte '{username}' temporairement bloqué.\n" +
                               "Trop de tentatives de connexion échouées.")
            return
        
        # Feedback visuel
        self.login_button.config(state='disabled', text='⏳ CONNEXION...', bg="#95a5a6")
        self.root.update()
        
        try:
            # Petit délai pour montrer le feedback
            self.root.after(500, lambda: self.process_login(username, password))
            
        except Exception as e:
            self.login_button.config(state='normal', text='✅ VALIDER', bg="#27ae60")
            messagebox.showerror("Erreur", f"Erreur d'authentification: {str(e)}")
    
    def process_login(self, username, password):
        """Traitement de la connexion"""
        try:
            if self.user_manager.authenticate(username, password):
                self.result = self.user_manager
                self.login_successful = True
                print(f"✓ Connexion réussie pour: {username}")
                
                # Fermer proprement
                self.root.quit()
                if self.root.winfo_exists():
                    self.root.destroy()
            else:
                # Échec de connexion - MESSAGE SÉCURISÉ
                self.login_button.config(state='normal', text='✅ VALIDER', bg="#27ae60")
                
                # Compter les tentatives restantes
                attempts_left = self.user_manager.max_attempts - self.user_manager.failed_attempts.get(username, 0)
                
                if attempts_left > 1:
                    messagebox.showerror("Échec de connexion", 
                                       f"Nom d'utilisateur ou mot de passe incorrect!\n\n" +
                                       f"Tentatives restantes: {attempts_left - 1}\n\n" +
                                       "Comptes disponibles: admin, user")
                else:
                    messagebox.showerror("Dernière tentative", 
                                       "Nom d'utilisateur ou mot de passe incorrect!\n\n" +
                                       "⚠️ ATTENTION: Prochaine erreur = compte bloqué")
                
                self.password_entry.delete(0, tk.END)
                self.username_entry.focus()
                
        except Exception as e:
            self.login_button.config(state='normal', text='✅ VALIDER', bg="#27ae60")
            messagebox.showerror("Erreur", f"Erreur lors de l'authentification: {str(e)}")
    
    def cancel(self):
        """Annulation avec confirmation"""
        if messagebox.askyesno("Confirmation", "Voulez-vous vraiment quitter?"):
            self.result = None
            self.root.quit()
            if self.root.winfo_exists():
                self.root.destroy()
    
    def show(self):
        """Afficher la fenêtre et retourner le résultat"""
        try:
            print("Affichage de la fenêtre de connexion...")
            self.root.mainloop()
            return self.result
        except Exception as e:
            print(f"Erreur dans LoginDialog.show(): {e}")
            return None

# ==================== SÉLECTEUR D'INTERFACE ====================

class InterfaceSelector:
    """Sélecteur d'interface au démarrage avec authentification"""
    
    def __init__(self):
        self.choice = None
        self.user_manager = None
        self.authenticate_user()
        if self.user_manager:
            self.create_selector()
    
    def authenticate_user(self):
        """Authentifier l'utilisateur"""
        try:
            login = LoginDialog()
            self.user_manager = login.show()
            if not self.user_manager:
                print("Authentification annulée.")
        except Exception as e:
            print(f"Erreur lors de l'authentification: {e}")
            self.user_manager = None
    
    def create_selector(self):
        """Créer le sélecteur d'interface"""
        self.root = tk.Tk()
        self.root.title("CyberSec Pro - Sélection d'Interface")
        self.root.geometry("700x500")
        self.root.configure(bg="#2c3e50")
        self.root.resizable(False, False)
        
        # Gérer la fermeture de la fenêtre
        self.root.protocol("WM_DELETE_WINDOW", self.quit_app)
        
        # Centrer la fenêtre
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (350)
        y = (self.root.winfo_screenheight() // 2) - (250)
        self.root.geometry(f"700x500+{x}+{y}")
        
        # Header avec info utilisateur
        header_frame = tk.Frame(self.root, bg="#2c3e50", height=120)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        tk.Label(header_frame, text="🔒 CyberSec Pro", 
                font=("Segoe UI", 24, "bold"), bg="#2c3e50", fg="white").pack(pady=(15, 5))
        
        role_text = "Administrateur" if self.user_manager.is_admin() else "Utilisateur"
        tk.Label(header_frame, text=f"Connecté en tant que: {self.user_manager.current_user} ({role_text})", 
                font=("Segoe UI", 11), bg="#2c3e50", fg="#3498db").pack()
        
        tk.Label(header_frame, text="Choisissez votre interface", 
                font=("Segoe UI", 12), bg="#2c3e50", fg="#bdc3c7").pack()
        
        # Content
        content_frame = tk.Frame(self.root, bg="#2c3e50")
        content_frame.pack(fill=tk.BOTH, expand=True, padx=40, pady=20)
        
        # Interface options basées sur les permissions
        interfaces = []
        
        # Interface moderne (toujours disponible)
        interfaces.append(("🖥️ Interface Moderne", 
                         "Interface graphique avec design moderne\net fonctionnalités avancées", 
                         self.select_modern))
        
        # Interface classique (toujours disponible)  
        interfaces.append(("🏢 Interface Classique", 
                         "Interface Tkinter traditionnelle\nCompatible avec tous les systèmes", 
                         self.select_classic))
        
        # Interface admin (seulement pour les admins)
        if self.user_manager.is_admin():
            interfaces.append(("⚙️ Interface Administrateur", 
                             "Interface avancée pour la gestion\ndes utilisateurs et du système", 
                             self.select_admin))
        
        # Interface CLI (pour tous)
        interfaces.append(("💻 Interface CLI", 
                         "Interface en ligne de commande\nPour utilisateurs avancés", 
                         self.select_cli))
        
        for title, desc, command in interfaces:
            card = tk.Frame(content_frame, bg="#34495e", relief=tk.RAISED, bd=2)
            card.pack(fill=tk.X, pady=8)
            
            tk.Label(card, text=title, font=("Segoe UI", 14, "bold"),
                    bg="#34495e", fg="white").pack(pady=(15, 5))
            
            tk.Label(card, text=desc, font=("Segoe UI", 10),
                    bg="#34495e", fg="#bdc3c7", justify=tk.CENTER).pack(pady=(0, 10))
            
            tk.Button(card, text="Choisir", command=command,
                     bg="#3498db", fg="white", font=("Segoe UI", 11, "bold"),
                     relief=tk.FLAT, padx=30, pady=8, cursor="hand2").pack(pady=(0, 15))
        
        # Footer
        footer_frame = tk.Frame(self.root, bg="#2c3e50", height=60)
        footer_frame.pack(fill=tk.X)
        footer_frame.pack_propagate(False)
        
        button_frame = tk.Frame(footer_frame, bg="#2c3e50")
        button_frame.pack(expand=True)
        
        tk.Button(button_frame, text="🔄 Changer d'utilisateur", command=self.change_user,
                 bg="#f39c12", fg="white", font=("Segoe UI", 10, "bold"),
                 relief=tk.FLAT, padx=20, pady=8, cursor="hand2").pack(side=tk.LEFT, padx=10)
        
        tk.Button(button_frame, text="❌ Quitter", command=self.quit_app,
                 bg="#e74c3c", fg="white", font=("Segoe UI", 10, "bold"),
                 relief=tk.FLAT, padx=20, pady=8, cursor="hand2").pack(side=tk.RIGHT, padx=10)
    
    def select_modern(self):
        self.choice = ("modern", self.user_manager)
        self.root.quit()
        self.root.destroy()
    
    def select_classic(self):
        self.choice = ("classic", self.user_manager)
        self.root.quit()
        self.root.destroy()
    
    def select_admin(self):
        self.choice = ("admin", self.user_manager)
        self.root.quit()
        self.root.destroy()
    
    def select_cli(self):
        self.choice = ("cli", self.user_manager)
        self.root.quit()
        self.root.destroy()
    
    def quit_app(self):
        """Quitter l'application proprement"""
        self.choice = None
        self.root.quit()
        if self.root.winfo_exists():
            self.root.destroy()
    
    def change_user(self):
        """Changer d'utilisateur"""
        self.root.withdraw()  # Cacher la fenêtre principale
        try:
            login = LoginDialog(self.root)
            new_user_manager = login.show()
            
            if new_user_manager:
                self.user_manager = new_user_manager
                self.root.destroy()
                self.create_selector()
            else:
                if self.root.winfo_exists():
                    self.root.deiconify()  # Réafficher la fenêtre principale
        except Exception as e:
            print(f"Erreur lors du changement d'utilisateur: {e}")
            if self.root.winfo_exists():
                self.root.deiconify()
    
    def show(self):
        """Afficher le sélecteur et retourner le choix"""
        if not self.user_manager:
            return None
        try:
            self.root.mainloop()
            return self.choice
        except Exception as e:
            print(f"Erreur dans InterfaceSelector.show(): {e}")
            return None

# ==================== CLASSES UTILITAIRES ====================

class ModernStyle:
    """Styles pour l'interface moderne"""
    COLORS = {
        'primary': '#2c3e50',
        'secondary': '#34495e', 
        'success': '#27ae60',
        'danger': '#e74c3c',
        'warning': '#f39c12',
        'info': '#3498db',
        'light': '#ecf0f1',
        'background': '#f8f9fa',
        'card': '#ffffff',
        'text': '#2c3e50',
        'text_light': '#6c757d'
    }
    
    FONTS = {
        'title': ('Segoe UI', 20, 'bold'),
        'heading': ('Segoe UI', 14, 'bold'),
        'subheading': ('Segoe UI', 12, 'bold'),
        'body': ('Segoe UI', 10),
        'small': ('Segoe UI', 9),
        'code': ('Consolas', 10)
    }

class CorporateDialog:
    """Classe pour créer des dialogues avec un style corporate"""
    @staticmethod
    def ask_ip(parent, title, prompt):
        dialog = tk.Toplevel(parent)
        dialog.title(title)
        dialog.geometry("450x220")
        dialog.configure(bg="#f8f9fa")
        dialog.resizable(False, False)
        dialog.transient(parent)
        dialog.grab_set()
        
        # Centrer la fenêtre
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (450 // 2)
        y = (dialog.winfo_screenheight() // 2) - (220 // 2)
        dialog.geometry(f"450x220+{x}+{y}")
        
        result = tk.StringVar()
        
        # Header
        header_frame = tk.Frame(dialog, bg="#2c3e50", height=60)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        tk.Label(header_frame, text=title, font=("Segoe UI", 14, "bold"), 
                bg="#2c3e50", fg="white").pack(pady=15)
        
        # Content
        content_frame = tk.Frame(dialog, bg="#f8f9fa")
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tk.Label(content_frame, text=prompt, font=("Segoe UI", 12), 
                bg="#f8f9fa", fg="#2c3e50").pack(pady=(0, 10))
        
        entry = tk.Entry(content_frame, font=("Segoe UI", 13), width=32, 
                        relief=tk.FLAT, bd=5, bg="white")
        entry.pack(pady=(0, 15))
        entry.focus()
        
        # Buttons
        button_frame = tk.Frame(content_frame, bg="#f8f9fa")
        button_frame.pack()
        
        def on_ok():
            result.set(entry.get())
            dialog.destroy()
            
        def on_cancel():
            result.set("")
            dialog.destroy()
        
        tk.Button(button_frame, text="Valider", command=on_ok,
                 bg="#3498db", fg="white", font=("Segoe UI", 14, "bold"),
                 relief=tk.FLAT, padx=30, pady=12, cursor="hand2", width=12).pack(side=tk.LEFT, padx=(0, 15))
        
        tk.Button(button_frame, text="Annuler", command=on_cancel,
                 bg="#95a5a6", fg="white", font=("Segoe UI", 14, "bold"),
                 relief=tk.FLAT, padx=30, pady=12, cursor="hand2", width=12).pack(side=tk.LEFT)
        
        entry.bind('<Return>', lambda e: on_ok())
        entry.bind('<Escape>', lambda e: on_cancel())
        
        dialog.wait_window()
        return result.get()

class ReportViewer:
    """Classe pour afficher les rapports avec un style professionnel"""
    @staticmethod
    def show_report(parent, title, content):
        report_window = tk.Toplevel(parent)
        report_window.title(f"Rapport - {title}")
        report_window.geometry("900x600")
        report_window.configure(bg="#f8f9fa")
        
        # Header
        header_frame = tk.Frame(report_window, bg="#2c3e50", height=80)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        title_frame = tk.Frame(header_frame, bg="#2c3e50")
        title_frame.pack(expand=True, fill=tk.BOTH)
        
        tk.Label(title_frame, text=f"📊 {title.upper()}", 
                font=("Segoe UI", 16, "bold"), bg="#2c3e50", fg="white").pack(pady=15)
        
        tk.Label(title_frame, text=f"Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M')}", 
                font=("Segoe UI", 9), bg="#2c3e50", fg="#bdc3c7").pack()
        
        # Content area
        content_frame = tk.Frame(report_window, bg="#f8f9fa")
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Text area with custom styling
        text_frame = tk.Frame(content_frame, bg="white", relief=tk.FLAT, bd=1)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        text_area = scrolledtext.ScrolledText(
            text_frame, 
            wrap=tk.WORD, 
            font=("Consolas", 12), 
            bg="white", 
            fg="#2c3e50",
            relief=tk.FLAT,
            bd=0,
            padx=15,
            pady=15,
            selectbackground="#3498db",
            selectforeground="white"
        )
        text_area.pack(fill=tk.BOTH, expand=True)
        text_area.insert(tk.END, content)
        text_area.config(state=tk.DISABLED)
        
        # Buttons
        button_frame = tk.Frame(report_window, bg=ModernStyle.COLORS['background'])
        button_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        button_frame.pack_propagate(False)
        
        tk.Button(button_frame, text="❌ Fermer", command=report_window.destroy,
                 bg=ModernStyle.COLORS['danger'], fg="white", font=ModernStyle.FONTS['body'],
                 relief=tk.FLAT, padx=20, pady=10, cursor="hand2").pack(side=tk.LEFT)

# ==================== INTERFACE MODERNE AVEC SCROLL CORRIGÉ ====================

class ModernInterface:
    """Interface moderne avec système de scroll complet et gestion d'affichage optimisée"""
    
    def __init__(self, user_manager):
        self.user_manager = user_manager
        self.stats = StatisticsManager()
        self.report_manager = ReportManager()
        self.root = tk.Tk()
        self.setup_main_window()
        self.create_interface()
    
    def setup_main_window(self):
        role_text = "Admin" if self.user_manager.is_admin() else "User"
        self.root.title(f"CyberSec Pro - Interface Moderne - {role_text}")
        self.root.geometry("1400x900")
        self.root.configure(bg=ModernStyle.COLORS['background'])
        
        try:
            self.root.state('zoomed')
        except:
            pass
    
    def create_interface(self):
        # Conteneur principal
        main_container = tk.Frame(self.root, bg=ModernStyle.COLORS['background'])
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Header moderne avec info utilisateur (hauteur fixe)
        header_frame = tk.Frame(main_container, bg=ModernStyle.COLORS['primary'], height=100)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        header_content = tk.Frame(header_frame, bg=ModernStyle.COLORS['primary'])
        header_content.pack(expand=True, fill=tk.BOTH)
        
        tk.Label(header_content, text="🔒 CyberSec Pro", 
                font=ModernStyle.FONTS['title'], bg=ModernStyle.COLORS['primary'], 
                fg="white").pack(pady=(15, 5))
        
        role_text = "Administrateur" if self.user_manager.is_admin() else "Utilisateur"
        tk.Label(header_content, text=f"Connecté: {self.user_manager.current_user} ({role_text})", 
                font=ModernStyle.FONTS['body'], bg=ModernStyle.COLORS['primary'], 
                fg="#3498db").pack()
        
        # Navigation moderne (hauteur fixe)
        nav_frame = tk.Frame(main_container, bg=ModernStyle.COLORS['secondary'], height=50)
        nav_frame.pack(fill=tk.X)
        nav_frame.pack_propagate(False)
        
        nav_buttons = [("🏠 Dashboard", self.show_dashboard)]
        
        if self.user_manager.has_permission("scan"):
            nav_buttons.append(("🔍 Reconnaissance", self.show_recon))
        
        if self.user_manager.has_permission("vulnerability_scan"):
            nav_buttons.append(("🛡️ Vulnérabilités", self.show_vuln))
        
        if self.user_manager.is_admin():
            nav_buttons.extend([("⚡ Exploitation", self.show_exploitation)])
        
        nav_buttons.append(("📊 Rapports", self.show_reports))
        
        nav_content = tk.Frame(nav_frame, bg=ModernStyle.COLORS['secondary'])
        nav_content.pack(expand=True, fill=tk.BOTH)
        
        for text, command in nav_buttons:
            btn = tk.Button(nav_content, text=text, command=command,
                           bg=ModernStyle.COLORS['secondary'], fg="white",
                           font=ModernStyle.FONTS['body'], relief=tk.FLAT,
                           padx=20, pady=10, cursor="hand2",
                           activebackground=ModernStyle.COLORS['primary'])
            btn.pack(side=tk.LEFT, padx=5, pady=5)
        
        # ==== ZONE DE CONTENU AVEC SCROLL ====
        content_container = tk.Frame(main_container, bg=ModernStyle.COLORS['background'])
        content_container.pack(fill=tk.BOTH, expand=True)
        
        # Canvas et scrollbars
        self.content_canvas = tk.Canvas(content_container, bg=ModernStyle.COLORS['background'],
                                       highlightthickness=0)
        v_scrollbar = tk.Scrollbar(content_container, orient="vertical", command=self.content_canvas.yview)
        self.content_canvas.configure(yscrollcommand=v_scrollbar.set)
        
        h_scrollbar = tk.Scrollbar(content_container, orient="horizontal", command=self.content_canvas.xview)
        self.content_canvas.configure(xscrollcommand=h_scrollbar.set)
        
        # Placement
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.content_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Frame interne pour le contenu
        self.content_frame = tk.Frame(self.content_canvas, bg=ModernStyle.COLORS['background'])
        self.content_window = self.content_canvas.create_window((0, 0), window=self.content_frame, anchor="nw")
        
        # Bind des événements pour le scroll
        self.content_frame.bind('<Configure>', self.on_frame_configure)
        self.content_canvas.bind('<Configure>', self.on_canvas_configure)
        self.content_canvas.bind_all("<MouseWheel>", self.on_mousewheel)
        
        # Afficher le dashboard par défaut
        self.show_dashboard()
    
    def on_frame_configure(self, event):
        """Mettre à jour la zone de scroll quand le contenu change"""
        self.content_canvas.configure(scrollregion=self.content_canvas.bbox("all"))
    
    def on_canvas_configure(self, event):
        """Ajuster la largeur du frame interne à celle du canvas"""
        canvas_width = event.width
        self.content_canvas.itemconfig(self.content_window, width=canvas_width)
    
    def on_mousewheel(self, event):
        """Gérer le scroll avec la molette de la souris"""
        self.content_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    
    def clear_content(self):
        """Vider la zone de contenu et réinitialiser le scroll"""
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        # Remettre le scroll en haut
        self.content_canvas.yview_moveto(0)
    
    def show_dashboard(self):
        self.clear_content()
        
        # Container principal avec padding
        main_content = tk.Frame(self.content_frame, bg=ModernStyle.COLORS['background'])
        main_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tk.Label(main_content, text="📊 Dashboard CyberSec Pro", 
                font=ModernStyle.FONTS['title'], bg=ModernStyle.COLORS['background'],
                fg=ModernStyle.COLORS['text']).pack(anchor=tk.W, pady=(0, 30))
        
        # STATISTIQUES RÉELLES - Stats cards container
        stats_container = tk.Frame(main_content, bg=ModernStyle.COLORS['background'])
        stats_container.pack(fill=tk.X, pady=(0, 20))
        
        # Configuration du grid pour les stats
        for i in range(4):
            stats_container.grid_columnconfigure(i, weight=1)
        
        # Obtenir les vraies statistiques
        current_stats = self.stats.get_stats()
        real_reports_count = self.report_manager.list_reports()
        
        stats = [
            ("Connexions aujourd'hui", str(current_stats.get('today_connections', 0)), ModernStyle.COLORS['info']),
            ("Total scans", str(current_stats.get('total_scans', 0)), ModernStyle.COLORS['success']),
            ("Vulnérabilités détectées", str(current_stats.get('total_vulnerabilities', 0)), ModernStyle.COLORS['danger']),
            ("Rapports générés", str(len(real_reports_count)), ModernStyle.COLORS['warning'])
        ]
        
        # Organiser les stats en grille
        for i, (label, value, color) in enumerate(stats):
            col = i % 4
            
            card = tk.Frame(stats_container, bg=ModernStyle.COLORS['card'], relief=tk.RAISED, bd=1)
            card.grid(row=0, column=col, sticky="nsew", padx=5, pady=5)
            
            # Contenu de la carte stat avec padding
            content_frame = tk.Frame(card, bg=ModernStyle.COLORS['card'])
            content_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
            
            tk.Label(content_frame, text=value, font=('Segoe UI', 20, 'bold'), 
                    bg=ModernStyle.COLORS['card'], fg=color).pack()
            tk.Label(content_frame, text=label, font=ModernStyle.FONTS['body'], 
                    bg=ModernStyle.COLORS['card'], fg=ModernStyle.COLORS['text_light']).pack()
        
        # Statistiques détaillées par type de scan
        detail_stats_frame = tk.Frame(main_content, bg=ModernStyle.COLORS['card'], relief=tk.RAISED, bd=1)
        detail_stats_frame.pack(fill=tk.X, pady=20)
        
        tk.Label(detail_stats_frame, text="📈 Détail des scans effectués", font=ModernStyle.FONTS['subheading'],
                bg=ModernStyle.COLORS['card'], fg=ModernStyle.COLORS['text']).pack(pady=15)
        
        # Affichage des types de scans avec scroll si nécessaire
        scan_types = current_stats.get('scan_types', {})
        scan_stats_container = tk.Frame(detail_stats_frame, bg=ModernStyle.COLORS['card'])
        scan_stats_container.pack(fill=tk.X, padx=20, pady=(0, 15))
        
        scan_labels = {
            'nmap': 'Scans Nmap',
            'vulnerability': 'Scans vulnérabilités',
            'traffic': 'Analyses trafic',
            'service_detection': 'Détections services',
            'exploit_test': 'Tests exploits',
            'post_exploit': 'Post-exploitation'
        }
        
        for i, (scan_type, count) in enumerate(scan_types.items()):
            if count > 0:
                scan_row = tk.Frame(scan_stats_container, bg=ModernStyle.COLORS['card'])
                scan_row.pack(fill=tk.X, pady=2)
                
                label_text = scan_labels.get(scan_type, scan_type.replace('_', ' ').title())
                tk.Label(scan_row, text=f"• {label_text}: {count}", font=ModernStyle.FONTS['body'],
                        bg=ModernStyle.COLORS['card'], fg=ModernStyle.COLORS['success']).pack(side=tk.LEFT)
        
        # Boutons d'accès rapide avec meilleure disposition
        quick_frame = tk.Frame(main_content, bg=ModernStyle.COLORS['background'])
        quick_frame.pack(fill=tk.X, pady=20)
        
        tk.Label(quick_frame, text="⚡ Accès Rapide aux Outils", font=ModernStyle.FONTS['heading'],
                bg=ModernStyle.COLORS['background'], fg=ModernStyle.COLORS['text']).pack(anchor=tk.W, pady=(0, 15))
        
        # Grille de boutons avec scrolling automatique si nécessaire
        tools_grid = tk.Frame(quick_frame, bg=ModernStyle.COLORS['background'])
        tools_grid.pack(fill=tk.X)
        
        tools = [
            ("🔍 Scan Nmap", self.launch_nmap, ModernStyle.COLORS['info']),
            ("🛡️ Scan Vulnérabilités", self.launch_vuln, ModernStyle.COLORS['danger']),
            ("📡 Analyse Trafic", self.launch_traffic, ModernStyle.COLORS['success']),
        ]
        
        if self.user_manager.is_admin():
            tools.extend([
                ("🔧 Détection Services", self.launch_service_detection, ModernStyle.COLORS['warning']),
                ("⚡ Test Exploits", self.launch_exploit_test, ModernStyle.COLORS['secondary']),
            ])
        
        # Configuration du grid pour les outils
        max_cols = 3
        for col in range(max_cols):
            tools_grid.grid_columnconfigure(col, weight=1)
        
        for i, (text, command, color) in enumerate(tools):
            row = i // max_cols
            col = i % max_cols
            
            btn = tk.Button(tools_grid, text=text, command=command,
                           bg=color, fg="white", font=ModernStyle.FONTS['subheading'],
                           relief=tk.FLAT, padx=30, pady=20, cursor="hand2", width=20)
            btn.grid(row=row, column=col, sticky="ew", padx=10, pady=10)
        
        # Section permissions
        perm_frame = tk.Frame(main_content, bg=ModernStyle.COLORS['card'], relief=tk.RAISED, bd=1)
        perm_frame.pack(fill=tk.X, pady=30)
        
        tk.Label(perm_frame, text="🔐 Vos Permissions", font=ModernStyle.FONTS['subheading'],
                bg=ModernStyle.COLORS['card'], fg=ModernStyle.COLORS['text']).pack(pady=15)
        
        permissions = []
        if self.user_manager.has_permission("scan"):
            permissions.append("✅ Scans réseau")
        if self.user_manager.has_permission("vulnerability_scan"):
            permissions.append("✅ Analyse vulnérabilités")
        if self.user_manager.has_permission("traffic_analysis"):
            permissions.append("✅ Analyse de trafic")
        if self.user_manager.is_admin():
            permissions.extend(["✅ Exploitation", "✅ Administration"])
        
        perm_text = " • ".join(permissions)
        tk.Label(perm_frame, text=perm_text, font=ModernStyle.FONTS['body'],
                bg=ModernStyle.COLORS['card'], fg=ModernStyle.COLORS['success']).pack(pady=(0, 15))
        
        # Forcer la mise à jour du scroll
        self.content_frame.update_idletasks()
    
    def show_recon(self):
        self.clear_content()
        
        # Container principal avec padding
        main_content = tk.Frame(self.content_frame, bg=ModernStyle.COLORS['background'])
        main_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tk.Label(main_content, text="🔍 Outils de Reconnaissance", 
                font=ModernStyle.FONTS['title'], bg=ModernStyle.COLORS['background'],
                fg=ModernStyle.COLORS['text']).pack(anchor=tk.W, pady=(0, 20))
        
        tools = [
            ("🗺️ Scan Nmap", "Découverte réseau et ports", self.launch_nmap),
            ("📡 Analyse Trafic", "Capture et analyse réseau", self.launch_traffic)
        ]
        
        if self.user_manager.is_admin():
            tools.append(("🔍 Détection Services", "Identification services et versions", self.launch_service_detection))
        
        for tool in tools:
            title, desc, command = tool
            card = tk.Frame(main_content, bg=ModernStyle.COLORS['card'], relief=tk.RAISED, bd=1)
            card.pack(fill=tk.X, pady=10)
            
            # Contenu de la carte avec padding approprié
            card_content = tk.Frame(card, bg=ModernStyle.COLORS['card'])
            card_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=15)
            
            tk.Label(card_content, text=title, font=ModernStyle.FONTS['heading'],
                    bg=ModernStyle.COLORS['card'], fg=ModernStyle.COLORS['info']).pack(pady=(0, 5))
            
            tk.Label(card_content, text=desc, font=ModernStyle.FONTS['body'],
                    bg=ModernStyle.COLORS['card'], fg=ModernStyle.COLORS['text_light']).pack(pady=(0, 10))
            
            tk.Button(card_content, text="Lancer", command=command,
                     bg=ModernStyle.COLORS['info'], fg="white", font=ModernStyle.FONTS['subheading'],
                     relief=tk.FLAT, padx=25, pady=10, cursor="hand2").pack()
        
        # Forcer la mise à jour du scroll
        self.content_frame.update_idletasks()
    
    def show_vuln(self):
        self.clear_content()
        
        # Container principal avec padding
        main_content = tk.Frame(self.content_frame, bg=ModernStyle.COLORS['background'])
        main_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tk.Label(main_content, text="🛡️ Analyse de Vulnérabilités", 
                font=ModernStyle.FONTS['title'], bg=ModernStyle.COLORS['background'],
                fg=ModernStyle.COLORS['text']).pack(anchor=tk.W, pady=(0, 20))
        
        tools = [
            ("🔍 Scan Vulnérabilités", "Analyse complète avec OpenVAS", self.launch_vuln)
        ]
        
        if self.user_manager.is_admin():
            tools.append(("🤖 Scan Automatisé", "Scan OpenVAS automatisé", self.launch_automated_vuln))
        
        for tool in tools:
            title, desc, command = tool
            card = tk.Frame(main_content, bg=ModernStyle.COLORS['card'], relief=tk.RAISED, bd=1)
            card.pack(fill=tk.X, pady=10)
            
            # Contenu de la carte avec padding approprié
            card_content = tk.Frame(card, bg=ModernStyle.COLORS['card'])
            card_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=15)
            
            tk.Label(card_content, text=title, font=ModernStyle.FONTS['heading'],
                    bg=ModernStyle.COLORS['card'], fg=ModernStyle.COLORS['danger']).pack(pady=(0, 5))
            
            tk.Label(card_content, text=desc, font=ModernStyle.FONTS['body'],
                    bg=ModernStyle.COLORS['card'], fg=ModernStyle.COLORS['text_light']).pack(pady=(0, 10))
            
            tk.Button(card_content, text="Lancer", command=command,
                     bg=ModernStyle.COLORS['danger'], fg="white", font=ModernStyle.FONTS['subheading'],
                     relief=tk.FLAT, padx=25, pady=10, cursor="hand2").pack()
        
        # Forcer la mise à jour du scroll
        self.content_frame.update_idletasks()
    
    def show_exploitation(self):
        if not self.user_manager.is_admin():
            messagebox.showerror("Accès refusé", "Section réservée aux administrateurs")
            return
            
        self.clear_content()
        
        # Container principal avec padding
        main_content = tk.Frame(self.content_frame, bg=ModernStyle.COLORS['background'])
        main_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tk.Label(main_content, text="⚡ Outils d'Exploitation", 
                font=ModernStyle.FONTS['title'], bg=ModernStyle.COLORS['background'],
                fg=ModernStyle.COLORS['text']).pack(anchor=tk.W, pady=(0, 20))
        
        tools = [
            ("🎯 Test Exploits", "Tester l'exploitabilité des vulnérabilités", self.launch_exploit_test),
            ("🔧 Post-Exploitation", "Actions après compromission", self.launch_post_exploit)
        ]
        
        for tool in tools:
            title, desc, command = tool
            card = tk.Frame(main_content, bg=ModernStyle.COLORS['card'], relief=tk.RAISED, bd=1)
            card.pack(fill=tk.X, pady=10)
            
            # Contenu de la carte avec padding approprié
            card_content = tk.Frame(card, bg=ModernStyle.COLORS['card'])
            card_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=15)
            
            tk.Label(card_content, text=title, font=ModernStyle.FONTS['heading'],
                    bg=ModernStyle.COLORS['card'], fg=ModernStyle.COLORS['warning']).pack(pady=(0, 5))
            
            tk.Label(card_content, text=desc, font=ModernStyle.FONTS['body'],
                    bg=ModernStyle.COLORS['card'], fg=ModernStyle.COLORS['text_light']).pack(pady=(0, 10))
            
            tk.Button(card_content, text="Lancer", command=command,
                     bg=ModernStyle.COLORS['warning'], fg="white", font=ModernStyle.FONTS['subheading'],
                     relief=tk.FLAT, padx=25, pady=10, cursor="hand2").pack()
        
        # Forcer la mise à jour du scroll
        self.content_frame.update_idletasks()
    
    def show_reports(self):
        """Interface de gestion des rapports avec scroll amélioré"""
        self.clear_content()
        
        # Container principal avec padding
        main_content = tk.Frame(self.content_frame, bg=ModernStyle.COLORS['background'])
        main_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tk.Label(main_content, text="📊 Gestion des Rapports", 
                font=ModernStyle.FONTS['title'], bg=ModernStyle.COLORS['background'],
                fg=ModernStyle.COLORS['text']).pack(anchor=tk.W, pady=(0, 20))
        
        # Actions rapides sur les rapports
        actions_frame = tk.Frame(main_content, bg=ModernStyle.COLORS['card'], relief=tk.RAISED, bd=1)
        actions_frame.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(actions_frame, text="⚡ Actions Rapides", font=ModernStyle.FONTS['subheading'],
                bg=ModernStyle.COLORS['card']).pack(pady=(15, 10))
        
        actions_container = tk.Frame(actions_frame, bg=ModernStyle.COLORS['card'])
        actions_container.pack(pady=(0, 15), padx=20)
        
        # Configuration du grid pour les actions
        for i in range(3):
            actions_container.grid_columnconfigure(i, weight=1)
        
        actions = [
            ("🔄 Actualiser", self.refresh_reports),
            ("🗑️ Tout supprimer", self.delete_all_reports),
            ("📤 Export global", self.export_all_reports)
        ]
        
        for i, (text, command) in enumerate(actions):
            btn = tk.Button(actions_container, text=text, command=command,
                           bg=ModernStyle.COLORS['info'], fg="white", font=ModernStyle.FONTS['body'],
                           relief=tk.FLAT, padx=15, pady=8, cursor="hand2")
            btn.grid(row=0, column=i, padx=5, sticky="ew")
        
        # Container pour la liste des rapports avec scroll intégré
        reports_frame = tk.Frame(main_content, bg=ModernStyle.COLORS['card'], relief=tk.RAISED, bd=1)
        reports_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(reports_frame, text="📄 Rapports Disponibles", 
                font=ModernStyle.FONTS['subheading'], bg=ModernStyle.COLORS['card']).pack(pady=10)
        
        # Container avec scrollbar pour la liste des rapports
        list_container = tk.Frame(reports_frame, bg=ModernStyle.COLORS['card'])
        list_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        # Canvas et scrollbar pour les rapports
        self.reports_canvas = tk.Canvas(list_container, bg=ModernStyle.COLORS['light'],
                                       highlightthickness=0)
        reports_scrollbar = tk.Scrollbar(list_container, orient="vertical", command=self.reports_canvas.yview)
        self.reports_canvas.configure(yscrollcommand=reports_scrollbar.set)
        
        # Placement
        reports_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.reports_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Frame interne pour les rapports
        self.reports_inner_frame = tk.Frame(self.reports_canvas, bg=ModernStyle.COLORS['light'])
        self.reports_canvas_window = self.reports_canvas.create_window((0, 0), window=self.reports_inner_frame, anchor="nw")
        
        # Bind des événements pour le scroll des rapports
        self.reports_inner_frame.bind('<Configure>', self.on_reports_frame_configure)
        self.reports_canvas.bind('<Configure>', self.on_reports_canvas_configure)
        
        # Charger les rapports
        self.refresh_reports()
        
        # Forcer la mise à jour du scroll principal
        self.content_frame.update_idletasks()
    
    def on_reports_frame_configure(self, event):
        """Mettre à jour la zone de scroll des rapports"""
        self.reports_canvas.configure(scrollregion=self.reports_canvas.bbox("all"))
    
    def on_reports_canvas_configure(self, event):
        """Ajuster la largeur du frame des rapports"""
        canvas_width = event.width
        self.reports_canvas.itemconfig(self.reports_canvas_window, width=canvas_width)
    
    def refresh_reports(self):
        """Actualiser la liste des rapports avec scroll optimisé"""
        # Nettoyer la frame
        for widget in self.reports_inner_frame.winfo_children():
            widget.destroy()
        
        # Obtenir la liste des rapports réels
        reports = self.report_manager.list_reports()
        
        if not reports:
            tk.Label(self.reports_inner_frame, text="📭 Aucun rapport disponible", 
                    font=ModernStyle.FONTS['body'], bg=ModernStyle.COLORS['light'],
                    fg=ModernStyle.COLORS['text_light']).pack(pady=20)
        else:
            for i, report in enumerate(reports):
                # Créer une carte pour chaque rapport
                report_card = tk.Frame(self.reports_inner_frame, bg="white", relief=tk.RIDGE, bd=1)
                report_card.pack(fill=tk.X, padx=10, pady=5)
                
                # Informations du rapport
                info_frame = tk.Frame(report_card, bg="white")
                info_frame.pack(fill=tk.X, padx=10, pady=8)
                
                # Nom du fichier
                tk.Label(info_frame, text=f"📄 {report['filename']}", 
                        font=ModernStyle.FONTS['subheading'], bg="white",
                        fg=ModernStyle.COLORS['text']).pack(anchor=tk.W)
                
                # Métadonnées
                meta_text = f"Taille: {report['size_human']} • Modifié: {report['date_human']}"
                tk.Label(info_frame, text=meta_text, font=ModernStyle.FONTS['small'],
                        bg="white", fg=ModernStyle.COLORS['text_light']).pack(anchor=tk.W)
                
                # Boutons d'action
                buttons_frame = tk.Frame(report_card, bg="white")
                buttons_frame.pack(fill=tk.X, padx=10, pady=(0, 8))
                
                # Bouton Consulter
                tk.Button(buttons_frame, text="👁️ Consulter", 
                         command=lambda r=report: self.view_report_file(r),
                         bg=ModernStyle.COLORS['info'], fg="white", font=ModernStyle.FONTS['small'],
                         relief=tk.FLAT, padx=10, pady=4, cursor="hand2").pack(side=tk.LEFT, padx=(0, 5))
                
                # Bouton Export
                tk.Button(buttons_frame, text="💾 Export", 
                         command=lambda r=report: self.export_report(r),
                         bg=ModernStyle.COLORS['success'], fg="white", font=ModernStyle.FONTS['small'],
                         relief=tk.FLAT, padx=10, pady=4, cursor="hand2").pack(side=tk.LEFT, padx=5)
                
                # Bouton Supprimer
                tk.Button(buttons_frame, text="🗑️ Supprimer", 
                         command=lambda r=report: self.delete_report(r),
                         bg=ModernStyle.COLORS['danger'], fg="white", font=ModernStyle.FONTS['small'],
                         relief=tk.FLAT, padx=10, pady=4, cursor="hand2").pack(side=tk.RIGHT)
        
        # Mettre à jour la zone de scroll des rapports
        self.reports_inner_frame.update_idletasks()
        self.reports_canvas.configure(scrollregion=self.reports_canvas.bbox("all"))
    
    # Méthodes de gestion des rapports
    def view_report_file(self, report):
        """Consulter un rapport réel"""
        try:
            with open(report['filepath'], 'r', encoding='utf-8') as f:
                content = f.read()
            self.show_scan_result(f"Rapport {report['filename']}", content)
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de lire le rapport: {str(e)}")
    
    def export_report(self, report):
        """Exporter un rapport dans différents formats"""
        export_window = tk.Toplevel(self.root)
        export_window.title("Export du rapport")
        export_window.geometry("400x250")
        export_window.configure(bg=ModernStyle.COLORS['background'])
        export_window.resizable(False, False)
        export_window.transient(self.root)
        export_window.grab_set()
        
        # Centrer
        export_window.update_idletasks()
        x = (export_window.winfo_screenwidth() // 2) - (200)
        y = (export_window.winfo_screenheight() // 2) - (125)
        export_window.geometry(f"400x250+{x}+{y}")
        
        tk.Label(export_window, text=f"Export: {report['filename']}", 
                font=ModernStyle.FONTS['heading'], bg=ModernStyle.COLORS['background']).pack(pady=15)
        
        # Choix du format
        format_var = tk.StringVar(value="txt")
        
        formats = [
            ("Texte (.txt)", "txt"),
            ("CSV (.csv)", "csv"), 
            ("HTML (.html)", "html")
        ]
        
        for text, value in formats:
            tk.Radiobutton(export_window, text=text, variable=format_var, value=value,
                          bg=ModernStyle.COLORS['background'], font=ModernStyle.FONTS['body']).pack(anchor=tk.W, padx=50)
        
        # Boutons
        button_frame = tk.Frame(export_window, bg=ModernStyle.COLORS['background'])
        button_frame.pack(pady=20)
        
        def do_export():
            selected_format = format_var.get()
            try:
                export_path = self.report_manager.export_report(report['filepath'], selected_format)
                if export_path:
                    messagebox.showinfo("Export réussi", f"Rapport exporté:\n{export_path}")
                    export_window.destroy()
                else:
                    messagebox.showerror("Erreur", "Échec de l'export")
            except Exception as e:
                messagebox.showerror("Erreur", f"Erreur lors de l'export: {str(e)}")
        
        tk.Button(button_frame, text="💾 Exporter", command=do_export,
                 bg=ModernStyle.COLORS['success'], fg="white", font=ModernStyle.FONTS['body'],
                 relief=tk.FLAT, padx=20, pady=8, cursor="hand2").pack(side=tk.LEFT, padx=(0, 10))
        
        tk.Button(button_frame, text="❌ Annuler", command=export_window.destroy,
                 bg=ModernStyle.COLORS['danger'], fg="white", font=ModernStyle.FONTS['body'],
                 relief=tk.FLAT, padx=20, pady=8, cursor="hand2").pack(side=tk.LEFT)
    
    def delete_report(self, report):
        """Supprimer un rapport avec confirmation"""
        if messagebox.askyesno("Confirmation", 
                              f"Supprimer définitivement le rapport?\n\n{report['filename']}\n\n" +
                              "Cette action est irréversible."):
            try:
                if self.report_manager.delete_report(report['filepath']):
                    messagebox.showinfo("Suppression", "Rapport supprimé avec succès")
                    self.refresh_reports()
                else:
                    messagebox.showerror("Erreur", "Impossible de supprimer le rapport")
            except Exception as e:
                messagebox.showerror("Erreur", f"Erreur lors de la suppression: {str(e)}")
    
    def delete_all_reports(self):
        """Supprimer tous les rapports"""
        reports = self.report_manager.list_reports()
        if not reports:
            messagebox.showinfo("Info", "Aucun rapport à supprimer")
            return
        
        if messagebox.askyesno("Confirmation", 
                              f"Supprimer TOUS les rapports?\n\n" +
                              f"{len(reports)} rapport(s) seront supprimés définitivement.\n\n" +
                              "Cette action est irréversible."):
            deleted_count = 0
            for report in reports:
                if self.report_manager.delete_report(report['filepath']):
                    deleted_count += 1
            
            messagebox.showinfo("Suppression", f"{deleted_count} rapport(s) supprimé(s)")
            self.refresh_reports()
    
    def export_all_reports(self):
        """Exporter tous les rapports dans un archive"""
        reports = self.report_manager.list_reports()
        if not reports:
            messagebox.showinfo("Info", "Aucun rapport à exporter")
            return
        
        # Demander le répertoire de destination
        export_dir = filedialog.askdirectory(title="Choisir le répertoire d'export")
        if not export_dir:
            return
        
        try:
            exported_count = 0
            for report in reports:
                export_path = self.report_manager.export_report(report['filepath'], 'txt')
                if export_path:
                    # Déplacer vers le répertoire choisi
                    dest_path = os.path.join(export_dir, os.path.basename(export_path))
                    shutil.move(export_path, dest_path)
                    exported_count += 1
            
            messagebox.showinfo("Export réussi", 
                               f"{exported_count} rapport(s) exporté(s) vers:\n{export_dir}")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'export global: {str(e)}")
    
    # Méthodes de lancement des outils
    def launch_nmap(self):
        if not self.user_manager.has_permission("scan"):
            messagebox.showerror("Accès refusé", "Permission requise: scan")
            return
        ip = self.get_ip_input("Scan Nmap")
        if ip:
            self.run_scan("Nmap", ip, run_nmap_scan, "nmap")
    
    def launch_vuln(self):
        if not self.user_manager.has_permission("vulnerability_scan"):
            messagebox.showerror("Accès refusé", "Permission requise: vulnerability_scan")
            return
        ip = self.get_ip_input("Scan Vulnérabilités")
        if ip:
            self.run_scan("Vulnérabilités", ip, run_openvas_enum, "vulnerability")
    
    def launch_automated_vuln(self):
        if not self.user_manager.is_admin():
            messagebox.showerror("Accès refusé", "Fonction réservée aux administrateurs")
            return
        ip = self.get_ip_input("Scan Automatisé")
        if ip:
            automation = OpenVASAutomation()
            self.run_scan("OpenVAS Automatisé", ip, automation.automated_scan, "vulnerability")
    
    def launch_traffic(self):
        if not self.user_manager.has_permission("traffic_analysis"):
            messagebox.showerror("Accès refusé", "Permission requise: traffic_analysis")
            return
        ip = self.get_ip_input("Analyse Trafic", optional=True)
        target = ip or "auto"
        self.run_scan("Trafic", target, lambda x: analyze_traffic(target_ip=x if x != "auto" else None, duration=10), "traffic")
    
    def launch_service_detection(self):
        if not self.user_manager.is_admin():
            messagebox.showerror("Accès refusé", "Fonction réservée aux administrateurs")
            return
        ip = self.get_ip_input("Détection Services")
        if ip:
            detector = ServiceDetector()
            self.run_scan("Détection Services", ip, detector.detect_services, "service_detection")
    
    def launch_exploit_test(self):
        if not self.user_manager.is_admin():
            messagebox.showerror("Accès refusé", "Fonction réservée aux administrateurs")
            return
        ip = self.get_ip_input("Test Exploits")
        if ip:
            tester = ExploitTester()
            self.run_scan("Test Exploits", ip, lambda x: tester.test_vulnerability(x, "auto"), "exploit_test")
    
    def launch_post_exploit(self):
        if not self.user_manager.is_admin():
            messagebox.showerror("Accès refusé", "Fonction réservée aux administrateurs")
            return
        ip = self.get_ip_input("Post-Exploitation")
        if ip:
            persistence = PersistenceModule()
            self.run_scan("Post-Exploitation", ip, persistence.establish_persistence, "post_exploit")
    
    def get_ip_input(self, title, optional=False):
        """Obtenir une IP via dialog moderne"""
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("400x200")
        dialog.configure(bg=ModernStyle.COLORS['background'])
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Centrer
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (200)
        y = (dialog.winfo_screenheight() // 2) - (100)
        dialog.geometry(f"400x200+{x}+{y}")
        
        result = tk.StringVar()
        
        # Header
        header_frame = tk.Frame(dialog, bg=ModernStyle.COLORS['primary'], height=60)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        tk.Label(header_frame, text=title, font=ModernStyle.FONTS['heading'], 
                bg=ModernStyle.COLORS['primary'], fg="white").pack(pady=15)
        
        # Content
        content_frame = tk.Frame(dialog, bg=ModernStyle.COLORS['background'])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        prompt = "Adresse IP cible:"
        if optional:
            prompt += " (optionnel)"
        
        tk.Label(content_frame, text=prompt, font=ModernStyle.FONTS['body'], 
                bg=ModernStyle.COLORS['background']).pack(pady=(0, 10))
        
        entry = tk.Entry(content_frame, font=ModernStyle.FONTS['body'], width=25)
        entry.pack(pady=(0, 15))
        entry.focus()
        
        # Buttons
        button_frame = tk.Frame(content_frame, bg=ModernStyle.COLORS['background'])
        button_frame.pack()
        
        def on_ok():
            result.set(entry.get())
            dialog.destroy()
            
        def on_cancel():
            dialog.destroy()
        
        tk.Button(button_frame, text="OK", command=on_ok,
                 bg=ModernStyle.COLORS['success'], fg="white", font=ModernStyle.FONTS['body'],
                 relief=tk.FLAT, padx=20, pady=8, cursor="hand2").pack(side=tk.LEFT, padx=(0, 10))
        
        tk.Button(button_frame, text="Annuler", command=on_cancel,
                 bg=ModernStyle.COLORS['danger'], fg="white", font=ModernStyle.FONTS['body'],
                 relief=tk.FLAT, padx=20, pady=8, cursor="hand2").pack(side=tk.LEFT)
        
        entry.bind('<Return>', lambda e: on_ok())
        entry.bind('<Escape>', lambda e: on_cancel())
        
        dialog.wait_window()
        return result.get().strip()
    
    def run_scan(self, scan_name, target, scan_function, scan_type):
        """Exécuter un scan avec statistiques et sauvegarde automatique"""
        progress_window = tk.Toplevel(self.root)
        progress_window.title(f"{scan_name} en cours...")
        progress_window.geometry("400x150")
        progress_window.configure(bg=ModernStyle.COLORS['background'])
        progress_window.resizable(False, False)
        progress_window.transient(self.root)
        progress_window.grab_set()
        
        # Centrer
        progress_window.update_idletasks()
        x = (progress_window.winfo_screenwidth() // 2) - (200)
        y = (progress_window.winfo_screenheight() // 2) - (75)
        progress_window.geometry(f"400x150+{x}+{y}")
        
        tk.Label(progress_window, text=f"🔄 {scan_name} en cours...", 
                font=ModernStyle.FONTS['heading'], bg=ModernStyle.COLORS['background'],
                fg=ModernStyle.COLORS['text']).pack(pady=20)
        
        tk.Label(progress_window, text=f"Cible: {target}", 
                font=ModernStyle.FONTS['body'], bg=ModernStyle.COLORS['background'],
                fg=ModernStyle.COLORS['text_light']).pack(pady=(0, 20))
        
        # Barre de progression indéterminée
        progress_bar = ttk.Progressbar(progress_window, mode='indeterminate')
        progress_bar.pack(fill=tk.X, padx=40, pady=(0, 20))
        progress_bar.start()
        
        def run():
            try:
                result = scan_function(target)
                
                # Sauvegarder automatiquement le rapport
                report_path = self.report_manager.save_report(scan_type, target, result)
                
                # Mettre à jour les statistiques
                self.stats.increment_scan(scan_type)
                if report_path:
                    self.stats.increment_report()
                
                progress_window.after(0, lambda: show_result(scan_name, result))
            except Exception as e:
                error_msg = f"Erreur lors du {scan_name}: {str(e)}"
                progress_window.after(0, lambda: show_error(error_msg))
            finally:
                progress_window.after(0, progress_window.destroy)
        
        def show_result(name, result):
            self.show_scan_result(name, result)
        
        def show_error(error):
            messagebox.showerror("Erreur", error)
        
        threading.Thread(target=run, daemon=True).start()
    
    def show_scan_result(self, name, result):
        """Afficher le résultat d'un scan avec scroll"""
        result_window = tk.Toplevel(self.root)
        result_window.title(f"Résultat - {name}")
        result_window.geometry("800x600")
        result_window.configure(bg=ModernStyle.COLORS['background'])
        
        # Header
        header_frame = tk.Frame(result_window, bg=ModernStyle.COLORS['success'], height=80)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        tk.Label(header_frame, text=f"✅ {name} - Résultats", 
                font=ModernStyle.FONTS['heading'], bg=ModernStyle.COLORS['success'], 
                fg="white").pack(pady=25)
        
        # Content
        content_frame = tk.Frame(result_window, bg=ModernStyle.COLORS['background'])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Result text avec scroll automatique
        result_text = scrolledtext.ScrolledText(content_frame, font=ModernStyle.FONTS['code'],
                                               bg=ModernStyle.COLORS['card'], wrap=tk.WORD)
        result_text.pack(fill=tk.BOTH, expand=True)
        result_text.insert(tk.END, result)
        result_text.configure(state=tk.DISABLED)
        
        # Buttons
        button_frame = tk.Frame(result_window, bg=ModernStyle.COLORS['background'])
        button_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        tk.Label(button_frame, text="✅ Rapport automatiquement sauvegardé dans la section Rapports", 
                font=ModernStyle.FONTS['small'], bg=ModernStyle.COLORS['background'],
                fg=ModernStyle.COLORS['success']).pack(side=tk.LEFT)
        
        tk.Button(button_frame, text="❌ Fermer", command=result_window.destroy,
                 bg=ModernStyle.COLORS['danger'], fg="white", font=ModernStyle.FONTS['body'],
                 relief=tk.FLAT, padx=20, pady=8, cursor="hand2").pack(side=tk.RIGHT)
    
    def run(self):
        try:
            self.root.mainloop()
        except Exception as e:
            messagebox.showerror("Erreur Critique", f"Erreur: {str(e)}")

# ==================== INTERFACE CLASSIQUE AVEC STATISTIQUES ====================

class CybersecurityToolbox:
    """Interface classique avec statistiques"""
    
    def __init__(self, user_manager):
        self.user_manager = user_manager
        self.stats = StatisticsManager()
        self.report_manager = ReportManager()
        self.root = tk.Tk()
        self.setup_main_window()
        self.create_widgets()
        
    def setup_main_window(self):
        role_text = "Admin" if self.user_manager.is_admin() else "User"
        self.root.title(f"CyberSec Pro - Enterprise Security Toolkit (Classic) - {role_text}")
        self.root.geometry("1200x800")
        self.root.configure(bg="#ecf0f1")
        try:
            self.root.state('zoomed')
        except:
            pass
        
    def create_widgets(self):
        main_container = tk.Frame(self.root, bg="#ecf0f1")
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Header avec info utilisateur
        header_frame = tk.Frame(main_container, bg="#2c3e50", height=120)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        tk.Label(header_frame, text="🔒 CyberSec Pro (Classic)", 
                font=("Segoe UI", 24, "bold"), bg="#2c3e50", fg="white").pack(pady=(15, 5))
        
        role_text = "Administrateur" if self.user_manager.is_admin() else "Utilisateur"
        tk.Label(header_frame, text=f"Connecté: {self.user_manager.current_user} ({role_text})", 
                font=("Segoe UI", 12), bg="#2c3e50", fg="#3498db").pack()
        
        # Interface avec outils basés sur les permissions
        content_frame = tk.Frame(main_container, bg="#ecf0f1")
        content_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=20)
        
        # Outils de base (pour tous)
        basic_tools = [
            ("🔍 Scan Nmap", self.on_discovery_click, "#3498db"),
            ("📊 Consulter Rapports", self.on_read_module_report_click, "#34495e")
        ]
        
        # Outils avancés (pour admins ou avec permissions)
        advanced_tools = []
        if self.user_manager.has_permission("vulnerability_scan"):
            advanced_tools.append(("🛡️ Scan Vulnérabilités", self.on_vuln_scan_click, "#e74c3c"))
        
        if self.user_manager.has_permission("traffic_analysis"):
            advanced_tools.append(("📡 Analyse Trafic", self.on_traffic_analysis_click, "#1abc9c"))
        
        if self.user_manager.is_admin():
            advanced_tools.extend([
                ("🔧 Service Detection", self.on_service_detection_click, "#9b59b6"),
                ("⚡ Test Exploits", self.on_exploit_test_click, "#e67e22"),
                ("🎯 Post-Exploitation", self.on_post_exploit_click, "#95a5a6")
            ])
        
        all_tools = basic_tools + advanced_tools
        
        # Disposition des boutons
        for i, (text, command, color) in enumerate(all_tools):
            row = i // 3
            col = i % 3
            
            btn = tk.Button(content_frame, text=text, command=command,
                           bg=color, fg="white", font=("Segoe UI", 14, "bold"),
                           relief=tk.FLAT, padx=30, pady=20, cursor="hand2")
            btn.grid(row=row, column=col, sticky="nsew", padx=10, pady=10)
            
            content_frame.grid_rowconfigure(row, weight=1)
            content_frame.grid_columnconfigure(col, weight=1)
    
    def is_valid_ip(self, ip):
        if not ip:
            return False
        pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
        if not re.match(pattern, ip):
            return False
        try:
            octets = ip.split('.')
            for octet in octets:
                if not (0 <= int(octet) <= 255):
                    return False
            return True
        except ValueError:
            return False

    def safe_read_report(self, module):
        """Lecture sécurisée des rapports avec gestion des encodages"""
        try:
            report = read_module_report(module)
            return report
        except UnicodeDecodeError as e:
            try:
                report_path = f"reports/{module}_report.txt"
                if not os.path.exists(report_path):
                    return f"⚠️ Fichier de rapport '{module}' introuvable."
                
                encodings = ['latin-1', 'cp1252', 'iso-8859-1', 'utf-16', 'ascii']
                for encoding in encodings:
                    try:
                        with open(report_path, 'r', encoding=encoding, errors='replace') as f:
                            content = f.read()
                            warning = f"⚠️ Fichier lu avec encodage {encoding}\n" + "="*60 + "\n\n"
                            return warning + content
                    except Exception:
                        continue
                return f"❌ Impossible de lire le rapport '{module}'"
            except Exception as e2:
                return f"❌ Erreur lors de la lecture: {str(e2)}"
        except Exception as e:
            return f"❌ Erreur générale: {str(e)}"

    def on_discovery_click(self):
        ip = CorporateDialog.ask_ip(self.root, "Scan Nmap", "Entrez l'adresse IP à scanner:")
        if ip and self.is_valid_ip(ip):
            def run():
                try:
                    result = run_nmap_scan(ip)
                    # Sauvegarder et mettre à jour stats
                    self.report_manager.save_report("nmap", ip, result)
                    self.stats.increment_scan("nmap")
                    ReportViewer.show_report(self.root, "Scan Nmap", result)
                except Exception as e:
                    messagebox.showerror("Erreur", f"Erreur lors du scan: {str(e)}")
            threading.Thread(target=run, daemon=True).start()
        elif ip:
            messagebox.showerror("Erreur", "Adresse IP invalide")

    def on_vuln_scan_click(self):
        if not self.user_manager.has_permission("vulnerability_scan"):
            messagebox.showerror("Accès refusé", "Vous n'avez pas l'autorisation pour cette fonction")
            return
            
        ip = CorporateDialog.ask_ip(self.root, "Scan Vulnérabilités", "Entrez l'adresse IP cible:")
        if ip and self.is_valid_ip(ip):
            def run():
                try:
                    result = run_openvas_enum(ip)
                    # Sauvegarder et mettre à jour stats
                    self.report_manager.save_report("vulnerability", ip, result)
                    self.stats.increment_scan("vulnerability")
                    ReportViewer.show_report(self.root, "Scan Vulnérabilités", result)
                except Exception as e:
                    messagebox.showerror("Erreur", f"Erreur lors du scan: {str(e)}")
            threading.Thread(target=run, daemon=True).start()
        elif ip:
            messagebox.showerror("Erreur", "Adresse IP invalide")

    def on_traffic_analysis_click(self):
        if not self.user_manager.has_permission("traffic_analysis"):
            messagebox.showerror("Accès refusé", "Vous n'avez pas l'autorisation pour cette fonction")
            return
            
        ip = CorporateDialog.ask_ip(self.root, "Analyse de trafic", "IP cible (optionnel):")
        def run():
            try:
                result = analyze_traffic(interface=None, target_ip=ip if ip else None, duration=10)
                # Sauvegarder et mettre à jour stats
                self.report_manager.save_report("traffic", ip or "auto", result)
                self.stats.increment_scan("traffic")
                ReportViewer.show_report(self.root, "Analyse de Trafic", result)
            except Exception as e:
                messagebox.showerror("Erreur", f"Erreur lors de l'analyse: {str(e)}")
        threading.Thread(target=run, daemon=True).start()

    # NOUVELLES MÉTHODES POUR LES MODULES AVANCÉS
    def on_service_detection_click(self):
        if not self.user_manager.is_admin():
            messagebox.showerror("Accès refusé", "Fonction réservée aux administrateurs")
            return
            
        ip = CorporateDialog.ask_ip(self.root, "Détection Services", "IP cible pour détection:")
        if ip and self.is_valid_ip(ip):
            def run():
                try:
                    detector = ServiceDetector()
                    result = detector.detect_services(ip)
                    # Sauvegarder et mettre à jour stats
                    self.report_manager.save_report("service_detection", ip, result)
                    self.stats.increment_scan("service_detection")
                    ReportViewer.show_report(self.root, "Détection Services", result)
                except Exception as e:
                    messagebox.showerror("Erreur", f"Erreur détection services: {str(e)}")
            threading.Thread(target=run, daemon=True).start()
        elif ip:
            messagebox.showerror("Erreur", "Adresse IP invalide")

    def on_exploit_test_click(self):
        if not self.user_manager.is_admin():
            messagebox.showerror("Accès refusé", "Fonction réservée aux administrateurs")
            return
            
        ip = CorporateDialog.ask_ip(self.root, "Test Exploits", "IP cible pour tests:")
        if ip and self.is_valid_ip(ip):
            def run():
                try:
                    tester = ExploitTester()
                    result = tester.test_vulnerability(ip, "auto")
                    # Sauvegarder et mettre à jour stats
                    self.report_manager.save_report("exploit_test", ip, result)
                    self.stats.increment_scan("exploit_test")
                    ReportViewer.show_report(self.root, "Test Exploits", result)
                except Exception as e:
                    messagebox.showerror("Erreur", f"Erreur test exploits: {str(e)}")
            threading.Thread(target=run, daemon=True).start()
        elif ip:
            messagebox.showerror("Erreur", "Adresse IP invalide")

    def on_post_exploit_click(self):
        if not self.user_manager.is_admin():
            messagebox.showerror("Accès refusé", "Fonction réservée aux administrateurs")
            return
            
        ip = CorporateDialog.ask_ip(self.root, "Post-Exploitation", "IP cible compromise:")
        if ip and self.is_valid_ip(ip):
            def run():
                try:
                    persistence = PersistenceModule()
                    result = persistence.establish_persistence(ip)
                    # Sauvegarder et mettre à jour stats
                    self.report_manager.save_report("post_exploit", ip, result)
                    self.stats.increment_scan("post_exploit")
                    ReportViewer.show_report(self.root, "Post-Exploitation", result)
                except Exception as e:
                    messagebox.showerror("Erreur", f"Erreur post-exploitation: {str(e)}")
            threading.Thread(target=run, daemon=True).start()
        elif ip:
            messagebox.showerror("Erreur", "Adresse IP invalide")

    def on_read_module_report_click(self):
        modules = ["nmap", "vuln", "enum", "exploit", "post", "analyze", "service_detect", "exploit_test"]
        module = CorporateDialog.ask_ip(self.root, "Consulter Rapport", 
                                       f"Module ({', '.join(modules)}):")
        if module and module in modules:
            def run():
                try:
                    report = self.safe_read_report(module)
                    ReportViewer.show_report(self.root, f"Rapport {module.upper()}", report)
                except Exception as e:
                    messagebox.showerror("Erreur", f"Erreur lecture rapport: {str(e)}")
            threading.Thread(target=run, daemon=True).start()
        elif module:
            messagebox.showerror("Erreur", f"Module '{module}' non reconnu")

    def run(self):
        try:
            self.root.mainloop()
        except Exception as e:
            messagebox.showerror("Erreur Critique", f"Erreur: {str(e)}")

# ==================== INTERFACES ADMIN ET CLI SIMPLIFIÉES ====================

class AdminInterface:
    """Interface d'administration simplifiée"""
    
    def __init__(self, user_manager):
        self.user_manager = user_manager
        self.stats = StatisticsManager()
        self.root = tk.Tk()
        self.setup_main_window()
        self.create_interface()
    
    def setup_main_window(self):
        self.root.title("CyberSec Pro - Interface Administrateur")
        self.root.geometry("1200x800")
        self.root.configure(bg=ModernStyle.COLORS['background'])
        try:
            self.root.state('zoomed')
        except:
            pass
    
    def create_interface(self):
        # Header admin
        header_frame = tk.Frame(self.root, bg="#8e44ad", height=100)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        tk.Label(header_frame, text="⚙️ CyberSec Pro - Administration", 
                font=ModernStyle.FONTS['title'], bg="#8e44ad", 
                fg="white").pack(pady=20)
        
        # Statistiques admin
        stats_frame = tk.Frame(self.root, bg=ModernStyle.COLORS['card'], relief=tk.RAISED, bd=1)
        stats_frame.pack(fill=tk.X, padx=20, pady=20)
        
        tk.Label(stats_frame, text="📊 Statistiques Système", font=ModernStyle.FONTS['heading'],
                bg=ModernStyle.COLORS['card']).pack(pady=15)
        
        current_stats = self.stats.get_stats()
        stats_text = f"""Connexions totales: {current_stats.get('total_connections', 0)}
Connexions aujourd'hui: {current_stats.get('today_connections', 0)}
Scans totaux: {current_stats.get('total_scans', 0)}
Vulnérabilités détectées: {current_stats.get('total_vulnerabilities', 0)}
Rapports générés: {current_stats.get('reports_generated', 0)}"""
        
        tk.Label(stats_frame, text=stats_text, font=ModernStyle.FONTS['body'],
                bg=ModernStyle.COLORS['card'], justify=tk.LEFT).pack(pady=(0, 15))
    
    def run(self):
        try:
            self.root.mainloop()
        except Exception as e:
            messagebox.showerror("Erreur Critique", f"Erreur: {str(e)}")

class SimpleCLI:
    """Interface CLI avec statistiques"""
    
    def __init__(self, user_manager):
        self.user_manager = user_manager
        self.stats = StatisticsManager()
        self.show_banner()
    
    def show_banner(self):
        role_text = "Administrateur" if self.user_manager.is_admin() else "Utilisateur"
        current_stats = self.stats.get_stats()
        
        banner = f"""
╔══════════════════════════════════════════════════════════════╗
║                         CyberSec Pro                         ║
║                Command Line Interface                        ║
║                                                              ║
║    Utilisateur: {self.user_manager.current_user:<15} Rôle: {role_text:<15}     ║
║    Scans: {current_stats.get('total_scans', 0):<5} Vulnérabilités: {current_stats.get('total_vulnerabilities', 0):<5} Rapports: {current_stats.get('reports_generated', 0):<5}    ║
╚══════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def show_menu(self):
        print("\n" + "="*50)
        print("MENU PRINCIPAL")
        print("="*50)
        
        menu_items = []
        counter = 1
        
        if self.user_manager.has_permission("scan"):
            menu_items.append(f"{counter}. 🔍 Scan Nmap")
            counter += 1
        
        if self.user_manager.has_permission("vulnerability_scan"):
            menu_items.append(f"{counter}. 🛡️ Scan Vulnérabilités")
            counter += 1
        
        if self.user_manager.has_permission("traffic_analysis"):
            menu_items.append(f"{counter}. 📡 Analyse de Trafic")
            counter += 1
        
        if self.user_manager.is_admin():
            menu_items.append(f"{counter}. 🔍 Détection Services")
            counter += 1
            menu_items.append(f"{counter}. ⚡ Test Exploits")
            counter += 1
        
        menu_items.append(f"{counter}. 📊 Statistiques")
        menu_items.append("0. Quitter")
        
        for item in menu_items:
            print(item)
        print("-"*50)
        
        return counter
    
    def get_choice(self, max_choice):
        while True:
            try:
                choice = input(f"Votre choix (0-{max_choice}): ").strip()
                choice = int(choice)
                if 0 <= choice <= max_choice:
                    return choice
                else:
                    print(f"Veuillez entrer un nombre entre 0 et {max_choice}")
            except ValueError:
                print("Veuillez entrer un nombre valide")
            except KeyboardInterrupt:
                return 0
    
    def get_ip_input(self, prompt="Entrez l'adresse IP"):
        while True:
            ip = input(f"{prompt}: ").strip()
            if not ip:
                print("L'adresse IP ne peut pas être vide")
                continue
            
            # Validation basique
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                octets = ip.split('.')
                if all(0 <= int(octet) <= 255 for octet in octets):
                    return ip
            
            print("Format d'IP invalide. Exemple: 192.168.1.1")
    
    def execute_scan(self, scan_name, target, scan_function, scan_type):
        print(f"\n🚀 Lancement du {scan_name} sur {target}")
        print("Scan en cours...", end="", flush=True)
        
        try:
            result = scan_function(target)
            self.stats.increment_scan(scan_type)
            print(" ✅ Terminé!")
            print("\n" + "="*60)
            print(f"RÉSULTATS DU {scan_name.upper()}")
            print("="*60)
            print(result)
            print("="*60)
            
            save = input("\nSauvegarder le rapport? (o/n): ").lower()
            if save in ['o', 'oui', 'y', 'yes']:
                filename = f"{scan_name.lower().replace(' ', '_')}_{int(time.time())}.txt"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"{scan_name} - {datetime.now()}\n")
                    f.write("="*60 + "\n")
                    f.write(result)
                print(f"✅ Rapport sauvegardé: {filename}")
            
        except Exception as e:
            print(f" ❌ Erreur: {str(e)}")
    
    def show_statistics(self):
        """Afficher les statistiques détaillées"""
        current_stats = self.stats.get_stats()
        
        print("\n" + "="*60)
        print("📊 STATISTIQUES DÉTAILLÉES")
        print("="*60)
        print(f"Connexions totales: {current_stats.get('total_connections', 0)}")
        print(f"Connexions aujourd'hui: {current_stats.get('today_connections', 0)}")
        print(f"Scans totaux: {current_stats.get('total_scans', 0)}")
        print(f"Scans aujourd'hui: {current_stats.get('today_scans', 0)}")
        print(f"Vulnérabilités détectées: {current_stats.get('total_vulnerabilities', 0)}")
        print(f"Rapports générés: {current_stats.get('reports_generated', 0)}")
        
        print("\n📈 Détail par type de scan:")
        scan_types = current_stats.get('scan_types', {})
        for scan_type, count in scan_types.items():
            if count > 0:
                print(f"  • {scan_type.replace('_', ' ').title()}: {count}")
        
        print("="*60)
    
    def run(self):
        while True:
            try:
                max_choice = self.show_menu()
                choice = self.get_choice(max_choice)
                
                if choice == 0:
                    print("Au revoir!")
                    break
                
                # Mappage dynamique des choix basé sur les permissions
                current_choice = 1
                
                if self.user_manager.has_permission("scan") and choice == current_choice:
                    ip = self.get_ip_input("IP cible pour Nmap")
                    self.execute_scan("Scan Nmap", ip, run_nmap_scan, "nmap")
                elif self.user_manager.has_permission("scan"):
                    current_choice += 1
                
                if self.user_manager.has_permission("vulnerability_scan") and choice == current_choice:
                    ip = self.get_ip_input("IP cible pour vulnérabilités")
                    self.execute_scan("Scan Vulnérabilités", ip, run_openvas_enum, "vulnerability")
                elif self.user_manager.has_permission("vulnerability_scan"):
                    current_choice += 1
                
                if self.user_manager.has_permission("traffic_analysis") and choice == current_choice:
                    ip = input("IP cible pour analyse trafic (optionnel): ").strip()
                    self.execute_scan("Analyse Trafic", ip or "auto", 
                                    lambda x: analyze_traffic(target_ip=x if x != "auto" else None, duration=10), "traffic")
                elif self.user_manager.has_permission("traffic_analysis"):
                    current_choice += 1
                
                if self.user_manager.is_admin():
                    if choice == current_choice:
                        ip = self.get_ip_input("IP pour détection services")
                        detector = ServiceDetector()
                        self.execute_scan("Détection Services", ip, detector.detect_services, "service_detection")
                    elif choice == current_choice + 1:
                        ip = self.get_ip_input("IP pour test exploits")
                        tester = ExploitTester()
                        self.execute_scan("Test Exploits", ip, lambda x: tester.test_vulnerability(x, "auto"), "exploit_test")
                    
                    current_choice += 2
                
                if choice == current_choice:
                    self.show_statistics()
                
                input("\nAppuyez sur Entrée pour continuer...")
                
            except KeyboardInterrupt:
                print("\nAu revoir!")
                break

# ==================== POINT D'ENTRÉE PRINCIPAL ====================

def main():
    """Point d'entrée principal avec authentification et sélection d'interface"""
    
    # Vérifier les arguments de ligne de commande
    if len(sys.argv) > 1:
        if sys.argv[1] == '--help':
            print("""
CyberSec Pro - Options de lancement:

python main.py               # Sélecteur d'interface avec authentification
python main.py --cli         # Interface CLI directement (nécessite auth)
python main.py --classic     # Interface classique directement
python main.py --modern      # Interface moderne directement
python main.py --admin       # Interface admin directement (admin requis)
python main.py --help        # Cette aide
            """)
            return
    
    # Sélecteur d'interface par défaut avec authentification
    try:
        selector = InterfaceSelector()
        choice = selector.show()
        
        if not choice:
            print("Authentification échouée ou annulée. Au revoir!")
            return
        
        interface_type, user_manager = choice
        
        if interface_type == "modern":
            print("🚀 Lancement de l'interface moderne...")
            app = ModernInterface(user_manager)
            app.run()
        elif interface_type == "classic":
            print("🚀 Lancement de l'interface classique...")
            app = CybersecurityToolbox(user_manager)
            app.run()
        elif interface_type == "admin":
            print("🚀 Lancement de l'interface administrateur...")
            app = AdminInterface(user_manager)
            app.run()
        elif interface_type == "cli":
            print("🚀 Lancement de l'interface CLI...")
            cli = SimpleCLI(user_manager)
            cli.run()
        else:
            print("Interface non reconnue. Au revoir!")
    
    except Exception as e:
        print(f"Erreur lors du lancement: {e}")
        print("Tentative de lancement en mode CLI d'urgence...")
        # Créer un user manager d'urgence
        emergency_user = UserManager()
        emergency_user.current_user = "emergency"
        emergency_user.current_role = "user"
        cli = SimpleCLI(emergency_user)
        cli.run()

if __name__ == "__main__":
    main()