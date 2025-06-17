#!/usr/bin/env python3
"""
Script d'installation et de configuration pour CyberSec Pro
Créé pour configurer l'environnement et installer les dépendances
"""

from datetime import datetime
import os
import sys
import subprocess
import json
import shutil
from pathlib import Path

class CyberSecSetup:
    """Installation et configuration de CyberSec Pro"""
    
    def __init__(self):
        self.base_dir = Path.cwd()
        self.required_dirs = [
            'toolbox',
            'toolbox/discovery',
            'toolbox/vulnerability', 
            'toolbox/enumeration',
            'toolbox/exploitation',
            'toolbox/post_exploitation',
            'toolbox/analyzer',
            'toolbox/reporting',
            'toolbox/plugins',
            'toolbox/plugins/scanners',
            'toolbox/plugins/analyzers',
            'toolbox/plugins/exploits',
            'toolbox/plugins/reports',
            'toolbox/plugins/utils',
            'config',
            'reports',
            'logs',
            'plugins',
            'data',
            'backup'
        ]
        
        self.python_deps = [
            'requests',
            'python-nmap',
            'paramiko',
            'cryptography',
            'beautifulsoup4',
            'lxml',
            'colorama',
            'tabulate',
            'matplotlib',
            'pandas',
            'scapy',
            'netaddr'
        ]
        
        self.system_deps = {
            'debian': ['nmap', 'masscan', 'nikto', 'dirb', 'gobuster', 'hydra', 'john'],
            'redhat': ['nmap', 'masscan', 'nikto', 'dirb', 'gobuster', 'hydra', 'john'],
            'arch': ['nmap', 'masscan', 'nikto', 'dirb', 'gobuster', 'hydra', 'john']
        }
    
    def run_setup(self):
        """Exécuter l'installation complète"""
        print("=" * 60)
        print("🔒 CYBERSEC PRO - INSTALLATION")
        print("=" * 60)
        print()
        
        try:
            # Vérifications préliminaires
            self.check_requirements()
            
            # Création de la structure
            self.create_directory_structure()
            
            # Installation des dépendances
            self.install_dependencies()
            
            # Configuration initiale
            self.initial_configuration()
            
            # Création des fichiers manquants
            self.create_missing_modules()
            
            # Configuration des permissions
            self.setup_permissions()
            
            # Tests de base
            self.run_basic_tests()
            
            print("\n" + "=" * 60)
            print("✅ INSTALLATION TERMINÉE AVEC SUCCÈS!")
            print("=" * 60)
            print("\nPour démarrer CyberSec Pro:")
            print("python3 main.py")
            print("\nComptes par défaut:")
            print("👤 admin/admin123 (Administrateur)")
            print("👤 user/user123 (Utilisateur)")
            
        except Exception as e:
            print(f"\n❌ Erreur lors de l'installation: {e}")
            print("Vérifiez les logs pour plus de détails.")
            sys.exit(1)
    
    def check_requirements(self):
        """Vérifier les prérequis système"""
        print("🔍 Vérification des prérequis...")
        
        # Vérifier Python
        if sys.version_info < (3, 6):
            raise Exception("Python 3.6+ requis")
        
        # Vérifier les permissions
        if not os.access('.', os.W_OK):
            raise Exception("Permissions d'écriture requises dans le répertoire courant")
        
        # Vérifier pip
        try:
            import pip
        except ImportError:
            raise Exception("pip non trouvé. Installez python3-pip")
        
        print("✅ Prérequis validés")
    
    def create_directory_structure(self):
        """Créer la structure de répertoires"""
        print("📁 Création de la structure de répertoires...")
        
        for directory in self.required_dirs:
            dir_path = self.base_dir / directory
            dir_path.mkdir(parents=True, exist_ok=True)
            
            # Créer un fichier __init__.py pour les modules Python
            if 'toolbox' in directory:
                init_file = dir_path / '__init__.py'
                if not init_file.exists():
                    init_file.write_text('# CyberSec Pro Module\n')
        
        print("✅ Structure de répertoires créée")
    
    def install_dependencies(self):
        """Installer les dépendances"""
        print("📦 Installation des dépendances Python...")
        
        for dep in self.python_deps:
            try:
                print(f"   Installing {dep}...")
                subprocess.run([sys.executable, '-m', 'pip', 'install', dep], 
                             check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                print(f"   ⚠️  Erreur installation {dep}: {e}")
        
        print("✅ Dépendances Python installées")
        
        # Installation automatique des outils système sur Kali/Debian
        if os.path.exists('/etc/debian_version'):
            print("\n🔧 Installation des outils de sécurité...")
            
            tools_to_install = ['nmap', 'tcpdump', 'wireshark', 'tshark']
            
            try:
                # Mise à jour des paquets
                subprocess.run(['sudo', 'apt', 'update'], check=True, capture_output=True, timeout=60)
                print("   ✅ Mise à jour des paquets")
                
                # Installation des outils essentiels
                for tool in tools_to_install:
                    try:
                        # Vérifier si déjà installé
                        result = subprocess.run(['which', tool], capture_output=True)
                        if result.returncode == 0:
                            print(f"   ✅ {tool} déjà installé")
                            continue
                        
                        # Installer l'outil
                        if tool == 'tshark':
                            # tshark est inclus avec wireshark
                            continue
                        
                        print(f"   📦 Installation de {tool}...")
                        subprocess.run(['sudo', 'apt', 'install', '-y', tool], 
                                     check=True, capture_output=True, timeout=120)
                        print(f"   ✅ {tool} installé")
                        
                    except subprocess.CalledProcessError:
                        print(f"   ⚠️  Échec installation {tool}")
                    except subprocess.TimeoutExpired:
                        print(f"   ⚠️  Timeout installation {tool}")
                
                # Configuration spéciale pour Wireshark
                self.configure_wireshark()
                
            except subprocess.CalledProcessError:
                print("   ⚠️  Erreur lors de la mise à jour des paquets")
            except subprocess.TimeoutExpired:
                print("   ⚠️  Timeout lors de la mise à jour")
        
        else:
            # Suggestions pour les autres OS
            print("\n📋 Outils système recommandés:")
            print("   Sur Debian/Ubuntu: sudo apt install nmap tcpdump wireshark")
            print("   Sur CentOS/RHEL:   sudo yum install nmap tcpdump wireshark")
            print("   Sur Arch Linux:    sudo pacman -S nmap tcpdump wireshark-qt")
    
    def configure_wireshark(self):
        """Configuration spéciale pour Wireshark"""
        try:
            username = os.getenv('USER')
            if username and username != 'root':
                print("   🔧 Configuration des permissions Wireshark...")
                
                # Ajouter l'utilisateur au groupe wireshark
                subprocess.run(['sudo', 'usermod', '-a', '-G', 'wireshark', username], 
                             capture_output=True, timeout=10)
                
                # Permissions sur dumpcap
                subprocess.run(['sudo', 'chmod', '+x', '/usr/bin/dumpcap'], 
                             capture_output=True, timeout=10)
                
                print("   ✅ Permissions Wireshark configurées")
                print("   ⚠️  Redémarrez votre session pour appliquer les changements")
            
        except Exception as e:
            print(f"   ⚠️  Erreur configuration Wireshark: {e}")
            print("   💡 Configurez manuellement avec:")
            print(f"      sudo usermod -a -G wireshark {username}")
            print("      sudo chmod +x /usr/bin/dumpcap")
    
    def initial_configuration(self):
        """Configuration initiale"""
        print("⚙️  Configuration initiale...")
        
        # Fichier de configuration principal
        config = {
            "version": "1.0.0",
            "installation_date": str(Path.cwd()),
            "default_timeout": 30,
            "max_threads": 10,
            "log_level": "INFO",
            "interfaces": {
                "modern": True,
                "classic": True,
                "cli": True,
                "admin": True
            },
            "security": {
                "encryption_enabled": True,
                "session_timeout": 3600,
                "max_login_attempts": 3
            },
            "tools": {
                "nmap_path": "/usr/bin/nmap",
                "masscan_path": "/usr/bin/masscan",
                "nikto_path": "/usr/bin/nikto",
                "dirb_path": "/usr/bin/dirb"
            }
        }
        
        config_file = self.base_dir / 'config' / 'cybersec_config.json'
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        # Configuration des logs
        log_config = {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "standard": {
                    "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
                }
            },
            "handlers": {
                "file": {
                    "level": "INFO",
                    "formatter": "standard",
                    "class": "logging.FileHandler",
                    "filename": "logs/cybersec.log",
                    "mode": "a"
                }
            },
            "loggers": {
                "": {
                    "handlers": ["file"],
                    "level": "INFO",
                    "propagate": False
                }
            }
        }
        
        log_config_file = self.base_dir / 'config' / 'logging.json'
        with open(log_config_file, 'w') as f:
            json.dump(log_config, f, indent=2)
        
        print("✅ Configuration initiale créée")
    
    def create_missing_modules(self):
        """Créer les modules manquants avec des implémentations de base"""
        print("🔧 Création des modules manquants...")
        
        # Module nmap_scanner de base
        nmap_module = self.base_dir / 'toolbox' / 'discovery' / 'nmap_scanner.py'
        if not nmap_module.exists():
            nmap_code = '''#!/usr/bin/env python3
"""
Module Nmap Scanner pour CyberSec Pro
"""

import subprocess
import json
from datetime import datetime

def run_nmap_scan(target, scan_type="basic"):
    """Exécuter un scan nmap"""
    try:
        if scan_type == "basic":
            cmd = ["nmap", "-sV", "-O", "--script=vuln", target]
        elif scan_type == "intense":
            cmd = ["nmap", "-A", "-T4", "-script=vuln", target]
        else:
            cmd = ["nmap", "-sS", target]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            return format_nmap_results(result.stdout, target)
        else:
            return f"Erreur nmap: {result.stderr}"
    
    except subprocess.TimeoutExpired:
        return f"Timeout lors du scan de {target}"
    except FileNotFoundError:
        return f"nmap non trouvé. Installez nmap: sudo apt install nmap"
    except Exception as e:
        return f"Erreur lors du scan: {str(e)}"

def format_nmap_results(raw_output, target):
    """Formater les résultats nmap"""
    formatted = []
    formatted.append("=" * 50)
    formatted.append("NMAP SCAN RESULTS")
    formatted.append("=" * 50)
    formatted.append(f"Target: {target}")
    formatted.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    formatted.append("")
    formatted.append(raw_output)
    
    return "\\n".join(formatted)

if __name__ == "__main__":
    target = input("Entrez l'IP cible: ")
    result = run_nmap_scan(target)
    print(result)
'''
            with open(nmap_module, 'w') as f:
                f.write(nmap_code)
        
        # Module OpenVAS Scanner de base
        openvas_module = self.base_dir / 'toolbox' / 'vulnerability' / 'openvas_scanner.py'
        if not openvas_module.exists():
            openvas_code = '''#!/usr/bin/env python3
"""
Module OpenVAS Scanner pour CyberSec Pro
"""

from datetime import datetime
import subprocess

def run_enum(target):
    """Scanner les vulnérabilités avec OpenVAS"""
    try:
        # Vérifier si OpenVAS est disponible
        result = subprocess.run(["which", "gvm-cli"], capture_output=True)
        
        if result.returncode != 0:
            return simulate_openvas_scan(target)
        
        # Commande OpenVAS réelle (nécessite configuration)
        # cmd = ["gvm-cli", "socket", "--xml", f"<start_task task_id='{task_id}'/>"]
        # Pour maintenant, simulation
        return simulate_openvas_scan(target)
        
    except Exception as e:
        return f"Erreur OpenVAS: {str(e)}"

def simulate_openvas_scan(target):
    """Simuler un scan OpenVAS"""
    return f"""
=== OPENVAS VULNERABILITY SCAN ===
Target: {target}
Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

VULNERABILITIES FOUND:
1. SSH-2.0-OpenSSH_7.4 (Medium Risk)
   - CVE: CVE-2018-15473
   - Description: User enumeration vulnerability
   
2. Apache/2.4.29 (Low Risk)
   - CVE: CVE-2019-0220
   - Description: URL normalization inconsistency

RECOMMENDATIONS:
- Update OpenSSH to latest version
- Apply Apache security patches
- Review system configurations

NOTE: This is a simulated scan. 
Install and configure OpenVAS for real scanning.
"""

if __name__ == "__main__":
    target = input("Entrez l'IP cible: ")
    result = run_enum(target)
    print(result)
'''
            with open(openvas_module, 'w') as f:
                f.write(openvas_code)
        
        # Module Wireshark Analyzer amélioré
        wireshark_module = self.base_dir / 'toolbox' / 'analyzer' / 'wireshark_analyzer.py'
        if not wireshark_module.exists():
            wireshark_code = '''#!/usr/bin/env python3
"""
Module Wireshark Analyzer pour CyberSec Pro (Version Améliorée)
"""

import subprocess
import time
import os
import sys
import shutil
from datetime import datetime
import logging

def setup_logging():
    logging.basicConfig(level=logging.INFO)
    return logging.getLogger(__name__)

logger = setup_logging()

def check_tool_availability():
    """Vérifier la disponibilité des outils de capture réseau"""
    tools = {
        'tshark': shutil.which('tshark'),
        'tcpdump': shutil.which('tcpdump'),
        'wireshark': shutil.which('wireshark')
    }
    return {k: v for k, v in tools.items() if v is not None}

def get_installation_instructions():
    """Instructions d'installation selon l'OS"""
    if os.path.exists('/etc/kali_version') or 'kali' in os.uname().release.lower():
        return {
            'commands': [
                'sudo apt update',
                'sudo apt install -y wireshark tshark',
                'sudo usermod -a -G wireshark $USER'
            ],
            'note': 'Sur Kali Linux, redémarrez votre session après installation.'
        }
    elif os.path.exists('/etc/debian_version'):
        return {
            'commands': [
                'sudo apt update',
                'sudo apt install -y wireshark-qt tshark',
                'sudo usermod -a -G wireshark $USER'
            ],
            'note': 'Redémarrez votre session pour appliquer les permissions.'
        }
    else:
        return {
            'commands': ['Visitez https://www.wireshark.org/download.html'],
            'note': 'Installation manuelle requise pour votre OS.'
        }

def analyze_traffic(interface=None, target_ip=None, duration=30):
    """Analyser le trafic réseau"""
    available_tools = check_tool_availability()
    
    if not available_tools:
        return generate_installation_report()
    
    # Utiliser tshark si disponible, sinon tcpdump
    if 'tshark' in available_tools:
        return analyze_with_tshark(interface, target_ip, duration)
    elif 'tcpdump' in available_tools:
        return analyze_with_tcpdump(interface, target_ip, duration)
    else:
        return generate_installation_report()

def analyze_with_tshark(interface, target_ip, duration):
    """Analyser avec tshark"""
    if interface is None:
        interface = 'any'
    
    try:
        cmd = ['tshark', '-i', interface, '-c', '50', '-a', f'duration:{duration}']
        if target_ip:
            cmd.extend(['-f', f'host {target_ip}'])
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 10)
        
        if result.returncode == 0:
            return format_results(result.stdout, "tshark", interface, target_ip, duration)
        else:
            if 'permission denied' in result.stderr.lower():
                return generate_permission_error()
            else:
                return f"Erreur tshark: {result.stderr}"
    
    except subprocess.TimeoutExpired:
        return f"Timeout lors de l'analyse sur {interface}"
    except Exception as e:
        return f"Erreur: {str(e)}"

def analyze_with_tcpdump(interface, target_ip, duration):
    """Analyser avec tcpdump"""
    if interface is None:
        interface = 'any'
    
    try:
        cmd = ['sudo', 'tcpdump', '-i', interface, '-c', '50']
        if target_ip:
            cmd.extend(['host', target_ip])
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 5)
        
        if result.returncode == 0:
            return format_results(result.stdout, "tcpdump", interface, target_ip, duration)
        else:
            return f"Erreur tcpdump: {result.stderr}"
    
    except Exception as e:
        return f"Erreur tcpdump: {str(e)}"

def format_results(raw_output, tool, interface, target_ip, duration):
    """Formater les résultats"""
    lines = raw_output.strip().split('\\n')
    packet_count = len([line for line in lines if line.strip() and not line.startswith('Capturing')])
    
    return f"""
=== ANALYSE TRAFIC RÉSEAU ({tool.upper()}) ===
Interface: {interface}
Cible: {target_ip or 'Toutes'}
Durée: {duration} secondes
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

📊 STATISTIQUES:
├─ Paquets capturés: {packet_count}
├─ Outil utilisé: {tool}
└─ Interface: {interface}

🔍 ÉCHANTILLON DE DONNÉES:
{raw_output[:400]}{'...' if len(raw_output) > 400 else ''}

💡 ANALYSE:
{'├─ Trafic détecté normalement' if packet_count > 0 else '├─ Aucun trafic détecté'}
{'├─ Surveillance active' if packet_count > 10 else '├─ Trafic faible'}
└─ Analyse terminée avec succès
"""

def generate_installation_report():
    """Rapport d'installation"""
    instructions = get_installation_instructions()
    
    return f"""
=== INSTALLATION WIRESHARK REQUISE ===
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

❌ PROBLÈME:
Aucun outil de capture réseau détecté (tshark, tcpdump, wireshark).

🔧 INSTALLATION:
{chr(10).join(f'    {cmd}' for cmd in instructions['commands'])}

💡 NOTE:
{instructions['note']}

🌐 TÉLÉCHARGEMENT:
https://www.wireshark.org/download.html

⚠️  APRÈS INSTALLATION:
Redémarrez votre session pour appliquer les permissions.

🧪 TEST:
Vérifiez avec: tshark --version
"""

def generate_permission_error():
    """Erreur de permissions"""
    username = os.getenv('USER', 'user')
    
    return f"""
=== ERREUR DE PERMISSIONS ===
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

❌ PROBLÈME:
Permissions insuffisantes pour la capture réseau.

🔧 SOLUTION:
    sudo usermod -a -G wireshark {username}
    sudo chmod +x /usr/bin/dumpcap

Puis redémarrez votre session.

🔄 ALTERNATIVE:
Utilisez sudo: sudo tshark -i any -c 10
"""

def stop_capture():
    """Arrêter la capture"""
    try:
        subprocess.run(['pkill', 'tshark'], check=False, capture_output=True)
        subprocess.run(['sudo', 'pkill', 'tcpdump'], check=False, capture_output=True)
    except:
        pass

if __name__ == "__main__":
    target = input("IP cible (optionnel): ").strip()
    duration = int(input("Durée (secondes, défaut 10): ") or "10")
    result = analyze_traffic(target_ip=target or None, duration=duration)
    print(result)
'''
            with open(wireshark_module, 'w') as f:
                f.write(wireshark_code)
        
        # Module Report Generator
        report_module = self.base_dir / 'toolbox' / 'reporting' / 'report_generator.py'
        if not report_module.exists():
            report_code = '''#!/usr/bin/env python3
"""
Module Report Generator pour CyberSec Pro
"""

import os
import json
from datetime import datetime
from pathlib import Path

REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)

def log_to_module_report(module, content):
    """Enregistrer dans un rapport de module"""
    try:
        report_file = REPORTS_DIR / f"{module}_report.txt"
        
        with open(report_file, 'a', encoding='utf-8') as f:
            f.write(f"\\n{'='*50}\\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\\n")
            f.write(f"Module: {module.upper()}\\n")
            f.write(f"{'='*50}\\n")
            f.write(content)
            f.write("\\n\\n")
        
        return True
    except Exception as e:
        print(f"Erreur lors de l'écriture du rapport: {e}")
        return False

def read_module_report(module):
    """Lire un rapport de module"""
    try:
        report_file = REPORTS_DIR / f"{module}_report.txt"
        
        if not report_file.exists():
            return f"Aucun rapport trouvé pour le module '{module}'"
        
        with open(report_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return content if content.strip() else f"Le rapport du module '{module}' est vide"
        
    except Exception as e:
        return f"Erreur lors de la lecture du rapport: {e}"

def export_module_report(module, format='txt'):
    """Exporter un rapport de module"""
    try:
        content = read_module_report(module)
        
        if format == 'json':
            export_file = REPORTS_DIR / f"{module}_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            data = {
                'module': module,
                'export_date': datetime.now().isoformat(),
                'content': content
            }
            with open(export_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        else:
            export_file = REPORTS_DIR / f"{module}_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(export_file, 'w', encoding='utf-8') as f:
                f.write(content)
        
        return str(export_file)
        
    except Exception as e:
        return f"Erreur lors de l'export: {e}"

def delete_module_report(module):
    """Supprimer un rapport de module"""
    try:
        report_file = REPORTS_DIR / f"{module}_report.txt"
        
        if report_file.exists():
            report_file.unlink()
            return True
        return False
        
    except Exception as e:
        print(f"Erreur lors de la suppression: {e}")
        return False

def list_existing_reports():
    """Lister les rapports existants"""
    try:
        reports = []
        for file in REPORTS_DIR.glob("*_report.txt"):
            module_name = file.stem.replace('_report', '')
            file_size = file.stat().st_size
            modified = datetime.fromtimestamp(file.stat().st_mtime)
            
            reports.append({
                'module': module_name,
                'file': str(file),
                'size': file_size,
                'modified': modified.strftime('%Y-%m-%d %H:%M:%S')
            })
        
        return reports
        
    except Exception as e:
        print(f"Erreur lors du listage: {e}")
        return []

if __name__ == "__main__":
    # Test du module
    test_content = "Test du système de rapport"
    log_to_module_report("test", test_content)
    
    print("Contenu du rapport test:")
    print(read_module_report("test"))
    
    print("\\nRapports existants:")
    for report in list_existing_reports():
        print(f"- {report['module']}: {report['size']} bytes, modifié {report['modified']}")
'''
            with open(report_module, 'w') as f:
                f.write(report_code)
        
        print("✅ Modules manquants créés")
    
    def setup_permissions(self):
        """Configurer les permissions"""
        print("🔐 Configuration des permissions...")
        
        try:
            # Rendre les scripts exécutables
            scripts = [
                'main.py',
                'setup.py',
                'toolbox/discovery/nmap_scanner.py',
                'toolbox/vulnerability/openvas_scanner.py',
                'toolbox/analyzer/wireshark_analyzer.py'
            ]
            
            for script in scripts:
                script_path = self.base_dir / script
                if script_path.exists():
                    os.chmod(script_path, 0o755)
            
            # Permissions sur les répertoires
            for directory in ['logs', 'reports', 'config', 'backup']:
                dir_path = self.base_dir / directory
                if dir_path.exists():
                    os.chmod(dir_path, 0o755)
            
            print("✅ Permissions configurées")
            
        except Exception as e:
            print(f"⚠️  Erreur permissions: {e}")
    
    def run_basic_tests(self):
        """Exécuter des tests de base"""
        print("🧪 Exécution des tests de base...")
        
        try:
            # Test d'import des modules
            sys.path.insert(0, str(self.base_dir))
            
            # Test du module de rapports
            from toolbox.reporting.report_generator import log_to_module_report, read_module_report
            
            test_content = f"Test d'installation - {datetime.now()}"
            log_to_module_report("installation", test_content)
            
            result = read_module_report("installation")
            if test_content in result:
                print("✅ Test système de rapports: OK")
            else:
                print("⚠️  Test système de rapports: ÉCHEC")
            
            # Test de la structure
            required_files = [
                'config/cybersec_config.json',
                'config/users.json',
                'toolbox/discovery/nmap_scanner.py',
                'toolbox/vulnerability/openvas_scanner.py'
            ]
            
            all_files_exist = True
            for file_path in required_files:
                if not (self.base_dir / file_path).exists():
                    print(f"⚠️  Fichier manquant: {file_path}")
                    all_files_exist = False
            
            if all_files_exist:
                print("✅ Test structure de fichiers: OK")
            else:
                print("⚠️  Test structure de fichiers: ÉCHEC")
            
        except Exception as e:
            print(f"⚠️  Erreur lors des tests: {e}")

def main():
    """Fonction principale"""
    if len(sys.argv) > 1 and sys.argv[1] == '--help':
        print("""
CyberSec Pro - Script d'installation

Usage:
    python3 setup.py          # Installation complète
    python3 setup.py --help   # Afficher cette aide

Ce script va:
1. Créer la structure de répertoires
2. Installer les dépendances Python
3. Créer les fichiers de configuration
4. Créer les modules manquants
5. Configurer les permissions
6. Exécuter des tests de base

Prérequis:
- Python 3.6+
- pip
- Permissions d'écriture dans le répertoire courant

Outils recommandés (à installer manuellement):
- nmap
- masscan  
- nikto
- dirb
- gobuster
- hydra
- john
- tcpdump/wireshark
        """)
        return
    
    setup = CyberSecSetup()
    setup.run_setup()

if __name__ == "__main__":
    main()