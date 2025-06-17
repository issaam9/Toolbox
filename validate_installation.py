#!/usr/bin/env python3
"""
Script de validation pour CyberSec Pro
Vérifie que tous les composants sont correctement installés et fonctionnels
"""

import os
import sys
import json
import subprocess
import importlib
from pathlib import Path
from datetime import datetime

class CyberSecValidator:
    """Validateur d'installation CyberSec Pro"""
    
    def __init__(self):
        self.base_dir = Path.cwd()
        self.errors = []
        self.warnings = []
        self.success_count = 0
        self.total_tests = 0
    
    def run_validation(self):
        """Exécuter la validation complète"""
        print("🔍 CYBERSEC PRO - VALIDATION D'INSTALLATION")
        print("=" * 60)
        print()
        
        # Tests de base
        self.test_python_version()
        self.test_directory_structure()
        self.test_configuration_files()
        self.test_python_dependencies()
        self.test_modules_import()
        self.test_system_tools()
        self.test_permissions()
        self.test_functionality()
        
        # Rapport final
        self.print_final_report()
    
    def test_python_version(self):
        """Tester la version Python"""
        self.total_tests += 1
        print("🐍 Test version Python...")
        
        if sys.version_info >= (3, 6):
            print(f"   ✅ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
            self.success_count += 1
        else:
            error = f"Python 3.6+ requis, trouvé {sys.version_info.major}.{sys.version_info.minor}"
            self.errors.append(error)
            print(f"   ❌ {error}")
    
    def test_directory_structure(self):
        """Tester la structure des répertoires"""
        self.total_tests += 1
        print("📁 Test structure des répertoires...")
        
        required_dirs = [
            'toolbox', 'toolbox/discovery', 'toolbox/vulnerability',
            'toolbox/enumeration', 'toolbox/exploitation', 'toolbox/post_exploitation',
            'toolbox/analyzer', 'toolbox/reporting', 'toolbox/plugins',
            'config', 'reports', 'logs', 'plugins'
        ]
        
        missing_dirs = []
        for directory in required_dirs:
            if not (self.base_dir / directory).exists():
                missing_dirs.append(directory)
        
        if not missing_dirs:
            print(f"   ✅ Structure complète ({len(required_dirs)} répertoires)")
            self.success_count += 1
        else:
            error = f"Répertoires manquants: {', '.join(missing_dirs)}"
            self.errors.append(error)
            print(f"   ❌ {error}")
    
    def test_configuration_files(self):
        """Tester les fichiers de configuration"""
        self.total_tests += 1
        print("⚙️  Test fichiers de configuration...")
        
        config_files = [
            'config/users.json',
            'config/cybersec_config.json'
        ]
        
        missing_files = []
        invalid_files = []
        
        for config_file in config_files:
            file_path = self.base_dir / config_file
            
            if not file_path.exists():
                missing_files.append(config_file)
                continue
            
            try:
                with open(file_path, 'r') as f:
                    json.load(f)
            except json.JSONDecodeError:
                invalid_files.append(config_file)
        
        if not missing_files and not invalid_files:
            print(f"   ✅ Configuration valide ({len(config_files)} fichiers)")
            self.success_count += 1
        else:
            if missing_files:
                error = f"Fichiers manquants: {', '.join(missing_files)}"
                self.errors.append(error)
                print(f"   ❌ {error}")
            
            if invalid_files:
                error = f"JSON invalide: {', '.join(invalid_files)}"
                self.errors.append(error)
                print(f"   ❌ {error}")
    
    def test_python_dependencies(self):
        """Tester les dépendances Python"""
        self.total_tests += 1
        print("📦 Test dépendances Python...")
        
        dependencies = [
            'requests', 'tkinter', 'json', 'threading', 'subprocess',
            'socket', 'time', 'datetime', 'os', 'sys', 're', 'pathlib'
        ]
        
        optional_deps = [
            'nmap', 'scapy', 'cryptography', 'paramiko', 
            'beautifulsoup4', 'matplotlib', 'pandas'
        ]
        
        missing_core = []
        missing_optional = []
        
        for dep in dependencies:
            try:
                importlib.import_module(dep)
            except ImportError:
                missing_core.append(dep)
        
        for dep in optional_deps:
            try:
                importlib.import_module(dep)
            except ImportError:
                missing_optional.append(dep)
        
        if not missing_core:
            print(f"   ✅ Dépendances principales OK ({len(dependencies)} modules)")
            self.success_count += 1
            
            if missing_optional:
                warning = f"Dépendances optionnelles manquantes: {', '.join(missing_optional)}"
                self.warnings.append(warning)
                print(f"   ⚠️  {warning}")
        else:
            error = f"Dépendances manquantes: {', '.join(missing_core)}"
            self.errors.append(error)
            print(f"   ❌ {error}")
    
    def test_modules_import(self):
        """Tester l'import des modules CyberSec"""
        self.total_tests += 1
        print("🔧 Test import des modules...")
        
        modules_to_test = [
            ('toolbox.discovery.nmap_scanner', 'run_nmap_scan'),
            ('toolbox.vulnerability.openvas_scanner', 'run_enum'),
            ('toolbox.analyzer.wireshark_analyzer', 'analyze_traffic'),
            ('toolbox.reporting.report_generator', 'log_to_module_report'),
            ('toolbox.plugins.plugin_manager', 'PluginManager'),
            ('toolbox.enumeration.service_detector', 'ServiceDetector'),
            ('toolbox.exploitation.exploit_tester', 'ExploitTester'),
            ('toolbox.post_exploitation.persistence_module', 'PersistenceModule'),
            ('toolbox.vulnerability.openvas_automation', 'OpenVASAutomation')
        ]
        
        failed_imports = []
        
        # Ajouter le répertoire courant au path
        sys.path.insert(0, str(self.base_dir))
        
        for module_name, function_name in modules_to_test:
            try:
                module = importlib.import_module(module_name)
                if not hasattr(module, function_name):
                    failed_imports.append(f"{module_name}.{function_name}")
            except ImportError as e:
                failed_imports.append(f"{module_name} ({str(e)})")
        
        if not failed_imports:
            print(f"   ✅ Modules importés ({len(modules_to_test)} modules)")
            self.success_count += 1
        else:
            error = f"Échec d'import: {', '.join(failed_imports[:3])}..."
            self.errors.append(error)
            print(f"   ❌ {error}")
    
    def test_system_tools(self):
        """Tester la disponibilité des outils système"""
        self.total_tests += 1
        print("🛠️  Test outils système...")
        
        tools = {
            'nmap': 'Scan réseau',
            'tcpdump': 'Capture réseau',
            'python3': 'Python',
            'pip3': 'Gestionnaire de paquets'
        }
        
        optional_tools = {
            'masscan': 'Scan rapide',
            'nikto': 'Scan web',
            'dirb': 'Découverte web',
            'hydra': 'Brute force',
            'john': 'Cassage mots de passe'
        }
        
        missing_core = []
        missing_optional = []
        
        for tool, description in tools.items():
            try:
                result = subprocess.run(['which', tool], capture_output=True)
                if result.returncode != 0:
                    missing_core.append(f"{tool} ({description})")
            except Exception:
                missing_core.append(f"{tool} ({description})")
        
        for tool, description in optional_tools.items():
            try:
                result = subprocess.run(['which', tool], capture_output=True)
                if result.returncode != 0:
                    missing_optional.append(f"{tool} ({description})")
            except Exception:
                missing_optional.append(f"{tool} ({description})")
        
        if not missing_core:
            print(f"   ✅ Outils principaux disponibles")
            self.success_count += 1
            
            if missing_optional:
                warning = f"Outils optionnels manquants: {', '.join(missing_optional[:3])}..."
                self.warnings.append(warning)
                print(f"   ⚠️  {warning}")
        else:
            error = f"Outils manquants: {', '.join(missing_core)}"
            self.errors.append(error)
            print(f"   ❌ {error}")
    
    def test_permissions(self):
        """Tester les permissions"""
        self.total_tests += 1
        print("🔐 Test permissions...")
        
        test_dirs = ['config', 'reports', 'logs']
        permission_errors = []
        
        for directory in test_dirs:
            dir_path = self.base_dir / directory
            
            if not dir_path.exists():
                continue
            
            # Test lecture
            if not os.access(dir_path, os.R_OK):
                permission_errors.append(f"Lecture {directory}")
            
            # Test écriture
            if not os.access(dir_path, os.W_OK):
                permission_errors.append(f"Écriture {directory}")
        
        # Test main.py exécutable
        main_file = self.base_dir / 'main.py'
        if main_file.exists() and not os.access(main_file, os.X_OK):
            permission_errors.append("Exécution main.py")
        
        if not permission_errors:
            print("   ✅ Permissions correctes")
            self.success_count += 1
        else:
            error = f"Problèmes de permissions: {', '.join(permission_errors)}"
            self.errors.append(error)
            print(f"   ❌ {error}")
    
    def test_functionality(self):
        """Tester les fonctionnalités de base"""
        self.total_tests += 1
        print("🧪 Test fonctionnalités...")
        
        try:
            # Test système de rapports
            sys.path.insert(0, str(self.base_dir))
            from toolbox.reporting.report_generator import log_to_module_report, read_module_report
            
            test_content = f"Test validation {datetime.now()}"
            success = log_to_module_report("validation", test_content)
            
            if success:
                result = read_module_report("validation")
                if test_content in result:
                    print("   ✅ Fonctionnalités de base OK")
                    self.success_count += 1
                else:
                    error = "Système de rapports défaillant"
                    self.errors.append(error)
                    print(f"   ❌ {error}")
            else:
                error = "Impossible d'écrire les rapports"
                self.errors.append(error)
                print(f"   ❌ {error}")
        
        except Exception as e:
            error = f"Test fonctionnel échoué: {str(e)}"
            self.errors.append(error)
            print(f"   ❌ {error}")
    
    def print_final_report(self):
        """Afficher le rapport final"""
        print("\n" + "=" * 60)
        print("📊 RAPPORT DE VALIDATION")
        print("=" * 60)
        
        success_rate = (self.success_count / self.total_tests) * 100
        
        print(f"Tests réussis: {self.success_count}/{self.total_tests} ({success_rate:.1f}%)")
        print(f"Erreurs: {len(self.errors)}")
        print(f"Avertissements: {len(self.warnings)}")
        
        if self.errors:
            print("\n🔴 ERREURS CRITIQUES:")
            for i, error in enumerate(self.errors, 1):
                print(f"   {i}. {error}")
        
        if self.warnings:
            print("\n🟡 AVERTISSEMENTS:")
            for i, warning in enumerate(self.warnings, 1):
                print(f"   {i}. {warning}")
        
        if not self.errors:
            print("\n✅ INSTALLATION VALIDÉE!")
            print("CyberSec Pro est prêt à être utilisé.")
            print("\nPour démarrer:")
            print("   python3 main.py")
            print("\nComptes par défaut:")
            print("   👤 admin/admin123 (Administrateur)")
            print("   👤 user/user123 (Utilisateur)")
        else:
            print("\n❌ VALIDATION ÉCHOUÉE!")
            print("Corrigez les erreurs avant d'utiliser CyberSec Pro.")
            print("\nActions recommandées:")
            print("   1. Exécutez: python3 setup.py")
            print("   2. Installez les dépendances manquantes")
            print("   3. Vérifiez les permissions")
            print("   4. Relancez la validation")
        
        print("\n" + "=" * 60)
    
    def fix_common_issues(self):
        """Proposer des corrections automatiques"""
        print("\n🔧 CORRECTION AUTOMATIQUE")
        print("-" * 30)
        
        # Créer les répertoires manquants
        required_dirs = ['config', 'reports', 'logs', 'plugins', 'data']
        for directory in required_dirs:
            dir_path = self.base_dir / directory
            if not dir_path.exists():
                dir_path.mkdir(parents=True, exist_ok=True)
                print(f"   ✅ Répertoire créé: {directory}")
        
        # Corriger les permissions
        try:
            os.chmod(self.base_dir / 'main.py', 0o755)
            print("   ✅ Permissions main.py corrigées")
        except:
            pass
        
        print("   ⚠️  Pour les autres corrections, utilisez: python3 setup.py")

def main():
    """Fonction principale"""
    validator = CyberSecValidator()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == '--fix':
            validator.fix_common_issues()
            return
        elif sys.argv[1] == '--help':
            print("""
Validateur d'installation CyberSec Pro

Usage:
    python3 validate_installation.py        # Validation complète
    python3 validate_installation.py --fix  # Corrections automatiques
    python3 validate_installation.py --help # Cette aide

Ce script vérifie:
- Version Python
- Structure des répertoires
- Fichiers de configuration
- Dépendances Python
- Import des modules
- Outils système
- Permissions
- Fonctionnalités de base
            """)
            return
    
    validator.run_validation()

if __name__ == "__main__":
    main()