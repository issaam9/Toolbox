#!/usr/bin/env python3
"""
Plugin Manager pour CyberSec Pro
Permet de charger et gérer des modules externes dynamiquement
"""

import os
import sys
import json
import importlib
import importlib.util
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging

class PluginManager:
    """Gestionnaire de plugins pour étendre CyberSec Pro"""
    
    def __init__(self, plugins_dir="plugins"):
        self.plugins_dir = plugins_dir
        self.loaded_plugins = {}
        self.plugin_configs = {}
        self.logger = self.setup_logging()
        
        # Créer le répertoire plugins s'il n'existe pas
        os.makedirs(self.plugins_dir, exist_ok=True)
        self.ensure_plugin_structure()
    
    def setup_logging(self):
        """Configuration du logging pour le plugin manager"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - PluginManager - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/plugin_manager.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)
    
    def ensure_plugin_structure(self):
        """Créer la structure de base pour les plugins"""
        # Créer les dossiers nécessaires
        subdirs = ['scanners', 'analyzers', 'exploits', 'reports', 'utils']
        for subdir in subdirs:
            os.makedirs(os.path.join(self.plugins_dir, subdir), exist_ok=True)
        
        # Créer le fichier de configuration des plugins
        config_file = os.path.join(self.plugins_dir, 'plugins_config.json')
        if not os.path.exists(config_file):
            default_config = {
                "enabled_plugins": [],
                "plugin_settings": {},
                "auto_load": True,
                "security_mode": "strict"
            }
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=2)
        
        # Créer un plugin d'exemple
        self.create_example_plugin()
    
    def create_example_plugin(self):
        """Créer un plugin d'exemple pour démonstration"""
        example_dir = os.path.join(self.plugins_dir, 'scanners', 'custom_scanner')
        os.makedirs(example_dir, exist_ok=True)
        
        # Fichier __init__.py
        init_file = os.path.join(example_dir, '__init__.py')
        if not os.path.exists(init_file):
            with open(init_file, 'w') as f:
                f.write('# Custom Scanner Plugin\n')
        
        # Plugin principal
        plugin_file = os.path.join(example_dir, 'scanner.py')
        if not os.path.exists(plugin_file):
            plugin_code = '''#!/usr/bin/env python3
"""
Plugin d'exemple - Scanner personnalisé
"""

class CustomScanner:
    """Scanner personnalisé d'exemple"""
    
    def __init__(self):
        self.name = "Custom Scanner"
        self.version = "1.0.0"
        self.description = "Scanner personnalisé d'exemple"
        self.author = "CyberSec Pro"
    
    def scan(self, target):
        """Effectuer un scan personnalisé"""
        return f"""
=== Custom Scanner Results ===
Target: {target}
Scan Time: {__import__('datetime').datetime.now()}
Status: Simulation - Plugin functioning correctly

Custom checks performed:
- Port verification: PASS
- Service detection: PASS
- Custom vulnerability check: INFO

This is a demonstration plugin.
Replace this code with your own scanning logic.
"""
    
    def get_info(self):
        """Retourner les informations du plugin"""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "capabilities": ["network_scan", "service_detection"]
        }

# Interface requise pour tous les plugins
def get_plugin_instance():
    """Fonction requise pour charger le plugin"""
    return CustomScanner()

def get_plugin_info():
    """Informations du plugin"""
    return {
        "name": "Custom Scanner",
        "version": "1.0.0",
        "type": "scanner",
        "description": "Plugin de démonstration",
        "requirements": []
    }
'''
            with open(plugin_file, 'w') as f:
                f.write(plugin_code)
        
        # Fichier de configuration du plugin
        config_file = os.path.join(example_dir, 'config.json')
        if not os.path.exists(config_file):
            config = {
                "enabled": True,
                "auto_load": True,
                "permissions": ["network_access"],
                "settings": {
                    "timeout": 30,
                    "max_threads": 5
                }
            }
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
    
    def load_plugins(self):
        """Charger tous les plugins disponibles"""
        self.logger.info("Début du chargement des plugins...")
        loaded_count = 0
        
        # Parcourir les répertoires de plugins
        for root, dirs, files in os.walk(self.plugins_dir):
            for file in files:
                if file.endswith('.py') and not file.startswith('__'):
                    plugin_path = os.path.join(root, file)
                    try:
                        if self.load_plugin(plugin_path):
                            loaded_count += 1
                    except Exception as e:
                        self.logger.error(f"Erreur lors du chargement de {plugin_path}: {e}")
        
        self.logger.info(f"{loaded_count} plugin(s) chargé(s) avec succès")
        return self.loaded_plugins
    
    def load_plugin(self, plugin_path):
        """Charger un plugin spécifique"""
        try:
            # Obtenir le nom du module
            module_name = os.path.splitext(os.path.basename(plugin_path))[0]
            
            # Vérifier si le plugin est activé
            if not self.is_plugin_enabled(plugin_path):
                self.logger.info(f"Plugin {module_name} désactivé, ignoré")
                return False
            
            # Charger le module
            spec = importlib.util.spec_from_file_location(module_name, plugin_path)
            if spec is None:
                self.logger.error(f"Impossible de créer spec pour {plugin_path}")
                return False
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Vérifier l'interface requise
            if not hasattr(module, 'get_plugin_instance'):
                self.logger.error(f"Plugin {module_name} manque get_plugin_instance()")
                return False
            
            # Instancier le plugin
            plugin_instance = module.get_plugin_instance()
            plugin_info = module.get_plugin_info() if hasattr(module, 'get_plugin_info') else {}
            
            # Enregistrer le plugin
            self.loaded_plugins[module_name] = {
                'instance': plugin_instance,
                'module': module,
                'info': plugin_info,
                'path': plugin_path,
                'loaded_at': datetime.now()
            }
            
            self.logger.info(f"Plugin {module_name} chargé avec succès")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur lors du chargement de {plugin_path}: {e}")
            return False
    
    def is_plugin_enabled(self, plugin_path):
        """Vérifier si un plugin est activé"""
        # Chercher un fichier config.json dans le répertoire du plugin
        plugin_dir = os.path.dirname(plugin_path)
        config_file = os.path.join(plugin_dir, 'config.json')
        
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                return config.get('enabled', True)
            except Exception:
                return True
        
        return True
    
    def execute_plugin(self, plugin_name, method_name, *args, **kwargs):
        """Exécuter une méthode d'un plugin"""
        if plugin_name not in self.loaded_plugins:
            return f"Plugin '{plugin_name}' non trouvé"
        
        try:
            plugin_instance = self.loaded_plugins[plugin_name]['instance']
            
            if not hasattr(plugin_instance, method_name):
                return f"Méthode '{method_name}' non trouvée dans le plugin '{plugin_name}'"
            
            method = getattr(plugin_instance, method_name)
            result = method(*args, **kwargs)
            
            self.logger.info(f"Exécution réussie: {plugin_name}.{method_name}")
            return result
            
        except Exception as e:
            error_msg = f"Erreur lors de l'exécution de {plugin_name}.{method_name}: {e}"
            self.logger.error(error_msg)
            return error_msg
    
    def get_plugin_list(self):
        """Obtenir la liste des plugins chargés"""
        plugin_list = []
        for name, plugin_data in self.loaded_plugins.items():
            info = plugin_data.get('info', {})
            plugin_list.append({
                'name': name,
                'display_name': info.get('name', name),
                'version': info.get('version', 'Unknown'),
                'description': info.get('description', 'No description'),
                'type': info.get('type', 'unknown'),
                'loaded_at': plugin_data['loaded_at'].strftime('%Y-%m-%d %H:%M:%S'),
                'path': plugin_data['path']
            })
        return plugin_list
    
    def get_plugins_by_type(self, plugin_type):
        """Obtenir les plugins d'un type spécifique"""
        filtered_plugins = {}
        for name, plugin_data in self.loaded_plugins.items():
            info = plugin_data.get('info', {})
            if info.get('type') == plugin_type:
                filtered_plugins[name] = plugin_data
        return filtered_plugins
    
    def reload_plugin(self, plugin_name):
        """Recharger un plugin spécifique"""
        if plugin_name not in self.loaded_plugins:
            return False
        
        plugin_path = self.loaded_plugins[plugin_name]['path']
        
        # Décharger le plugin
        del self.loaded_plugins[plugin_name]
        
        # Recharger le plugin
        return self.load_plugin(plugin_path)
    
    def unload_plugin(self, plugin_name):
        """Décharger un plugin"""
        if plugin_name in self.loaded_plugins:
            del self.loaded_plugins[plugin_name]
            self.logger.info(f"Plugin {plugin_name} déchargé")
            return True
        return False
    
    def install_plugin(self, plugin_archive_path):
        """Installer un nouveau plugin depuis une archive"""
        import zipfile
        import tempfile
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # Extraire l'archive
                with zipfile.ZipFile(plugin_archive_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
                
                # Chercher le fichier manifest
                manifest_path = os.path.join(temp_dir, 'manifest.json')
                if not os.path.exists(manifest_path):
                    return "Erreur: Fichier manifest.json manquant"
                
                with open(manifest_path, 'r') as f:
                    manifest = json.load(f)
                
                plugin_name = manifest.get('name')
                plugin_type = manifest.get('type', 'utils')
                
                # Créer le répertoire de destination
                dest_dir = os.path.join(self.plugins_dir, plugin_type, plugin_name)
                os.makedirs(dest_dir, exist_ok=True)
                
                # Copier les fichiers
                import shutil
                for item in os.listdir(temp_dir):
                    s = os.path.join(temp_dir, item)
                    d = os.path.join(dest_dir, item)
                    if os.path.isdir(s):
                        shutil.copytree(s, d, dirs_exist_ok=True)
                    else:
                        shutil.copy2(s, d)
                
                self.logger.info(f"Plugin {plugin_name} installé avec succès")
                return f"Plugin {plugin_name} installé dans {dest_dir}"
                
        except Exception as e:
            error_msg = f"Erreur lors de l'installation: {e}"
            self.logger.error(error_msg)
            return error_msg
    
    def create_plugin_template(self, plugin_name, plugin_type="scanner"):
        """Créer un template de plugin"""
        plugin_dir = os.path.join(self.plugins_dir, plugin_type, plugin_name)
        os.makedirs(plugin_dir, exist_ok=True)
        
        # Template de base
        template_code = f'''#!/usr/bin/env python3
"""
{plugin_name} Plugin pour CyberSec Pro
Généré automatiquement le {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""

class {plugin_name.title().replace('_', '')}Plugin:
    """Plugin {plugin_name}"""
    
    def __init__(self):
        self.name = "{plugin_name}"
        self.version = "1.0.0"
        self.description = "Description du plugin {plugin_name}"
        self.author = "Your Name"
    
    def execute(self, target):
        """Méthode principale du plugin"""
        # TODO: Implémenter la logique du plugin
        return f"Résultat du plugin {{self.name}} pour la cible {{target}}"
    
    def get_info(self):
        """Retourner les informations du plugin"""
        return {{
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "capabilities": []
        }}

# Interface requise
def get_plugin_instance():
    return {plugin_name.title().replace('_', '')}Plugin()

def get_plugin_info():
    return {{
        "name": "{plugin_name}",
        "version": "1.0.0",
        "type": "{plugin_type}",
        "description": "Plugin {plugin_name}",
        "requirements": []
    }}
'''
        
        # Écrire le fichier principal
        with open(os.path.join(plugin_dir, f'{plugin_name}.py'), 'w') as f:
            f.write(template_code)
        
        # Fichier de configuration
        config = {
            "enabled": True,
            "auto_load": True,
            "permissions": [],
            "settings": {}
        }
        
        with open(os.path.join(plugin_dir, 'config.json'), 'w') as f:
            json.dump(config, f, indent=2)
        
        # Fichier __init__.py
        with open(os.path.join(plugin_dir, '__init__.py'), 'w') as f:
            f.write(f'# {plugin_name} Plugin\n')
        
        return f"Template de plugin créé dans {plugin_dir}"
    
    def get_plugin_status(self):
        """Obtenir le statut complet des plugins"""
        return {
            "total_loaded": len(self.loaded_plugins),
            "plugins": self.get_plugin_list(),
            "plugins_directory": self.plugins_dir,
            "last_load_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

# Fonction utilitaire pour utilisation externe
def main():
    """Fonction principale pour tests"""
    pm = PluginManager()
    
    print("=== CyberSec Pro Plugin Manager ===")
    print("Chargement des plugins...")
    
    plugins = pm.load_plugins()
    print(f"\\n{len(plugins)} plugin(s) chargé(s):")
    
    for name, plugin_data in plugins.items():
        info = plugin_data.get('info', {})
        print(f"- {name}: {info.get('description', 'No description')}")
    
    # Test du plugin d'exemple
    if 'scanner' in plugins:
        print("\\nTest du plugin scanner:")
        result = pm.execute_plugin('scanner', 'scan', '192.168.1.1')
        print(result)

if __name__ == "__main__":
    main()