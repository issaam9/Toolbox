#!/usr/bin/env python3
"""
Module Wireshark Analyzer pour CyberSec Pro (Version Améliorée)
Analyse du trafic réseau avec installation automatique et alternatives
"""

import subprocess
import time
import os
import sys
import threading
import socket
import shutil
from datetime import datetime
from pathlib import Path
import logging

def setup_logging():
    """Configuration du logging"""
    logging.basicConfig(level=logging.INFO)
    return logging.getLogger(__name__)

logger = setup_logging()

def check_tool_availability():
    """Vérifier la disponibilité des outils de capture réseau"""
    tools = {
        'tshark': shutil.which('tshark'),
        'tcpdump': shutil.which('tcpdump'),
        'wireshark': shutil.which('wireshark'),
        'dumpcap': shutil.which('dumpcap')
    }
    
    available_tools = {k: v for k, v in tools.items() if v is not None}
    logger.info(f"Outils disponibles: {list(available_tools.keys())}")
    
    return available_tools

def get_installation_instructions():
    """Obtenir les instructions d'installation selon l'OS"""
    
    # Détecter l'OS
    if os.path.exists('/etc/debian_version'):
        # Debian/Ubuntu/Kali
        if os.path.exists('/etc/kali_version') or 'kali' in os.uname().release.lower():
            os_type = 'kali'
        else:
            os_type = 'debian'
    elif os.path.exists('/etc/redhat-release'):
        os_type = 'redhat'
    elif os.path.exists('/etc/arch-release'):
        os_type = 'arch'
    else:
        os_type = 'unknown'
    
    instructions = {
        'kali': {
            'commands': [
                'sudo apt update',
                'sudo apt install -y wireshark tshark',
                'sudo usermod -a -G wireshark $USER',
                'sudo chmod +x /usr/bin/dumpcap'
            ],
            'note': 'Sur Kali Linux, Wireshark est souvent pré-installé mais peut nécessiter une configuration.'
        },
        'debian': {
            'commands': [
                'sudo apt update', 
                'sudo apt install -y wireshark-qt tshark',
                'sudo usermod -a -G wireshark $USER',
                'sudo chmod +x /usr/bin/dumpcap'
            ],
            'note': 'Redémarrez votre session après installation pour appliquer les permissions.'
        },
        'redhat': {
            'commands': [
                'sudo yum install -y wireshark wireshark-cli',
                'sudo usermod -a -G wireshark $USER'
            ],
            'note': 'Utilisez dnf au lieu de yum sur les versions récentes.'
        },
        'arch': {
            'commands': [
                'sudo pacman -S wireshark-qt wireshark-cli',
                'sudo usermod -a -G wireshark $USER'
            ],
            'note': 'Installation via pacman.'
        },
        'unknown': {
            'commands': [
                'Visitez https://www.wireshark.org/download.html',
                'Téléchargez la version pour votre OS',
                'Suivez les instructions d\'installation'
            ],
            'note': 'OS non reconnu, installation manuelle requise.'
        }
    }
    
    return instructions.get(os_type, instructions['unknown'])

def auto_install_wireshark():
    """Tentative d'installation automatique de Wireshark"""
    instructions = get_installation_instructions()
    
    print("🔧 INSTALLATION AUTOMATIQUE DE WIRESHARK")
    print("=" * 50)
    
    try:
        # Essayer l'installation automatique sur Debian/Kali
        if os.path.exists('/etc/debian_version'):
            print("Détection: Système basé sur Debian")
            print("Tentative d'installation automatique...")
            
            # Mettre à jour les paquets
            result = subprocess.run(['sudo', 'apt', 'update'], 
                                  capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                print("✅ Mise à jour des paquets réussie")
                
                # Installer Wireshark
                result = subprocess.run(['sudo', 'apt', 'install', '-y', 'wireshark', 'tshark'], 
                                      capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0:
                    print("✅ Installation de Wireshark réussie")
                    
                    # Configurer les permissions
                    username = os.getenv('USER')
                    subprocess.run(['sudo', 'usermod', '-a', '-G', 'wireshark', username], 
                                 capture_output=True)
                    subprocess.run(['sudo', 'chmod', '+x', '/usr/bin/dumpcap'], 
                                 capture_output=True)
                    
                    print("✅ Configuration des permissions terminée")
                    print("⚠️  Redémarrez votre session pour appliquer les changements")
                    return True
                else:
                    print(f"❌ Erreur d'installation: {result.stderr}")
            else:
                print(f"❌ Erreur mise à jour: {result.stderr}")
    
    except subprocess.TimeoutExpired:
        print("❌ Timeout lors de l'installation")
    except Exception as e:
        print(f"❌ Erreur: {e}")
    
    return False

def get_available_interfaces():
    """Obtenir la liste des interfaces réseau disponibles"""
    interfaces = []
    
    try:
        # Méthode 1: ip command (Linux)
        result = subprocess.run(['ip', 'link', 'show'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if ': ' in line and 'state' in line.lower():
                    interface = line.split(':')[1].strip().split('@')[0]
                    if interface and interface != 'lo':
                        interfaces.append(interface)
            
            if interfaces:
                return interfaces
    except:
        pass
    
    try:
        # Méthode 2: ifconfig
        result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line and not line.startswith(' ') and ':' in line:
                    interface = line.split(':')[0].strip()
                    if interface and interface != 'lo':
                        interfaces.append(interface)
            
            if interfaces:
                return interfaces
    except:
        pass
    
    # Fallback: interfaces communes
    common_interfaces = ['eth0', 'wlan0', 'enp0s3', 'wlp3s0', 'ens33', 'ens34', 'wlan1']
    
    # Vérifier lesquelles existent
    for iface in common_interfaces:
        if os.path.exists(f'/sys/class/net/{iface}'):
            interfaces.append(iface)
    
    return interfaces if interfaces else ['any']

def analyze_traffic(interface=None, target_ip=None, duration=30, packet_count=100):
    """Analyser le trafic réseau"""
    
    available_tools = check_tool_availability()
    
    if not available_tools:
        return generate_installation_report()
    
    # Choisir l'outil disponible
    if 'tshark' in available_tools:
        return analyze_with_tshark(interface, target_ip, duration, packet_count)
    elif 'tcpdump' in available_tools:
        return analyze_with_tcpdump(interface, target_ip, duration, packet_count)
    else:
        return generate_installation_report()

def analyze_with_tshark(interface=None, target_ip=None, duration=30, packet_count=100):
    """Analyser avec tshark"""
    
    if interface is None:
        interfaces = get_available_interfaces()
        interface = interfaces[0] if interfaces else 'any'
    
    logger.info(f"Démarrage analyse tshark - Interface: {interface}, Durée: {duration}s")
    
    try:
        # Construire la commande tshark
        cmd = ['tshark', '-i', interface, '-c', str(packet_count)]
        
        if target_ip:
            cmd.extend(['-f', f'host {target_ip}'])
        
        # Ajouter timeout
        cmd.extend(['-a', f'duration:{duration}'])
        
        # Exécuter tshark
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 10)
        
        if result.returncode == 0:
            return format_tshark_results(result.stdout, interface, target_ip, duration)
        else:
            error_msg = result.stderr
            if 'permission denied' in error_msg.lower():
                return generate_permission_error_report()
            else:
                return f"Erreur tshark: {error_msg}"
    
    except subprocess.TimeoutExpired:
        return f"Timeout lors de l'analyse sur {interface}"
    except PermissionError:
        return generate_permission_error_report()
    except Exception as e:
        return f"Erreur lors de l'analyse: {str(e)}"

def analyze_with_tcpdump(interface=None, target_ip=None, duration=30, packet_count=100):
    """Analyser avec tcpdump (fallback)"""
    
    if interface is None:
        interfaces = get_available_interfaces()
        interface = interfaces[0] if interfaces else 'any'
    
    logger.info(f"Démarrage analyse tcpdump - Interface: {interface}")
    
    try:
        cmd = ['sudo', 'tcpdump', '-i', interface, '-c', str(packet_count)]
        
        if target_ip:
            cmd.extend(['host', target_ip])
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 5)
        
        if result.returncode == 0:
            return format_tcpdump_results(result.stdout, interface, target_ip, duration)
        else:
            return f"Erreur tcpdump: {result.stderr}"
    
    except subprocess.TimeoutExpired:
        return f"Timeout lors de l'analyse tcpdump sur {interface}"
    except Exception as e:
        return f"Erreur tcpdump: {str(e)}"

def format_tshark_results(raw_output, interface, target_ip, duration):
    """Formater les résultats tshark"""
    
    lines = raw_output.strip().split('\n')
    packet_count = len([line for line in lines if line.strip() and not line.startswith('Capturing')])
    
    # Analyser les protocoles
    protocols = {}
    ips = set()
    ports = set()
    
    for line in lines:
        if '->' in line:
            parts = line.split()
            if len(parts) >= 5:
                # Extraire IP source et destination
                if '->' in parts[2]:
                    src_dst = parts[2].split('->')
                    if len(src_dst) == 2:
                        ips.add(src_dst[0].strip())
                        ips.add(src_dst[1].strip())
                
                # Compter les protocoles
                if len(parts) >= 5:
                    protocol = parts[4] if len(parts) > 4 else 'Unknown'
                    protocols[protocol] = protocols.get(protocol, 0) + 1
    
    return f"""
=== ANALYSE TRAFIC RÉSEAU (TSHARK) ===
Interface: {interface}
Cible: {target_ip or 'Toutes'}
Durée: {duration} secondes
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

📊 STATISTIQUES:
├─ Paquets capturés: {packet_count}
├─ IPs uniques: {len(ips)}
├─ Protocoles détectés: {len(protocols)}
└─ Interfaces: {interface}

🌐 PROTOCOLES:
{format_protocol_stats(protocols)}

🔍 ADRESSES IP DÉTECTÉES:
{format_ip_list(list(ips)[:10])}

💡 ANALYSE:
{generate_traffic_analysis(protocols, packet_count)}

Données brutes disponibles:
{raw_output[:500]}{'...' if len(raw_output) > 500 else ''}
"""

def format_tcpdump_results(raw_output, interface, target_ip, duration):
    """Formater les résultats tcpdump"""
    
    lines = raw_output.strip().split('\n')
    packet_count = len([line for line in lines if line.strip()])
    
    return f"""
=== ANALYSE TRAFIC RÉSEAU (TCPDUMP) ===
Interface: {interface}
Cible: {target_ip or 'Toutes'}
Durée: {duration} secondes
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

📊 STATISTIQUES:
├─ Paquets capturés: {packet_count}
├─ Interface: {interface}
└─ Outil utilisé: tcpdump

📋 DONNÉES BRUTES:
{raw_output}

💡 NOTE:
Pour une analyse plus détaillée, installez tshark/Wireshark.
"""

def format_protocol_stats(protocols):
    """Formater les statistiques de protocoles"""
    if not protocols:
        return "Aucun protocole détecté"
    
    total = sum(protocols.values())
    stats = []
    
    for protocol, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True)[:5]:
        percentage = (count / total) * 100
        stats.append(f"├─ {protocol}: {count} paquets ({percentage:.1f}%)")
    
    return '\n'.join(stats)

def format_ip_list(ips):
    """Formater la liste des IPs"""
    if not ips:
        return "Aucune IP détectée"
    
    formatted = []
    for ip in ips[:8]:
        formatted.append(f"├─ {ip}")
    
    if len(ips) > 8:
        formatted.append(f"└─ ... et {len(ips) - 8} autres")
    
    return '\n'.join(formatted)

def generate_traffic_analysis(protocols, packet_count):
    """Générer une analyse du trafic"""
    analysis = []
    
    if packet_count == 0:
        analysis.append("├─ Aucun trafic détecté")
        analysis.append("├─ Vérifiez l'interface réseau")
        analysis.append("└─ Assurez-vous qu'il y a de l'activité réseau")
    elif packet_count < 10:
        analysis.append("├─ Trafic faible détecté")
        analysis.append("└─ Augmentez la durée de capture")
    else:
        analysis.append("├─ Trafic normal détecté")
        
        if 'TCP' in str(protocols):
            analysis.append("├─ Trafic TCP présent")
        if 'UDP' in str(protocols):
            analysis.append("├─ Trafic UDP présent")
        if 'HTTP' in str(protocols):
            analysis.append("├─ ⚠️  Trafic HTTP non chiffré détecté")
        
        analysis.append("└─ Analyse complétée avec succès")
    
    return '\n'.join(analysis)

def generate_installation_report():
    """Générer un rapport d'installation"""
    instructions = get_installation_instructions()
    
    return f"""
=== INSTALLATION WIRESHARK REQUISE ===
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

❌ PROBLÈME:
Aucun outil de capture réseau détecté.
Les outils suivants sont requis: tshark, tcpdump, ou wireshark

🔧 SOLUTION AUTOMATIQUE:
Exécutez la commande suivante pour installer automatiquement:

    python3 -c "
    from toolbox.analyzer.wireshark_analyzer import auto_install_wireshark
    auto_install_wireshark()
    "

📋 INSTALLATION MANUELLE:

{chr(10).join(f'    {cmd}' for cmd in instructions['commands'])}

💡 NOTE:
{instructions['note']}

🌐 ALTERNATIVE:
Si l'installation échoue, visitez:
https://www.wireshark.org/download.html

⚠️  PERMISSIONS:
Après installation, redémarrez votre session pour appliquer
les permissions de groupe wireshark.

🧪 TEST:
Testez l'installation avec: tshark --version
"""

def generate_permission_error_report():
    """Générer un rapport d'erreur de permissions"""
    username = os.getenv('USER', 'utilisateur')
    
    return f"""
=== ERREUR DE PERMISSIONS ===
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

❌ PROBLÈME:
Permissions insuffisantes pour capturer le trafic réseau.

🔧 SOLUTION:
Exécutez les commandes suivantes:

    sudo usermod -a -G wireshark {username}
    sudo chmod +x /usr/bin/dumpcap

Puis redémarrez votre session.

🔄 ALTERNATIVE IMMÉDIATE:
Utilisez sudo pour cette session:

    sudo tshark -i any -c 10

💡 VÉRIFICATION:
Vérifiez vos groupes avec: groups
Vous devriez voir 'wireshark' dans la liste.
"""

def stop_capture():
    """Arrêter la capture en cours"""
    try:
        # Arrêter tshark
        subprocess.run(['pkill', 'tshark'], check=False, capture_output=True)
        # Arrêter tcpdump
        subprocess.run(['sudo', 'pkill', 'tcpdump'], check=False, capture_output=True)
        logger.info("Capture arrêtée")
    except Exception as e:
        logger.error(f"Erreur arrêt capture: {e}")

def main():
    """Fonction principale pour tests"""
    print("🔍 CYBERSEC PRO - ANALYSEUR DE TRAFIC")
    print("=" * 50)
    
    # Vérifier les outils disponibles
    tools = check_tool_availability()
    
    if tools:
        print(f"✅ Outils détectés: {', '.join(tools.keys())}")
        
        # Obtenir les interfaces
        interfaces = get_available_interfaces()
        print(f"📡 Interfaces disponibles: {', '.join(interfaces)}")
        
        # Test d'analyse
        target = input("\nEntrez l'IP cible (optionnel): ").strip()
        duration = input("Durée d'analyse en secondes (défaut: 10): ").strip()
        
        if not duration.isdigit():
            duration = 10
        else:
            duration = int(duration)
        
        print(f"\n🚀 Démarrage de l'analyse...")
        result = analyze_traffic(target_ip=target if target else None, duration=duration)
        print(result)
    
    else:
        print("❌ Aucun outil de capture détecté")
        
        install = input("\nVoulez-vous essayer l'installation automatique? (o/n): ").lower()
        if install in ['o', 'oui', 'y', 'yes']:
            auto_install_wireshark()
        else:
            print(generate_installation_report())

if __name__ == "__main__":
    main()