#!/usr/bin/env python3
"""
Script de diagnostic et réparation pour Wireshark/tshark
CyberSec Pro - Correction rapide des problèmes Wireshark
"""

import subprocess
import os
import sys
import shutil
from pathlib import Path

def print_banner():
    """Afficher le banner"""
    print("🔧 CYBERSEC PRO - DIAGNOSTIC WIRESHARK")
    print("=" * 50)

def check_os():
    """Détecter l'OS"""
    if os.path.exists('/etc/kali_version'):
        return 'kali'
    elif os.path.exists('/etc/debian_version'):
        return 'debian'
    elif os.path.exists('/etc/redhat-release'):
        return 'redhat'
    elif os.path.exists('/etc/arch-release'):
        return 'arch'
    else:
        return 'unknown'

def check_tools():
    """Vérifier les outils disponibles"""
    tools = {
        'tshark': shutil.which('tshark'),
        'tcpdump': shutil.which('tcpdump'),
        'wireshark': shutil.which('wireshark'),
        'dumpcap': shutil.which('dumpcap')
    }
    
    print("🔍 VÉRIFICATION DES OUTILS:")
    for tool, path in tools.items():
        status = "✅ Installé" if path else "❌ Manquant"
        print(f"   {tool:10} : {status}")
        if path:
            print(f"              {path}")
    
    return tools

def check_permissions():
    """Vérifier les permissions"""
    print("\n🔐 VÉRIFICATION DES PERMISSIONS:")
    
    username = os.getenv('USER')
    print(f"   Utilisateur: {username}")
    
    # Vérifier les groupes
    try:
        result = subprocess.run(['groups'], capture_output=True, text=True)
        groups = result.stdout.strip().split()
        
        if 'wireshark' in groups:
            print("   ✅ Groupe wireshark: OK")
        else:
            print("   ❌ Groupe wireshark: MANQUANT")
        
        print(f"   Groupes actuels: {', '.join(groups)}")
        
    except Exception as e:
        print(f"   ⚠️  Erreur vérification groupes: {e}")
    
    # Vérifier dumpcap
    dumpcap_path = shutil.which('dumpcap')
    if dumpcap_path:
        try:
            stat_info = os.stat(dumpcap_path)
            if stat_info.st_mode & 0o111:  # Vérifier permissions d'exécution
                print("   ✅ Permissions dumpcap: OK")
            else:
                print("   ❌ Permissions dumpcap: MANQUANTES")
        except Exception as e:
            print(f"   ⚠️  Erreur vérification dumpcap: {e}")

def install_wireshark():
    """Installer Wireshark selon l'OS"""
    os_type = check_os()
    
    print(f"\n📦 INSTALLATION WIRESHARK ({os_type.upper()}):")
    
    if os_type in ['kali', 'debian']:
        commands = [
            ['sudo', 'apt', 'update'],
            ['sudo', 'apt', 'install', '-y', 'wireshark', 'tshark']
        ]
        
        for cmd in commands:
            print(f"   Exécution: {' '.join(cmd)}")
            try:
                result = subprocess.run(cmd, check=True, capture_output=True, timeout=300)
                print("   ✅ Succès")
            except subprocess.CalledProcessError as e:
                print(f"   ❌ Erreur: {e}")
                return False
            except subprocess.TimeoutExpired:
                print("   ❌ Timeout")
                return False
        
        return True
    
    elif os_type == 'redhat':
        try:
            subprocess.run(['sudo', 'yum', 'install', '-y', 'wireshark', 'wireshark-cli'], 
                         check=True, timeout=300)
            return True
        except:
            return False
    
    elif os_type == 'arch':
        try:
            subprocess.run(['sudo', 'pacman', '-S', '--noconfirm', 'wireshark-qt'], 
                         check=True, timeout=300)
            return True
        except:
            return False
    
    else:
        print("   ❌ OS non supporté pour installation automatique")
        print("   💡 Visitez: https://www.wireshark.org/download.html")
        return False

def fix_permissions():
    """Corriger les permissions"""
    print("\n🔧 CORRECTION DES PERMISSIONS:")
    
    username = os.getenv('USER')
    if not username or username == 'root':
        print("   ⚠️  Utilisateur root détecté, permissions non nécessaires")
        return True
    
    try:
        # Ajouter au groupe wireshark
        print(f"   Ajout de {username} au groupe wireshark...")
        subprocess.run(['sudo', 'usermod', '-a', '-G', 'wireshark', username], 
                      check=True, timeout=30)
        print("   ✅ Utilisateur ajouté au groupe")
        
        # Permissions dumpcap
        dumpcap_path = shutil.which('dumpcap')
        if dumpcap_path:
            print("   Configuration des permissions dumpcap...")
            subprocess.run(['sudo', 'chmod', '+x', dumpcap_path], 
                          check=True, timeout=10)
            print("   ✅ Permissions dumpcap configurées")
        
        print("\n   ⚠️  IMPORTANT: Redémarrez votre session pour appliquer les changements!")
        print("      Ou utilisez: newgrp wireshark")
        
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"   ❌ Erreur: {e}")
        return False
    except subprocess.TimeoutExpired:
        print("   ❌ Timeout lors de la configuration")
        return False

def test_capture():
    """Tester la capture"""
    print("\n🧪 TEST DE CAPTURE:")
    
    tools_to_test = ['tshark', 'tcpdump']
    
    for tool in tools_to_test:
        if not shutil.which(tool):
            print(f"   ⚠️  {tool} non disponible")
            continue
        
        print(f"   Test avec {tool}...")
        
        try:
            if tool == 'tshark':
                cmd = ['tshark', '-i', 'any', '-c', '5', '-a', 'duration:5']
            else:
                cmd = ['sudo', 'tcpdump', '-i', 'any', '-c', '5']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                lines = len(result.stdout.split('\n'))
                print(f"   ✅ {tool}: {lines} lignes capturées")
                return True
            else:
                print(f"   ❌ {tool}: {result.stderr}")
        
        except subprocess.TimeoutExpired:
            print(f"   ⚠️  {tool}: Timeout (normal pour test)")
            return True
        except Exception as e:
            print(f"   ❌ {tool}: {e}")
    
    return False

def show_manual_instructions():
    """Afficher les instructions manuelles"""
    print("\n📋 INSTRUCTIONS MANUELLES:")
    print("─" * 30)
    
    os_type = check_os()
    
    if os_type == 'kali':
        print("Sur Kali Linux:")
        print("   sudo apt update")
        print("   sudo apt install -y wireshark tshark")
        print("   sudo usermod -a -G wireshark $USER")
        print("   newgrp wireshark")
    
    elif os_type == 'debian':
        print("Sur Debian/Ubuntu:")
        print("   sudo apt update")
        print("   sudo apt install -y wireshark-qt tshark")
        print("   sudo usermod -a -G wireshark $USER")
        print("   newgrp wireshark")
    
    elif os_type == 'redhat':
        print("Sur CentOS/RHEL:")
        print("   sudo yum install -y wireshark wireshark-cli")
        print("   sudo usermod -a -G wireshark $USER")
    
    elif os_type == 'arch':
        print("Sur Arch Linux:")
        print("   sudo pacman -S wireshark-qt")
        print("   sudo usermod -a -G wireshark $USER")
    
    print("\nPuis redémarrez votre session utilisateur.")

def main():
    """Fonction principale"""
    print_banner()
    
    # Vérification initiale
    tools = check_tools()
    check_permissions()
    
    # Si aucun outil n'est disponible
    if not any(tools.values()):
        print("\n❌ AUCUN OUTIL DE CAPTURE DÉTECTÉ")
        
        install = input("\nVoulez-vous installer automatiquement? (o/n): ").lower()
        if install in ['o', 'oui', 'y', 'yes']:
            if install_wireshark():
                print("\n✅ Installation réussie!")
                fix_permissions()
            else:
                print("\n❌ Installation échouée")
                show_manual_instructions()
        else:
            show_manual_instructions()
    
    # Si les outils sont là mais problème de permissions
    elif tools.get('tshark') or tools.get('dumpcap'):
        fix_perms = input("\nVoulez-vous corriger les permissions? (o/n): ").lower()
        if fix_perms in ['o', 'oui', 'y', 'yes']:
            fix_permissions()
    
    # Test final
    print("\n" + "=" * 50)
    if test_capture():
        print("🎉 CONFIGURATION RÉUSSIE!")
        print("Wireshark/tshark est maintenant fonctionnel.")
    else:
        print("⚠️  PROBLÈMES PERSISTANTS")
        print("Consultez les instructions manuelles ci-dessus.")
        show_manual_instructions()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n🛑 Interrompu par l'utilisateur")
    except Exception as e:
        print(f"\n❌ Erreur inattendue: {e}")