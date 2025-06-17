# 🛡️ Toolbox de Cybersécurité – Projet Fil Rouge

Bienvenue dans la **Toolbox de Cybersécurité**, un outil développé dans le cadre du Mastère Cybersécurité. Cette application permet d'automatiser plusieurs phases d'un test d'intrusion via une interface graphique locale en Python.

---

## 🧰 Fonctionnalités principales

- 📡 **Scan Nmap** : découverte réseau, ports ouverts, services
- 🧠 **Détection de services** : version et type des services actifs
- 💥 **Exploit vulnérabilités (Metasploit)** : test de failles connues
- 🔐 **Brute-force (Hydra)** : tentative d'accès SSH
- 📊 **Analyse de trafic** : parsing de logs
- 📂 **Génération de rapports** : en `.txt`, `.json`, `.pdf`

---

## 🖥️ Interface utilisateur

L’interface a été réalisée avec **Tkinter**. Elle est simple, rapide à lancer et propose une navigation par bouton pour chaque outil.

---

## ⚙️ Installation

> ✅ Compatible Linux (testée sur **Kali Linux**), mais aussi fonctionnelle sous Windows.

### 1. Cloner le projet

```bash
git clone https://github.com/issaam9/Toolbox.git
cd Toolbox
```

### 2. Créer un environnement virtuel (facultatif)

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Installer les dépendances

```bash
pip install -r requirements.txt
```

---

## 🚀 Lancer l’application

Depuis le dossier racine, exécuter :

```bash
python TOOLBOX_PROJECT_GUI/main.py
```

Une fenêtre graphique s’ouvrira avec tous les boutons pour lancer les outils.

---

## 🗂️ Structure du projet

```
TOOLBOX_PROJECT_GUI/
│
├── main.py                # Lancement principal de l’interface
├── modules/               # Tous les modules (Nmap, Metasploit, etc.)
├── config/                # Utilisateurs, statistiques
├── reports/               # Résultats des analyses
└── requirements.txt       # Dépendances Python
```

🧩 Modules disponibles et comment les utiliser
Module	Description	Utilisation
Nmap	Scan de ports et services d’un hôte	Entrer l’IP cible → Cliquer sur “Scan Nmap”
Hydra	Brute force (ex. SSH)	Entrer IP, login, mot de passe → Cliquer sur “Hydra SSH”
Metasploit	Lancement d’exploits automatiques	Entrer l’IP → Cliquer sur “Scan Metasploit”
Trafic Log	Analyse de fichiers logs réseaux	Charger un .log → Cliquer sur “Analyser le trafic”
Rapport	Génère un rapport des résultats	Cliquer sur “Générer rapport” (PDF ou TXT)
Connexion	Accès utilisateur (admin/user)	Authentification au lancement de l’outil

📁 Tous les résultats sont automatiquement stockés dans le dossier /reports.

---

## 📤 Résultats générés

Les résultats sont stockés automatiquement dans le dossier `/reports/`, sous différents formats :

- `Scan_report.txt`
- `VulnScan_report.txt`
- `traffic_auto_YYYYMMDD_HHMM.txt`
- `export_rapport.pdf` *(si conversion active)*

---

## 🧑‍💻 Utilisateurs

Deux profils sont disponibles :
- `admin` : accès à tous les modules (exploitation, trafic, brute force)
- `user` : accès limité aux scans de reconnaissance


---

## 📄 Licence

Ce projet est fourni à titre pédagogique. Aucune exploitation commerciale autorisée.
