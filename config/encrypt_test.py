import sys
import os

# Ajoute le dossier parent à PYTHONPATH pour que 'toolbox' soit reconnu
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from toolbox.utils.chiffrement_module import encrypt_file

# Chiffre le fichier JSON normal pour tester ensuite le déchiffrement
encrypt_file("config/users.json", "config/users.encrypted")
print("✅ Chiffrement effectué : 'users.encrypted' généré.")
