import sys
import os
import json

# Ajoute le chemin vers le projet pour importer les modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from toolbox.utils.chiffrement_module import decrypt_file

# Fichiers de test
encrypted_file = "config/users.encrypted"
decrypted_file = "config/users_decrypted.json"

# Déchiffrement
decrypt_file(encrypted_file, decrypted_file)

# Affiche le contenu pour vérification
with open(decrypted_file, "r") as f:
    users = json.load(f)

print("✅ Contenu déchiffré :\n")
for user, data in users.items():
    #print(f"- {user} : {data}")
    print(f"- {user} : Mot de passe : {data['password']}, Rôle : {data['role']}, Permissions : {data['permissions']}")
