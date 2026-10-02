exploitation de la vulnérabilité **ZIP Symlink** 
---

```markdown
# Exploitation d'un upload ZIP via lien symbolique

## 📌 Contexte

Une application web permet de téléverser des archives ZIP et les décompresse automatiquement dans un répertoire accessible publiquement. L'objectif est de lire le code source d'un fichier sensible (`index.php`) situé à la racine de l'application.

## 🕳️ Vulnérabilité

L'application ne vérifie pas le contenu de l'archive avant extraction. Il est donc possible d'inclure un **lien symbolique** (symlink) dans l'archive ZIP. Lors de la décompression, le serveur crée un fichier qui pointe vers un fichier arbitraire du système, ce qui permet de le lire via le navigateur.

## 🎯 Exploitation pas à pas

### 1. Créer un lien symbolique vers le fichier cible

On crée un lien symbolique nommé `index.txt` qui pointe vers `index.php`.  
Le chemin relatif doit être ajusté en fonction de la profondeur du répertoire d'extraction. Ici, on remonte de 3 niveaux (`../../../`) pour atteindre la racine de l'application.

```bash
ln -s ../../../index.php index.txt
```

### 2. Compresser le lien symbolique

L'option `--symlinks` (ou `-y`) est **essentielle** : elle force `zip` à conserver le lien symbolique tel quel, au lieu de copier le contenu du fichier cible.

```bash
zip --symlinks index.zip index.txt
```

### 3. Téléverser l'archive

On envoie le fichier `index.zip` via le formulaire d'upload de l'application.

### 4. Accéder au fichier extrait

Une fois l'upload terminé, le serveur renvoie un lien vers le répertoire d'extraction, par exemple :

```
http://<cible>/tmp/upload/<id_unique>/index.txt
```

En cliquant sur ce lien, le serveur suit le lien symbolique et affiche le contenu de `index.php`.

## 🏁 Résultat

Le code source de `index.php` est affiché. Il contient généralement le mot de passe de validation ou une information sensible.

## 🛡️ Recommandations de sécurité

- Ne jamais décompresser d'archives fournies par des utilisateurs sans validation préalable.
- Vérifier le contenu de l'archive avant extraction (rejeter les symlinks, les chemins `../`, etc.).
- Utiliser des options sécurisées lors de la décompression (ex : `unzip -j` pour ignorer les chemins, ou des bibliothèques qui désactivent les symlinks).
- Isoler les fichiers extraits dans un répertoire sans accès aux fichiers sensibles.
- Limiter les permissions du serveur web pour qu'il ne puisse pas lire des fichiers hors de son périmètre.

## 📚 Références

- [Zip Symlink Attack](https://en.wikipedia.org/wiki/Symlink_attack)
- [CWE-59: Improper Link Resolution Before File Access](https://cwe.mitre.org/data/definitions/59.html)
- [OWASP: Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
```

---
