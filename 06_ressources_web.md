# 06 — RESSOURCES WEB (sites & bases)

> Casier des **sites** et bases de données qu'on ouvre dans le navigateur — pas des commandes.
> Ressources : CyberChef · GTFOBins · Exploit-DB / NVD · jwt.io · CrackStation · Snyk / npm audit

---

## CyberChef

**Rôle** — Le couteau suisse de l'encodage : décoder, encoder, chiffrer, générer — en empilant des opérations (« recette »).
**URL** — `cyberchef.org` (aussi dispo hors-ligne).

**Comment s'en servir** — glisser des opérations dans la « Recipe » : `From Base64`, `From Base85`, `ROT13`, `URL Decode`, `Generate TOTP`… Elles s'appliquent dans l'ordre, de haut en bas.

**Exemples vécus**
- **Nested Easter Egg** : recette empilée `From Base64` → `ROT13` → `URL Decode`.
- **Forged Coupon** : `From Base85` avec l'alphabet Z85 → recette coupon → ré-encodage.
- **Pic 2FA** : `Generate TOTP` à partir du secret Base32 volé → code 6 chiffres.

**Pièges & leçons**
- **Choisir le bon alphabet** : Base85 a des dialectes (Z85 = celui de ZeroMQ). Mauvais alphabet = charabia.
- **Encodage ≠ chiffrement** : ce que CyberChef décode SANS clé n'était jamais du secret.

---

## GTFOBins

**Rôle** — La bible du détournement : pour un binaire Unix donné, comment l'abuser pour lire des fichiers, obtenir un shell, ou **monter en root**.
**URL** — `gtfobins.github.io`.

**Comment s'en servir** — chercher le binaire (`systemctl`, `nmap`, `find`, `vim`…) → filtrer par **capacité** : SUID (privesc via find), Sudo, Shell, File read/write.

**Exemples vécus**
- **Vulnversity** : `systemctl` (SUID) → faux `.service` exécuté en root.
- **Metasploitable** : `nmap` (SUID) → `nmap --interactive` → `!/bin/sh` → root.

**Piège** — Les recettes contiennent des **placeholders** (`/path/to/command`) = des trous à remplir avec de vrais chemins, sinon `Directory nonexistent`.

---

## Exploit-DB / NVD

**Rôle** — Les bases de failles connues. NVD = catalogue officiel des CVE (+ score CVSS). Exploit-DB = code d'exploit prêt à l'emploi.
**URL** — `nvd.nist.gov` · `exploit-db.com`.

**Comment s'en servir** — le pont **version → CVE → exploit** : une version de service repérée au `nmap -sV` → chercher sa CVE (NVD) → trouver l'exploit (Exploit-DB). En local, `searchsploit` = Exploit-DB hors-ligne (casier 01).

**Exemple** — `CVE-2021-44228` = Log4Shell. Sur le home lab, `searchsploit UnrealIRCd` évite la fouille manuelle NVD.

**Piège** — Toujours **LIRE** l'exploit avant de le lancer (payloads destructifs / URL mortes) — cf. casier 02.

---

## jwt.io

**Rôle** — Décoder et inspecter un JWT (JSON Web Token) : lire son header et son payload en clair.
**URL** — `jwt.io`.

**Comment s'en servir** — coller le jeton (`header.payload.signature`, 3 blocs base64url séparés par des points) → le site affiche `alg`, les claims (`email`, `role`, `iat`…).

**Exemples vécus**
- **Unsigned JWT** : décodé un jeton (`alg:RS256`, `role:admin`) → forgé un jeton `alg:none` + signature **vide** (`header.payload.`) → usurpation.
- **2FA** : `totp_tmp_token` décodé = ticket mi-parcours (`type:"…needs_second_factor"`), PAS le secret.

**Piège** — Les outils re-signent par réflexe : pour `alg:none`, il faut une signature **réellement vide** (finir par un point, rien après).

---

## CrackStation

**Rôle** — Lookup de hash via des **rainbow tables** (correspondances pré-calculées hash → mot de passe). Instantané quand ça marche.
**URL** — `crackstation.net`.

**Comment s'en servir** — coller un hash (MD5/SHA1…) → si le mot de passe est dans leur table, il ressort sans calcul.

**Exemple vécu** — tenté sur un hash MD5 → CrackStation cale → le hash était un **leurre** → la vraie porte était une SQLi bypass (zéro crackage).

**Piège — LA faiblesse fatale = le SALT** : un hash **salé** n'est dans aucune rainbow table (le sel change le hash) → CrackStation échoue → il faut John/hashcat (attaque par dictionnaire, casier 04). *Différent d'un cassage : ici on ne calcule pas, on cherche dans une table toute faite.*

---

## Snyk / npm audit

**Rôle** — Les bases de vulnérabilités de dépendances : confronter les briques d'un projet (versions) à une base de CVE connues (composants vulnérables, OWASP A06).
**URL** — `snyk.io` · `npm audit` (commande, côté projet Node).

**Comment s'en servir (méthode de l'inspecteur)** — (1) recenser les pièces + versions (manifeste `package.json`) → (2) lire les versions (**semver** : `~`=patchs, `^`=mineures, **version nue = verrouillée = signal**) → (3) confronter à Snyk/CVE → (4) signaler avec **nom exact + version**.

**Exemple vécu** — `express-jwt 0.1.3` (CVE-2020-15084, contournement d'auth) + `sanitize-html 1.4.2` (XSS — ironie : la brique de sécurité EST le trou), tous deux en `dependencies` (prod).

**Pièges & leçons**
- **`dependencies` (prod, dangereux) ≠ `devDependencies`** (atelier tests, hors portée distante).
- **Attaque de la chaîne d'approvisionnement** : un paquet piraté pour voler les tokens npm (le danger n'est pas toujours une CVE de code).
- **`package.json` = Node/JS**, PAS `requirements.txt` (ça, c'est Python).
