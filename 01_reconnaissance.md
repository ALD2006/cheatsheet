# 01 — RECONNAISSANCE

> Casier des outils qui repèrent avant de frapper (80 % du job).
> Outils : `nmap` · `gobuster` (`dir` + `vhost`) · `git` (dépôt exposé / historique) · MailHog · `showmount` · `searchsploit` · `ldapsearch`

---

## nmap

**Rôle** — Le sondeur de portes. Il frappe à chaque port de la machine et note lesquels sont **ouverts** (la porte) + quelle **version** de service tourne derrière (la serrure, la voie vers les CVE). *Port = porte, version = serrure.*

**Invocation type**
```bash
nmap <cible>                        # top 1000 ports
nmap -p- <cible>                    # les 65 535 ports (exhaustif, plus lent)
nmap -sV -p <ports> <cible>         # versions des services sur des ports ciblés
nmap -sV --script vuln -p- <cible>  # versions + recherche de CVE connues
```

**Flags décodés**
- `-sV` = **V**ersion des services (la serrure derrière la porte).
- `-p-` = **tous** les 65 535 ports · `-p 443` = un port précis · (sans `-p` = top 1000).
- `-sS` = **S**YN scan « half-open », furtif (SYN → SYN-ACK → RST, ne complète jamais le 3ᵉ temps). Demande les droits admin, sinon bascule en `-sT` (handshake complet).
- `-T4` = vitesse (T0 lent/furtif → T5 brutal/bruyant).
- `--script vuln` = nmap cherche lui-même les CVE connues (≠ `-sC`/`default` qui lance juste les scripts standards).
- `-O` = détection d'**O**S. À ne pas confondre avec `-o…` (minuscule = sauver la sortie dans un fichier).

**Exemple vécu**
- **Vulnversity** : `nmap -sV` → serveur web sur le **port 3333** (non standard).
- **Blue** : `nmap -sV --script vuln -p- <ip>` → SMB sur **139 + 445** → verdict `ms17-010 VULNERABLE` (EternalBlue).
- **Metasploitable 2** : scan en 2 passes — `nmap -p-` (30 ports) puis `nmap -sV -p <ports>` → repéré `1524/ingreslock` = backdoor en libre-service.

**Pièges & leçons**
- **Sensible à la casse** : `-sV` ≠ `-O` ≠ `-o`. Une majuscule change tout.
- **Scan en 2 passes** (anti-lenteur) : `-p- --script vuln` = très lent. En vrai : (1) `nmap -p-` rapide pour les ports, (2) `nmap -sV --script vuln -p <ports trouvés>` ciblé.
- **Service déguisé** : un nom de service rare/incohérent (`1524/ingreslock`) = tiquer → confirmer au `-sV` → souvent une backdoor.
- **`http` ≠ `http-proxy`** : distinguer le vrai serveur web du proxy Squid (port 3128).
- **IP périmée** : après un redéploiement de lab, la cible change d'IP → l'ancien scan est mort. Toujours vérifier l'IP courante.
- **Légal** : ne scanner QUE ses propres machines ou une cible explicitement autorisée (`scanme.nmap.org`).

---

## gobuster

**Rôle** — Le passe-partout de répertoires web. Il essaie des noms de dossiers/fichiers depuis une wordlist et note ceux qui répondent → révèle les pages **non liées** (invisibles depuis le site). Forced browsing automatisé.

**Invocation type**
```bash
gobuster dir -u http://<cible>:3333 -w <wordlist>
```

**Flags décodés**
- `dir` = mode **répertoires** (le plus courant).
- `vhost` = mode **virtual hosts** (voir plus bas).
- `-u` = **U**RL de la cible · `-w` = **w**ordlist · `-x php,txt` = extensions à accoler aux mots.

**Exemple vécu**
- **Vulnversity** : `gobuster dir -u http://<ip>:3333 -w <wordlist>` → **`/internal`** (formulaire d'upload) qui sort du lot face à `/css` `/js` `/images` → point d'entrée de la kill chain.

**Pièges & leçons**
- **Trier le signal du décor** : `/css` `/js` `/images` = mobilier normal ; ce qui sort du lot (`/internal`, `/admin`) = la vraie piste.
- **Toujours confirmer dans le navigateur** — gobuster dit qu'une porte répond, pas ce qu'il y a derrière.
- **Timeouts en rafale ≠ « rien à trouver »** = l'outil n'obtient pas de réponse (box lente / VPN saturé). Baisser les threads (`-t 10`, voire 5), allonger `--timeout 15s`, et ne pas faire tourner gobuster + `nmap -p-` en même temps (ils se battent pour la bande passante).

### Mode `vhost` — énumération de sous-domaines (vital sur une box 22/80)
**Rôle** — Un même serveur / une même IP héberge plusieurs sites, distingués par l'en-tête HTTP **`Host:`**. `gobuster vhost` envoie plein d'en-têtes `Host: FUZZ.domaine` et garde ceux dont la réponse **diffère** de la page par défaut. *`dir` cherche des dossiers ; `vhost` cherche des sous-domaines.*
```bash
gobuster vhost -u http://cible.htb \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain -t 20
```
- **`--append-domain`** = LE flag à ne pas oublier (gobuster ≥ 3.x) : accole `.cible.htb` à chaque mot → teste `mail.cible.htb`, `git.cible.htb`… Sans lui, les mots sont traités comme des hôtes complets → résultats vides.
- **wordlist de SOUS-DOMAINES** (pas de dossiers) : `Discovery/DNS/subdomains-top1million-5000.txt`.
- **Geste d'après obligatoire** : un vhost trouvé n'est pas encore joignable → l'**ajouter dans `/etc/hosts`** (même IP) avant de l'ouvrir. *Un vhost trouvé ≠ un vhost accessible.*

**Exemple vécu** — **Three** (Starting Point) : `gobuster vhost --append-domain` → `s3.thetoppers.htb` (bucket S3 factice).

---

## git (dépôt exposé) — « Git n'oublie jamais »

**Rôle** — Un service Git exposé (Gitea/GitLab/cgit, ou un `/.git/` web) = le code source en libre accès. Trésor : logique d'auth, config, et surtout des **secrets** (`.env`, creds DB, clés API). Le code **dit** comment l'appli marche.

**Où chercher**
- Dépôts **publics** sans login (utilisateur `admin`, repos « infra »…).
- Fichiers sensibles : `.env`, `config.php`, `docker-compose.yml`, `settings.py`.
- **L'HISTORIQUE DES COMMITS** (pas seulement l'état courant) : un diff `-DB_PASSWORD=xxxx` / `+DB_PASSWORD=` = un secret commité puis « retiré »… mais gravé à jamais dans le log.

**Exemple vécu (générique)** — Gitea exposé → repo de `admin` → `.env` dont le fichier courant a un `DB_PASSWORD` vide, MAIS l'**historique** (`git log` / diff) montrait un `DB_PASSWORD=...` supprimé au commit suivant → réutilisé pour devenir admin de l'appli.

**Pièges & leçons**
- **Toujours lire le `git log` / les diffs**, pas juste les fichiers actuels. Un secret « supprimé » vit dans l'historique.
- **Secret de repo souvent bidon/expurgé** (`APP_KEY=`, `password1`, `DB_PASSWORD=` vide) = placeholders → ne pas perdre de temps dessus, viser les diffs.
- **Purple** : ne jamais commiter de secret ; scanner les repos (gitleaks / trufflehog) ; ne pas exposer un Git interne.

### MailHog — mail-catcher de dev
Faux serveur SMTP de **développement** : il **capture** les mails sortants d'une appli (SMTP `1025`) au lieu de les envoyer, et les affiche dans une **UI web** (~`8025`). Repéré via `MAIL_HOST=mailhog` dans un `.env`. **Offensif :** si on atteint son UI, on **lit les mails de reset de mot de passe** → prise de compte. Explique le paradoxe « appli qui envoie des mails sans serveur mail exposé ».

---

## showmount

**Rôle** — L'inventaire des partages NFS. Interroge le service `mountd` de la cible et liste les dossiers exportés sur le réseau (avant même de monter quoi que ce soit).

**Invocation type**
```bash
showmount -e <ip>    # exports : quels dossiers sont partagés, et pour qui
showmount -a <ip>    # montages actifs en ce moment (qui est branché)
```

**Flags décodés** — `-e` = **e**xports (la liste des partages proposés) · `-a` = **a**ctive (les montages en cours).

**Exemple vécu**
- **Metasploitable 2** : `showmount -e <ip>` → **`/ *`** = disque **entier** (`/`) exporté au monde **entier** (`*`) = misconfig majeure → porte du chemin NFS `no_root_squash`.

**Pièges & leçons**
- **Lire la sortie** : colonne gauche = quel dossier / colonne droite = pour qui. `/ *` = tout, à tout le monde.
- **`showmount -a` vide = normal**, pas un échec.
- **Ne dit PAS `no_root_squash`** : cette option vit dans `/etc/exports` du serveur (illisible à distance) → elle se teste empiriquement en montant et en lisant un fichier root-only (`/etc/shadow`).

---

## searchsploit

**Rôle** — Exploit-DB en ligne de commande, HORS-LIGNE. Le testeur de clés : on lui donne un produit + version, il sort les exploits connus. *Le port dit qu'une porte existe ; la version dit si elle est déverrouillée → `searchsploit`.*

**Invocation type**
```bash
searchsploit <produit>        # chercher (dans les TITRES, logique ET)
searchsploit -x <path>        # LIRE un exploit (l'examiner avant de lancer)
searchsploit -m <path>        # copier (mirror) l'exploit dans le dossier courant
searchsploit --nmap scan.xml  # auto : scanne tous les services depuis un XML nmap
```

**Flags décodés** — `-x` = e**X**aminer / lire · `-m` = **m**irror = copier chez soi · `--nmap` = alimenter depuis la sortie XML de nmap.

**Exemple vécu**
- **Metasploitable 2** : `searchsploit UnrealIRCd` → `searchsploit -x linux/remote/16922.rb`. Le cœur d'un exploit n'est PAS dans les métadonnées (`initialize`/`update_info`) mais dans **la fonction qui AGIT** (`def exploit`) → ligne clé `sock.put("AB;" + payload.encoded + "\n")` = préfixe magique `AB;`. *Un module Metasploit et un `nc` manuel font exactement la même chose.*

**Pièges & leçons**
- **Logique ET** : cherche tous les mots dans le même titre → **un PRODUIT à la fois** (`searchsploit vsftpd unrealircd` = 0 résultat).
- **NE JAMAIS lancer un exploit sans le LIRE** (`-x`) : un payload peut être destructif (`rm -rf`) ou pointer une URL morte/piégée.
- **Base hors-ligne** = pas besoin d'Internet, mais penser à la mettre à jour (`searchsploit -u`).

---

## ldapsearch

**Rôle** — L'interrogateur d'annuaire LDAP. Il se connecte à un serveur LDAP (OpenDJ, Active Directory, OpenLDAP…) et **lit son arbre** : utilisateurs, groupes, attributs, config. *Un annuaire, c'est l'organigramme de l'entreprise en base de données — souvent bavard, parfois avec des mots de passe dedans.*

**Invocation type**
```bash
# 1) Le root DSE — "serveur, décris-toi" (versions + naming contexts)
ldapsearch -x -H ldap://<ip>:<port> -s base -b "" "(objectclass=*)" "*" "+"

# 2) Dumper une branche entière (base DN trouvée à l'étape 1)
ldapsearch -x -H ldap://<ip>:<port> -b "dc=exemple,dc=htb" "(objectclass=*)"

# 3) Bind AUTHENTIFIÉ (quand l'anonyme est muré) + filtre ciblé
ldapsearch -x -H ldap://<ip>:<port> -D "cn=admin,dc=exemple,dc=htb" -w '<mdp>' \
           -b "dc=exemple,dc=htb" "(objectClass=person)" userPassword
```

**Flags décodés**
- `-x` = **simple authentication** = bind anonyme (si aucun `-D`/`-w`). C'est lui qui exploite un « Anonymous bind OK ».
- `-H ldap://…` = URI du serveur. `ldap://` = clair · `ldaps://` = TLS (port type 636/4444).
- `-b "<DN>"` = base DN = point de départ dans l'arbre. `-b ""` = le **root DSE**.
- `-s` = scope : `base` (l'entrée seule) · `one` (enfants directs) · `sub` (tout l'arbre, défaut).
- `-D "<bindDN>"` = le DN qui s'authentifie · `-w '<mdp>'` = son mot de passe (`-W` = demander en interactif).
- `"*" "+"` en fin = renvoyer les attributs normaux (`*`) et opérationnels (`+`, dont `namingContexts`).

**Exemple vécu (générique)** — Sur une box à `ldap (Anonymous bind OK)` : le **root DSE** (`-s base -b ""`) a craché le `vendorVersion` (ex. `OpenDJ Server 5.0.3`) que le web cachait + `namingContexts: dc=exemple,dc=htb`. Mais le dump de la branche → `result: 0 Success` avec **0 entrée** = **ACIs qui bloquent la lecture anonyme des données**.

**Pièges & leçons**
- **`bind` ≠ `read`** : un bind anonyme réussi (`Success`) ne donne PAS forcément la lecture des entrées. « Success + 0 entrée » = les ACIs verrouillent, pas « annuaire vide ». OpenDJ renvoie le vide poli, pas une erreur.
- **Un DN est un CHEMIN COMPLET** `attribut=valeur` séparé par des virgules (`dc=exemple,dc=htb`). `-b "htb"` seul = `result: 34 Invalid DN syntax`. `dc` = *domain component*.
- **Toujours commencer par le root DSE** (`-b ""`) : lisible en anonyme même quand les données ne le sont pas → versions + naming contexts + contrôles supportés gratuitement.
- **Chercher les trésors** : `userPassword`, hashes (`{SSHA}`, `$6$`…), `description`, comptes de service. Et se demander : **puis-je ÉCRIRE ?** (`ldapmodify`) — parfois la vraie porte.
- **`ldap://` vs `ldaps://`** : le port admin (OpenDJ 4444) est en TLS → `ldaps://` (et souvent `LDAPTLS_REQCERT=never` pour un certif self-signed).
- **`curl` sur un port LDAP** = `Received HTTP/0.9 when not allowed` + octets binaires → ce n'est pas de l'HTTP, sortir `ldapsearch`.
