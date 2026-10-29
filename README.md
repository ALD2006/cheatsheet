# cheatsheet

Mon dictionnaire d'outils offensifs, rangé par phase de la kill chain. Chaque fiche couvre un outil que j'ai réellement utilisé en lab (TryHackMe, HackTheBox retired, PortSwigger, home lab) ou sur des cibles explicitement autorisées.

Notes personnelles d'apprentissage, en français. Ce n'est pas un framework : chaque fiche suit la même anatomie — **Rôle** (la métaphore qui m'aide à retenir), **Invocation type**, **Flags décodés**, **Exemple vécu**, **Pièges & leçons**.

## Les casiers

| # | Fiche | Ce qu'il abrite |
|---|---|---|
| 01 | [`01_reconnaissance.md`](01_reconnaissance.md) | `nmap` · `gobuster` (`dir` + `vhost`) · `git` (dépôt exposé / historique) · MailHog · `showmount` · `searchsploit` · `ldapsearch` (root DSE, `bind` ≠ `read` = ACIs) |
| 02 | [`02_exploitation.md`](02_exploitation.md) | `msfconsole` · `nc` · Burp Suite · exploits manuels · `hydra` (`http-post-form`) · `evil-winrm` · Impacket (`smbclient` / `mssqlclient` / `psexec` · `xp_cmdshell`) · download cradle PowerShell · Log4Shell / JNDI (`marshalsec` · `rogue-jndi`) · `ysoserial` (désérialisation Java) · `setsid` (stabiliser un shell web) |
| 03 | [`03_elevation_privileges.md`](03_elevation_privileges.md) | `find -perm` (SUID) · `linpeas` · `strings` · PATH hijacking · `getcap` / Linux Capabilities · `incron` / config relue par un service root · surface interne (service `127.0.0.1` en root) · CVE locale amont vs backport (race TOCTOU) · job root + entrée non assainie (path traversal, CWE-22) |
| 04 | [`04_identifiants_post_exploitation.md`](04_identifiants_post_exploitation.md) | meterpreter · `hashdump` · `Responder` (NetNTLMv2) · John the Ripper (`--format=netntlmv2`) · hashcat · `mongo` post-exploit (base sans auth) · `mkpasswd` / `openssl passwd` (forger un `$6$`) |
| 05 | [`05_reseau_transfert.md`](05_reseau_transfert.md) | `ss` · `ip a` · `ping` / `arp` · `openvpn` · `http.server` + `wget` · `mount` (NFS) · `tshark` · `/proc/net/tcp` (sockets sans `ss`/`netstat`) |
| 06 | [`06_ressources_web.md`](06_ressources_web.md) | CyberChef · GTFOBins · Exploit-DB / NVD · jwt.io · CrackStation · Snyk / npm audit |

## Règle non négociable

N'attaquer QUE ses propres machines, un lab, ou une cible **explicitement autorisée** (`scanme.nmap.org`, TryHackMe, HackTheBox retired). Ces notes sont destinées à l'apprentissage et au test autorisé uniquement.

## Licence

[CC BY 4.0](LICENSE) — réutilisation libre avec attribution.
