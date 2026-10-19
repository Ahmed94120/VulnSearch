# VulnSearch

Surveillance du catalogue [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) pour Société Générale : chaque nouvelle CVE exploitée déclenche un mail et une carte Microsoft Teams.

Le script tourne toutes les heures en cron sur `p-tvm-ctl-l-01`, depuis `/home/sysroot/VulnSG/`.

## Fichiers

| Fichier | Rôle |
|---|---|
| `vulnAlert.py` | Point d'entrée du cron. Envoie les mails et les cartes Teams, et tient l'historique des alertes. |
| `vulnSearch.py` | Récupère le KEV et sélectionne les entrées depuis le dernier passage, par date. |
| `vulnScore.py` | Critères SG : sous-scores CVSS et type RCE / contournement d'authentification, depuis CVE.org puis NVD. |
| `vulnExploit.py` | Enrichissement KEV / Metasploit / Exploit-DB. N'est plus appelé par le cron. |
| `teams_only.py` | Poste des cartes Teams sur une période, sans mail ni modification de l'état. |
| `render.py` | Contenu des cartes Teams et des mails (HTML + texte). |
| `send_test.py` | Envoie les mails (et cartes) d'une période à une seule adresse de test, sans modifier l'état. |
| `config.py` | Charge le `.env` au démarrage. |
| `tests/` | Tests hors ligne : réseau, SMTP et Teams simulés. |

## Configuration

La configuration se met dans un fichier `.env` à côté des scripts, jamais commité. Pars de `.env.example` :

```bash
cp .env.example .env && chmod 600 .env
```

`config.py` charge ce fichier au démarrage, sans dépendance. Une variable déjà définie dans l'environnement (crontab, shell) garde la priorité sur le `.env`.

| Variable | Défaut | Effet |
|---|---|---|
| `TEAMS_WEBHOOK_URL` | (vide) | URL du webhook Power Automate. À défaut, le script lit `.teams_webhook`. |
| `NOTIFY_MODE` | `all` | `all` : un mail par nouvelle entrée KEV. `filtered` : critères SG (voir plus bas). |
| `L1_EMAILS` | (vide) | Destinataires des alertes `MATCH`, séparés par des virgules. Obligatoire en mode `filtered`. |
| `REVIEW_EMAILS` | (vide) | Destinataires des revues manuelles `TO_CHECK`. Obligatoire en mode `filtered`. |
| `NVD_API_KEY` | (vide) | Clé NVD facultative : 50 requêtes / 30 s au lieu de 5. |
| `DRY_RUN` | (vide) | `1` : affiche ce qui serait envoyé, n'envoie rien et n'écrit aucun état. |
| `SMTP_HOST` / `SMTP_PORT` | `relay.itm.lan` / `25` | Serveur SMTP. |
| `SMTP_USER` / `SMTP_PASSWORD` | (vide) | Si renseignés : STARTTLS + authentification (ex. Gmail, port 587, mot de passe d'application). |
| `SMTP_FROM` | `monitoring_cybertools@...` | Expéditeur. Avec Gmail, mettre l'adresse du compte. |
| `MAIL_TEST_TO` | (vide) | Tous les mails partent uniquement à cette adresse (ni client ni BCC), objet préfixé `[TEST]`. |
| `MAIL_EML_DIR` | (vide) | Écrit chaque mail en `.eml` dans ce dossier au lieu de l'envoyer. |
| `VULNSG_DIR` | `/home/sysroot/VulnSG` | Dossier des logs et des fichiers d'état. |
| `VULN_STATE_FILE` | `$VULNSG_DIR/alerted_cves.json` | Historique des CVE déjà traitées. |
| `VULNSG_ENV_FILE` | `.env` à côté des scripts | Fichier de configuration à charger. |

Le serveur sort par le proxy `http://172.18.9.100:8080`, déjà déclaré dans la crontab. En shell interactif, il faut l'exporter (`export HTTPS_PROXY=...`).

## Fonctionnement

1. `vulnSearch.scan()` télécharge le KEV et garde les entrées dont la date d'ajout est postérieure ou égale à la veille du dernier repère (`previous_run.json`).
2. `vulnAlert.alert()` écarte celles déjà présentes dans `alerted_cves.json`, puis envoie le mail et la carte Teams.
3. Une CVE n'est marquée comme traitée qu'une fois son mail parti. Le repère n'avance qu'après l'envoi, et jamais au-delà d'une CVE en attente.

L'ordre des entrées dans le fichier CISA n'a aucune importance. C'est la correction de l'incident du 13/10/2026 : CVE-2026-96951 avait été insérée par CISA sous une CVE déjà traitée, et l'ancien script, qui s'arrêtait sur la dernière CVE vue, ne l'a jamais lue.

### Mode `filtered` (critères SG, étude de faisabilité)

Pour chaque nouvelle entrée, `vulnScore.py` lit le vecteur CVSS sur CVE.org (CNA, puis ADP comme CISA-ADP), sinon sur NVD :

| Statut | Condition | Action |
|---|---|---|
| `MATCH` | `AV:N`, `AC:L`, `PR:N`, `UI:N`, au moins un de C/I/A à High, et type RCE ou contournement d'authentification | Mail aux L1 |
| `TO_CHECK` | Vecteur absent ou inexploitable, CVSS v2 seul, sources injoignables, fiche REJECTED, ou type indéterminable | Mail de revue manuelle, avec la raison |
| `NO_MATCH` | Données disponibles et au moins un critère non rempli | Pas de mail |

Toutes les entrées gardent une carte Teams interne avec leur statut. Le type est déduit des CWE puis de la description : c'est une heuristique, à valider avec SG.

## Déploiement

```bash
cd /home/sysroot/VulnSG
mkdir -p bak && cp *.py previous_run.json alerted_cves.json bak/
# copier les fichiers .py du dépôt ici
cp .env.example .env && chmod 600 .env     # puis renseigner TEAMS_WEBHOOK_URL
export HTTPS_PROXY=http://172.18.9.100:8080
DRY_RUN=1 python3 vulnAlert.py        # test à blanc
```

Crontab actuelle :

```
0 */1 * * * /usr/bin/python3 /home/sysroot/VulnSG/vulnAlert.py >> /home/sysroot/logs/vulnAlert_$(date +\%Y\%m\%d).log 2>&1
```

## Commandes utiles

```bash
# Cartes Teams seules, sans mail ni état, depuis une date
python3 teams_only.py --since 2026-10-17 --dry
python3 teams_only.py --since 2026-10-13 --assess        # avec les critères SG

# Test à blanc du mode SG
DRY_RUN=1 NOTIFY_MODE=filtered L1_EMAILS=test REVIEW_EMAILS=test python3 vulnAlert.py

# Mails de test vers une seule adresse (aperçu HTML local avec --preview)
python3 send_test.py --since 2026-10-15 --to moi@example.com --preview
python3 send_test.py --since 2026-10-15 --to moi@example.com [--teams]
python3 send_test.py --since 2026-10-15 --eml ~/Downloads/eml --teams   # cartes postées, mails en .eml

# Tests hors ligne
./tests/run_all.sh
```
