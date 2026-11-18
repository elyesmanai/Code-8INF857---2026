# Mini-SOAR 8INF857

On reconstruit, en petit, un SOAR open source réel : **Tracecat** (Python, FastAPI, playbooks YAML).
Chaque exercice ajoute **une pièce** du SOAR, dans **un fichier** du dossier `minisoar/`, puis rejoue
la même matinée d'alertes (serveur LabSZ, 10 décembre 2016). Un correcteur automatique note le SOAR sur 100.

```
 SIEM, Wazuh ──► API (webhooks) ──► file + travailleurs ──► moteur ──► actions ──► pare-feu, comptes, serveur
                  ex. 3              ex. 4                  ex. 2      ex. 1
                                         └──► cas et approbations (ex. 5) · étape IA (ex. 6)
```

| Exercice | Fichier | Ce qu'on apprend | Tâche |
|---|---|---|---|
| `ex1` Registre d'actions | `actions.py` | intégrations, entrées validées, garde-fous, idempotence, secrets, réessais | écrire `hote.cles_ssh` |
| `ex2` Moteur de workflow | `moteur.py` | playbook YAML, expressions `${{ }}` sans `eval`, tri topologique, historique | compléter `playbooks/force-brute.yaml` |
| `ex3` API | `api.py` | webhooks authentifiés, normalisation (SIEM, Wazuh), déduplication, **premier rejeu** | normaliser une source EDR |
| `ex4` Exécution durable | `file.py` | file SQLite, travailleurs, bail, reprise après panne, « au moins une fois » | écrire `annuler()` |
| `ex5` Cas et approbations | `cas.py` | cas, observables, fusion, humain dans la boucle, MTTD et MTTC | des cas pour les robots |
| `ex6` Étape IA | `ia.py` | `ai.action` (sortie par schéma), `ai.agent` (liste blanche), défense contre l'injection | comparer deux modèles |

## Installation (une fois)

1. **Python 3.10 ou plus**, dans ce dossier :
   ```
   python -m venv .venv
   .venv\Scripts\activate            (Windows)
   source .venv/bin/activate         (macOS, Linux)
   pip install -r requirements.txt
   ```
2. **VS Code** : ouvrez CE dossier (`SOAR`), ouvrez `ex1 - le registre d'actions.ipynb`, choisissez le noyau `.venv`.
3. **Pour l'exercice 6 seulement** : installez Ollama (https://ollama.com/download), puis dans un terminal
   ```
   ollama pull qwen2.5:3b
   ```
   Machine puissante : `qwen2.5:7b` (variable d'environnement `SOAR_MODELE`, ou `ia.MODELE = ...` dans le notebook).
4. **Vérifiez**, dans le terminal de VS Code, `.venv` activé :
   ```
   python verifier_installation.py
   ```
   Faites une capture d'écran. Un ❌ : envoyez-la à l'enseignant **avant** la séance. Un ⚠️ ne bloque que l'exercice 6.

## Problèmes fréquents

| Symptôme | Solution |
|---|---|
| `python` introuvable (Windows) | Réinstallez Python depuis python.org en cochant **« Add Python to PATH »**, ou utilisez `py` à la place de `python` |
| PowerShell refuse `.venv\Scripts\activate` | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, puis réessayez |
| `ModuleNotFoundError` dans un notebook | En haut à droite du notebook, choisissez le noyau **`.venv`** (cause n° 1). Installez les extensions VS Code *Python* et *Jupyter* |
| `No module named 'banc'` ou `'minisoar'` | Ouvrez **le dossier `SOAR`** dans VS Code (Fichier → Ouvrir le dossier), pas un notebook seul |
| macOS : erreurs avec le Python du système | Installez Python depuis python.org ou Homebrew, recréez le `.venv` |
| `SQLite 3.xx : il faut 3.35 ou plus` | Installez Python depuis python.org (il inclut un SQLite récent) |
| Exercice 6 : la première cellule IA « ne répond pas » | C'est normal : le premier appel charge le modèle (jusqu'à 2 minutes). Ensuite, environ 1 minute par analyse |
| Ollama trop lent, ou moins de 8 Go de RAM | Faites l'exercice 6 en équipe, sur la machine d'un coéquipier |
| Exercice 3 : `curl` ne marche pas sous Windows | Utilisez la page **http://localhost:8000/docs** à la place : on y envoie la même alerte depuis le navigateur |
| `ollama pull` interminable | Le modèle pèse 1,9 Go : téléchargez-le **chez vous**, pas sur le Wi-Fi du campus pendant la séance |

## Le dossier

- `minisoar/` : le SOAR, un fichier par exercice. C'est là que vous travaillez.
- `playbooks/` : les playbooks YAML. Les versions `-cas` (ex. 5) et `-ia` (ex. 6) ajoutent une étape.
- `banc/` : le banc d'essai (scénario, environnement simulé, rejeu, correcteur). Vous n'avez pas à le modifier.
- `donnees/OpenSSH_2k.log` : le vrai journal SSH.
- `solutions/` : les playbooks des tâches. Les autres solutions sont dans la cellule « Réponse » de chaque notebook.
- `environnement/` (créé à chaque rejeu) : pare-feu en syntaxe nftables, comptes, disque du serveur, journal d'audit, base SQLite. **Ouvrez ces fichiers** pour voir ce que le SOAR a fait.
- `resultats/` (créé au premier rejeu) : le rapport de chaque exercice et `scores.csv`.

## Ce qui est réel, ce qui est inventé

- **Réel** : le journal SSH (Loghub, OpenSSH_2k), le registre RDAP (`ip.enrichir`), les notifications ntfy.sh (`messagerie.notifier`).
- **Inventé** : l'attaquant lent 203.0.113.77, l'intrusion sur `webadmin`, ce qu'il fait sur le serveur, l'injection depuis 198.51.100.23, l'administratrice `jtremblay`. Les IP inventées sont dans les plages réservées à la documentation.
- Le rejeu est un **enregistrement** : bloquer l'attaquant à 08:21 n'efface pas son intrusion de 08:41 dans le journal.
