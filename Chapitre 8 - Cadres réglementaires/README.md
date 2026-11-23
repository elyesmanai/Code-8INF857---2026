# Chapitre 8 : Cadres réglementaires — On se fait auditer

**La situation.** Vous êtes l'équipe TI de **NordHébergement inc.**, un hébergeur Web de Saguenay (35 employés, clients au Québec, en Ontario et en France).
Son plus gros client exige la certification **ISO 27001**. Le cabinet **Boréal Audit** envoie sa lettre : 8 pièces à déposer dans `livrables/` avant sa visite.

Un **auditeur automatique** (`auditeur.py`) relit vos pièces et répond demande par demande :
✅ acceptée, ⚠️ incomplète (avec ses raisons), ❌ refusée. Puis il donne un score sur 100.

## 🎯 L'objectif à atteindre

> **80 / 100, et aucune demande critique refusée (❌) = recommandé pour la certification.**

Vous partez de **0 / 100**. Chaque exercice produit une pièce et fait monter le score.
Attention : sans les tâches « À vous », vous plafonnez à **75 / 100**, avec une demande critique refusée. Il faut les faire.

| ✔ | Demande | Pièce dans `livrables/` | Exercice | Points |
|---|---|---|---|---|
| ☐ | D-01 Textes applicables | `applicabilite.csv` | ex1 | 10 |
| ☐ | D-02 Inventaire des actifs **(critique)** | `inventaire.csv` | ex2 | 15 |
| ☐ | D-03 Configuration sécurisée | `controles.csv` | ex3 | 15 |
| ☐ | D-04 Sauvegardes **(critique)** | `controles.csv` | ex3 | 10 |
| ☐ | D-05 Revue des accès **(critique)** | `revue_acces.csv` | ex4 | 15 |
| ☐ | D-06 Registre des risques | `registre_risques.csv` | ex5 | 15 |
| ☐ | D-07 Registre des incidents **(critique)** | `registre_incidents.csv` | ex6 | 15 |
| ☐ | D-08 Lettre de réponse | `reponse_auditeur.md` | ex6 | 5 |

**La règle d'or de l'auditeur :** il ne demande pas que tout soit parfait. Une **non-conformité** avec sa **preuve** et un **plan d'action** est acceptée.
Une déclaration sans preuve (« c'est fait ») ou une pièce inexacte ne l'est pas.

## Le parcours

Faites les exercices **dans l'ordre**, dans le **même dossier** : l'auditeur relit tout `livrables/` à chaque fois.

```
 ex1 Quelles règles ? ──► ex2 Quels actifs ? ──► ex3 Bien configurés ? ──► ex4 Qui a accès ? ──► ex5 Quels risques ? ──► ex6 Quels incidents ?
     loi / cadre /           CMDB vs scan            preuves dans les         RH vs comptes          budget de 50 k$         Loi 25, RGPD, 72 h
     norme / standard        nmap                    fichiers de config                                                     + lettre et verdict
```

| Exercice | La question de l'auditeur | Ce qu'on apprend | Votre tâche « À vous » | Durée |
|---|---|---|---|---|
| `ex1` La lettre d'audit | Quels textes s'appliquent à vous ? | loi, cadre, norme, standard ; un texte étranger peut s'appliquer ; une norme peut être exigée par contrat | la règle de NIS2 (seuil de taille) | 15 min |
| `ex2` L'inventaire | Connaissez-vous tous vos actifs ? | rapprocher l'inventaire d'un scan nmap ; *shadow IT* ; un propriétaire par actif | nommer les propriétaires des actifs inconnus | 15 min |
| `ex3` Les preuves techniques | Vos serveurs sont-ils bien configurés ? | lire une configuration (lignes commentées, valeurs par défaut) ; une preuve = la ligne du fichier ; non-conformité + plan d'action | vérifier les sauvegardes et le test de restauration | 25 min |
| `ex4` La revue des accès | Qui a accès à quoi ? | croiser RH et comptes ; départs mal fermés, privilèges en trop, MFA, comptes sans propriétaire | analyser les comptes des serveurs (`/etc/passwd`, `sudo`) | 20 min |
| `ex5` Le registre de risques | Où mettez-vous votre budget ? | probabilité × impact ; réduire, transférer, éviter, accepter ; appétit pour le risque ; amende vs coût | trouver un plan sous 50 000 $ | 20 min |
| `ex6` Les incidents | Avez-vous déclaré ce qu'il fallait ? | incident de confidentialité, préjudice sérieux, CAI, CNIL, 72 h ; le chiffrement change tout | la règle du préjudice sérieux | 25 min |

Dans chaque notebook, repérez :
- **Ce qu'on fait** : ce que fait la cellule suivante ;
- **👀 Ce qu'on doit voir** : les chiffres attendus, et le score de l'auditeur avant et après votre tâche ;
- **❓ Question pour la classe** : on en discute, la piste est juste en dessous ;
- **À vous** : votre tâche. La **réponse** est dans la cellule juste après : essayez d'abord !
- **`<-- MODIFIABLE`** : des valeurs à changer pour expérimenter.

Après une tâche « À vous », **relancez les cellules suivantes** (dépôt, puis auditeur) pour voir le score monter.

## Démarrer

**Option A, en local avec VS Code (recommandée).** Dans ce dossier :
```
python -m venv .venv
.venv\Scripts\activate            (Windows)
source .venv/bin/activate         (macOS, Linux)
pip install pandas matplotlib ipykernel
```
Ouvrez **le dossier du chapitre** dans VS Code (Fichier → Ouvrir le dossier), ouvrez `ex1`, choisissez le noyau `.venv`.

**Option B, Google Colab.** Ouvrez le notebook, exécutez **l'Étape 0** : elle télécharge le dossier et doit afficher `Prêt : True`.
Lisez la FAQ : sur Colab, chaque notebook a sa propre machine.

Rien à installer d'autre : pas de modèle, pas de réseau, pas de compte. Tout est dans `donnees/`.

## ❓ FAQ

**L'Étape 0 affiche `Prêt : False`.**
Sur Colab : le téléchargement depuis GitHub a échoué ; *Exécution → Redémarrer la session*, puis relancez l'Étape 0. En local : vous n'avez pas ouvert le **dossier du chapitre** dans VS Code.

**`ModuleNotFoundError: No module named 'helper'` (ou `auditeur`).**
Même cause : ouvrez le dossier du chapitre, pas un notebook seul. Vérifiez aussi le noyau `.venv` en haut à droite.

**Sur Colab, l'auditeur dit « fichier introuvable » pour les pièces des exercices précédents.**
Sur Colab, chaque notebook tourne sur **sa propre machine** : `livrables/` repart à zéro dans chaque notebook. L'auditeur ne voit que les pièces de la session en cours.
Pour suivre le score jusqu'à 80, travaillez **en local**. Sur Colab, regardez seulement la ligne de la demande de l'exercice en cours.

**J'ai fait ma tâche, mais le score n'a pas bougé.**
La pièce n'a pas été redéposée. Relancez **toutes les cellules après** votre tâche : celle qui dépose la pièce (« Pièce déposée : livrables/… »), puis celle de l'auditeur.

**L'auditeur refuse ma pièce mais je ne comprends pas pourquoi.**
Lisez ses remarques (les lignes `·` sous la demande) : il dit exactement quelle ligne pose problème. Le rapport complet est aussi dans `livrables/rapport_auditeur.md`.
Et vous pouvez lire `auditeur.py` : un vrai auditeur aussi publie ses critères.

**Pourquoi D-03 est ✅ alors que `bd01` échoue à tous les contrôles ?**
Parce que l'auditeur vérifie que votre pièce est **exacte, prouvée et accompagnée d'un plan**, pas que vos serveurs sont parfaits. Déclarer `bd01` conforme serait une **fausse déclaration** : la demande serait refusée.

**Je suis à 75 / 100 et le verdict dit « reportée ». Pourquoi ?**
Une demande **critique** refusée (❌) suffit à reporter la certification, quel que soit le score. Regardez laquelle : c'est presque toujours D-04, la tâche des sauvegardes de l'ex3.

**Mon plan de risques respecte le budget, mais D-06 n'est pas à 15.**
Prenez la mesure **exactement** comme elle est écrite dans `mesures.csv`, avec son numéro de ligne. Vérifiez aussi qu'aucun risque résiduel ne dépasse 8.

**Faut-il connaître les articles de loi par cœur ?**
Non. Les références (Loi 25 art. 3.5, RGPD art. 33, CIS 11.2…) sont là pour savoir **où chercher**. Retenez les idées : qui doit déclarer quoi, à qui, et en combien de temps.

**Les règles de l'ex6 (préjudice sérieux) sont-elles exactement la loi ?**
Non, c'est une **simplification** pour l'exercice. Dans la vraie vie, le risque de préjudice sérieux s'évalue au cas par cas, avec les facteurs de l'art. 3.7 de la Loi 25, et l'évaluation est documentée.

**Je veux tout recommencer à zéro.**
Supprimez le dossier `livrables/`. L'historique des scores (`livrables/scores.csv`) part avec lui.

**J'ai fini en avance.**
Essayez les défis ci-dessous.

## Défis (facultatifs)

1. **ex1** : passez `faits['employes']` à 55. Qu'est-ce qui change ? Et si NordHébergement ouvrait un bureau à Lyon (`etablissement_dans_ue = True`) ?
2. **ex3** : ajoutez un contrôle `ssh_essais` : `MaxAuthTries` ≤ 4 (défaut : 6). Quel serveur est conforme ? (L'auditeur ne le note pas, mais un vrai le demanderait.)
3. **ex5** : la direction baisse le budget à 35 000 $. Existe-t-il encore un plan qui garde tous les risques sous 8 ? Sinon, quel risque proposez-vous d'**accepter**, et comment le justifier ?
4. **ex6** : INC-052 a été détecté le 23 novembre. Rédigez en 5 lignes l'avis aux 45 candidats touchés : quoi, quand, quels renseignements, ce qu'on a fait, ce qu'ils peuvent faire.

## Le dossier

- `ex1` à `ex6` : les notebooks, à faire dans l'ordre.
- `donnees/` : tout ce que l'entreprise a fourni. `lettre_audit.md` (la lettre), `fiche_entreprise.md`, la CMDB, le scan nmap, les fichiers extraits de `web01` et `bd01`, les listes RH et Microsoft 365, les risques, les tickets d'incident. **Ouvrez ces fichiers.**
- `livrables/` (créé au premier dépôt) : vos pièces, `rapport_auditeur.md` et `scores.csv`.
- `helper.py` : lire les données, lire une directive de configuration, déposer une pièce.
- `auditeur.py` : l'auditeur automatique. À lire, pas à modifier.

## Ce qui est réel, ce qui est inventé

- **Réel** : les formats de fichiers (`sshd_config`, `login.defs`, `pwquality.conf`, `ufw status`, `logrotate`, journaux `restic`, `/etc/passwd`, `/etc/group`, sortie `nmap -oG`), les références (CIS Controls v8, ISO/IEC 27001:2022, Loi 25, RGPD, NIS2) et les règles qu'elles posent.
- **Inventé** : NordHébergement, Boréal Audit, la Banque Saguenéenne, les employés, les incidents. Les IP sont des adresses privées.
- **Simplifié** : l'applicabilité des lois et le « préjudice sérieux » sont traduits en règles simples. Ce chapitre montre la démarche d'un audit, ce n'est **pas un avis juridique**.
