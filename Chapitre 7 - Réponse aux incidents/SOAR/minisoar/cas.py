"""Exercice 5 : les cas et l'humain dans la boucle.

Un CAS regroupe les alertes qui parlent du même incident. Il a un statut, une sévérité, une
chronologie (les événements) et des OBSERVABLES (IP, comptes, fichiers, URL). Une nouvelle alerte
rejoint le cas avec lequel elle partage un observable ; si elle en touche deux, ils FUSIONNENT.
Dans Tracecat, ce sont les actions core.cases.* ; ici, l'action « cas.rattacher ».

Une étape marquée « approbation: true » met l'exécution EN ATTENTE ; elle reprend quand un
analyste a décidé (route POST /approbations/... de l'API).
"""
import json, re
from datetime import datetime, timedelta

from banc import environnement as env, scenario as sc
from . import file
from .actions import action


def base():
    c = file.base()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS cas (id TEXT PRIMARY KEY, titre TEXT, statut TEXT, severite TEXT, ouvert TEXT);
        CREATE TABLE IF NOT EXISTS evenements (cas TEXT, heure TEXT, type TEXT, texte TEXT);
        CREATE TABLE IF NOT EXISTS observables (cas TEXT, type TEXT, valeur TEXT, PRIMARY KEY (cas, type, valeur));
        CREATE TABLE IF NOT EXISTS approbations (execution TEXT, ref TEXT, action TEXT, args TEXT, demande TEXT,
                                                 decision TEXT, analyste TEXT, decide TEXT, PRIMARY KEY (execution, ref));""")
    return c


def _maintenant():
    return f"{env.HORLOGE:%H:%M:%S}"


# ---------------------------------------------------------------------------------------
# 1. Les observables
# ---------------------------------------------------------------------------------------
def extraire(texte: str) -> set:
    """Les observables cités dans un texte : IP, comptes connus, fichiers, URL."""
    obs = {("ip", ip) for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", texte)}
    obs |= {("compte", c) for c in set(env.comptes()) | {"oracle"} if re.search(rf"\b{c}\b", texte)}
    obs |= {("fichier", f) for f in re.findall(r"(/tmp/\S+|\b\w+\.sh\b)", texte)}
    obs |= {("url", u.rstrip(".;,)")) for u in re.findall(r"https?://\S+", texte)}
    return obs


# ---------------------------------------------------------------------------------------
# 2. Rattacher une alerte à un cas (une action, appelée par les playbooks)
# ---------------------------------------------------------------------------------------
@action("cas.rattacher")
def rattacher(alerte: dict) -> dict:
    """Rattache l'alerte au cas ouvert qui partage un observable avec elle, ou ouvre un nouveau cas."""
    db = base()
    obs = extraire(alerte.get("description", ""))
    obs |= {(t, alerte[t]) for t in ("ip", "compte") if alerte.get(t)}
    touches = []
    for t, v in obs:
        touches += [r["id"] for r in db.execute("""SELECT DISTINCT c.id FROM cas c JOIN observables o ON o.cas = c.id
                                                   WHERE c.statut != 'fermé' AND o.type = ? AND o.valeur = ?""", (t, v))]
    touches = sorted(set(touches))
    if touches:
        id_, nouveau = touches[0], False
        for autre in touches[1:]:                                   # fusion dans le plus ancien
            for table in ("evenements", "observables"):
                db.execute(f"UPDATE OR IGNORE {table} SET cas = ? WHERE cas = ?", (id_, autre))
            db.execute("DELETE FROM observables WHERE cas = ?", (autre,))
            db.execute("DELETE FROM cas WHERE id = ?", (autre,))
            db.execute("INSERT INTO evenements VALUES (?, ?, 'fusion', ?)", (id_, _maintenant(), f"{autre} fusionné dans {id_}"))
    else:
        id_, nouveau = f"C{db.execute('SELECT COUNT(*) FROM evenements WHERE type = ?', ('ouverture',)).fetchone()[0] + 1:03d}", True
        severite = "haute" if alerte.get("niveau", 0) >= 8 else "moyenne" if alerte.get("niveau", 0) >= 5 else "basse"
        db.execute("INSERT INTO cas VALUES (?, ?, 'nouveau', ?, ?)", (id_, alerte.get("description", "")[:90], severite, _maintenant()))
        db.execute("INSERT INTO evenements VALUES (?, ?, 'ouverture', ?)", (id_, _maintenant(), f"cas ouvert par {alerte.get('id')}"))
    db.execute("INSERT INTO evenements VALUES (?, ?, 'alerte', ?)",
               (id_, _maintenant(), f"{alerte.get('id')} {alerte.get('regle')} : {alerte.get('description')}"))
    db.executemany("INSERT OR IGNORE INTO observables VALUES (?, ?, ?)", [(id_, t, v) for t, v in obs])
    notes = [r["texte"] for r in db.execute("SELECT texte FROM evenements WHERE cas = ? AND type = 'note' ORDER BY rowid", (id_,))]
    return {"cas": id_, "nouveau": nouveau, "notes": notes[-5:]}


def consigner(sortie: dict, trigger: dict):
    """Appelée par le travailleur à la fin d'un playbook : le rapport devient une note du cas."""
    if not sortie or not sortie.get("cas"):
        return
    db, id_ = base(), sortie["cas"]
    rapport, verdict = sortie.get("rapport", ""), sortie.get("verdict", "")
    db.execute("INSERT INTO evenements VALUES (?, ?, 'note', ?)", (id_, _maintenant(), f"[{verdict}] {rapport}"))
    db.executemany("INSERT OR IGNORE INTO observables VALUES (?, ?, ?)", [(id_, t, v) for t, v in extraire(rapport)])
    if verdict == "incident":
        db.execute("UPDATE cas SET statut = 'en cours', severite = 'critique' WHERE id = ?", (id_,))
    elif verdict in ("faux positif", "attaque sans impact"):
        db.execute("UPDATE cas SET statut = 'fermé' WHERE id = ? AND statut = 'nouveau'", (id_,))
        db.execute("INSERT INTO evenements VALUES (?, ?, 'fermeture', ?)", (id_, _maintenant(), verdict))


# ---------------------------------------------------------------------------------------
# 3. L'humain dans la boucle
# ---------------------------------------------------------------------------------------
def demander(execution: str, etape, args: dict):
    """Appelée par le moteur devant une étape « approbation: true ». None = pas encore de réponse."""
    db = base()
    r = db.execute("SELECT * FROM approbations WHERE execution = ? AND ref = ?", (execution, etape.ref)).fetchone()
    if r is None:
        db.execute("INSERT INTO approbations VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL)",
                   (execution, etape.ref, etape.action, json.dumps(args), _maintenant()))
        return None
    if r["decision"] is None:
        return None
    return r["decision"] == "approuvée"


def en_attente():
    import pandas as pd
    return pd.read_sql("SELECT execution, ref, action, args, demande FROM approbations WHERE decision IS NULL", base())


def decider(execution: str, ref: str, approuver: bool, analyste: str, apres_minutes: float = 0):
    """L'analyste répond. `apres_minutes` : combien de temps il a mis (pour le rejeu)."""
    db = base()
    r = db.execute("SELECT demande FROM approbations WHERE execution = ? AND ref = ?", (execution, ref)).fetchone()
    if r is None:
        raise KeyError("aucune demande d'approbation pour cette étape")
    decide = sc._h(r["demande"]) + timedelta(minutes=apres_minutes)
    db.execute("UPDATE approbations SET decision = ?, analyste = ?, decide = ? WHERE execution = ? AND ref = ?",
               ("approuvée" if approuver else "refusée", analyste, f"{decide:%H:%M:%S}", execution, ref))
    db.execute("UPDATE executions SET statut = 'en file' WHERE id = ? AND statut = 'en attente'", (execution,))


def reprendre_horloge(execution: str):
    """Après une approbation, le playbook reprend à l'heure de la décision, pas à celle de l'alerte."""
    r = base().execute("SELECT MAX(decide) AS d FROM approbations WHERE execution = ?", (execution,)).fetchone()
    if r["d"] and sc._h(r["d"]) > env.HORLOGE:
        env.HORLOGE = sc._h(r["d"])


# ---------------------------------------------------------------------------------------
# 4. Lire les cas
# ---------------------------------------------------------------------------------------
def tableau():
    import pandas as pd
    return pd.read_sql("""SELECT c.id, c.statut, c.severite, c.ouvert,
                                 (SELECT COUNT(*) FROM evenements e WHERE e.cas = c.id AND e.type = 'alerte') AS alertes,
                                 c.titre
                          FROM cas c ORDER BY c.id""", base())


def mesures(id_: str) -> dict:
    """MTTD (début de l'attaque → ouverture du cas) et MTTC (ouverture → premier confinement)."""
    db = base()
    c = db.execute("SELECT * FROM cas WHERE id = ?", (id_,)).fetchone()
    notes = " ".join(r["texte"] for r in db.execute("SELECT texte FROM evenements WHERE cas = ?", (id_,)))
    debuts = re.findall(r"premier essai à \w+ +\d+ (\d\d:\d\d:\d\d)", notes)
    valeurs = {r["valeur"] for r in db.execute("SELECT valeur FROM observables WHERE cas = ?", (id_,))}
    confinements = sorted(a["heure"] for a in env.audit()
                          if a["cible"] in valeurs and a["resultat"] in ("bloquée", "désactivé", "arrêté"))
    if not confinements:   # un processus arrêté a pour cible un pid : on le rattache par le compte du cas
        confinements = sorted(a["heure"] for a in env.audit() if a["action"] == "tuer_processus" and a["resultat"] == "arrêté")
    ouvert = sc._h(c["ouvert"])
    return {"debut": min(debuts) if debuts else None, "detection": c["ouvert"],
            "confinement": confinements[0] if confinements else None,
            "MTTD": str(ouvert - sc._h(min(debuts))) if debuts else None,
            "MTTC": str(sc._h(confinements[0]) - ouvert) if confinements else None}


def rapport(id_: str) -> str:
    """Le rapport d'incident du cas, en Markdown : chronologie, observables, mesures."""
    db = base()
    c = db.execute("SELECT * FROM cas WHERE id = ?", (id_,)).fetchone()
    lignes = [f"# Cas {id_} — {c['titre']}", f"Statut : {c['statut']} · sévérité : {c['severite']} · ouvert à {c['ouvert']}", "",
              "## Chronologie"]
    lignes += [f"- {r['heure']} [{r['type']}] {r['texte']}"
               for r in db.execute("SELECT * FROM evenements WHERE cas = ? ORDER BY heure, rowid", (id_,))]
    lignes += ["", "## Observables"]
    for t in ("ip", "compte", "fichier", "url"):
        v = [r["valeur"] for r in db.execute("SELECT valeur FROM observables WHERE cas = ? AND type = ? ORDER BY valeur", (id_, t))]
        if v:
            lignes.append(f"- {t} : {', '.join(v)}")
    m = mesures(id_)
    lignes += ["", "## Mesures", f"- Début de l'attaque : {m['debut']} · détection : {m['detection']} · premier confinement : {m['confinement']}",
               f"- MTTD : {m['MTTD']} · MTTC : {m['MTTC']}"]
    appro = list(db.execute("SELECT * FROM approbations"))
    if appro:
        lignes += ["", "## Approbations"] + [f"- {a['action']} {a['args']} : demandée à {a['demande']}, {a['decision'] or 'EN ATTENTE'}"
                                             + (f" par {a['analyste']} à {a['decide']}" if a["decision"] else "") for a in appro]
    return "\n".join(lignes)
