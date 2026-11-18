"""Exercice 4 : l'exécution durable.

Un incident dure des heures ; un serveur redémarre, un processus plante. Tracecat confie ses
exécutions à Temporal : chaque étape terminée est ENREGISTRÉE, et après une panne, l'exécution
reprend là où elle s'était arrêtée, sans refaire ce qui est fait.

On fait la même chose avec une base SQLite :
  - l'API DÉPOSE une exécution dans une file (table `executions`) et répond tout de suite ;
  - des TRAVAILLEURS (plusieurs processus) PRENNENT les exécutions, avec un BAIL (un délai) ;
  - chaque étape terminée est écrite dans la table `etapes` ;
  - si un travailleur meurt, son bail expire, un autre reprend l'exécution, et le moteur
    saute les étapes déjà enregistrées.

Lancer un travailleur dans un terminal :   python -m minisoar.file
"""
import json, os, socket, sqlite3, sys, time, uuid
from datetime import datetime

from banc import environnement as env
from . import moteur

BAIL = float(os.environ.get("SOAR_BAIL", 5))        # secondes avant qu'une exécution « orpheline » soit reprise
HUMAIN = None       # exercice 5 : HUMAIN = cas  → approbations humaines et cas. None : tout est accepté.


def base():
    c = sqlite3.connect(env.ENV / "soar.db", timeout=10, isolation_level=None)   # autocommit
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")            # plusieurs processus lisent et écrivent sans se bloquer
    c.executescript("""
        CREATE TABLE IF NOT EXISTS executions (
            id TEXT PRIMARY KEY, playbook TEXT, trigger TEXT, statut TEXT, depose REAL,
            travailleur TEXT, bail REAL, sortie TEXT);
        CREATE TABLE IF NOT EXISTS etapes (
            execution TEXT, ref TEXT, trace TEXT, PRIMARY KEY (execution, ref));""")
    return c


def deposer(playbook: str, trigger: dict) -> str:
    """Met une exécution dans la file et rend la main tout de suite."""
    id_ = uuid.uuid4().hex[:8]
    base().execute("INSERT INTO executions VALUES (?, ?, ?, 'en file', ?, NULL, NULL, NULL)",
                   (id_, playbook, json.dumps(trigger), time.time()))
    return id_


def prendre(travailleur: str):
    """Réserve UNE exécution, de façon atomique : deux travailleurs ne prennent jamais la même.
    Une exécution « en cours » dont le bail a expiré est orpheline : on la reprend."""
    maintenant = time.time()
    return base().execute("""
        UPDATE executions SET statut = 'en cours', travailleur = ?, bail = ?
        WHERE id = (SELECT id FROM executions
                    WHERE statut = 'en file' OR (statut = 'en cours' AND bail < ?)
                    ORDER BY depose LIMIT 1)
        RETURNING *""", (travailleur, maintenant + BAIL, maintenant)).fetchone()


def executer(ligne, travailleur: str):
    """Exécute (ou reprend) une exécution réservée."""
    db, id_ = base(), ligne["id"]
    trigger = json.loads(ligne["trigger"])
    env.a_l_heure(trigger)
    deja = {r["ref"]: json.loads(r["trace"]) for r in db.execute("SELECT * FROM etapes WHERE execution = ?", (id_,))}

    def enregistrer(trace):
        if os.environ.get("SOAR_PANNE_APRES") == trace["ref"]:      # pour l'exercice : panne simulée,
            print(f"💥 {travailleur} plante juste après l'étape « {trace['ref']} »", flush=True)
            os._exit(1)                                               # APRÈS l'action, AVANT l'écriture
        db.execute("INSERT OR REPLACE INTO etapes VALUES (?, ?, ?)", (id_, trace["ref"], json.dumps(trace)))
        db.execute("UPDATE executions SET bail = ? WHERE id = ?", (time.time() + BAIL, id_))   # « je suis vivant »

    approuver = None
    if HUMAIN:                                   # exercice 5
        HUMAIN.reprendre_horloge(id_)            # l'analyste a peut-être répondu plus tard
        approuver = lambda etape, args: HUMAIN.demander(id_, etape, args)
    ex = moteur.executer(moteur.charger(ligne["playbook"]), trigger, deja_fait=deja,
                         sur_etape=enregistrer, approuver=approuver)
    db.execute("UPDATE executions SET statut = ?, sortie = ? WHERE id = ?",
               (ex.statut, json.dumps(ex.sortie), id_))
    if HUMAIN and ex.statut == "terminée":
        HUMAIN.consigner(ex.sortie, trigger)
    return ex


def travailler(une_fois=False, travailleur=None, bavard=False):
    """Boucle d'un travailleur. une_fois=True : vide la file puis s'arrête. bavard : affiche chaque prise."""
    travailleur = travailleur or f"{socket.gethostname()}-{os.getpid()}"
    fait = 0
    while True:
        ligne = prendre(travailleur)
        if ligne is None:
            if une_fois:
                return fait
            time.sleep(0.5)
            continue
        if bavard:
            print(f"[{datetime.now():%H:%M:%S}] {travailleur} prend {ligne['id']} ({ligne['playbook']})", flush=True)
        executer(ligne, travailleur)
        fait += 1


def etat(id_: str) -> dict:
    db = base()
    e = db.execute("SELECT * FROM executions WHERE id = ?", (id_,)).fetchone()
    if e is None:
        return None
    etapes = [json.loads(r["trace"]) for r in db.execute("SELECT trace FROM etapes WHERE execution = ? ORDER BY rowid", (id_,))]
    return {"id": id_, "playbook": e["playbook"], "statut": e["statut"], "travailleur": e["travailleur"],
            "sortie": json.loads(e["sortie"]) if e["sortie"] else None, "etapes": etapes}


def tableau():
    import pandas as pd
    return pd.read_sql("SELECT id, playbook, statut, travailleur FROM executions ORDER BY depose", base())


if __name__ == "__main__":
    travailler(une_fois="--une-fois" in sys.argv, bavard=True)
