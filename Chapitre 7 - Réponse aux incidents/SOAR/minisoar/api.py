"""Exercice 3 : l'API du mini-SOAR.

Les outils de détection (SIEM, Wazuh, EDR…) envoient leurs alertes par HTTP sur un **webhook**.
L'API :
  1. vérifie que l'appel vient bien d'un outil autorisé (clé d'API) ;
  2. **normalise** l'alerte : chaque outil a son format, le SOAR n'en connaît qu'un ;
  3. **dédoublonne** : la même alerte envoyée 50 fois ne lance pas 50 playbooks ;
  4. **route** l'alerte vers le bon playbook, et le lance.

Lancer le serveur dans un terminal :   uvicorn minisoar.api:app --port 8000
Documentation interactive :            http://localhost:8000/docs
"""
import hashlib, uuid
from datetime import datetime, timedelta

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, IPvAnyAddress, ValidationError

from banc import environnement as env
from . import moteur
from .actions import secret, SecretManquant


# ---------------------------------------------------------------------------------------
# 1. Le format commun (un petit sous-ensemble des idées d'ECS / OCSF)
# ---------------------------------------------------------------------------------------
class Alerte(BaseModel):
    id: str = Field(max_length=64)
    horodatage: datetime
    regle: str = Field(pattern=r"^R\d+-[a-z-]+$")
    niveau: int = Field(ge=0, le=15)
    hote: str = Field(max_length=64)
    ip: IPvAnyAddress | None = None
    compte: str | None = Field(None, pattern=r"^[a-z_][a-z0-9_-]{0,31}$")
    description: str = Field(max_length=500)


REGLES_WAZUH = {"100204": "R4-sortant-suspect", "100310": "R5-cpu"}


def normaliser(source: str, brut: dict) -> Alerte:
    """Traduit l'alerte d'un outil vers le format commun. Lève ValidationError si elle est invalide."""
    if source == "siem":
        return Alerte(**brut)
    if source == "wazuh":
        return Alerte(id=brut["id"], horodatage=brut["timestamp"][:19],
                      regle=REGLES_WAZUH.get(brut["rule"]["id"], f"R0-wazuh-{brut['rule']['id']}"),
                      niveau=brut["rule"]["level"], hote=brut["agent"]["name"],
                      ip=brut.get("data", {}).get("srcip"), compte=brut.get("data", {}).get("dstuser"),
                      description=brut["rule"]["description"])
    raise ValueError(f"source inconnue : {source}")


# ---------------------------------------------------------------------------------------
# 2. Dédoublonner
# ---------------------------------------------------------------------------------------
FENETRE = timedelta(minutes=10)
VUES: dict[str, datetime] = {}                     # empreinte -> dernière fois qu'on l'a vue


def empreinte(a: Alerte) -> str:
    """Deux alertes ont la même empreinte si elles disent la même chose : même règle, même IP, même compte."""
    return hashlib.sha256(f"{a.regle}|{a.ip}|{a.compte}|{a.hote}".encode()).hexdigest()[:16]


def est_doublon(a: Alerte) -> bool:
    e, avant = empreinte(a), VUES.get(empreinte(a))
    VUES[e] = a.horodatage
    return avant is not None and a.horodatage - avant < FENETRE


# ---------------------------------------------------------------------------------------
# 3. Router et lancer
# ---------------------------------------------------------------------------------------
ROUTAGE = {"R1-force-brute": "force-brute", "R2-succes-apres-echecs": "connexion-suspecte",
           "R3-compte-leurre": "connexion-suspecte", "R4-sortant-suspect": "activite-hote", "R5-cpu": "activite-hote"}
EXECUTIONS: dict[str, moteur.Execution] = {}


def lancer(alerte: Alerte, playbook: str) -> dict:
    """Exécute le playbook tout de suite et attend la fin (l'exercice 4 le remplacera par une file)."""
    env.a_l_heure({"horodatage": alerte.horodatage.isoformat()})   # rejeu : l'horloge suit les alertes
    ex = moteur.executer(moteur.charger(playbook), alerte.model_dump(mode="json"))
    id_ = uuid.uuid4().hex[:8]
    EXECUTIONS[id_] = ex
    return {"execution": id_, "statut": ex.statut, "sortie": ex.sortie}


def lancer_en_file(alerte: Alerte, playbook: str) -> dict:
    """Exercice 4 : on dépose l'exécution dans la file et on répond tout de suite (202)."""
    from . import file
    return {"execution": file.deposer(playbook, alerte.model_dump(mode="json")), "statut": "en file"}


LANCER = lancer                     # exercice 4 : api.LANCER = api.lancer_en_file

app = FastAPI(title="mini-SOAR 8INF857")


@app.post("/webhooks/{source}")
def recevoir(source: str, brut: dict, x_soar_cle: str | None = Header(None)):
    try:
        if x_soar_cle != secret("webhook"):
            raise HTTPException(401, "clé d'API absente ou invalide")
    except SecretManquant:
        raise HTTPException(500, "le SOAR n'a pas de clé de webhook configurée")
    try:
        alerte = normaliser(source, brut)
    except (ValidationError, KeyError, ValueError) as e:
        raise HTTPException(422, f"alerte invalide : {str(e)[:300]}")
    if est_doublon(alerte):
        return {"alerte": alerte.id, "statut": "doublon ignoré", "empreinte": empreinte(alerte)}
    playbook = ROUTAGE.get(alerte.regle)
    if playbook is None:
        return {"alerte": alerte.id, "statut": "aucun playbook : à trier par un analyste"}
    return {"alerte": alerte.id, "playbook": playbook, **LANCER(alerte, playbook)}


@app.get("/executions/{id_}")
def execution(id_: str):
    if id_ not in EXECUTIONS:
        from . import file
        e = file.etat(id_)
        if e is None:
            raise HTTPException(404, "exécution inconnue")
        return e
    ex = EXECUTIONS[id_]
    return {"playbook": ex.playbook, "statut": ex.statut, "etapes": list(ex.historique.values()), "sortie": ex.sortie}


# ---------------------------------------------------------------------------------------
# Exercice 5 : les cas et les approbations (pour les analystes, avec LEUR clé)
# ---------------------------------------------------------------------------------------
from typing import Literal


class Decision(BaseModel):
    decision: Literal["approuver", "refuser"]
    analyste: str = Field(min_length=2, max_length=40)
    apres_minutes: float = 0          # rejeu seulement : le temps que l'analyste a mis à répondre


def _analyste(cle):
    try:
        if cle != secret("analystes"):
            raise HTTPException(401, "réservé aux analystes")
    except SecretManquant:
        raise HTTPException(500, "aucune clé d'analyste configurée")


@app.get("/cas")
def liste_cas(x_soar_cle: str | None = Header(None)):
    _analyste(x_soar_cle)
    from . import cas
    return cas.tableau().to_dict("records")


@app.get("/cas/{id_}")
def un_cas(id_: str, x_soar_cle: str | None = Header(None)):
    _analyste(x_soar_cle)
    from . import cas
    return {"rapport": cas.rapport(id_), "mesures": cas.mesures(id_)}


@app.get("/approbations")
def approbations(x_soar_cle: str | None = Header(None)):
    _analyste(x_soar_cle)
    from . import cas
    return cas.en_attente().to_dict("records")


@app.post("/approbations/{execution}/{ref}")
def decider(execution: str, ref: str, d: Decision, x_soar_cle: str | None = Header(None)):
    _analyste(x_soar_cle)
    from . import cas
    try:
        cas.decider(execution, ref, d.decision == "approuver", d.analyste, d.apres_minutes)
    except KeyError as e:
        raise HTTPException(404, str(e))
    return {"execution": execution, "ref": ref, "decision": d.decision, "statut": "remise en file"}
