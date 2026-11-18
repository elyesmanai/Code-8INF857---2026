"""Exercice 1 : le registre d'actions du mini-SOAR.

Dans Tracecat, une intégration est une fonction Python enregistrée avec @registry.register :
un nom (« namespace.nom »), des entrées typées, des secrets déclarés. Le moteur de workflow
(exercice 2) n'appelle jamais une fonction directement : il demande au registre
d'exécuter l'action « pare_feu.bloquer_ip » avec des arguments venus d'un fichier YAML.
Le registre vérifie les entrées et les secrets, réessaie si le réseau échoue, et chronomètre.
"""
import inspect, ipaddress, os, re, time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as Expire
from dataclasses import dataclass, field
from typing import Annotated, Callable

import requests
from pydantic import Field, IPvAnyAddress, ValidationError, validate_call

from banc import environnement as env

REGISTRE: dict[str, "Action"] = {}


class SecretManquant(Exception):
    pass


class ErreurTemporaire(Exception):
    """Une panne qui vaut la peine de réessayer (réseau, service occupé)."""


@dataclass
class Action:
    nom: str
    fonction: Callable
    description: str
    secrets: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------------------
# Le registre
# ---------------------------------------------------------------------------------------
def action(nom: str, secrets: list[str] = ()):
    """Décorateur : enregistre une fonction comme action du SOAR, sous le nom « namespace.nom »."""
    def enregistrer(f):
        if not re.fullmatch(r"[a-z_]+\.[a-z_]+", nom):
            raise ValueError(f"Nom d'action invalide : {nom} (attendu : namespace.nom)")
        REGISTRE[nom] = Action(nom, validate_call(f), (f.__doc__ or "").strip(), list(secrets))
        return f
    return enregistrer


def secret(nom: str) -> str:
    """Lit un secret dans les variables d'environnement (SOAR_SECRET_<NOM>), jamais dans un playbook."""
    valeur = os.environ.get(f"SOAR_SECRET_{nom.upper()}")
    if not valeur:
        raise SecretManquant(f"Secret « {nom} » absent : définissez la variable SOAR_SECRET_{nom.upper()}")
    return valeur


def executer(nom: str, args: dict, essais: int = 1, delai_max: float = 30) -> dict:
    """Exécute une action du registre. Renvoie {"result", "essais", "duree"} ou lève une erreur.

    - les entrées sont validées par pydantic AVANT toute exécution ;
    - les secrets déclarés doivent exister AVANT toute exécution ;
    - une ErreurTemporaire est réessayée (attente 1 s, 2 s, 4 s…) ; les autres erreurs, jamais ;
    - au-delà de `delai_max` secondes, l'essai est abandonné.
    """
    if nom not in REGISTRE:
        raise KeyError(f"Action inconnue : {nom}")
    a = REGISTRE[nom]
    for s in a.secrets:
        secret(s)
    debut = time.time()
    for essai in range(1, essais + 1):
        try:
            with ThreadPoolExecutor(1) as pool:
                resultat = pool.submit(a.fonction, **args).result(timeout=delai_max)
            return {"result": resultat, "essais": essai, "duree": round(time.time() - debut, 2)}
        except (ErreurTemporaire, Expire) as e:
            if essai == essais:
                raise ErreurTemporaire(f"{nom} : échec après {essais} essai(s) ({type(e).__name__})") from e
            time.sleep(2 ** (essai - 1))


def catalogue():
    """Le catalogue des actions : ce qu'un analyste voit dans l'interface d'un SOAR."""
    import pandas as pd
    lignes = []
    for a in REGISTRE.values():
        entrees = inspect.signature(a.fonction).parameters
        lignes.append({"action": a.nom, "entrées": ", ".join(entrees), "secrets": ", ".join(a.secrets),
                       "description": a.description.splitlines()[0] if a.description else ""})
    return pd.DataFrame(lignes).sort_values("action").reset_index(drop=True)


# ---------------------------------------------------------------------------------------
# Les intégrations
# ---------------------------------------------------------------------------------------
IP = Annotated[IPvAnyAddress, Field(description="Une adresse IPv4 ou IPv6")]
DOCUMENTATION = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def _interne(ip) -> bool:
    """Réseau de l'entreprise ? (Les plages de documentation jouent ici le rôle d'Internet.)"""
    a = ipaddress.ip_address(str(ip))
    return a.is_private and not any(a in n for n in DOCUMENTATION)


@action("journaux.chercher")
def chercher(motif: Annotated[str, Field(min_length=2)], journal: str = "auth.log") -> dict:
    """Les lignes d'un journal (auth.log, pare-feu.log, supervision.log) qui contiennent un texte."""
    lignes = env.chercher(motif, journal)
    return {"nombre": len(lignes), "lignes": lignes[-50:]}


@action("journaux.connexions")
def connexions(ip: IP) -> dict:
    """Le bilan SSH d'une IP : échecs, succès, comptes essayés, premier et dernier essai."""
    lignes = sorted(set(l for l in env.chercher(str(ip), "auth.log") if re.search(rf"\b{re.escape(str(ip))}\b", l)))
    echecs = [l for l in lignes if "Failed password" in l]
    succes = [l for l in lignes if "Accepted" in l]
    comptes = sorted({m.group(1) for l in echecs if (m := re.search(r"for (?:invalid user )?(\S+) from", l))})
    return {"echecs": len(echecs), "succes": len(succes), "comptes_essayes": comptes,
            "comptes_entres": sorted({l.split(" for ")[1].split()[0] for l in succes}),
            "premier": lignes[0][:15] if lignes else None, "dernier": lignes[-1][:15] if lignes else None}


@action("ip.enrichir")
def enrichir(ip: IP) -> dict:
    """Interne ou externe, et à qui appartient l'adresse (registre RDAP public)."""
    doc = any(ipaddress.ip_address(str(ip)) in n for n in DOCUMENTATION)
    info = {"ip": str(ip), "interne": _interne(ip), "documentation": doc, "proprietaire": None, "pays": None}
    if info["interne"] or doc:
        return info
    try:
        r = requests.get(f"https://rdap.org/ip/{ip}", timeout=8)
    except requests.RequestException as e:
        raise ErreurTemporaire(str(e))
    if r.status_code >= 500 or r.status_code == 429:
        raise ErreurTemporaire(f"RDAP a répondu {r.status_code}")
    d = r.json()
    info.update(proprietaire=d.get("name"), pays=d.get("country"))
    return info


@action("hote.lire")
def lire(chemin: str) -> dict:
    """Lit un fichier du serveur LabSZ (ex. home/webadmin/.ssh/authorized_keys)."""
    if chemin.lstrip("/").startswith(("etc/shadow", "root/")):
        raise PermissionError("lecture interdite : fichier sensible")
    contenu = env.lire(chemin)
    if contenu is None:
        raise FileNotFoundError(chemin)
    return {"chemin": chemin, "lignes": contenu.splitlines()}


@action("hote.processus")
def processus() -> dict:
    """Les processus du serveur, du plus gourmand au moins gourmand en CPU."""
    return {"processus": sorted(env.processus(), key=lambda p: -p["cpu"])}


@action("pare_feu.bloquer_ip")
def bloquer_ip(ip: IP) -> dict:
    """Bloque une IP externe dans le pare-feu (nftables). Idempotent."""
    if _interne(ip):
        raise PermissionError(f"{ip} est une adresse interne : on ne bloque pas un poste de l'entreprise")
    return {"ip": str(ip), "statut": env.bloquer_ip(str(ip))}


@action("pare_feu.debloquer_ip")
def debloquer_ip(ip: IP) -> dict:
    """Retire une IP du pare-feu (retour arrière)."""
    return {"ip": str(ip), "statut": env.debloquer_ip(str(ip))}


@action("comptes.desactiver")
def desactiver(compte: Annotated[str, Field(pattern=r"^[a-z_][a-z0-9_-]{0,31}$")]) -> dict:
    """Désactive un compte du serveur. Idempotent."""
    if compte == "root":
        raise PermissionError("on ne désactive pas root à distance")
    return {"compte": compte, "statut": env.desactiver_compte(compte)}


@action("hote.retirer_ligne")
def retirer_ligne(chemin: str, texte: Annotated[str, Field(min_length=6)]) -> dict:
    """Retire d'un fichier du serveur LA ligne qui contient un texte (clé SSH, entrée cron)."""
    contenu = env.lire(chemin) or ""
    n = sum(texte in l for l in contenu.splitlines())
    if n > 1:
        raise ValueError(f"« {texte} » désigne {n} lignes : soyez plus précis")
    return {"chemin": chemin, "statut": env.retirer_ligne(chemin, texte) if n else "rien à retirer"}


@action("hote.tuer_processus")
def tuer(pid: Annotated[int, Field(ge=1000)]) -> dict:
    """Arrête un processus (jamais un processus système, pid < 1000)."""
    return {"pid": pid, "statut": env.tuer_processus(pid)}


@action("messagerie.notifier", secrets=["ntfy"])
def notifier(titre: str, message: str, priorite: Annotated[int, Field(ge=1, le=5)] = 3) -> dict:
    """Envoie une notification sur le téléphone de l'analyste de garde (service ntfy.sh)."""
    try:
        r = requests.post(f"https://ntfy.sh/{secret('ntfy')}", data=message.encode(),
                          headers={"Title": titre, "Priority": str(priorite)}, timeout=8)
    except requests.RequestException as e:
        raise ErreurTemporaire(str(e))
    if r.status_code >= 500 or r.status_code == 429:
        raise ErreurTemporaire(f"ntfy a répondu {r.status_code}")
    r.raise_for_status()
    return {"envoye": True}
