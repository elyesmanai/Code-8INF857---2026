"""Exercice 2 : le moteur de workflow.

Un playbook est un fichier YAML (même format que Tracecat, en plus petit) :

    title: ...
    actions:
      - ref: bilan                              # nom unique de l'étape
        action: journaux.connexions             # une action du registre (exercice 1)
        args: {ip: "${{ TRIGGER.ip }}"}         # expressions : TRIGGER, ACTIONS, SECRETS, FN
        depends_on: [autre_etape]               # facultatif : attendre ces étapes
        run_if: "${{ ACTIONS.x.result.n > 0 }}" # facultatif : sinon l'étape est ignorée
        retry_policy: {max_attempts: 3, timeout: 30}
        approbation: true                       # facultatif (exercice 5) : un humain doit accepter
    returns: {...}                              # la sortie du playbook, avec des expressions

Le moteur valide le playbook, calcule l'ordre des étapes, évalue les expressions SANS eval(),
exécute chaque étape par le registre, et garde l'historique de tout ce qu'il a fait.
"""
import ast, operator, re, time
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from banc import environnement as env
from . import actions as registre

DOSSIER = Path(__file__).resolve().parent.parent / "playbooks"


# ---------------------------------------------------------------------------------------
# 1. Charger et valider
# ---------------------------------------------------------------------------------------
class PlaybookInvalide(Exception):
    pass


@dataclass
class Etape:
    ref: str
    action: str
    args: dict = field(default_factory=dict)
    depends_on: list = field(default_factory=list)
    run_if: str | None = None
    essais: int = 1
    delai: float = 30
    approbation: bool = False


@dataclass
class Playbook:
    titre: str
    etapes: dict            # ref -> Etape, dans l'ordre d'exécution
    sortie: dict


def charger(nom_ou_chemin) -> Playbook:
    chemin = Path(nom_ou_chemin)
    if not chemin.exists():
        chemin = DOSSIER / f"{nom_ou_chemin}.yaml"
    return valider(yaml.safe_load(chemin.read_text()))


def valider(d: dict) -> Playbook:
    etapes = {}
    for a in d.get("actions", []):
        ref = a.get("ref", "")
        if not re.fullmatch(r"[a-z][a-z0-9_]*", ref):
            raise PlaybookInvalide(f"ref invalide : « {ref} » (minuscules, chiffres, _)")
        if ref in etapes:
            raise PlaybookInvalide(f"ref en double : {ref}")
        if a.get("action") not in registre.REGISTRE:
            raise PlaybookInvalide(f"{ref} : action inconnue « {a.get('action')} »")
        r = a.get("retry_policy", {})
        etapes[ref] = Etape(ref, a["action"], a.get("args", {}), a.get("depends_on", []), a.get("run_if"),
                            r.get("max_attempts", 1), r.get("timeout", 30), a.get("approbation", False))
    for e in etapes.values():
        for dep in e.depends_on:
            if dep not in etapes:
                raise PlaybookInvalide(f"{e.ref} dépend de « {dep} », qui n'existe pas")
    ordre = tri_topologique({e.ref: e.depends_on for e in etapes.values()})
    return Playbook(d.get("title", "sans titre"), {r: etapes[r] for r in ordre}, d.get("returns", {}))


def tri_topologique(dependances: dict) -> list:
    """Ordre où chaque étape vient après celles dont elle dépend (algorithme de Kahn)."""
    restantes = {r: set(d) for r, d in dependances.items()}
    ordre = []
    while restantes:
        pretes = [r for r, d in restantes.items() if not d]       # l'ordre du fichier est conservé
        if not pretes:
            raise PlaybookInvalide(f"cycle entre les étapes : {sorted(restantes)}")
        for r in pretes:
            ordre.append(r)
            del restantes[r]
        for d in restantes.values():
            d.difference_update(pretes)
    return ordre


# ---------------------------------------------------------------------------------------
# 2. Les expressions ${{ ... }}, sans eval()
# ---------------------------------------------------------------------------------------
class ExpressionInterdite(Exception):
    pass


MOTIF = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")
OPERATEURS = {ast.Eq: operator.eq, ast.NotEq: operator.ne, ast.Lt: operator.lt, ast.LtE: operator.le,
              ast.Gt: operator.gt, ast.GtE: operator.ge, ast.In: lambda a, b: a in b,
              ast.NotIn: lambda a, b: a not in b, ast.Is: operator.is_, ast.IsNot: operator.is_not,
              ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
              ast.Div: operator.truediv, ast.Mod: operator.mod}
FONCTIONS = {                                     # les FN.* de Tracecat, en petit
    "length": lambda x: len(x or []), "lower": lambda s: str(s).lower(),
    "join": lambda l, sep=", ": sep.join(map(str, l or [])),
    "contains": lambda texte, motif: motif in texte, "now": lambda: f"{env.HORLOGE:%H:%M:%S}",
    "filter_lines": lambda lignes, motif: [l for l in lignes if motif in l],
}


class _Secrets:
    """SECRETS.ntfy -> la valeur, lue au dernier moment dans l'environnement."""
    def get(self, nom):
        return registre.secret(nom)


def evaluer(valeur, contexte: dict):
    """Remplace les ${{ ... }} dans une valeur (texte, liste ou dictionnaire)."""
    if isinstance(valeur, dict):
        return {k: evaluer(v, contexte) for k, v in valeur.items()}
    if isinstance(valeur, list):
        return [evaluer(v, contexte) for v in valeur]
    if not isinstance(valeur, str):
        return valeur
    seule = MOTIF.fullmatch(valeur.strip())
    if seule:                                     # "${{ x }}" seul : on garde le type (nombre, liste…)
        return expression(seule.group(1), contexte)
    return MOTIF.sub(lambda m: str(expression(m.group(1), contexte)), valeur)


def expression(code: str, contexte: dict):
    code = code.replace("&&", " and ").replace("||", " or ")
    try:
        arbre = ast.parse(code, mode="eval").body
    except SyntaxError as e:
        raise ExpressionInterdite(f"syntaxe invalide : {code}") from e
    return _calculer(arbre, {**contexte, "SECRETS": _Secrets(), "FN": FONCTIONS})


def _calculer(n, ctx):
    c = lambda x: _calculer(x, ctx)
    match n:
        case ast.Constant():
            return n.value
        case ast.Name() if n.id in ("TRIGGER", "ACTIONS", "SECRETS", "FN"):
            return ctx[n.id]
        case ast.Attribute() if not n.attr.startswith("_"):
            objet = c(n.value)
            if isinstance(objet, _Secrets):
                return objet.get(n.attr)
            return objet.get(n.attr) if isinstance(objet, dict) else None   # champ absent -> None
        case ast.Subscript():
            objet, cle = c(n.value), c(n.slice)
            try:
                return objet[cle]
            except (KeyError, IndexError, TypeError):
                return None
        case ast.Call() if (isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
                            and n.func.value.id == "FN" and n.func.attr in FONCTIONS and not n.keywords):
            return FONCTIONS[n.func.attr](*map(c, n.args))
        case ast.Compare():
            gauche = c(n.left)
            for op, droite in zip(n.ops, map(c, n.comparators)):
                try:
                    if not OPERATEURS[type(op)](gauche, droite):
                        return False
                except TypeError:                 # ex. None > 3 : faux plutôt qu'une panne
                    return False
                gauche = droite
            return True
        case ast.BoolOp():
            valeurs = [c(v) for v in n.values]
            return all(valeurs) if isinstance(n.op, ast.And) else any(valeurs)
        case ast.UnaryOp(op=ast.Not()):
            return not c(n.operand)
        case ast.UnaryOp(op=ast.USub()):
            return -c(n.operand)
        case ast.BinOp() if type(n.op) in OPERATEURS:
            return OPERATEURS[type(n.op)](c(n.left), c(n.right))
        case ast.IfExp():
            return c(n.body) if c(n.test) else c(n.orelse)
        case ast.List() | ast.Tuple():
            return [c(x) for x in n.elts]
        case ast.Dict():
            return {c(k): c(v) for k, v in zip(n.keys, n.values)}
    raise ExpressionInterdite(f"interdit dans une expression : {ast.unparse(n)}")


# ---------------------------------------------------------------------------------------
# 3. Exécuter
# ---------------------------------------------------------------------------------------
@dataclass
class Execution:
    playbook: str
    statut: str = "en cours"          # en cours, terminée, en attente (d'une approbation)
    historique: dict = field(default_factory=dict)      # ref -> ce qui s'est passé
    sortie: dict | None = None


def executer(pb: Playbook, trigger: dict, deja_fait: dict | None = None,
             sur_etape=None, approuver=None) -> Execution:
    """Exécute un playbook pour une alerte (TRIGGER).

    deja_fait  : historique d'une exécution interrompue (exercice 4) : ces étapes ne sont PAS refaites.
    sur_etape  : appelée après chaque étape (exercice 4 : on l'enregistre sur disque).
    approuver  : (etape, args) -> True / False / None (= pas encore de réponse) (exercice 5).
    """
    ex = Execution(pb.titre, historique=dict(deja_fait or {}))
    for ref, e in pb.etapes.items():
        if ref in ex.historique and ex.historique[ref]["statut"] != "en attente":
            continue                                          # déjà fait avant la panne
        trace = {"ref": ref, "action": e.action, "heure": f"{env.HORLOGE:%H:%M:%S}", "entrees": None,
                 "result": None, "error": None, "essais": 0, "duree": 0.0}
        ctx = {"TRIGGER": trigger, "ACTIONS": {r: {"result": h["result"], "error": h["error"], "statut": h["statut"]}
                                                for r, h in ex.historique.items()}}
        bloquante = [d for d in e.depends_on if ex.historique.get(d, {}).get("statut") != "réussie"]
        try:
            if bloquante:
                trace.update(statut="ignorée", error=f"dépendance non réussie : {bloquante}")
            elif e.run_if and not evaluer(e.run_if, ctx):
                trace.update(statut="ignorée", error="condition run_if fausse")
            else:
                trace["entrees"] = evaluer(e.args, ctx)
                decision = approuver(e, trace["entrees"]) if (e.approbation and approuver) else True
                if decision is None:
                    trace["statut"] = "en attente"
                    ex.historique[ref] = trace
                    ex.statut = "en attente"
                    if sur_etape:
                        sur_etape(trace)
                    return ex
                if decision is False:
                    trace.update(statut="refusée", error="refusée par l'analyste")
                else:
                    r = registre.executer(e.action, trace["entrees"], essais=e.essais, delai_max=e.delai)
                    trace.update(statut="réussie", result=r["result"], essais=r["essais"], duree=r["duree"])
        except Exception as err:
            trace.update(statut="échec", error=f"{type(err).__name__} : {err}")
        ex.historique[ref] = trace
        if sur_etape:
            sur_etape(trace)
    ctx = {"TRIGGER": trigger, "ACTIONS": {r: {"result": h["result"], "error": h["error"], "statut": h["statut"]}
                                            for r, h in ex.historique.items()}}
    try:
        ex.sortie = evaluer(pb.sortie, ctx)
    except Exception as err:
        ex.sortie = {"erreur": f"{type(err).__name__} : {err}"}
    ex.statut = "terminée"
    return ex


def tableau(ex: Execution):
    """L'historique d'une exécution, en tableau (comme l'onglet « Runs » d'un SOAR)."""
    import pandas as pd
    return pd.DataFrame([{k: h[k] for k in ("ref", "action", "statut", "essais", "duree", "error")}
                         | {"result": str(h["result"])[:80]} for h in ex.historique.values()])
