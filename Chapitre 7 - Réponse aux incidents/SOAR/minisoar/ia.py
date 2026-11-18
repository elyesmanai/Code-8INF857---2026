"""Exercice 6 : l'IA comme une ÉTAPE du playbook.

Tracecat propose deux actions d'IA, qu'on reproduit en petit avec un modèle local (Ollama) :
  - ai.action : UN appel au modèle, avec une sortie JSON imposée par un schéma. Pas d'outils.
                Le playbook décide quoi faire de la réponse (et un humain l'approuve).
  - ai.agent  : une boucle où le modèle appelle des actions du registre, mais SEULEMENT
                celles de sa liste blanche, et au plus `max_appels` fois.
Le modèle ne touche jamais l'infrastructure directement : tout passe par le registre
(validation, garde-fous) et par le moteur (run_if, approbations).
"""
import functools, inspect, json, os

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import StructuredTool

from . import actions as registre
from .actions import action

MODELE = os.environ.get("SOAR_MODELE", "qwen2.5:3b")
LLM = None          # pour les tests : un faux modèle peut être mis ici


def modele(**options):
    if LLM is not None:
        return LLM
    from langchain_ollama import ChatOllama
    return ChatOllama(model=MODELE, temperature=0, num_ctx=8192, **options)


# ---------------------------------------------------------------------------------------
# ai.action : un appel, une sortie structurée
# ---------------------------------------------------------------------------------------
@action("ai.action")
def ai_action(consigne: str, donnees: dict, sortie: dict) -> dict:
    """Demande au modèle une réponse JSON conforme au schéma `sortie`, à partir de `donnees`."""
    llm = modele(format=sortie)                 # Ollama contraint la sortie au schéma JSON
    reponse = llm.invoke([SystemMessage(consigne),
                          HumanMessage(json.dumps(donnees, ensure_ascii=False, indent=1))])
    try:
        resultat = json.loads(reponse.content)
    except json.JSONDecodeError:
        raise ValueError(f"le modèle n'a pas renvoyé de JSON : {reponse.content[:200]}")
    manquants = [c for c in sortie.get("required", []) if c not in resultat]
    if manquants:
        raise ValueError(f"champs manquants dans la réponse du modèle : {manquants}")
    return resultat


# ---------------------------------------------------------------------------------------
# ai.agent : une boucle bornée, sur une liste blanche d'actions
# ---------------------------------------------------------------------------------------
def _outil(nom: str) -> StructuredTool:
    """Transforme une action du registre en outil pour le modèle (même signature, même description)."""
    a = registre.REGISTRE[nom]
    originale = inspect.unwrap(a.fonction)

    @functools.wraps(originale)
    def appeler(**args):
        return registre.executer(nom, args)["result"]

    return StructuredTool.from_function(func=appeler, name=nom.replace(".", "__"), description=a.description)


@action("ai.agent")
def ai_agent(consigne: str, demande: str, actions: list[str], max_appels: int = 8) -> dict:
    """Le modèle enquête avec les actions autorisées (liste blanche), puis répond en texte."""
    interdites = [n for n in actions if n not in registre.REGISTRE or n.startswith("ai.")]
    if interdites:
        raise PermissionError(f"actions non autorisées pour l'agent : {interdites}")
    outils = {o.name: o for o in map(_outil, actions)}
    llm = modele().bind_tools(list(outils.values()))
    messages, appels = [SystemMessage(consigne), HumanMessage(demande)], []
    while len(appels) < max_appels:
        r = llm.invoke(messages)
        messages.append(r)
        if not r.tool_calls:
            return {"reponse": r.content, "appels": appels}
        for appel in r.tool_calls:
            nom = appel["name"].replace("__", ".")
            try:
                resultat = outils[appel["name"]].invoke(appel["args"])
            except Exception as e:                     # refus, entrée invalide… renvoyés au modèle
                resultat = f"ERREUR : {type(e).__name__} : {e}"
            appels.append({"action": nom, "args": appel["args"], "resultat": str(resultat)[:300]})
            messages.append(ToolMessage(str(resultat)[:4000], tool_call_id=appel["id"]))
    return {"reponse": "Arrêt : nombre maximal d'appels atteint.", "appels": appels}
