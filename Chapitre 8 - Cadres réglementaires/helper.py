"""Petits outils pour le Ch. 8 (8INF857) : lire les données de NordHébergement et déposer les pièces pour l'auditeur."""
import re
from pathlib import Path

import pandas as pd

ICI = Path(__file__).resolve().parent
DONNEES = ICI / "donnees"
LIVRABLES = ICI / "livrables"


def lire_csv(nom):
    """Lit un CSV du dossier donnees/ (ex. lire_csv('cmdb_inventaire.csv'))."""
    return pd.read_csv(DONNEES / nom, dtype=str, keep_default_na=False)


def lire_texte(nom):
    """Lit un fichier texte du dossier donnees/ (ex. lire_texte('lettre_audit.md'))."""
    return (DONNEES / nom).read_text(encoding="utf-8")


def lire_serveur(serveur, chemin):
    """Lit un fichier extrait d'un serveur (ex. lire_serveur('bd01', 'etc/ssh/sshd_config')). Chaîne vide s'il n'existe pas."""
    p = DONNEES / "serveurs" / serveur / chemin
    return p.read_text(encoding="utf-8") if p.exists() else ""


def directive(texte, cle):
    """Valeur ACTIVE d'une directive de configuration, et la ligne qui la prouve.

    Les lignes commentées (#) sont ignorées ; si la directive apparaît plusieurs fois, la dernière l'emporte.
    Retourne (valeur, ligne) ou (None, None) si la directive est absente (le logiciel prend alors sa valeur par défaut).
    """
    valeur, preuve = None, None
    for ligne in texte.splitlines():
        m = re.match(rf"^\s*{cle}\s*=?\s*(\S+)", ligne, re.I)
        if m:
            valeur, preuve = m.group(1), ligne.strip()
    return valeur, preuve


def deposer(nom, contenu):
    """Dépose une pièce dans livrables/ (un DataFrame devient un CSV, un texte reste un texte). Retourne le chemin."""
    LIVRABLES.mkdir(exist_ok=True)
    chemin = LIVRABLES / nom
    if isinstance(contenu, pd.DataFrame):
        contenu.to_csv(chemin, index=False, encoding="utf-8")
    else:
        chemin.write_text(contenu, encoding="utf-8")
    print(f"Pièce déposée : livrables/{nom}")
    return chemin


def afficher_md(texte):
    """Affiche du Markdown joliment dans le notebook."""
    from IPython.display import Markdown, display
    display(Markdown(texte))
