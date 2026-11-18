"""Vérifie que tout est prêt pour le mini-SOAR.   Lancer :  python verifier_installation.py

Faites une capture d'écran du résultat. S'il y a un ❌, envoyez-la à l'enseignant AVANT la séance.
"""
import importlib, json, os, shutil, sqlite3, sys, urllib.request
from pathlib import Path

ICI = Path(__file__).resolve().parent
MODELE = os.environ.get("SOAR_MODELE", "qwen2.5:3b")
resultats = []


def verifier(nom, fonction, conseil, bloquant=True):
    try:
        detail = fonction()
        resultats.append(("✅", nom, detail or ""))
    except Exception as e:
        resultats.append(("❌" if bloquant else "⚠️ ", nom, f"{e}\n      → {conseil}"))


def python():
    v = sys.version_info
    if v < (3, 10):
        raise RuntimeError(f"Python {v.major}.{v.minor} trouvé, il faut 3.10 ou plus")
    return f"Python {v.major}.{v.minor}.{v.micro} ({sys.executable})"


def venv():
    if sys.prefix == sys.base_prefix:
        raise RuntimeError("vous n'êtes pas dans l'environnement virtuel .venv")
    return sys.prefix


def paquets():
    manquants = []
    for p in ["fastapi", "uvicorn", "httpx", "pydantic", "yaml", "requests", "pandas",
              "matplotlib", "langchain_core", "langchain_ollama", "ipykernel"]:
        try:
            importlib.import_module(p)
        except ImportError:
            manquants.append(p)
    if manquants:
        raise RuntimeError(f"paquets manquants : {', '.join(manquants)}")
    import pydantic
    if int(pydantic.VERSION.split(".")[0]) < 2:
        raise RuntimeError(f"pydantic {pydantic.VERSION} : il faut la version 2")
    return "tous présents"


def sqlite():
    v = tuple(map(int, sqlite3.sqlite_version.split(".")))
    if v < (3, 35):
        raise RuntimeError(f"SQLite {sqlite3.sqlite_version} : il faut 3.35 ou plus (exercice 4)")
    return f"SQLite {sqlite3.sqlite_version}"


def dossier():
    manquants = [d for d in ("banc", "minisoar", "playbooks", "donnees/OpenSSH_2k.log") if not (ICI / d).exists()]
    if manquants:
        raise RuntimeError(f"introuvables : {', '.join(manquants)}")
    if Path.cwd().resolve() != ICI:
        raise RuntimeError(f"le terminal est dans {Path.cwd()}, pas dans le dossier SOAR")
    return str(ICI)


def banc():
    sys.path.insert(0, str(ICI))
    from banc import scenario
    from minisoar import moteur
    alertes = scenario.construire()
    moteur.charger("connexion-suspecte")
    shutil.rmtree(ICI / "environnement", ignore_errors=True)
    return f"{len(alertes)} alertes générées, playbooks lisibles"


def ollama():
    try:
        r = json.load(urllib.request.urlopen("http://localhost:11434/api/tags", timeout=3))
    except Exception:
        raise RuntimeError("Ollama ne répond pas sur localhost:11434")
    noms = [m["name"] for m in r.get("models", [])]
    if not any(n == MODELE or n.startswith(MODELE + ":") for n in noms):
        raise RuntimeError(f"modèle {MODELE} absent (modèles présents : {', '.join(noms) or 'aucun'})")
    return f"{MODELE} présent"


def memoire():
    if hasattr(os, "sysconf") and "SC_PHYS_PAGES" in os.sysconf_names:
        go = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 1e9
    elif sys.platform == "win32":
        import ctypes
        class M(ctypes.Structure):
            _fields_ = [("l", ctypes.c_ulong), ("c", ctypes.c_ulong), ("t", ctypes.c_ulonglong)] + \
                       [(f"x{i}", ctypes.c_ulonglong) for i in range(6)]
        m = M(); m.l = ctypes.sizeof(M)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
        go = m.t / 1e9
    else:
        return "inconnue"
    if go < 8:
        raise RuntimeError(f"{go:.0f} Go de RAM : Ollama risque d'être très lent")
    return f"{go:.0f} Go de RAM"


verifier("Python 3.10 ou plus", python, "installez Python depuis python.org (Windows : cochez « Add Python to PATH »)")
verifier("Environnement virtuel", venv, "activez-le : .venv\\Scripts\\activate (Windows) ou source .venv/bin/activate", bloquant=False)
verifier("Paquets Python", paquets, "dans le .venv activé : pip install -r requirements.txt")
verifier("SQLite", sqlite, "installez Python depuis python.org (il inclut un SQLite récent)")
verifier("Dossier SOAR", dossier, "ouvrez le DOSSIER SOAR dans VS Code et lancez la commande depuis son terminal")
verifier("Banc d'essai", banc, "vérifiez les lignes ❌ ci-dessus ; sinon envoyez la capture à l'enseignant")
verifier("Ollama (exercice 6)", ollama, f"installez Ollama (ollama.com), lancez-le, puis : ollama pull {MODELE}", bloquant=False)
verifier("Mémoire (exercice 6)", memoire, "vous ferez l'exercice 6 en équipe, sur la machine d'un coéquipier", bloquant=False)

print("\nMini-SOAR 8INF857 — vérification de l'installation\n")
for icone, nom, detail in resultats:
    print(f"{icone} {nom:<24} {detail}")
bloquants = [r for r in resultats if r[0] == "❌"]
tout_vert = all(r[0] == "✅" for r in resultats)
print("\n" + ("Tout est prêt, exercices 1 à 6." if tout_vert else
              "Tout est prêt pour les exercices 1 à 5." if not bloquants else
              f"{len(bloquants)} problème(s) à régler : envoyez cette capture à l'enseignant avant la séance."))
if not bloquants and any(r[0] != "✅" for r in resultats):
    print("Les lignes ⚠️ ne bloquent pas : seul l'exercice 6 en dépend (vous pourrez le faire en équipe).")
