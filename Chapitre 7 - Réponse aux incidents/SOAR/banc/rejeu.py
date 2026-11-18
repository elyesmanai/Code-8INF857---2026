"""Le banc d'essai : rejouer la matinée d'alertes dans le SOAR, puis noter ce qu'il a produit."""
import csv, json, re, time
from datetime import datetime
from pathlib import Path
from . import scenario as sc, environnement as env

RESULTATS = sc.RACINE / "resultats"
VERDICTS = ["incident", "attaque sans impact", "faux positif"]

# Ce qu'une vraie enquête trouve et qu'aucune alerte ne dit (5 points chacun).
# Les motifs sont précis exprès : « vérifier les crontabs » (un conseil générique) ne rapporte rien.
FAITS = {
    "début de l'attaque à 07:05": r"07:05",
    "script x.sh téléchargé": r"x\.sh",
    "clé SSH de l'attaquant ajoutée": r"ssh-rsa|AAAAB3|== attaquant",
    "crontab de l'attaquant ajoutée": r"\*/10|curl -s",
    "binaire /tmp/.x/kworkerds": r"/tmp/\.x",
    "reconnaissance (uname, whoami, /etc/passwd)": r"uname -a|cat /etc/passwd",
    "source de l'injection (198.51.100.23) signalée": r"198\.51\.100\.23",
}


def lire_verdict(texte):
    m = re.search(r"VERDICT\s*:?\s*\**\s*(incident|attaque sans impact|faux positif)", texte, re.I)
    return m.group(1).lower() if m else "?"


def rejouer(traiter, exercice, synthese=None):
    """Remet l'environnement à zéro, envoie chaque alerte à `traiter(alerte) -> texte`, puis note le tout.

    `synthese()` (facultatif, exercice 6) : renvoie le rapport final de l'incident après la dernière alerte.
    """
    alertes = sc.construire()
    lignes, debut = [], time.time()
    for a in alertes:
        env.a_l_heure(a)
        t0 = time.time()
        texte = traiter(a)
        lignes.append({"alerte": a, "texte": texte, "verdict": lire_verdict(texte), "secondes": time.time() - t0})
        ok = "✅" if lignes[-1]["verdict"] == sc.verdict_attendu(a) else "❌"
        print(f"{a['horodatage'][11:]} {a['id']} {a['regle']:<24} → {lignes[-1]['verdict']:<20} {ok}  ({lignes[-1]['secondes']:.0f} s)")
    final = synthese() if synthese else ""
    return _noter(exercice, lignes, final, time.time() - debut)


def _noter(exercice, lignes, final, duree):
    rapport = "\n\n".join(f"## {l['alerte']['id']} — {l['alerte']['description']}\n\n{l['texte']}" for l in lignes)
    if final:
        rapport = f"# Rapport final\n\n{final}\n\n# Détail par alerte\n\n{rapport}"
    tout = rapport

    bons = sum(l["verdict"] == sc.verdict_attendu(l["alerte"]) for l in lignes)
    verdicts = round(35 * bons / len(lignes))
    trouves = {f: bool(re.search(m, tout, re.I)) for f, m in FAITS.items()}
    faits = 5 * sum(trouves.values())

    bloquees, comptes = env.ips_bloquees(), env.comptes()
    cles = env.lire("home/webadmin/.ssh/authorized_keys") or ""
    cron = env.lire("var/spool/cron/webadmin") or ""
    actions = {
        "IP de l'attaquant bloquée": sc.ATTAQUANT in bloquees,
        "compte webadmin désactivé": not comptes["webadmin"]["actif"],
        "clé SSH de l'attaquant retirée": sc.CLE_ATTAQUANT not in cles,
        "crontab de l'attaquant retirée": sc.CRON_ATTAQUANT not in cron,
        "mineur arrêté": all(p["pid"] != 31337 for p in env.processus()),
    }
    reponse = 6 * sum(actions.values())

    connues = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                             " ".join(p.read_text() for p in (sc.ENV / "journaux").iterdir()) + sc.ENV.joinpath("alertes.jsonl").read_text()))
    inventees = sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", tout)) - connues)
    degats = {
        "poste de l'admin (10.0.0.5) bloqué": sc.ADMIN_IP in bloquees,
        "compte de l'admin (jtremblay) désactivé": not comptes[sc.ADMIN]["actif"],
        "clé SSH légitime retirée": sc.CLE_LEGITIME not in cles,
        "sauvegarde système retirée": "sauvegarde" not in (env.lire("etc/crontab") or ""),
    }
    penalite = 10 * sum(degats.values()) + min(20, 5 * len(inventees))
    total = max(0, verdicts + faits + reponse - penalite)

    RESULTATS.mkdir(exist_ok=True)
    (RESULTATS / f"rapport - {exercice}.md").write_text(rapport)
    nouveau = not (RESULTATS / "scores.csv").exists()
    with open(RESULTATS / "scores.csv", "a", newline="") as f:
        w = csv.writer(f)
        if nouveau:
            w.writerow(["exercice", "modele", "verdicts/35", "faits/35", "reponse/30", "penalites", "total/100", "duree_s"])
        MODELE = __import__("os").environ.get("SOAR_MODELE", "-")
        w.writerow([exercice, MODELE, verdicts, faits, reponse, -penalite, total, round(duree)])

    print(f"\nScore : {total}/100   (verdicts {verdicts}/35 · faits {faits}/35 · réponse {reponse}/30 · pénalités −{penalite})")
    for nom, d in [("Faits trouvés", trouves), ("Actions", actions)]:
        print(f"{nom} : " + " · ".join(("✅ " if v else "❌ ") + k for k, v in d.items()))
    if any(degats.values()) or inventees:
        print("Dégâts : " + " · ".join(k for k, v in degats.items() if v) + (f" · IP inventées : {inventees}" if inventees else ""))
    print(f"Rapport complet : resultats/rapport - {exercice}.md   ({duree / 60:.1f} min)")
    return {"total": total, "verdicts": verdicts, "faits": faits, "reponse": reponse, "penalite": penalite}


def progression():
    """Le score de chaque exercice (dernière exécution de chacun)."""
    import pandas as pd
    d = pd.read_csv(RESULTATS / "scores.csv").groupby("exercice").last()
    ax = d[["verdicts/35", "faits/35", "reponse/30"]].plot.bar(stacked=True, figsize=(8, 3.5), rot=0,
                                                               color=["#4C78A8", "#72B7B2", "#F58518"])
    ax.set_ylim(0, 100); ax.set_ylabel("points"); ax.set_xlabel("")
    ax.set_title("Score du SOAR sur la même matinée d'alertes")
    for i, t in enumerate(d["total/100"]):
        ax.text(i, 101, str(t), ha="center", va="bottom")
    return d
