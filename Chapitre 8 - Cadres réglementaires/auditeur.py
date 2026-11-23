"""L'auditeur automatique du Cabinet Boréal Audit.

Il relit les pièces déposées dans livrables/ et répond demande par demande :
✅ acceptée, ⚠️ incomplète (avec les raisons), ❌ refusée ou manquante. Puis il donne un score sur 100.

Vous n'avez pas à modifier ce fichier. Vous pouvez le lire : un vrai auditeur aussi publie ses critères.
Lancer :  import auditeur; auditeur.auditer()
"""
import csv, re
from datetime import date, datetime, timedelta
from pathlib import Path

ICI = Path(__file__).resolve().parent
DONNEES = ICI / "donnees"
LIVRABLES = ICI / "livrables"
DATE_EXTRACTION = date(2026, 11, 26)      # date à laquelle les fichiers des serveurs ont été extraits
BUDGET = 50000
APPETIT_RISQUE = 8                         # politique : risque résiduel accepté si probabilité × impact <= 8

DEMANDES = [  # id, titre, fichier, points, critique
    ("D-01", "Textes applicables et justification", "applicabilite.csv", 10, False),
    ("D-02", "Inventaire des actifs rapproché du réseau", "inventaire.csv", 15, True),
    ("D-03", "Configuration sécurisée des serveurs", "controles.csv", 15, False),
    ("D-04", "Sauvegardes et test de restauration", "controles.csv", 10, True),
    ("D-05", "Revue des droits d'accès", "revue_acces.csv", 15, True),
    ("D-06", "Registre et plan de traitement des risques", "registre_risques.csv", 15, False),
    ("D-07", "Registre des incidents et notifications", "registre_incidents.csv", 15, True),
    ("D-08", "Lettre de réponse à l'auditeur", "reponse_auditeur.md", 5, False),
]


# ============================================================================ outils
def _csv(chemin):
    with open(chemin, newline="", encoding="utf-8") as f:
        return [{(k or "").strip(): (v or "").strip() for k, v in ligne.items()} for ligne in csv.DictReader(f)]


def _norm(x):
    x = str(x).strip().lower()
    for a, b in [("é", "e"), ("è", "e"), ("ê", "e"), ("à", "a"), ("ô", "o"), ("î", "i"), ("ç", "c")]:
        x = x.replace(a, b)
    return re.sub(r"\s+", " ", x)


def _lire(serveur, chemin):
    p = DONNEES / "serveurs" / serveur / chemin
    return p.read_text(encoding="utf-8") if p.exists() else ""


def _directive(texte, cle):
    """Dernière valeur active (non commentée) d'une directive « Cle valeur » ou « cle = valeur »."""
    val = None
    for ligne in texte.splitlines():
        m = re.match(rf"^\s*{cle}\s*=?\s*(\S+)", ligne, re.I)
        if m:
            val = m.group(1)
    return val


# ============================================================================ la vérité (calculée sur les données)
def _verite_applicabilite():
    return {  # texte : (type, applicable)
        "loi 25": ("loi", "oui"), "rgpd": ("loi", "oui"), "nis2": ("loi", "non"),
        "hipaa": ("loi", "non"), "ccpa": ("loi", "non"), "iso 27001": ("norme", "oui"),
        "nist csf 2.0": ("cadre", "volontaire"), "cis controls v8": ("cadre", "volontaire"),
        "mitre att&ck": ("standard", "volontaire"),
    }


def _scan():
    hotes = {}
    for ligne in (DONNEES / "scan_2026-11-23.gnmap").read_text(encoding="utf-8").splitlines():
        m = re.match(r"Host: (\S+) \((.*?)\)\tPorts: (.*?)\t", ligne)
        if m:
            hotes[m.group(1)] = [p.split("/")[0] for p in m.group(3).split(", ")]
    return hotes


def _verite_inventaire():
    cmdb = {l["ip"] for l in _csv(DONNEES / "cmdb_inventaire.csv")}
    scan = set(_scan())
    v = {}
    for ip in cmdb | scan:
        if ip in cmdb and ip in scan:
            v[ip] = ("cmdb+scan", "conforme")
        elif ip in scan:
            v[ip] = ("scan", "non inventorie")
        else:
            v[ip] = ("cmdb", "introuvable")
    return v


def _verite_controles():
    v = {}
    for s in ["web01", "bd01"]:
        sshd = _lire(s, "etc/ssh/sshd_config")
        v[(s, "ssh_root")] = _directive(sshd, "PermitRootLogin") == "no"
        v[(s, "ssh_mot_de_passe")] = _directive(sshd, "PasswordAuthentication") == "no"
        minlen = _directive(_lire(s, "etc/security/pwquality.conf"), "minlen")
        v[(s, "mot_de_passe_14")] = minlen is not None and int(minlen) >= 14
        v[(s, "pare_feu")] = _lire(s, "ufw_status.txt").startswith("Status: active")
        lr = _lire(s, "etc/logrotate.d/rsyslog")
        jours = {"daily": 1, "weekly": 7, "monthly": 30}[re.search(r"\b(daily|weekly|monthly)\b", lr).group(1)]
        v[(s, "journaux_90_jours")] = jours * int(re.search(r"rotate (\d+)", lr).group(1)) >= 90
        sauv = _lire(s, "var/log/sauvegarde.log").splitlines()
        oks = [date.fromisoformat(l[:10]) for l in sauv if "STATUT=OK" in l]
        tests = [date.fromisoformat(l[:10]) for l in sauv if "TEST_RESTAURATION=OK" in l]
        v[(s, "sauvegarde_24h")] = bool(oks) and (DATE_EXTRACTION - max(oks)).days <= 1
        v[(s, "test_restauration_12_mois")] = bool(tests) and (DATE_EXTRACTION - max(tests)).days <= 365
    return v


CONTROLES_D03 = ["ssh_root", "ssh_mot_de_passe", "mot_de_passe_14", "pare_feu", "journaux_90_jours"]
CONTROLES_D04 = ["sauvegarde_24h", "test_restauration_12_mois"]


def _verite_acces():
    rh = {l["identifiant"]: l for l in _csv(DONNEES / "rh_employes.csv")}
    v = set()
    for c in _csv(DONNEES / "comptes_m365.csv"):
        login = c["utilisateur"].split("@")[0]
        if c["compte_actif"] != "oui":
            continue
        e = rh.get(login)
        if e is None:
            v.add((login, "m365", "sans_proprietaire"))
        elif e["statut"] == "parti":
            v.add((login, "m365", "parti_actif"))
        else:
            if c["roles_admin"] and e["service"] != "TI":
                v.add((login, "m365", "admin_injustifie"))
            if c["mfa"] != "oui":
                v.add((login, "m365", "sans_mfa"))
    for s in ["web01", "bd01"]:
        sudo = re.search(r"^sudo:x:\d+:(.*)$", _lire(s, "etc/group"), re.M).group(1).split(",")
        for ligne in _lire(s, "etc/passwd").splitlines():
            login, _, uid = ligne.split(":")[:3]
            if int(uid) < 1000:
                continue
            e = rh.get(login)
            if e is None:
                v.add((login, s, "sans_proprietaire"))
            elif e["statut"] == "parti":
                v.add((login, s, "parti_actif"))
            elif login in sudo and e["service"] != "TI":
                v.add((login, s, "admin_injustifie"))
    return v


def _verite_incidents():
    v = {}
    for t in _csv(DONNEES / "tickets_incidents_2026.csv"):
        conf = t["renseignements_personnels"] == "oui" and t["nature"] in ("accès", "communication", "perte")
        prej = conf and t["donnees_chiffrees"] != "oui" and (t["sensibilite"] == "élevée" or t["utilisation_malveillante"] == "probable")
        cai = prej and int(t["personnes_quebec"]) > 0
        cnil = conf and int(t["personnes_france"]) > 0 and t["utilisation_malveillante"] != "improbable"
        ech = (datetime.fromisoformat(t["detecte_le"]) + timedelta(hours=72)).strftime("%Y-%m-%dT%H:%M") if cnil else ""
        v[t["ticket"]] = {"incident_confidentialite": conf, "prejudice_serieux": prej,
                          "aviser_cai": cai, "aviser_cnil": cnil, "echeance_cnil": ech}
    return v


def _oui(x):
    return _norm(x) in ("oui", "true", "vrai", "1", "yes")


# ============================================================================ les vérifications, une par demande
def _d01(lignes):
    verite, raisons, ok = _verite_applicabilite(), [], 0
    recu = {_norm(l.get("texte", "")): l for l in lignes}
    for texte, (typ, app) in verite.items():
        l = recu.get(texte)
        if l is None:
            raisons.append(f"{texte} : absent"); continue
        bon = 0
        if _norm(l.get("type", "")) == typ: bon += 1
        else: raisons.append(f"{texte} : type « {l.get('type')} » incorrect")
        if _norm(l.get("applicable", "")) == app: bon += 1
        else: raisons.append(f"{texte} : applicabilité « {l.get('applicable')} » incorrecte")
        if len(l.get("justification", "")) >= 15: bon += 1
        else: raisons.append(f"{texte} : justification manquante ou trop courte")
        ok += bon / 3
    return ok / len(verite), raisons


def _d02(lignes):
    verite, raisons, ok = _verite_inventaire(), [], 0
    recu = {l.get("ip", ""): l for l in lignes}
    for ip, (source, statut) in sorted(verite.items()):
        l = recu.get(ip)
        if l is None:
            raisons.append(f"{ip} : absent de l'inventaire"); continue
        bon = 0
        if _norm(l.get("source", "")) == source: bon += 1
        else: raisons.append(f"{ip} : source « {l.get('source')} » incorrecte")
        if _norm(l.get("statut", "")) == statut: bon += 1
        else: raisons.append(f"{ip} : statut « {l.get('statut')} » incorrect")
        if l.get("proprietaire", ""): bon += 1
        else: raisons.append(f"{ip} : aucun propriétaire")
        ok += bon / 3
    return ok / len(verite), raisons


def _controles(lignes, noms):
    verite, raisons, ok = _verite_controles(), [], 0
    recu = {(l.get("serveur", ""), l.get("controle", "")): l for l in lignes}
    cles = [(s, c) for (s, c) in verite if c in noms]
    for s, c in cles:
        l = recu.get((s, c))
        if l is None:
            raisons.append(f"{s} / {c} : absent"); continue
        attendu = "conforme" if verite[(s, c)] else "non conforme"
        bon = 0
        if _norm(l.get("resultat", "")) == attendu: bon += 1
        else: raisons.append(f"{s} / {c} : résultat « {l.get('resultat')} » incorrect")
        if len(l.get("preuve", "")) >= 5: bon += 1
        else: raisons.append(f"{s} / {c} : aucune preuve (« c'est fait » ne suffit pas)")
        if attendu == "non conforme":   # une non-conformité est acceptable SI elle vient avec un plan d'action
            if len(l.get("action", "")) >= 5: bon += 1
            else: raisons.append(f"{s} / {c} : non-conformité sans action corrective")
            ok += bon / 3
        else:
            ok += bon / 2
    return ok / len(cles), raisons


def _d05(lignes):
    verite, raisons = _verite_acces(), []
    recu = {(l.get("compte", ""), _norm(l.get("systeme", "")), _norm(l.get("anomalie", ""))): l for l in lignes}
    vp = [k for k in verite if k in recu]
    fp = [k for k in recu if k not in verite]
    for k in sorted(verite - set(vp)):
        raisons.append(f"anomalie non trouvée : {k[0]} sur {k[1]} ({k[2]})")
    for k in fp:
        raisons.append(f"fausse anomalie : {k[0]} sur {k[1]} ({k[2]})")
    sans_action = [k for k in vp if len(recu[k].get("action", "")) < 5]
    for k in sans_action:
        raisons.append(f"{k[0]} sur {k[1]} : aucune action corrective")
    score = max(0, len(vp) - len(fp) - 0.5 * len(sans_action)) / len(verite)
    return score, raisons


def _d06(lignes):
    risques = {l["id"]: l for l in _csv(DONNEES / "risques.csv")}
    mesures = _csv(DONNEES / "mesures.csv")
    raisons, ok, total = [], 0, 0
    recu = {l.get("risque", ""): l for l in lignes}
    for rid, r in risques.items():
        l = recu.get(rid)
        if l is None:
            raisons.append(f"{rid} : absent du registre"); continue
        bon = 0
        p_i = int(r["probabilite"]) * int(r["impact"])
        if l.get("score_initial", "") == str(p_i): bon += 1
        else: raisons.append(f"{rid} : score initial « {l.get('score_initial')} » faux (probabilité × impact)")
        m = next((m for m in mesures if m["risque"] == rid and m["mesure"] == l.get("mesure", "")), None)
        if m is None:
            raisons.append(f"{rid} : mesure inconnue (prenez-la telle quelle dans mesures.csv)")
        else:
            total += int(m["cout"])
            residuel = int(m["probabilite_apres"]) * int(m["impact_apres"])
            if l.get("score_residuel", "") == str(residuel): bon += 1
            else: raisons.append(f"{rid} : score résiduel « {l.get('score_residuel')} » faux")
            if residuel <= APPETIT_RISQUE: bon += 1
            else: raisons.append(f"{rid} : risque résiduel {residuel} au-dessus de l'appétit pour le risque ({APPETIT_RISQUE})")
        ok += bon / 3
    score = ok / len(risques)
    if total > BUDGET:
        raisons.append(f"plan à {total:,} $ : dépasse le budget approuvé de {BUDGET:,} $".replace(",", " "))
        score *= 0.5
    return score, raisons


def _d07(lignes):
    verite, raisons, ok = _verite_incidents(), [], 0
    recu = {l.get("ticket", ""): l for l in lignes}
    for t, v in verite.items():
        l = recu.get(t)
        if l is None:
            raisons.append(f"{t} : absent du registre"); continue
        bon = 0
        for champ in ["incident_confidentialite", "prejudice_serieux", "aviser_cai", "aviser_cnil"]:
            if _oui(l.get(champ, "")) == v[champ]: bon += 1
            else: raisons.append(f"{t} : « {champ} » incorrect")
        if l.get("echeance_cnil", "")[:16] == v["echeance_cnil"]: bon += 1
        else: raisons.append(f"{t} : échéance CNIL « {l.get('echeance_cnil')} » incorrecte (attendu : « {v['echeance_cnil'] or 'vide'} »)")
        ok += bon / 5
    return ok / len(verite), raisons


def _d08(texte):
    raisons = [f"section {d} absente ou vide" for d, *_ in DEMANDES[:7]
               if not re.search(rf"##\s*{d}.*?\n\s*\S.{{20,}}", texte, re.S)]
    return (7 - len(raisons)) / 7, raisons


# ============================================================================ l'audit
def auditer(verbeux=True):
    """Relit livrables/, affiche le résultat de chaque demande, le score et le verdict. Retourne le score."""
    resultats = []
    for did, titre, fichier, points, critique in DEMANDES:
        chemin = LIVRABLES / fichier
        if not chemin.exists():
            frac, raisons = 0.0, [f"fichier {fichier} introuvable dans livrables/"]
        else:
            try:
                if did == "D-08":
                    frac, raisons = _d08(chemin.read_text(encoding="utf-8"))
                else:
                    lignes = _csv(chemin)
                    frac, raisons = {"D-01": _d01, "D-02": _d02, "D-05": _d05, "D-06": _d06, "D-07": _d07,
                                     "D-03": lambda l: _controles(l, CONTROLES_D03),
                                     "D-04": lambda l: _controles(l, CONTROLES_D04)}[did](lignes)
            except Exception as e:  # fichier mal formé
                frac, raisons = 0.0, [f"fichier illisible : {type(e).__name__} {e}"]
        statut = "✅" if frac >= 0.999 else ("⚠️" if frac >= 0.5 else "❌")
        resultats.append((did, titre, points, critique, frac, statut, raisons))

    score = round(sum(p * f for _, _, p, _, f, _, _ in resultats))
    critiques_refusees = [d for d, _, _, c, _, s, _ in resultats if c and s == "❌"]
    certifiable = score >= 80 and not critiques_refusees

    if verbeux:
        print("Cabinet Boréal Audit — revue des pièces déposées\n")
        for did, titre, points, critique, frac, statut, raisons in resultats:
            print(f"{statut} {did} {titre:<42} {points * frac:5.1f} / {points}{'  (critique)' if critique else ''}")
            for r in raisons[:4]:
                print(f"      · {r}")
            if len(raisons) > 4:
                print(f"      · … et {len(raisons) - 4} autre(s) remarque(s)")
        print(f"\nSCORE : {score} / 100")
        if certifiable:
            print("VERDICT : ✅ recommandé pour la certification ISO/IEC 27001.")
        else:
            pourquoi = [f"score sous 80"] if score < 80 else []
            pourquoi += [f"demande(s) critique(s) refusée(s) : {', '.join(critiques_refusees)}"] if critiques_refusees else []
            print(f"VERDICT : ❌ certification reportée ({' ; '.join(pourquoi)}).")

    _rapport(resultats, score, certifiable)
    return score


def _rapport(resultats, score, certifiable):
    LIVRABLES.mkdir(exist_ok=True)
    lignes = [f"# Rapport de l'auditeur — {datetime.now():%Y-%m-%d %H:%M}", "",
              f"**Score : {score} / 100** — " + ("recommandé pour la certification" if certifiable else "certification reportée"), "",
              "| Demande | Statut | Points | Remarques |", "|---|---|---|---|"]
    for did, titre, points, critique, frac, statut, raisons in resultats:
        lignes.append(f"| {did} {titre}{' (critique)' if critique else ''} | {statut} | {points * frac:.1f} / {points} | "
                      f"{'<br>'.join(raisons) if raisons else '—'} |")
    (LIVRABLES / "rapport_auditeur.md").write_text("\n".join(lignes) + "\n", encoding="utf-8")
    hist = LIVRABLES / "scores.csv"
    neuf = not hist.exists()
    with open(hist, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if neuf:
            w.writerow(["horodatage", "score"] + [r[0] for r in resultats])
        w.writerow([datetime.now().isoformat(timespec="seconds"), score] + [round(r[2] * r[4], 1) for r in resultats])


def progression():
    """Graphique de l'évolution du score au fil de vos dépôts."""
    import pandas as pd, matplotlib.pyplot as plt
    h = pd.read_csv(LIVRABLES / "scores.csv")
    ax = h["score"].plot(marker="o", figsize=(8, 3))
    ax.axhline(80, color="green", ls="--", label="seuil de certification (80)")
    ax.set_ylim(0, 100); ax.set_ylabel("score / 100"); ax.set_xlabel("dépôt n°"); ax.legend()
    plt.title("Progression vers la certification"); plt.show()


if __name__ == "__main__":
    auditer()
