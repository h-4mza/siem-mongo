"""
Expérience de cohérence, durabilité et réplication (MongoDB Replica Set & Standalone)

Ce script évalue les compromis latence / cohérence / durabilité :
1. Écritures (T1 - insert d'une authentification) avec différents Write Concerns :
   - w: 1
   - w: "majority"
   - w: "majority" + j: True
   (200 insertions pour chaque configuration, mesure du temps moyen et du p95)

2. Lectures (T3 - profil utilisateur) avec différentes combinaisons de :
   - readConcern : "local" vs "majority"
   - readPreference : "primary" vs "secondaryPreferred"
   (200 lectures pour chaque configuration, mesure du temps moyen et du p95)

Les résultats sont sauvegardés dans results/consistency_experiments.csv.
"""

import csv
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from pymongo import MongoClient, ReadPreference
from pymongo.read_concern import ReadConcern
from pymongo.write_concern import WriteConcern

# Configuration de l'encodage console pour Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Répertoires et fichiers de sortie
BASE_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = BASE_DIR / "results"
CSV_FILE = RESULTS_DIR / "consistency_experiments.csv"

DEFAULT_MONGO_URI = "mongodb://mongo1:27018,mongo2:27019,mongo3:27020/?replicaSet=rs0"
DB_NAME = "siem"


def get_client_and_db():
    """
    Connecte le client MongoDB et détecte la topologie (Replica Set ou Standalone).
    Retourne (client, db, is_replica_set, topology_info).
    """
    uri = os.getenv("MONGO_URI", DEFAULT_MONGO_URI)
    is_replica_set = False
    topology_info = {}

    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=3000)
        client.admin.command("ping")
        # Vérification du statut de replica set
        try:
            rs_status = client.admin.command("replSetGetStatus")
            is_replica_set = True
            topology_info = {
                "set_name": rs_status.get("set"),
                "members": [m.get("name") for m in rs_status.get("members", [])],
                "primary": client.primary,
            }
        except Exception:
            # Connecté en standalone même si URI avait replicaSet (ou fallback)
            is_replica_set = False
            topology_info = {"address": client.address}
        return client, client[DB_NAME], is_replica_set, topology_info
    except Exception:
        # Fallback standalone sans paramètre replicaSet
        fallback_uri = uri.split("?")[0]
        client = MongoClient(fallback_uri, serverSelectionTimeoutMS=3000)
        client.admin.command("ping")
        return client, client[DB_NAME], False, {"address": client.address}


def compute_stats(latencies: list[float]) -> tuple[float, float]:
    """
    Calcule le temps moyen et le 95e percentile (p95) en millisecondes.
    """
    if not latencies:
        return 0.0, 0.0
    avg = sum(latencies) / len(latencies)
    try:
        import numpy as np
        p95 = float(np.percentile(latencies, 95))
    except ImportError:
        sorted_l = sorted(latencies)
        idx = min(int(len(sorted_l) * 0.95), len(sorted_l) - 1)
        p95 = sorted_l[idx]
    return round(avg, 2), round(p95, 2)


def run_t1_write_concern_experiments(db, iterations: int = 200) -> list[dict]:
    """
    Exécute l'expérience T1 (insertion unitaire) sous 3 niveaux de Write Concern :
    - w: 1
    - w: 'majority'
    - w: 'majority', j: True
    """
    print(f"\n[*] 1/2 Mesure des écritures T1 ({iterations} insertions par configuration)...")
    results = []

    configs = [
        {
            "config_name": "w:1",
            "wc": WriteConcern(w=1),
            "wc_label": "w:1",
            "j_label": "False",
            "desc": "Accusé dès réception mémoire/WAL du primaire (latence minimale)"
        },
        {
            "config_name": "w:majority",
            "wc": WriteConcern(w="majority"),
            "wc_label": "w:majority",
            "j_label": "False",
            "desc": "Consensus majorité (2/3 nœuds) : protège contre le rollback sur failover"
        },
        {
            "config_name": "w:majority+j:true",
            "wc": WriteConcern(w="majority", j=True),
            "wc_label": "w:majority",
            "j_label": "True",
            "desc": "Majorité + fsync journal sur disque : durabilité ACID absolue"
        }
    ]

    inserted_ids = []

    for cfg in configs:
        coll = db.get_collection("authentications", write_concern=cfg["wc"])
        latencies = []

        print(f"    -> Test en cours : {cfg['config_name']} ...", end="", flush=True)

        for i in range(iterations):
            auth_id = f"auth_ce_{cfg['config_name'].replace(':', '_').replace('+', '_')}_{i:04d}_{uuid.uuid4().hex[:6]}"
            doc = {
                "auth_id": auth_id,
                "timestamp": datetime.now(timezone.utc),
                "user_id": f"usr_{((i % 20) + 1):05d}",
                "host_id": "host_0001",
                "source_ip": "194.214.120.45",
                "result": "success",
                "method": "password",
                "geo": {
                    "country": "FR",
                    "city": "Paris",
                    "lat": 48.8566,
                    "lon": 2.3522
                },
                "user_department": "Finance"
            }

            t0 = time.perf_counter()
            res = coll.insert_one(doc)
            t1 = time.perf_counter()

            latencies.append((t1 - t0) * 1000.0)
            inserted_ids.append(res.inserted_id)

        avg_ms, p95_ms = compute_stats(latencies)
        print(f" Terminé | Moyenne = {avg_ms:6.2f} ms | P95 = {p95_ms:6.2f} ms")

        results.append({
            "operation": "T1",
            "type": "write_concern",
            "configuration": cfg["config_name"],
            "write_concern": cfg["wc_label"],
            "journal": cfg["j_label"],
            "read_concern": "N/A",
            "read_preference": "N/A",
            "iterations": iterations,
            "temps_moyen_ms": avg_ms,
            "p95_ms": p95_ms,
            "description": cfg["desc"]
        })

    # Nettoyage des documents de test insérés dans authentications
    if inserted_ids:
        del_res = db.authentications.delete_many({"_id": {"$in": inserted_ids}})
        print(f"    [i] Nettoyage : {del_res.deleted_count} documents de test supprimés.")

    return results


def run_t3_read_concern_experiments(db, iterations: int = 200) -> list[dict]:
    """
    Exécute l'expérience T3 (lecture profil utilisateur) sous 4 combinaisons :
    - readConcern: 'local' vs 'majority'
    - readPreference: 'primary' vs 'secondaryPreferred'
    """
    print(f"\n[*] 2/2 Mesure des lectures T3 ({iterations} lectures par configuration)...")
    results = []

    configs = [
        {
            "config_name": "rc:local + rp:primary",
            "rc": ReadConcern(level="local"),
            "rc_label": "local",
            "rp": ReadPreference.PRIMARY,
            "rp_label": "primary",
            "desc": "Lecture mémoire primaire directe : latence minimale, dirty read possible si rollback"
        },
        {
            "config_name": "rc:majority + rp:primary",
            "rc": ReadConcern(level="majority"),
            "rc_label": "majority",
            "rp": ReadPreference.PRIMARY,
            "rp_label": "primary",
            "desc": "Lecture primaire sur snapshot validé majorité : lecture cohérente sans dirty read"
        },
        {
            "config_name": "rc:local + rp:secondaryPreferred",
            "rc": ReadConcern(level="local"),
            "rc_label": "local",
            "rp": ReadPreference.SECONDARY_PREFERRED,
            "rp_label": "secondaryPreferred",
            "desc": "Lecture déportée sur réplica secondaire si dispo : décharge le primaire"
        },
        {
            "config_name": "rc:majority + rp:secondaryPreferred",
            "rc": ReadConcern(level="majority"),
            "rc_label": "majority",
            "rp": ReadPreference.SECONDARY_PREFERRED,
            "rp_label": "secondaryPreferred",
            "desc": "Lecture déportée sur secondaire avec consensus majorité garanti"
        }
    ]

    for cfg in configs:
        coll = db.get_collection("users", read_concern=cfg["rc"], read_preference=cfg["rp"])
        latencies = []

        print(f"    -> Test en cours : {cfg['config_name']:<32} ...", end="", flush=True)

        for i in range(iterations):
            user_id = f"usr_{((i % 200) + 1):05d}"

            t0 = time.perf_counter()
            _ = coll.find_one({"user_id": user_id})
            t1 = time.perf_counter()

            latencies.append((t1 - t0) * 1000.0)

        avg_ms, p95_ms = compute_stats(latencies)
        print(f" Terminé | Moyenne = {avg_ms:6.2f} ms | P95 = {p95_ms:6.2f} ms")

        results.append({
            "operation": "T3",
            "type": "read_concern_and_preference",
            "configuration": cfg["config_name"],
            "write_concern": "N/A",
            "journal": "N/A",
            "read_concern": cfg["rc_label"],
            "read_preference": cfg["rp_label"],
            "iterations": iterations,
            "temps_moyen_ms": avg_ms,
            "p95_ms": p95_ms,
            "description": cfg["desc"]
        })

    return results


def save_results_to_csv(all_results: list[dict]):
    """
    Sauvegarde l'ensemble des résultats dans results/consistency_experiments.csv.
    """
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "operation",
        "type",
        "configuration",
        "write_concern",
        "journal",
        "read_concern",
        "read_preference",
        "iterations",
        "temps_moyen_ms",
        "p95_ms",
        "description"
    ]

    with open(CSV_FILE, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_results)

    print(f"\n[+] Résultats enregistrés avec succès dans : {CSV_FILE}")


def display_summary_table(all_results: list[dict]):
    """
    Affiche un tableau récapitulatif stylisé dans la console.
    """
    print("\n" + "=" * 110)
    print(f"{'RÉSULTATS DE L EXPÉRIENCE DE COHÉRENCE ET DURABILITÉ (SIEM MONGODB)':^110}")
    print("=" * 110)
    print(f"{'Op':<4} | {'Configuration':<32} | {'WriteConcern':<14} | {'ReadConcern':<11} | {'ReadPref':<18} | {'Moy (ms)':<9} | {'P95 (ms)':<9}")
    print("-" * 110)

    for r in all_results:
        wc_text = r['write_concern']
        if r.get('journal') == "True":
            wc_text += " + j:true"
        print(f"{r['operation']:<4} | {r['configuration']:<32} | {wc_text:<14} | {r['read_concern']:<11} | {r['read_preference']:<18} | {r['temps_moyen_ms']:>8.2f}  | {r['p95_ms']:>8.2f} ")

    print("=" * 110)


def main():
    print("=" * 80)
    print("   SIEM MONGODB - BENCHMARK DE COHÉRENCE, DURABILITÉ & RÉPLICATION   ")
    print("=" * 80)

    client, db, is_rs, topo = get_client_and_db()

    if is_rs:
        print(f"[i] Topologie détectée : REPLICA SET '{topo.get('set_name')}'")
        print(f"    • Nœud primaire actuel : {topo.get('primary')}")
        print(f"    • Membres déclarés     : {', '.join(topo.get('members', []))}")
    else:
        print("[!] Topologie détectée : STANDALONE (ou replica set non accessible sur l'URI courante)")
        print(f"    • Adresse connectée    : {topo.get('address')}")
        print("    • Note : Les Write Concerns w:'majority' sont résolus localement par MongoDB en mode standalone.")

    # Exécution des expériences
    t1_results = run_t1_write_concern_experiments(db, iterations=200)
    t3_results = run_t3_read_concern_experiments(db, iterations=200)

    all_results = t1_results + t3_results

    # Enregistrement et affichage
    save_results_to_csv(all_results)
    display_summary_table(all_results)


if __name__ == "__main__":
    main()
