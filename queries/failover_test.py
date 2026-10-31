"""
Test de basculement automatique (Failover) sur MongoDB Replica Set

Ce script simule une charge applicative continue d'écriture à haute fréquence :
- Lance 1 insertion toutes les 100 ms avec retryWrites=True
- Affiche l'horodatage précis de chaque succès et de chaque erreur
- Détecte l'arrêt du nœud primaire (ex: via 'docker stop <primary>')
- Mesure avec précision la durée d'indisponibilité jusqu'à l'élection d'un nouveau primaire
- Détecte et affiche la reprise des écritures et l'adresse du nouveau primaire

Utilisation :
    python queries/failover_test.py
    (Puis dans un autre terminal : docker stop <nom_du_container_mongo_primaire>)
"""

import argparse
import os
import signal
import socket
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pymongo
from pymongo import MongoClient
from pymongo.errors import PyMongoError, ServerSelectionTimeoutError, AutoReconnect

# Configuration de l'encodage console pour Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

DEFAULT_MONGO_URI = "mongodb://localhost:27017/?replicaSet=rs0&retryWrites=true"
DB_NAME = "siem"
COLLECTION_NAME = "failover_heartbeat"


def now_str() -> str:
    """Retourne l'horodatage actuel au format HH:MM:SS.mmm."""
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def main():
    parser = argparse.ArgumentParser(description="Test de Failover automatique sur MongoDB Replica Set")
    parser.add_argument("--uri", default=os.getenv("MONGO_URI", DEFAULT_MONGO_URI), help="URI de connexion MongoDB")
    parser.add_argument("--interval", type=float, default=0.1, help="Intervalle entre chaque écriture en secondes (défaut: 0.1s = 100ms)")
    parser.add_argument("--timeout", type=int, default=2000, help="serverSelectionTimeoutMS en ms (défaut: 2000)")
    parser.add_argument("--keep-data", action="store_true", help="Conserver les documents de test dans MongoDB")
    args = parser.parse_args()

    # S'assurer que retryWrites=True est activé dans l'URI ou options
    uri = args.uri
    if "retryWrites" not in uri:
        sep = "&" if "?" in uri else "?"
        uri = f"{uri}{sep}retryWrites=true"

    print("=" * 85)
    print("       TEST DE BASCULEMENT AUTOMATIQUE (FAILOVER) - SIEM MONGODB REPLICA SET       ")
    print("=" * 85)
    print(f" • URI de connexion           : {uri}")
    print(f" • Fréquence d'écriture       : 1 insertion toutes les {int(args.interval * 1000)} ms")
    print(f" • Server Selection Timeout   : {args.timeout} ms")
    print(f" • retryWrites activé         : OUI (retryWrites=True)")
    print(f" • Collection cible           : {DB_NAME}.{COLLECTION_NAME}")
    print("-" * 85)
    print("Instructions :")
    print(" 1. Laissez ce script tourner pour observer le flux normal d'écritures.")
    print(" 2. Dans un autre terminal, stoppez le primaire (ex: docker stop mongo1).")
    print(" 3. Observez l'heure d'apparition des erreurs, l'élection et l'heure de reprise.")
    print(" 4. Appuyez sur Ctrl+C à tout moment pour terminer et afficher le bilan complet.")
    print("=" * 85 + "\n")

    # Initialisation du client MongoDB
    try:
        client = MongoClient(
            uri,
            retryWrites=True,
            serverSelectionTimeoutMS=args.timeout,
            connectTimeoutMS=args.timeout,
            socketTimeoutMS=args.timeout
        )
        client.admin.command("ping")
    except Exception as e:
        # Tentative de repli standalone si l'URI replicaSet n'est pas joignable
        fallback_uri = uri.split("?")[0]
        print(f"[!] Avertissement : Impossible de joindre '{uri}' ({e}).")
        print(f"[*] Tentative de connexion de secours sur : {fallback_uri} ...")
        try:
            client = MongoClient(
                fallback_uri,
                retryWrites=True,
                serverSelectionTimeoutMS=args.timeout,
                connectTimeoutMS=args.timeout,
                socketTimeoutMS=args.timeout
            )
            client.admin.command("ping")
        except Exception as e2:
            print(f"[-] Erreur fatale : Impossible de se connecter à MongoDB : {e2}")
            sys.exit(1)

    db = client[DB_NAME]
    coll = db[COLLECTION_NAME]

    test_run_id = f"run_{uuid.uuid4().hex[:8]}"
    hostname = socket.gethostname()

    # Variables de suivi métrique
    total_attempts = 0
    total_success = 0
    total_failures = 0

    in_outage = False
    outage_start_time = 0.0
    outage_start_str = ""
    outage_fail_count = 0
    outage_events = []

    inserted_ids = []

    # Gestion propre de l'arrêt Ctrl+C
    def handle_exit(sig=None, frame=None):
        print("\n\n" + "=" * 85)
        print("                   BILAN FINAL DU TEST DE FAILOVER                    ")
        print("=" * 85)
        print(f" • Tentatives totales d'écriture : {total_attempts}")
        print(f" • Écritures réussies           : {total_success} ({(total_success / max(1, total_attempts) * 100):.1f}%)")
        print(f" • Écritures échouées           : {total_failures}")
        print(f" • Nombre de basculements (pannes) détectés : {len(outage_events)}")

        if outage_events:
            print("\n Détail des basculements mesurés :")
            for idx, ev in enumerate(outage_events, 1):
                print(f"   [{idx}] Début: {ev['start']} | Reprise: {ev['end']} | Durée: {ev['duration']:.3f} s | Échecs: {ev['failures']}")
            avg_downtime = sum(e["duration"] for e in outage_events) / len(outage_events)
            print(f"\n >>> Durée moyenne d'indisponibilité : {avg_downtime:.3f} secondes <<<")
        else:
            print("\n [i] Aucun basculement / interruption détecté pendant cette session.")

        if not args.keep_data and inserted_ids:
            try:
                del_res = coll.delete_many({"test_run": test_run_id})
                print(f"\n [i] Nettoyage : {del_res.deleted_count} documents de test purgés.")
            except Exception:
                pass

        print("=" * 85)
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_exit)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handle_exit)

    print(f"[*] Démarrage de la boucle d'écriture (Session ID : {test_run_id})...\n")

    seq = 0
    while True:
        seq += 1
        total_attempts += 1
        t_start = time.perf_counter()

        doc = {
            "seq": seq,
            "timestamp": datetime.now(timezone.utc),
            "test_run": test_run_id,
            "host": hostname,
            "message": f"Heartbeat failover #{seq}"
        }

        try:
            res = coll.insert_one(doc)
            latency_ms = (time.perf_counter() - t_start) * 1000.0
            total_success += 1
            inserted_ids.append(res.inserted_id)

            # Si on était en panne, on vient d'observer la REPRISE !
            if in_outage:
                t_recovery = time.time()
                downtime_sec = t_recovery - outage_start_time
                rec_str = now_str()
                primary_node = getattr(client, "primary", None) or client.address

                outage_events.append({
                    "start": outage_start_str,
                    "end": rec_str,
                    "duration": downtime_sec,
                    "failures": outage_fail_count,
                    "new_primary": str(primary_node)
                })

                print("\n" + "#" * 85)
                print(f"[{rec_str}] >>> REPRISE CONFIRMÉE : NOUVEAU PRIMAIRE OPÉRATIONNEL ! <<<")
                print("#" * 85)
                print(f"  • Début de la coupure     : {outage_start_str}")
                print(f"  • Heure de reprise        : {rec_str}")
                print(f"  • DURÉE D'INDISPONIBILITÉ : {downtime_sec:.3f} secondes")
                print(f"  • Requêtes bloquées/échec : {outage_fail_count}")
                print(f"  • Nouveau primaire actif  : {primary_node}")
                print("#" * 85 + "\n")

                in_outage = False
                outage_start_time = 0.0
                outage_fail_count = 0
            else:
                # Affichage régulier du flux normal
                if seq == 1 or seq % 10 == 0:
                    current_node = getattr(client, "primary", None) or client.address
                    print(f"[{now_str()}] [OK] Écriture #{seq:<5} réussie | Latence: {latency_ms:5.2f} ms | Nœud: {current_node}")

        except Exception as e:
            t_err = time.time()
            total_failures += 1
            err_str = now_str()
            err_type = type(e).__name__

            if not in_outage:
                # Début d'un nouvel épisode de basculement / panne
                in_outage = True
                outage_start_time = t_err
                outage_start_str = err_str
                outage_fail_count = 1

                print("\n" + "!" * 85)
                print(f"[{err_str}] [DÉBUT DE PANNE / ÉLECTION] Échec de l'écriture #{seq} !")
                print(f"  • Erreur initiale : {err_type} - {e}")
                print("  • Le cluster MongoDB est en cours d'élection de primaire...")
                print("!" * 85)
            else:
                outage_fail_count += 1
                # Affichage des erreurs intermédiaires
                print(f"[{err_str}] [EN PANNE #{outage_fail_count:<3}] Écriture #{seq} refusée ({err_type} : {str(e)[:60]}...)")

        time.sleep(args.interval)


if __name__ == "__main__":
    main()
