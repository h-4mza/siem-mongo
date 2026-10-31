"""
Script de chargement des données SIEM dans MongoDB.

Ce script :
  1. Lit les fichiers JSON Lines (.jsonl) générés dans data_generator/output/
  2. Convertit les dates formatées en chaînes ISO 8601 en objets datetime BSON
  3. Insère les documents par lots de 5 000 (insert_many) pour une performance optimale
  4. Mesure et affiche les temps de chargement par collection et au total
  5. Effectue un comptage de validation (count_documents) à la fin
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from pymongo import MongoClient

# Configuration de l'encodage console pour Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ==============================================================================
# CONFIGURATION & CONNEXION
# ==============================================================================
DEFAULT_MONGO_URI = "mongodb://localhost:27017/?replicaSet=rs0"
DB_NAME = "siem"
BATCH_SIZE = 5000

INPUT_DIR = Path(__file__).resolve().parent.parent / "data_generator" / "output"

def get_mongo_client():
    """Établit la connexion MongoDB avec gestion du repli standalone local si besoin."""
    uri = os.getenv("MONGO_URI", DEFAULT_MONGO_URI)
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=3000)
        client.admin.command("ping")
        return client
    except Exception as e:
        if "replicaSet" in uri and "MONGO_URI" not in os.environ:
            fallback_uri = uri.split("?")[0]
            try:
                client = MongoClient(fallback_uri, serverSelectionTimeoutMS=3000)
                client.admin.command("ping")
                return client
            except Exception as e2:
                raise e2
        raise e

def parse_iso(dt_str: str) -> datetime:
    """Convertit une chaîne ISO 8601 (ex: 2026-10-15T21:26:42Z) en objet datetime UTC."""
    if not dt_str:
        return None
    cleaned = dt_str.replace("Z", "+00:00")
    return datetime.fromisoformat(cleaned)

# ==============================================================================
# TRANSFORMATIONS SPÉCIFIQUES PAR COLLECTION
# ==============================================================================
def transform_doc(collection_name: str, doc: dict) -> dict:
    """Applique les conversions de types requises (datetime, types numériques, _id)."""
    if collection_name == "users":
        doc["failed_login_count"] = int(doc.get("failed_login_count", 0))

    elif collection_name == "hosts":
        pass  # Schéma déjà conforme

    elif collection_name == "authentications":
        doc["timestamp"] = parse_iso(doc["timestamp"])
        if "geo" in doc:
            doc["geo"]["lat"] = float(doc["geo"]["lat"])
            doc["geo"]["lon"] = float(doc["geo"]["lon"])

    elif collection_name == "network_flows":
        doc["timestamp"] = parse_iso(doc["timestamp"])
        doc["dst_port"] = int(doc["dst_port"])
        doc["bytes"] = int(doc["bytes"])

    elif collection_name == "alerts":
        doc["created_at"] = parse_iso(doc["created_at"])
        if doc.get("resolved_at"):
            doc["resolved_at"] = parse_iso(doc["resolved_at"])
        else:
            doc["resolved_at"] = None

    elif collection_name == "ip_blacklist":
        # Choix de conception : _id = ip
        doc["_id"] = doc["ip"]
        doc["created_at"] = parse_iso(doc["created_at"])
        doc["expires_at"] = parse_iso(doc["expires_at"])

    return doc

# ==============================================================================
# CHARGEMENT D'UNE COLLECTION PAR LOTS DE 5000
# ==============================================================================
def load_collection(db, collection_name: str, filepath: Path) -> tuple[int, float]:
    """Charge un fichier .jsonl dans la collection MongoDB par lots de 5 000 documents."""
    if not filepath.exists():
        print(f"[-] Fichier introuvable : {filepath}")
        return 0, 0.0

    coll = db[collection_name]
    start_time = time.time()
    batch = []
    total_inserted = 0

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if not line_str:
                continue
            doc = json.loads(line_str)
            doc = transform_doc(collection_name, doc)
            batch.append(doc)

            if len(batch) >= BATCH_SIZE:
                coll.insert_many(batch, ordered=False)
                total_inserted += len(batch)
                batch.clear()

        # Dernier lot restant
        if batch:
            coll.insert_many(batch, ordered=False)
            total_inserted += len(batch)
            batch.clear()

    elapsed = time.time() - start_time
    return total_inserted, elapsed

# ==============================================================================
# POINT D'ENTRÉE DU CHARGEMENT
# ==============================================================================
def main():
    print("======================================================================")
    print("          CHARGEMENT DES DONNÉES SIEM DANS MONGODB (LOTS DE 5000)     ")
    print("======================================================================")
    
    client = get_mongo_client()
    db = client[DB_NAME]
    total_start = time.time()

    collections_to_load = [
        ("users", INPUT_DIR / "users.jsonl"),
        ("hosts", INPUT_DIR / "hosts.jsonl"),
        ("ip_blacklist", INPUT_DIR / "ip_blacklist.jsonl"),
        ("authentications", INPUT_DIR / "authentications.jsonl"),
        ("network_flows", INPUT_DIR / "network_flows.jsonl"),
        ("alerts", INPUT_DIR / "alerts.jsonl"),
    ]

    loading_summary = []

    for coll_name, filepath in collections_to_load:
        print(f"[*] Chargement de '{coll_name}' depuis {filepath.name}...")
        nb_inserted, duration = load_collection(db, coll_name, filepath)
        actual_count = db[coll_name].count_documents({})
        speed = nb_inserted / duration if duration > 0 else 0
        print(f"    -> {nb_inserted} insérés en {duration:.2f}s ({speed:,.0f} docs/sec) | Total en base : {actual_count}")
        loading_summary.append({
            "collection": coll_name,
            "inserted": nb_inserted,
            "count_db": actual_count,
            "duration": duration,
            "speed": speed
        })

    total_duration = time.time() - total_start

    print("\n======================================================================")
    print("                   RÉSUMÉ DU CHARGEMENT EN BASE                       ")
    print("======================================================================")
    print(f"Durée totale d'ingestion : {total_duration:.2f} secondes\n")
    print(f"{'Collection':<18} | {'Insérés':>9} | {'En Base':>9} | {'Durée (s)':>10} | {'Débit (doc/s)':>14}")
    print("-" * 70)
    for s in loading_summary:
        print(f"{s['collection']:<18} | {s['inserted']:>9} | {s['count_db']:>9} | {s['duration']:>9.2f}s | {s['speed']:>13.0f}")
    print("=" * 70)

    client.close()

if __name__ == "__main__":
    main()
