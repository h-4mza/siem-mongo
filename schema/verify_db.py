"""
Script de vérification de l'état de la base MongoDB siem.
Affiche pour chaque collection le nombre de documents (count_documents)
et la liste exhaustive des index avec leurs propriétés (getIndexes).
"""

import os
import sys
from pymongo import MongoClient

# Configuration de l'encodage console pour Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

DEFAULT_MONGO_URI = "mongodb://mongo1:27018,mongo2:27019,mongo3:27020/?replicaSet=rs0"
DB_NAME = "siem"

def main():
    uri = os.getenv("MONGO_URI", DEFAULT_MONGO_URI)
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=2000)
        client.admin.command("ping")
    except Exception:
        client = MongoClient(uri.split("?")[0], serverSelectionTimeoutMS=2000)

    db = client[DB_NAME]
    collections = ["users", "hosts", "authentications", "network_flows", "alerts", "ip_blacklist"]

    print("======================================================================")
    print("         VÉRIFICATION DES COLLECTIONS ET INDEX (BASE 'siem')          ")
    print("======================================================================")

    for coll_name in collections:
        coll = db[coll_name]
        count = coll.count_documents({})
        indexes = list(coll.list_indexes())
        print(f"\n[Collection] {coll_name}")
        print(f"  • Nombre de documents : {count}")
        print(f"  • Index configurés ({len(indexes)}) :")
        for idx in indexes:
            key_repr = ", ".join([f"{k}: {v}" for k, v in idx["key"].items()])
            attrs = []
            if idx.get("unique"):
                attrs.append("UNIQUE")
            if "expireAfterSeconds" in idx:
                attrs.append(f"TTL({idx['expireAfterSeconds']}s)")
            attr_str = f" [{', '.join(attrs)}]" if attrs else ""
            print(f"    - {idx['name']:<32} : ({key_repr}){attr_str}")

    print("\n======================================================================\n")
    client.close()

if __name__ == "__main__":
    main()
