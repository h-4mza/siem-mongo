"""
Module des requêtes transactionnelles (T1 à T15) pour le SIEM distribué MongoDB.

Chaque fonction implémente une opération métier opérationnelle ou un workflow SOC
et dispose d'un docstring reprenant l'énoncé du sujet.
Le script intègre une routine de benchmark (moyenne sur 5 exécutions) avec
génération automatique du rapport dans results/timings.csv.
"""

import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from bson import ObjectId
from pymongo import MongoClient, ASCENDING, DESCENDING

# Import de l'utilitaire de mesure de performance
from timer import measure_execution, TIMINGS_FILE

# Configuration de l'encodage console pour Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ==============================================================================
# CONNEXION MONGODB
# ==============================================================================
DEFAULT_MONGO_URI = "mongodb://mongo1:27018,mongo2:27019,mongo3:27020/?replicaSet=rs0"
DB_NAME = "siem"

def get_database():
    """Établit la connexion à la base MongoDB 'siem'."""
    uri = os.getenv("MONGO_URI", DEFAULT_MONGO_URI)
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=2000)
        client.admin.command("ping")
        return client[DB_NAME]
    except Exception:
        fallback_uri = uri.split("?")[0]
        client = MongoClient(fallback_uri, serverSelectionTimeoutMS=2000)
        client.admin.command("ping")
        return client[DB_NAME]


# ==============================================================================
# REQUÊTES T1 À T15
# ==============================================================================

def t1_insert_authentication(db, doc: dict = None) -> str:
    """T1 insérer une authentification"""
    if doc is None:
        auth_id = f"auth_t1_{uuid.uuid4().hex[:8]}"
        doc = {
            "auth_id": auth_id,
            "timestamp": datetime.now(timezone.utc),
            "user_id": "usr_00001",
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
    res = db.authentications.insert_one(doc)
    return str(res.inserted_id)


def t2_insert_flows_batch(db, count: int = 1000) -> int:
    """T2 insérer 1000 flux en lot (insert_many)"""
    prefix = uuid.uuid4().hex[:6]
    now = datetime.now(timezone.utc)
    batch = []
    for i in range(count):
        batch.append({
            "flow_id": f"flow_t2_{prefix}_{i:04d}",
            "timestamp": now,
            "src_ip": "10.1.2.50",
            "dst_ip": "8.8.8.8",
            "dst_port": 443,
            "protocol": "TCP",
            "bytes": 1024 + (i * 10),
            "host_id": "host_0001"
        })
    res = db.network_flows.insert_many(batch, ordered=False)
    return len(res.inserted_ids)


def t3_get_user_profile(db, user_id: str = "usr_00001") -> dict:
    """T3 profil d'un utilisateur"""
    return db.users.find_one({"user_id": user_id})


def t4_get_recent_authentications(db, user_id: str = "usr_00001", limit: int = 20) -> list:
    """T4 20 dernières connexions (tri desc)"""
    cursor = db.authentications.find(
        {"user_id": user_id}
    ).sort("timestamp", DESCENDING).limit(limit)
    return list(cursor)


def t5_get_failed_logins_24h(db, user_id: str = "usr_00001", ref_date: datetime = None) -> list:
    """T5 échecs de connexion sur les dernières 24 h"""
    if ref_date is None:
        ref_date = datetime.now(timezone.utc)
    since_dt = ref_date - timedelta(hours=24)

    cursor = db.authentications.find({
        "user_id": user_id,
        "result": "failure",
        "timestamp": {"$gte": since_dt, "$lte": ref_date}
    }).sort("timestamp", ASCENDING)
    return list(cursor)


def t6_get_host_events_paginated(db, host_id: str = "host_0001", target_day: datetime = None, last_timestamp: datetime = None, page_size: int = 50) -> tuple[list, datetime]:
    """T6 événements d'un hôte pour un jour donné, 50 par page (pagination par curseur sur timestamp, pas skip)"""
    if target_day is None:
        target_day = datetime(2026, 10, 20, 0, 0, 0, tzinfo=timezone.utc)

    start_day = datetime(target_day.year, target_day.month, target_day.day, 0, 0, 0, tzinfo=timezone.utc)
    end_day = datetime(target_day.year, target_day.month, target_day.day, 23, 59, 59, tzinfo=timezone.utc)

    query = {
        "host_id": host_id,
        "timestamp": {"$gte": start_day, "$lte": end_day}
    }
    # Pagination par curseur strict sur timestamp
    if last_timestamp is not None:
        query["timestamp"]["$gt"] = last_timestamp

    cursor = db.authentications.find(query).sort("timestamp", ASCENDING).limit(page_size)
    events = list(cursor)
    next_cursor = events[-1]["timestamp"] if events else None
    return events, next_cursor


def t7_create_alert(db, alert_doc: dict = None) -> str:
    """T7 créer une alerte"""
    if alert_doc is None:
        alert_id = f"alt_t7_{uuid.uuid4().hex[:8]}"
        alert_doc = {
            "alert_id": alert_id,
            "rule": "Port Scanning Activity",
            "severity": "high",
            "status": "open",
            "analyst": None,
            "related_events": ["flow_000001"],
            "tags": ["network", "scan", "soc_alert"],
            "created_at": datetime.now(timezone.utc),
            "resolved_at": None
        }
    res = db.alerts.insert_one(alert_doc)
    return str(res.inserted_id)


def t8_update_alert_status_analyst(db, alert_id: str = "alt_00001", new_status: str = "in_progress", analyst: str = "Alice Martin") -> int:
    """T8 changer le statut d'une alerte et affecter un analyste (update_one)"""
    res = db.alerts.update_one(
        {"alert_id": alert_id},
        {"$set": {"status": new_status, "analyst": analyst}}
    )
    return res.modified_count


def t9_add_alert_tag(db, alert_id: str = "alt_00001", tag: str = "investigating") -> int:
    """T9 ajouter un tag (utiliser $addToSet)"""
    res = db.alerts.update_one(
        {"alert_id": alert_id},
        {"$addToSet": {"tags": tag}}
    )
    return res.modified_count


def t10_block_ip(db, ip: str = "198.51.100.99", reason: str = "Manual SOC Ban") -> bool:
    """T10 bloquer une IP avec expiration à 7 jours"""
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=7)
    res = db.ip_blacklist.update_one(
        {"_id": ip},
        {"$set": {
            "ip": ip,
            "reason": reason,
            "created_at": now,
            "expires_at": expires
        }},
        upsert=True
    )
    return res.acknowledged


def t11_is_ip_blocked(db, ip: str = "198.51.100.1") -> bool:
    """T11 vérifier si une IP est bloquée"""
    doc = db.ip_blacklist.find_one({"_id": ip})
    return doc is not None


def t12_increment_and_reset_failed_logins(db, user_id: str = "usr_00001") -> tuple[int, int]:
    """T12 incrémenter ($inc) puis remettre à zéro le compteur d'échecs"""
    # 1. Incrémentation atomique du compteur
    res_inc = db.users.update_one(
        {"user_id": user_id},
        {"$inc": {"failed_login_count": 1}}
    )
    # 2. Remise à zéro
    res_reset = db.users.update_one(
        {"user_id": user_id},
        {"$set": {"failed_login_count": 0}}
    )
    return res_inc.modified_count, res_reset.modified_count


def t13_delete_host_events(db, host_id: str = "host_test_decommission") -> tuple[int, int]:
    """T13 supprimer les événements d'un hôte retiré (delete_many sur authentications et network_flows)"""
    res_auth = db.authentications.delete_many({"host_id": host_id})
    res_flows = db.network_flows.delete_many({"host_id": host_id})
    return res_auth.deleted_count, res_flows.deleted_count


def t14_get_open_critical_alerts(db) -> list:
    """T14 alertes critiques ouvertes, plus récentes d'abord"""
    cursor = db.alerts.find(
        {"severity": "critical", "status": "open"}
    ).sort("created_at", DESCENDING)
    return list(cursor)


def t15_lock_user_account(db, user_id: str = "usr_00002") -> int:
    """T15 verrouiller un compte (status = locked)"""
    res = db.users.update_one(
        {"user_id": user_id},
        {"$set": {"status": "locked"}}
    )
    return res.modified_count


# ==============================================================================
# ROUTINE PRINCIPALE ET BENCHMARK DES 15 REQUÊTES
# ==============================================================================

def setup_test_host_for_t13(db, test_host_id: str = "host_test_decommission"):
    """Prépare des événements copiés pour le test de T13 afin de ne pas toucher aux données principales."""
    # Nettoyage préalable éventuel
    db.authentications.delete_many({"host_id": test_host_id})
    db.network_flows.delete_many({"host_id": test_host_id})

    # Copie de 50 authentications
    sample_auths = list(db.authentications.find({"host_id": "host_0001"}).limit(50))
    if sample_auths:
        for a in sample_auths:
            a.pop("_id", None)
            a["auth_id"] = f"auth_del_{uuid.uuid4().hex[:8]}"
            a["host_id"] = test_host_id
        db.authentications.insert_many(sample_auths, ordered=False)

    # Copie de 50 flux réseau
    sample_flows = list(db.network_flows.find({"host_id": "host_0001"}).limit(50))
    if sample_flows:
        for f in sample_flows:
            f.pop("_id", None)
            f["flow_id"] = f"flow_del_{uuid.uuid4().hex[:8]}"
            f["host_id"] = test_host_id
        db.network_flows.insert_many(sample_flows, ordered=False)


def main():
    print("======================================================================")
    print("      EXÉCUTION ET BENCHMARK DES REQUÊTES TRANSACTIONNELLES (T1-T15)  ")
    print("======================================================================")

    db = get_database()
    test_host_t13 = "host_test_decommission"
    results_summary = []

    # Définition des tâches de test avec leurs fonctions et docstrings
    benchmark_tasks = [
        ("T1", "insérer une authentification",
         lambda: t1_insert_authentication(db), None),

        ("T2", "insérer 1000 flux en lot (insert_many)",
         lambda: t2_insert_flows_batch(db, count=1000), None),

        ("T3", "profil d'un utilisateur",
         lambda: t3_get_user_profile(db, "usr_00001"), None),

        ("T4", "20 dernières connexions (tri desc)",
         lambda: t4_get_recent_authentications(db, "usr_00001", limit=20), None),

        ("T5", "échecs de connexion sur les dernières 24 h",
         lambda: t5_get_failed_logins_24h(db, "usr_00001"), None),

        ("T6", "événements d'un hôte pour un jour donné (page 50)",
         lambda: t6_get_host_events_paginated(db, "host_0001", target_day=datetime(2026, 10, 20, 0, 0, 0, tzinfo=timezone.utc)), None),

        ("T7", "créer une alerte",
         lambda: t7_create_alert(db), None),

        ("T8", "changer le statut d'une alerte et affecter un analyste",
         lambda: t8_update_alert_status_analyst(db, "alt_00001", "in_progress", "Alice Martin"), None),

        ("T9", "ajouter un tag (utiliser $addToSet)",
         lambda: t9_add_alert_tag(db, "alt_00001", "investigating"), None),

        ("T10", "bloquer une IP avec expiration à 7 jours",
         lambda: t10_block_ip(db, "198.51.100.99", "Manual SOC Ban"), None),

        ("T11", "vérifier si une IP est bloquée",
         lambda: t11_is_ip_blocked(db, "198.51.100.1"), None),

        ("T12", "incrémenter ($inc) puis remettre à zéro le compteur",
         lambda: t12_increment_and_reset_failed_logins(db, "usr_00001"), None),

        ("T13", "supprimer les événements d'un hôte retiré",
         lambda: t13_delete_host_events(db, test_host_t13),
         lambda: setup_test_host_for_t13(db, test_host_t13)),

        ("T14", "alertes critiques ouvertes, plus récentes d'abord",
         lambda: t14_get_open_critical_alerts(db), None),

        ("T15", "verrouiller un compte (status = locked)",
         lambda: t15_lock_user_account(db, "usr_00002"), None),
    ]

    print("[*] Lancement des 15 benchmarks (moyenne sur 5 itérations par requête)...")
    for q_id, desc, run_fn, setup_fn in benchmark_tasks:
        res, avg_ms = measure_execution(
            query_id=q_id,
            func=run_fn,
            query_type="transactional",
            iterations=5,
            setup_fn=setup_fn
        )
        results_summary.append({
            "requete": q_id,
            "description": desc,
            "temps_ms": avg_ms
        })

    # Affichage du tableau récapitulatif
    print("\n======================================================================")
    print("            TABLEAU DES TEMPS DE RÉPONSE TRANSACTIONNELS (T1-T15)    ")
    print("======================================================================")
    print(f"{'Réf':<5} | {'Description':<52} | {'Temps Moyen (ms)':>16}")
    print("-" * 78)
    for row in results_summary:
        print(f"{row['requete']:<5} | {row['description']:<52} | {row['temps_ms']:>14.2f} ms")
    print("=" * 78)
    print(f"\n[✓] Mesures enregistrées dans : {TIMINGS_FILE}\n")


if __name__ == "__main__":
    main()
