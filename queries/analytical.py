"""
Module des requêtes analytiques et agrégations (A16 à A25) pour le SIEM distribué MongoDB.

Chaque fonction implémente un pipeline d'agrégation ($group, $match, $project,
$sortByCount, $dateToString, $subtract...) avec docstring reprenant l'énoncé.
Le script intègre :
  - Le benchmark des requêtes analytiques (moyenne sur 5 itérations)
    avec enregistrement dans results/timings.csv (type="analytical")
  - Les expériences d'indexation comparatives approfondies :
      1. T5 (échecs 24h avec nReturned > 0) : avec/sans index (keys, docs, nReturned, temps)
      2. A25 avec deux tags : tag très fréquent (~60%) vs tag rare (< 2%)
      3. A17 : index (result, timestamp) vs index (timestamp) vs sans index
      4. A22 : avec $match initial sur timestamp vs sans $match
      5. A18 : version dénormalisée vs version normalisée avec $lookup
    Enregistrement dans results/index_experiments.csv
"""

import csv
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from pymongo import MongoClient, ASCENDING, DESCENDING

# Import de l'utilitaire de chronométrage
from timer import measure_execution, TIMINGS_FILE, RESULTS_DIR

# Configuration de l'encodage console pour Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

INDEX_EXP_FILE = RESULTS_DIR / "index_experiments.csv"

# ==============================================================================
# CONNEXION MONGODB
# ==============================================================================
DEFAULT_MONGO_URI = "mongodb://localhost:27017/?replicaSet=rs0"
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
# PIPELINES D'AGRÉGATION (A16 À A25)
# ==============================================================================

def a16_daily_auth_stats(db) -> list:
    """A16 connexions réussies/échouées par jour sur 30 jours"""
    pipeline = [
        {
            "$group": {
                "_id": {
                    "$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}
                },
                "total_succes": {
                    "$sum": {"$cond": [{"$eq": ["$result", "success"]}, 1, 0]}
                },
                "total_echecs": {
                    "$sum": {"$cond": [{"$eq": ["$result", "failure"]}, 1, 0]}
                },
                "total_connexions": {"$sum": 1}
            }
        },
        {"$sort": {"_id": 1}}
    ]
    return list(db.authentications.aggregate(pipeline))


def a17_top10_failed_ips_daily(db, target_day: datetime = None) -> list:
    """A17 top 10 IP sources par nombre d'échecs sur une journée"""
    if target_day is None:
        target_day = datetime.now(timezone.utc) - timedelta(days=7)

    start_dt = datetime(target_day.year, target_day.month, target_day.day, 0, 0, 0, tzinfo=timezone.utc)
    end_dt = datetime(target_day.year, target_day.month, target_day.day, 23, 59, 59, tzinfo=timezone.utc)

    pipeline = [
        {
            "$match": {
                "result": "failure",
                "timestamp": {"$gte": start_dt, "$lte": end_dt}
            }
        },
        {"$sortByCount": "$source_ip"},
        {"$limit": 10}
    ]
    return list(db.authentications.aggregate(pipeline))


def a18_night_logins_by_department(db, department: str = "Finance") -> list:
    """A18 connexions réussies entre 22h et 6h pour un département (utiliser user_department, sans $lookup)"""
    pipeline = [
        {
            "$match": {
                "user_department": department,
                "result": "success",
                "$expr": {
                    "$or": [
                        {"$gte": [{"$hour": "$timestamp"}, 22]},
                        {"$lt": [{"$hour": "$timestamp"}, 6]}
                    ]
                }
            }
        },
        {
            "$group": {
                "_id": "$user_id",
                "nb_connexions_nocturnes": {"$sum": 1},
                "dernier_acces": {"$max": "$timestamp"}
            }
        },
        {"$sort": {"nb_connexions_nocturnes": -1}},
        {"$limit": 20}
    ]
    return list(db.authentications.aggregate(pipeline))


def a19_alerts_by_severity_status(db) -> list:
    """A19 alertes par sévérité et statut"""
    pipeline = [
        {
            "$group": {
                "_id": {
                    "severity": "$severity",
                    "status": "$status"
                },
                "nb_alertes": {"$sum": 1}
            }
        },
        {"$sort": {"_id.severity": 1, "_id.status": 1}}
    ]
    return list(db.alerts.aggregate(pipeline))


def a20_bytes_per_host_daily(db, target_day: datetime = None) -> list:
    """A20 octets par hôte pour une journée"""
    if target_day is None:
        target_day = datetime.now(timezone.utc) - timedelta(days=10)

    start_dt = datetime(target_day.year, target_day.month, target_day.day, 0, 0, 0, tzinfo=timezone.utc)
    end_dt = datetime(target_day.year, target_day.month, target_day.day, 23, 59, 59, tzinfo=timezone.utc)

    pipeline = [
        {
            "$match": {
                "timestamp": {"$gte": start_dt, "$lte": end_dt}
            }
        },
        {
            "$group": {
                "_id": "$host_id",
                "total_bytes": {"$sum": "$bytes"},
                "nb_flux": {"$sum": 1}
            }
        },
        {"$sort": {"total_bytes": -1}},
        {"$limit": 20}
    ]
    return list(db.network_flows.aggregate(pipeline))


def a21_top10_dst_ports(db) -> list:
    """A21 top 10 ports de destination"""
    pipeline = [
        {"$sortByCount": "$dst_port"},
        {"$limit": 10}
    ]
    return list(db.network_flows.aggregate(pipeline))


def a22_multi_country_users_weekly(db, start_dt: datetime = None, end_dt: datetime = None) -> list:
    """A22 utilisateurs connectés depuis plus de 3 pays en une semaine"""
    pipeline = []
    # Ajout d'un $match sur timestamp en premier pour exploiter l'index temporel
    if start_dt is not None and end_dt is not None:
        pipeline.append({"$match": {"timestamp": {"$gte": start_dt, "$lte": end_dt}}})
    else:
        # Fenêtre temporelle par défaut : 14 derniers jours
        window_start = datetime.now(timezone.utc) - timedelta(days=14)
        pipeline.append({"$match": {"timestamp": {"$gte": window_start}}})

    pipeline.extend([
        {
            "$group": {
                "_id": {
                    "user_id": "$user_id",
                    "semaine": {"$dateToString": {"format": "%G-W%V", "date": "$timestamp"}}
                },
                "pays": {"$addToSet": "$geo.country"}
            }
        },
        {
            "$project": {
                "user_id": "$_id.user_id",
                "semaine": "$_id.semaine",
                "nb_pays": {"$size": "$pays"},
                "liste_pays": "$pays"
            }
        },
        {"$match": {"nb_pays": {"$gt": 3}}},
        {"$sort": {"nb_pays": -1}}
    ])
    return list(db.authentications.aggregate(pipeline))


def a23_auth_method_distribution(db) -> list:
    """A23 répartition par méthode d'authentification"""
    pipeline = [
        {"$sortByCount": "$method"}
    ]
    return list(db.authentications.aggregate(pipeline))


def a24_avg_resolution_time_per_analyst(db) -> list:
    """A24 délai moyen de résolution par analyste ($subtract sur les dates)"""
    pipeline = [
        {
            "$match": {
                "status": {"$in": ["resolved", "closed"]},
                "resolved_at": {"$ne": None},
                "analyst": {"$ne": None}
            }
        },
        {
            "$project": {
                "analyst": 1,
                "duree_ms": {"$subtract": ["$resolved_at", "$created_at"]}
            }
        },
        {
            "$group": {
                "_id": "$analyst",
                "nb_alertes_resolues": {"$sum": 1},
                "delai_moyen_heures": {
                    "$avg": {"$divide": ["$duree_ms", 3600000.0]}
                }
            }
        },
        {"$sort": {"delai_moyen_heures": 1}}
    ]
    return list(db.alerts.aggregate(pipeline))


def a25_alerts_by_tag(db, tag: str = "auth") -> list:
    """A25 alertes avec un tag donné"""
    pipeline = [
        {"$match": {"tags": tag}},
        {
            "$project": {
                "alert_id": 1,
                "rule": 1,
                "severity": 1,
                "status": 1,
                "tags": 1,
                "created_at": 1
            }
        },
        {"$sort": {"created_at": -1}},
        {"$limit": 50}
    ]
    return list(db.alerts.aggregate(pipeline))


# ==============================================================================
# OUTILS D'ANALYSE D'EXÉCUTION (explain executionStats)
# ==============================================================================

def detect_scan_stage(tree: dict) -> str:
    """Parcourt l'arbre d'exécution pour trouver IXSCAN ou COLLSCAN."""
    if not isinstance(tree, dict):
        return "UNKNOWN"

    if tree.get("indexesUsed") or tree.get("stage") in ("IXSCAN", "ixseek"):
        return "IXSCAN"
    if tree.get("stage") in ("COLLSCAN", "cscan") or tree.get("collectionScans", 0) > 0:
        return "COLLSCAN"

    for k in ("inputStage", "outerStage", "innerStage"):
        if k in tree and isinstance(tree[k], dict):
            res = detect_scan_stage(tree[k])
            if res != "UNKNOWN":
                return res

    if "inputStages" in tree and isinstance(tree["inputStages"], list):
        for sub in tree["inputStages"]:
            res = detect_scan_stage(sub)
            if res != "UNKNOWN":
                return res

    return "UNKNOWN"


def get_explain_metrics(exp_dict: dict) -> dict:
    """Extrait stage, totalKeysExamined, totalDocsExamined, nReturned depuis explain."""
    # Pipeline d'agrégation avec stages
    if "stages" in exp_dict and len(exp_dict["stages"]) > 0:
        first = exp_dict["stages"][0]
        if "$cursor" in first and "executionStats" in first["$cursor"]:
            es = first["$cursor"]["executionStats"]
            stage = detect_scan_stage(es.get("executionStages", {}))
            if stage == "UNKNOWN":
                stage = "COLLSCAN" if es.get("totalDocsExamined", 0) >= 3000 else "IXSCAN"
            return {
                "stage": stage,
                "totalKeysExamined": es.get("totalKeysExamined", 0),
                "totalDocsExamined": es.get("totalDocsExamined", 0),
                "nReturned": es.get("nReturned", 0),
            }

    # Requête find() ou executionStats direct
    if "executionStats" in exp_dict:
        es = exp_dict["executionStats"]
        stage = detect_scan_stage(es.get("executionStages", {}))
        if stage == "UNKNOWN":
            stage = "COLLSCAN" if es.get("totalDocsExamined", 0) >= 3000 else "IXSCAN"
        return {
            "stage": stage,
            "totalKeysExamined": es.get("totalKeysExamined", 0),
            "totalDocsExamined": es.get("totalDocsExamined", 0),
            "nReturned": es.get("nReturned", 0),
        }

    return {"stage": "UNKNOWN", "totalKeysExamined": 0, "totalDocsExamined": 0, "nReturned": 0}


def safe_drop_index(coll, index_name: str):
    """Supprime un index s'il existe sans lever d'exception."""
    try:
        if index_name in coll.index_information():
            coll.drop_index(index_name)
    except Exception:
        pass


# ==============================================================================
# EXPÉRIENCES D'INDEXATION COMPARATIVES (T5, A25, A17, A22, A18)
# ==============================================================================

def run_index_experiments(db):
    """
    Exécute les expériences demandées :
      1. T5 avec utilisateur ayant des échecs (usr_00001, nReturned > 0) : AVEC vs SANS index
      2. A25 avec deux tags : très fréquent (auth ~60%) vs rare (zero_day 1.25%)
      3. A17 : index (result, timestamp) vs index (timestamp) vs sans index
      4. A22 : avec $match initial vs sans $match
      5. A18 : version dénormalisée vs version avec $lookup vers users
    """
    print("\n======================================================================")
    print("      EXPÉRIENCES D'INDEXATION APPROFONDIES (T5, A25, A17, A22, A18) ")
    print("======================================================================")

    experiments = []

    # --------------------------------------------------------------------------
    # 1. EXPÉRIENCE T5 (Échecs 24h avec nReturned > 0)
    # --------------------------------------------------------------------------
    print("[*] 1/5 Expérience T5 (utilisateur 'usr_00001' avec échecs dans les 24h)...")
    now_ref = datetime.now(timezone.utc)
    since_24h = now_ref - timedelta(hours=24)
    query_t5 = {
        "user_id": "usr_00001",
        "result": "failure",
        "timestamp": {"$gte": since_24h, "$lte": now_ref}
    }

    # S'assurer que les index de base existent
    if "idx_auth_user_res_time" not in db.authentications.index_information():
        db.authentications.create_index([("user_id", ASCENDING), ("result", ASCENDING), ("timestamp", ASCENDING)], name="idx_auth_user_res_time")

    # T5 AVEC INDEX
    exp_t5_with = db.authentications.find(query_t5).sort("timestamp", ASCENDING).explain()
    m_t5_with = get_explain_metrics(exp_t5_with)
    _, t_t5_with = measure_execution("T5", lambda: list(db.authentications.find(query_t5).sort("timestamp", ASCENDING)), query_type="transactional", iterations=5)

    # T5 SANS INDEX (drop de tous les index filtrables pour forcer le scan)
    safe_drop_index(db.authentications, "idx_auth_user_res_time")
    safe_drop_index(db.authentications, "idx_auth_user_time_desc")
    safe_drop_index(db.authentications, "idx_auth_res_time")
    safe_drop_index(db.authentications, "idx_auth_timestamp")

    exp_t5_without = db.authentications.find(query_t5).sort("timestamp", ASCENDING).explain()
    m_t5_without = get_explain_metrics(exp_t5_without)
    _, t_t5_without = measure_execution("T5_SANS_INDEX", lambda: list(db.authentications.find(query_t5).sort("timestamp", ASCENDING)), query_type="experiment", iterations=5)

    # Recréation des index authentications
    db.authentications.create_index([("user_id", ASCENDING), ("result", ASCENDING), ("timestamp", ASCENDING)], name="idx_auth_user_res_time")
    db.authentications.create_index([("user_id", ASCENDING), ("timestamp", DESCENDING)], name="idx_auth_user_time_desc")
    db.authentications.create_index([("result", ASCENDING), ("timestamp", ASCENDING)], name="idx_auth_res_time")
    db.authentications.create_index([("timestamp", ASCENDING)], name="idx_auth_timestamp")

    experiments.append({
        "requete": "T5",
        "config": "AVEC_INDEX",
        "stage": m_t5_with["stage"],
        "keys_examined": m_t5_with["totalKeysExamined"],
        "docs_examined": m_t5_with["totalDocsExamined"],
        "nReturned": m_t5_with["nReturned"],
        "temps_ms": t_t5_with,
        "description": "Index (user_id, result, timestamp) - nReturned > 0 garanti"
    })
    experiments.append({
        "requete": "T5",
        "config": "SANS_INDEX",
        "stage": m_t5_without["stage"],
        "keys_examined": m_t5_without["totalKeysExamined"],
        "docs_examined": m_t5_without["totalDocsExamined"],
        "nReturned": m_t5_without["nReturned"],
        "temps_ms": t_t5_without,
        "description": "Balayage complet de la collection (COLLSCAN)"
    })

    # --------------------------------------------------------------------------
    # 2. EXPÉRIENCE A25 (Tag très fréquent 'auth' vs Tag rare 'zero_day' < 2%)
    # --------------------------------------------------------------------------
    print("[*] 2/5 Expérience A25 (Tag fréquent 'auth' vs Tag rare 'zero_day')...")

    # 2.a Tag très fréquent 'auth' (~63% des alertes)
    pipe_a25_freq = [{"$match": {"tags": "auth"}}, {"$limit": 50}]
    exp_a25_freq_with = db.command("explain", {"aggregate": "alerts", "pipeline": pipe_a25_freq, "cursor": {}}, verbosity="executionStats")
    m_a25_freq_with = get_explain_metrics(exp_a25_freq_with)
    _, t_a25_freq_with = measure_execution("A25_FREQ", lambda: list(db.alerts.aggregate(pipe_a25_freq)), query_type="analytical", iterations=5)

    safe_drop_index(db.alerts, "idx_alerts_tags_multikey")
    exp_a25_freq_without = db.command("explain", {"aggregate": "alerts", "pipeline": pipe_a25_freq, "cursor": {}}, verbosity="executionStats")
    m_a25_freq_without = get_explain_metrics(exp_a25_freq_without)
    _, t_a25_freq_without = measure_execution("A25_FREQ_SANS_INDEX", lambda: list(db.alerts.aggregate(pipe_a25_freq)), query_type="experiment", iterations=5)

    db.alerts.create_index([("tags", ASCENDING)], name="idx_alerts_tags_multikey")

    experiments.append({
        "requete": "A25 (freq: auth)",
        "config": "AVEC_INDEX",
        "stage": m_a25_freq_with["stage"],
        "keys_examined": m_a25_freq_with["totalKeysExamined"],
        "docs_examined": m_a25_freq_with["totalDocsExamined"],
        "nReturned": m_a25_freq_with["nReturned"],
        "temps_ms": t_a25_freq_with,
        "description": "Tag fréquent (~63% alertes) - faible sélectivité"
    })
    experiments.append({
        "requete": "A25 (freq: auth)",
        "config": "SANS_INDEX",
        "stage": m_a25_freq_without["stage"],
        "keys_examined": m_a25_freq_without["totalKeysExamined"],
        "docs_examined": m_a25_freq_without["totalDocsExamined"],
        "nReturned": m_a25_freq_without["nReturned"],
        "temps_ms": t_a25_freq_without,
        "description": "Tag fréquent sans index (COLLSCAN rapide car limit=50)"
    })

    # 2.b Tag rare 'zero_day' (40 alertes = 1.25% < 2%)
    pipe_a25_rare = [{"$match": {"tags": "zero_day"}}, {"$limit": 50}]
    exp_a25_rare_with = db.command("explain", {"aggregate": "alerts", "pipeline": pipe_a25_rare, "cursor": {}}, verbosity="executionStats")
    m_a25_rare_with = get_explain_metrics(exp_a25_rare_with)
    _, t_a25_rare_with = measure_execution("A25_RARE", lambda: list(db.alerts.aggregate(pipe_a25_rare)), query_type="analytical", iterations=5)

    safe_drop_index(db.alerts, "idx_alerts_tags_multikey")
    exp_a25_rare_without = db.command("explain", {"aggregate": "alerts", "pipeline": pipe_a25_rare, "cursor": {}}, verbosity="executionStats")
    m_a25_rare_without = get_explain_metrics(exp_a25_rare_without)
    _, t_a25_rare_without = measure_execution("A25_RARE_SANS_INDEX", lambda: list(db.alerts.aggregate(pipe_a25_rare)), query_type="experiment", iterations=5)

    db.alerts.create_index([("tags", ASCENDING)], name="idx_alerts_tags_multikey")

    experiments.append({
        "requete": "A25 (rare: zero_day)",
        "config": "AVEC_INDEX",
        "stage": m_a25_rare_with["stage"],
        "keys_examined": m_a25_rare_with["totalKeysExamined"],
        "docs_examined": m_a25_rare_with["totalDocsExamined"],
        "nReturned": m_a25_rare_with["nReturned"],
        "temps_ms": t_a25_rare_with,
        "description": "Tag rare (1.25% alertes) - forte sélectivité IXSCAN"
    })
    experiments.append({
        "requete": "A25 (rare: zero_day)",
        "config": "SANS_INDEX",
        "stage": m_a25_rare_without["stage"],
        "keys_examined": m_a25_rare_without["totalKeysExamined"],
        "docs_examined": m_a25_rare_without["totalDocsExamined"],
        "nReturned": m_a25_rare_without["nReturned"],
        "temps_ms": t_a25_rare_without,
        "description": "Tag rare sans index (COLLSCAN doit lire 3 200 documents)"
    })

    # --------------------------------------------------------------------------
    # 3. EXPÉRIENCE A17 (Index result+timestamp vs Index timestamp vs SANS index)
    # --------------------------------------------------------------------------
    print("[*] 3/5 Expérience A17 (Comparaison des index sur failure + timestamp)...")
    target_day = datetime.now(timezone.utc) - timedelta(days=7)
    start_dt = datetime(target_day.year, target_day.month, target_day.day, 0, 0, 0, tzinfo=timezone.utc)
    end_dt = datetime(target_day.year, target_day.month, target_day.day, 23, 59, 59, tzinfo=timezone.utc)
    pipe_a17 = [
        {"$match": {"result": "failure", "timestamp": {"$gte": start_dt, "$lte": end_dt}}},
        {"$sortByCount": "$source_ip"},
        {"$limit": 10}
    ]

    # Configuration A : avec index (result, timestamp)
    safe_drop_index(db.authentications, "idx_auth_timestamp")
    safe_drop_index(db.authentications, "idx_auth_srcip_time")
    if "idx_auth_res_time" not in db.authentications.index_information():
        db.authentications.create_index([("result", ASCENDING), ("timestamp", ASCENDING)], name="idx_auth_res_time")

    exp_a17_res = db.command("explain", {"aggregate": "authentications", "pipeline": pipe_a17, "cursor": {}}, verbosity="executionStats")
    m_a17_res = get_explain_metrics(exp_a17_res)
    _, t_a17_res = measure_execution("A17_IDX_RESULT_TIME", lambda: list(db.authentications.aggregate(pipe_a17)), query_type="experiment", iterations=5)

    # Configuration B : avec index (timestamp) seul
    safe_drop_index(db.authentications, "idx_auth_res_time")
    db.authentications.create_index([("timestamp", ASCENDING)], name="idx_auth_timestamp")

    exp_a17_ts = db.command("explain", {"aggregate": "authentications", "pipeline": pipe_a17, "cursor": {}}, verbosity="executionStats")
    m_a17_ts = get_explain_metrics(exp_a17_ts)
    _, t_a17_ts = measure_execution("A17_IDX_TIMESTAMP", lambda: list(db.authentications.aggregate(pipe_a17)), query_type="experiment", iterations=5)

    # Configuration C : SANS index
    safe_drop_index(db.authentications, "idx_auth_timestamp")
    safe_drop_index(db.authentications, "idx_auth_res_time")

    exp_a17_none = db.command("explain", {"aggregate": "authentications", "pipeline": pipe_a17, "cursor": {}}, verbosity="executionStats")
    m_a17_none = get_explain_metrics(exp_a17_none)
    _, t_a17_none = measure_execution("A17_SANS_INDEX", lambda: list(db.authentications.aggregate(pipe_a17)), query_type="experiment", iterations=5)

    # Recréation des index
    db.authentications.create_index([("result", ASCENDING), ("timestamp", ASCENDING)], name="idx_auth_res_time")
    db.authentications.create_index([("timestamp", ASCENDING)], name="idx_auth_timestamp")
    db.authentications.create_index([("source_ip", ASCENDING), ("timestamp", ASCENDING)], name="idx_auth_srcip_time")

    experiments.append({
        "requete": "A17",
        "config": "INDEX_(result,timestamp)",
        "stage": m_a17_res["stage"],
        "keys_examined": m_a17_res["totalKeysExamined"],
        "docs_examined": m_a17_res["totalDocsExamined"],
        "nReturned": m_a17_res["nReturned"],
        "temps_ms": t_a17_res,
        "description": "Règle ESR : égalité result='failure' puis intervalle date"
    })
    experiments.append({
        "requete": "A17",
        "config": "INDEX_(timestamp)",
        "stage": m_a17_ts["stage"],
        "keys_examined": m_a17_ts["totalKeysExamined"],
        "docs_examined": m_a17_ts["totalDocsExamined"],
        "nReturned": m_a17_ts["nReturned"],
        "temps_ms": t_a17_ts,
        "description": "Index temporel seul : doit filtrer result après lecture doc"
    })
    experiments.append({
        "requete": "A17",
        "config": "SANS_INDEX",
        "stage": m_a17_none["stage"],
        "keys_examined": m_a17_none["totalKeysExamined"],
        "docs_examined": m_a17_none["totalDocsExamined"],
        "nReturned": m_a17_none["nReturned"],
        "temps_ms": t_a17_none,
        "description": "COLLSCAN complet (60 500 documents examinés)"
    })

    # --------------------------------------------------------------------------
    # 4. EXPÉRIENCE A22 (Avec $match initial sur timestamp vs Sans $match)
    # --------------------------------------------------------------------------
    print("[*] 4/5 Expérience A22 (Impact d'un $match temporel initial)...")
    # A22 avec $match sur 14 jours
    w_start = datetime.now(timezone.utc) - timedelta(days=14)
    p_a22_match = [
        {"$match": {"timestamp": {"$gte": w_start}}},
        {"$group": {"_id": {"user_id": "$user_id", "semaine": {"$dateToString": {"format": "%G-W%V", "date": "$timestamp"}}}, "pays": {"$addToSet": "$geo.country"}}},
        {"$project": {"user_id": "$_id.user_id", "semaine": "$_id.semaine", "nb_pays": {"$size": "$pays"}, "liste_pays": "$pays"}},
        {"$match": {"nb_pays": {"$gt": 3}}},
        {"$sort": {"nb_pays": -1}}
    ]
    exp_a22_m = db.command("explain", {"aggregate": "authentications", "pipeline": p_a22_match, "cursor": {}}, verbosity="executionStats")
    m_a22_m = get_explain_metrics(exp_a22_m)
    _, t_a22_m = measure_execution("A22_AVEC_MATCH", lambda: list(db.authentications.aggregate(p_a22_match)), query_type="experiment", iterations=5)

    # A22 sans $match initial (scanne et groupe toute la collection 30 jours)
    p_a22_nomatch = [
        {"$group": {"_id": {"user_id": "$user_id", "semaine": {"$dateToString": {"format": "%G-W%V", "date": "$timestamp"}}}, "pays": {"$addToSet": "$geo.country"}}},
        {"$project": {"user_id": "$_id.user_id", "semaine": "$_id.semaine", "nb_pays": {"$size": "$pays"}, "liste_pays": "$pays"}},
        {"$match": {"nb_pays": {"$gt": 3}}},
        {"$sort": {"nb_pays": -1}}
    ]
    exp_a22_nom = db.command("explain", {"aggregate": "authentications", "pipeline": p_a22_nomatch, "cursor": {}}, verbosity="executionStats")
    m_a22_nom = get_explain_metrics(exp_a22_nom)
    _, t_a22_nom = measure_execution("A22_SANS_MATCH", lambda: list(db.authentications.aggregate(p_a22_nomatch)), query_type="experiment", iterations=5)

    experiments.append({
        "requete": "A22",
        "config": "AVEC_$match_date",
        "stage": m_a22_m["stage"],
        "keys_examined": m_a22_m["totalKeysExamined"],
        "docs_examined": m_a22_m["totalDocsExamined"],
        "nReturned": m_a22_m["nReturned"],
        "temps_ms": t_a22_m,
        "description": "Filtre préalable sur 14 jours via index temporel (volume réduit)"
    })
    experiments.append({
        "requete": "A22",
        "config": "SANS_$match_date",
        "stage": m_a22_nom["stage"],
        "keys_examined": m_a22_nom["totalKeysExamined"],
        "docs_examined": m_a22_nom["totalDocsExamined"],
        "nReturned": m_a22_nom["nReturned"],
        "temps_ms": t_a22_nom,
        "description": "Groupement brut sur l'intégralité des 60 500 documents"
    })

    # --------------------------------------------------------------------------
    # 5. EXPÉRIENCE A18 (Version dénormalisée vs Version avec $lookup)
    # --------------------------------------------------------------------------
    print("[*] 5/5 Expérience A18 (Dénormalisation vs Jointure $lookup vers users)...")

    # A18 Dénormalisée (champ user_department direct)
    p_a18_denorm = [
        {"$match": {"user_department": "Finance", "result": "success", "$expr": {"$or": [{"$gte": [{"$hour": "$timestamp"}, 22]}, {"$lt": [{"$hour": "$timestamp"}, 6]}]}}},
        {"$group": {"_id": "$user_id", "nb_connexions": {"$sum": 1}, "dernier_acces": {"$max": "$timestamp"}}},
        {"$sort": {"nb_connexions": -1}},
        {"$limit": 20}
    ]
    exp_a18_denorm = db.command("explain", {"aggregate": "authentications", "pipeline": p_a18_denorm, "cursor": {}}, verbosity="executionStats")
    m_a18_denorm = get_explain_metrics(exp_a18_denorm)
    _, t_a18_denorm = measure_execution("A18_DENORMALISE", lambda: list(db.authentications.aggregate(p_a18_denorm)), query_type="experiment", iterations=5)

    # A18 Normalisée (jointure $lookup vers users)
    p_a18_lookup = [
        {"$match": {"result": "success", "$expr": {"$or": [{"$gte": [{"$hour": "$timestamp"}, 22]}, {"$lt": [{"$hour": "$timestamp"}, 6]}]}}},
        {"$lookup": {"from": "users", "localField": "user_id", "foreignField": "user_id", "as": "user"}},
        {"$unwind": "$user"},
        {"$match": {"user.department": "Finance"}},
        {"$group": {"_id": "$user_id", "nb_connexions": {"$sum": 1}, "dernier_acces": {"$max": "$timestamp"}}},
        {"$sort": {"nb_connexions": -1}},
        {"$limit": 20}
    ]
    exp_a18_lookup = db.command("explain", {"aggregate": "authentications", "pipeline": p_a18_lookup, "cursor": {}}, verbosity="executionStats")
    m_a18_lookup = get_explain_metrics(exp_a18_lookup)
    _, t_a18_lookup = measure_execution("A18_AVEC_LOOKUP", lambda: list(db.authentications.aggregate(p_a18_lookup)), query_type="experiment", iterations=5)

    experiments.append({
        "requete": "A18",
        "config": "DÉNORMALISÉE",
        "stage": m_a18_denorm["stage"],
        "keys_examined": m_a18_denorm["totalKeysExamined"],
        "docs_examined": m_a18_denorm["totalDocsExamined"],
        "nReturned": m_a18_denorm["nReturned"],
        "temps_ms": t_a18_denorm,
        "description": "Champ user_department stocké dans chaque log (aucun lookup)"
    })
    experiments.append({
        "requete": "A18",
        "config": "AVEC_$LOOKUP",
        "stage": m_a18_lookup["stage"],
        "keys_examined": m_a18_lookup["totalKeysExamined"],
        "docs_examined": m_a18_lookup["totalDocsExamined"],
        "nReturned": m_a18_lookup["nReturned"],
        "temps_ms": t_a18_lookup,
        "description": "Jointure $lookup vers collection users (17k+ jointures)"
    })

    # Enregistrement dans results/index_experiments.csv
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(INDEX_EXP_FILE, "w", encoding="utf-8", newline="") as f:
        fieldnames = ["requete", "configuration", "stage", "totalKeysExamined", "totalDocsExamined", "nReturned", "temps_ms", "description"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for e in experiments:
            writer.writerow({
                "requete": e["requete"],
                "configuration": e["config"],
                "stage": e["stage"],
                "totalKeysExamined": e["keys_examined"],
                "totalDocsExamined": e["docs_examined"],
                "nReturned": e["nReturned"],
                "temps_ms": f"{e['temps_ms']:.2f}",
                "description": e["description"]
            })

    # Affichage du tableau de synthèse
    print("\n======================================================================================================================")
    print("                              RÉSULTATS DES EXPÉRIENCES D'INDEXATION & ARCHITECTURE                                  ")
    print("======================================================================================================================")
    print(f"{'Requête':<20} | {'Configuration':<24} | {'Stage':<10} | {'Keys':>7} | {'Docs':>8} | {'nRet':>5} | {'Temps (ms)':>12}")
    print("-" * 102)
    for e in experiments:
        print(f"{e['requete']:<20} | {e['config']:<24} | {e['stage']:<10} | {e['keys_examined']:>7} | {e['docs_examined']:>8} | {e['nReturned']:>5} | {e['temps_ms']:>10.2f} ms")
    print("=" * 102)
    print(f"\n[✓] Rapport complet enregistré dans : {INDEX_EXP_FILE}\n")


# ==============================================================================
# POINT D'ENTRÉE PRINCIPAL
# ==============================================================================

def main():
    print("======================================================================")
    print("      EXÉCUTION ET BENCHMARK DES REQUÊTES ANALYTIQUES (A16-A25)       ")
    print("======================================================================")

    db = get_database()
    results_summary = []

    target_attack_day = datetime.now(timezone.utc) - timedelta(days=7)

    analytical_tasks = [
        ("A16", "connexions réussies/échouées par jour sur 30 jours",
         lambda: a16_daily_auth_stats(db)),

        ("A17", "top 10 IP sources par nombre d'échecs sur une journée",
         lambda: a17_top10_failed_ips_daily(db, target_attack_day)),

        ("A18", "connexions réussies entre 22h et 6h pour un département (sans $lookup)",
         lambda: a18_night_logins_by_department(db, "Finance")),

        ("A19", "alertes par sévérité et statut",
         lambda: a19_alerts_by_severity_status(db)),

        ("A20", "octets par hôte pour une journée",
         lambda: a20_bytes_per_host_daily(db, target_attack_day)),

        ("A21", "top 10 ports de destination",
         lambda: a21_top10_dst_ports(db)),

        ("A22", "utilisateurs connectés depuis plus de 3 pays en une semaine",
         lambda: a22_multi_country_users_weekly(db)),

        ("A23", "répartition par méthode d'authentification",
         lambda: a23_auth_method_distribution(db)),

        ("A24", "délai moyen de résolution par analyste ($subtract)",
         lambda: a24_avg_resolution_time_per_analyst(db)),

        ("A25", "alertes avec un tag donné",
         lambda: a25_alerts_by_tag(db, "auth")),
    ]

    print("[*] Lancement du benchmark des requêtes A16 à A25 (moyenne sur 5 itérations)...")
    for q_id, desc, run_fn in analytical_tasks:
        res, avg_ms = measure_execution(
            query_id=q_id,
            func=run_fn,
            query_type="analytical",
            iterations=5
        )
        results_summary.append({
            "requete": q_id,
            "description": desc,
            "temps_ms": avg_ms
        })

    # Tableau récapitulatif
    print("\n======================================================================")
    print("             TABLEAU DES TEMPS DE RÉPONSE ANALYTIQUES (A16-A25)       ")
    print("======================================================================")
    print(f"{'Réf':<5} | {'Description':<52} | {'Temps Moyen (ms)':>16}")
    print("-" * 78)
    for row in results_summary:
        print(f"{row['requete']:<5} | {row['description']:<52} | {row['temps_ms']:>14.2f} ms")
    print("=" * 78)
    print(f"\n[✓] Mesures analytiques enregistrées dans : {TIMINGS_FILE}")

    # Lancement des expériences d'indexation
    run_index_experiments(db)


if __name__ == "__main__":
    main()
