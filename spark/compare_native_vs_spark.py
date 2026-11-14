"""
Comparaison de performance et validation des résultats : MongoDB Natif vs Apache Spark.
Porte sur trois requêtes analytiques représentatives :
  - A16 : Statistiques journalières (succès / échecs) sur 30 jours (authentications)
  - A17 : Top 10 des adresses IP par nombre d'échecs sur une journée (authentications)
  - A20 : Volume d'octets et flux par hôte sur une journée (network_flows)

Protocole de mesure :
  - Natif : Appels des fonctions pymongo depuis l'hôte (5 itérations, moyenne retenue).
  - Spark : Versions DataFrames distribuées sur le cluster (6 itérations, la 1ère écartée pour démarrage à froid).
            Mesure séparée de la lecture (.cache() + .count()) et du calcul (.collect()).
  - Validation : Rapprochement exact des résultats produits entre Natif et Spark.
  - Export : Enregistrement dans results/spark_vs_native.csv (requete, methode, temps_ms, nb_resultats).
"""

import os
import sys
import time
import json
import csv
import subprocess
from datetime import datetime, timedelta, timezone

TEMP_EXCHANGE_FILE = "/opt/results/spark_comparison_temp.json"
TEMP_EXCHANGE_HOST = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "results",
    "spark_comparison_temp.json"
)
OUTPUT_CSV_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "results",
    "spark_vs_native.csv"
)


# ==============================================================================
# 1. LOGIQUE SPARK (Exécutée dans le conteneur via spark-submit)
# ==============================================================================

def run_spark_worker(start_iso: str, end_iso: str):
    """
    Exécute le benchmark côté Spark dans le conteneur :
    6 itérations (la 1ère écartée pour le warmup).
    Mesure séparément la lecture et le calcul.
    """
    from pyspark.sql.functions import col, date_format, sum as spark_sum, count as spark_count, when, desc, lit
    from common import get_spark, read_collection

    spark = get_spark("SIEM-Compare-Native-vs-Spark")
    spark.conf.set("spark.sql.session.timeZone", "UTC")

    print("[Spark] Démarrage du benchmark Spark (6 itérations, warmup écarté)...")

    start_dt_str = start_iso.replace("T", " ")[:19]
    end_dt_str = end_iso.replace("T", " ")[:19]

    spark_benchmarks = {}

    # --------------------------------------------------------------------------
    # A16 : Statistiques journalières
    # --------------------------------------------------------------------------
    print("[Spark] Benchmark A16...")
    a16_lectures, a16_calculs = [], []
    a16_sample_results = []

    for i in range(6):
        spark.catalog.clearCache()
        # Lecture
        t0_read = time.perf_counter()
        auth_df = read_collection(spark, "authentications").cache()
        _ = auth_df.count()
        read_ms = (time.perf_counter() - t0_read) * 1000.0

        # Calcul
        t0_calc = time.perf_counter()
        df_a16 = (
            auth_df
            .withColumn("day", date_format(col("timestamp"), "yyyy-MM-dd"))
            .groupBy("day")
            .agg(
                spark_sum(when(col("result") == "success", 1).otherwise(0)).alias("total_succes"),
                spark_sum(when(col("result") == "failure", 1).otherwise(0)).alias("total_echecs"),
                spark_count("*").alias("total_connexions")
            )
            .orderBy("day")
        )
        rows_a16 = df_a16.collect()
        calc_ms = (time.perf_counter() - t0_calc) * 1000.0

        if i > 0:  # On écarte la 1ère itération (démarrage à froid)
            a16_lectures.append(read_ms)
            a16_calculs.append(calc_ms)
        else:
            print(f"  -> A16 Run 0 (warmup) : lecture {read_ms:.2f} ms, calcul {calc_ms:.2f} ms")

        if i == 5:
            a16_sample_results = [
                {
                    "day": r.day,
                    "total_succes": int(r.total_succes),
                    "total_echecs": int(r.total_echecs),
                    "total_connexions": int(r.total_connexions)
                }
                for r in rows_a16
            ]

    spark_benchmarks["A16"] = {
        "lecture_ms": sum(a16_lectures) / len(a16_lectures),
        "calcul_ms": sum(a16_calculs) / len(a16_calculs),
        "total_ms": (sum(a16_lectures) + sum(a16_calculs)) / len(a16_lectures),
        "nb_resultats": len(a16_sample_results),
        "data": a16_sample_results
    }

    # --------------------------------------------------------------------------
    # A17 : Top 10 IP échecs sur une journée
    # --------------------------------------------------------------------------
    print("[Spark] Benchmark A17...")
    a17_lectures, a17_calculs = [], []
    a17_sample_results = []

    for i in range(6):
        spark.catalog.clearCache()
        # Lecture
        t0_read = time.perf_counter()
        auth_df = read_collection(spark, "authentications").cache()
        _ = auth_df.count()
        read_ms = (time.perf_counter() - t0_read) * 1000.0

        # Calcul
        t0_calc = time.perf_counter()
        df_a17 = (
            auth_df
            .filter(
                (col("result") == "failure") &
                (col("timestamp") >= lit(start_dt_str)) &
                (col("timestamp") <= lit(end_dt_str))
            )
            .groupBy("source_ip")
            .count()
            .orderBy(desc("count"), "source_ip")
            .limit(10)
        )
        rows_a17 = df_a17.collect()
        calc_ms = (time.perf_counter() - t0_calc) * 1000.0

        if i > 0:
            a17_lectures.append(read_ms)
            a17_calculs.append(calc_ms)
        else:
            print(f"  -> A17 Run 0 (warmup) : lecture {read_ms:.2f} ms, calcul {calc_ms:.2f} ms")

        if i == 5:
            a17_sample_results = [
                {"source_ip": r.source_ip, "count": int(r["count"])}
                for r in rows_a17
            ]

    spark_benchmarks["A17"] = {
        "lecture_ms": sum(a17_lectures) / len(a17_lectures),
        "calcul_ms": sum(a17_calculs) / len(a17_calculs),
        "total_ms": (sum(a17_lectures) + sum(a17_calculs)) / len(a17_lectures),
        "nb_resultats": len(a17_sample_results),
        "data": a17_sample_results
    }

    # --------------------------------------------------------------------------
    # A20 : Octets par hôte sur une journée
    # --------------------------------------------------------------------------
    print("[Spark] Benchmark A20...")
    a20_lectures, a20_calculs = [], []
    a20_sample_results = []

    for i in range(6):
        spark.catalog.clearCache()
        # Lecture
        t0_read = time.perf_counter()
        flows_df = read_collection(spark, "network_flows").cache()
        _ = flows_df.count()
        read_ms = (time.perf_counter() - t0_read) * 1000.0

        # Calcul
        t0_calc = time.perf_counter()
        df_a20 = (
            flows_df
            .filter(
                (col("timestamp") >= lit(start_dt_str)) &
                (col("timestamp") <= lit(end_dt_str))
            )
            .groupBy("host_id")
            .agg(
                spark_sum("bytes").alias("total_bytes"),
                spark_count("*").alias("nb_flux")
            )
            .orderBy(desc("total_bytes"), desc("nb_flux"), "host_id")
            .limit(20)
        )
        rows_a20 = df_a20.collect()
        calc_ms = (time.perf_counter() - t0_calc) * 1000.0

        if i > 0:
            a20_lectures.append(read_ms)
            a20_calculs.append(calc_ms)
        else:
            print(f"  -> A20 Run 0 (warmup) : lecture {read_ms:.2f} ms, calcul {calc_ms:.2f} ms")

        if i == 5:
            a20_sample_results = [
                {
                    "host_id": r.host_id,
                    "total_bytes": int(r.total_bytes),
                    "nb_flux": int(r.nb_flux)
                }
                for r in rows_a20
            ]

    spark_benchmarks["A20"] = {
        "lecture_ms": sum(a20_lectures) / len(a20_lectures),
        "calcul_ms": sum(a20_calculs) / len(a20_calculs),
        "total_ms": (sum(a20_lectures) + sum(a20_calculs)) / len(a20_lectures),
        "nb_resultats": len(a20_sample_results),
        "data": a20_sample_results
    }

    # Sauvegarde du fichier temporaire d'échange
    os.makedirs(os.path.dirname(TEMP_EXCHANGE_FILE), exist_ok=True)
    with open(TEMP_EXCHANGE_FILE, "w", encoding="utf-8") as f:
        json.dump(spark_benchmarks, f, indent=2)

    print(f"[Spark] Benchmark terminé. Données écrites dans {TEMP_EXCHANGE_FILE}")
    spark.stop()


# ==============================================================================
# 2. LOGIQUE NATIVE & COORDINATEUR (Exécutée sur la machine hôte)
# ==============================================================================

def run_native_benchmark(db, target_day: datetime):
    """
    Exécute les fonctions de queries/analytical.py depuis l'hôte (5 itérations).
    """
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "queries"))
    from analytical import a16_daily_auth_stats, a17_top10_failed_ips_daily, a20_bytes_per_host_daily

    native_benchmarks = {}

    # A16
    print("[Natif] Benchmark A16 (5 itérations)...")
    a16_times = []
    a16_res = []
    for _ in range(5):
        t0 = time.perf_counter()
        a16_res = a16_daily_auth_stats(db)
        a16_times.append((time.perf_counter() - t0) * 1000.0)

    native_benchmarks["A16"] = {
        "temps_ms": sum(a16_times) / len(a16_times),
        "nb_resultats": len(a16_res),
        "data": [
            {
                "day": r["_id"],
                "total_succes": r["total_succes"],
                "total_echecs": r["total_echecs"],
                "total_connexions": r["total_connexions"]
            }
            for r in a16_res
        ]
    }

    # A17
    print("[Natif] Benchmark A17 (5 itérations)...")
    a17_times = []
    a17_res = []
    for _ in range(5):
        t0 = time.perf_counter()
        a17_res = a17_top10_failed_ips_daily(db, target_day)
        a17_times.append((time.perf_counter() - t0) * 1000.0)

    native_benchmarks["A17"] = {
        "temps_ms": sum(a17_times) / len(a17_times),
        "nb_resultats": len(a17_res),
        "data": [
            {"source_ip": r["_id"], "count": r["count"]}
            for r in a17_res
        ]
    }

    # A20
    print("[Natif] Benchmark A20 (5 itérations)...")
    a20_times = []
    a20_res = []
    for _ in range(5):
        t0 = time.perf_counter()
        a20_res = a20_bytes_per_host_daily(db, target_day)
        a20_times.append((time.perf_counter() - t0) * 1000.0)

    native_benchmarks["A20"] = {
        "temps_ms": sum(a20_times) / len(a20_times),
        "nb_resultats": len(a20_res),
        "data": [
            {
                "host_id": r["_id"],
                "total_bytes": r["total_bytes"],
                "nb_flux": r["nb_flux"]
            }
            for r in a20_res
        ]
    }

    return native_benchmarks


def verify_results_equality(native_data, spark_data):
    """
    Vérifie l'exactitude stricte des valeurs produites entre Natif et Spark.
    """
    print("\n" + "=" * 90)
    print("               VÉRIFICATION DE L'ÉGALITÉ STRICTE DES RÉSULTATS")
    print("=" * 90)

    all_matched = True

    # 1. Vérification A16
    nat_a16 = {r["day"]: r for r in native_data["A16"]["data"]}
    spk_a16 = {r["day"]: r for r in spark_data["A16"]["data"]}

    if set(nat_a16.keys()) != set(spk_a16.keys()):
        print(f"[!] A16 ERREUR : Les dates divergent (Natif {len(nat_a16)}, Spark {len(spk_a16)})")
        all_matched = False
    else:
        diff_count = 0
        for day, n_row in nat_a16.items():
            s_row = spk_a16[day]
            if (n_row["total_succes"] != s_row["total_succes"] or
                n_row["total_echecs"] != s_row["total_echecs"] or
                n_row["total_connexions"] != s_row["total_connexions"]):
                print(f"  [!] A16 Divergence sur {day}: Natif={n_row} vs Spark={s_row}")
                diff_count += 1
        if diff_count == 0:
            print(f"[✓] A16 : CONCORDANCE PARFAITE sur l'ensemble des {len(nat_a16)} jours !")
        else:
            all_matched = False

    # 2. Vérification A17
    nat_a17 = native_data["A17"]["data"]
    spk_a17 = spark_data["A17"]["data"]

    if len(nat_a17) != len(spk_a17):
        print(f"[!] A17 ERREUR : Nombre d'IP différent (Natif {len(nat_a17)}, Spark {len(spk_a17)})")
        all_matched = False
    else:
        nat_dict = {r["source_ip"]: r["count"] for r in nat_a17}
        spk_dict = {r["source_ip"]: r["count"] for r in spk_a17}
        if nat_dict == spk_dict:
            print(f"[✓] A17 : CONCORDANCE PARFAITE sur le Top 10 IP et les comptes d'échecs (10/10) !")
        else:
            print(f"  [!] A17 Divergence : Natif={nat_dict} vs Spark={spk_dict}")
            all_matched = False

    # 3. Vérification A20
    nat_a20 = native_data["A20"]["data"]
    spk_a20 = spark_data["A20"]["data"]

    if len(nat_a20) != len(spk_a20):
        print(f"[!] A20 ERREUR : Nombre d'hôtes différent (Natif {len(nat_a20)}, Spark {len(spk_a20)})")
        all_matched = False
    else:
        nat_h_dict = {r["host_id"]: (r["total_bytes"], r["nb_flux"]) for r in nat_a20}
        spk_h_dict = {r["host_id"]: (r["total_bytes"], r["nb_flux"]) for r in spk_a20}
        if nat_h_dict == spk_h_dict:
            print(f"[✓] A20 : CONCORDANCE PARFAITE sur le Top 20 hôtes (octets et flux) (20/20) !")
        else:
            print(f"  [!] A20 Divergence : Natif={nat_h_dict} vs Spark={spk_h_dict}")
            all_matched = False

    print("=" * 90 + "\n")
    return all_matched


def main_coordinator():
    print("=" * 90)
    print("       COMPARATIF DE PERFORMANCE : MONGODB NATIF vs APACHE SPARK (A16, A17, A20)")
    print("=" * 90)

    # Paramètres identiques
    target_day = datetime.now(timezone.utc) - timedelta(days=7)
    start_dt = datetime(target_day.year, target_day.month, target_day.day, 0, 0, 0, tzinfo=timezone.utc)
    end_dt = datetime(target_day.year, target_day.month, target_day.day, 23, 59, 59, tzinfo=timezone.utc)

    print(f"\n[*] Paramètres partagés :")
    print(f"  • Date cible (A17 & A20) : {target_day.date()}")
    print(f"  • Fenêtre temporelle      : {start_dt.isoformat()} -> {end_dt.isoformat()}\n")

    # 1. Exécution côté Natif sur la machine hôte
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "queries"))
    from analytical import get_database
    db = get_database()
    native_benchmarks = run_native_benchmark(db, target_day)

    # 2. Exécution côté Spark dans le conteneur Docker via spark-submit
    print("\n[*] Lancement du benchmark Spark dans le conteneur siem-spark-master...")
    spark_jars = (
        "/tmp/.ivy2/jars/org.mongodb.spark_mongo-spark-connector_2.12-10.3.0.jar,"
        "/tmp/.ivy2/jars/org.mongodb_mongodb-driver-sync-4.8.2.jar,"
        "/tmp/.ivy2/jars/org.mongodb_mongodb-driver-core-4.8.2.jar,"
        "/tmp/.ivy2/jars/org.mongodb_bson-4.8.2.jar,"
        "/tmp/.ivy2/jars/org.mongodb_bson-record-codec-4.8.2.jar"
    )
    spark_submit_cmd = [
        "docker", "exec", "siem-spark-master",
        "/opt/spark/bin/spark-submit",
        "--master", "spark://spark-master:7077",
        "--jars", spark_jars,
        "--conf", "spark.mongodb.read.connection.uri=mongodb://mongo1:27018,mongo2:27019,mongo3:27020/?replicaSet=rs0",
        "/opt/spark-apps/compare_native_vs_spark.py",
        "--spark-worker",
        start_dt.isoformat(),
        end_dt.isoformat()
    ]

    res = subprocess.run(spark_submit_cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[!] Erreur lors de l'exécution Spark :\n{res.stderr}\n{res.stdout}")
        sys.exit(1)
    else:
        print("[*] Job Spark terminé avec succès.")

    # 3. Récupération des résultats Spark depuis le fichier partagé
    if not os.path.exists(TEMP_EXCHANGE_HOST):
        print(f"[!] Fichier de résultat introuvable : {TEMP_EXCHANGE_HOST}")
        sys.exit(1)

    with open(TEMP_EXCHANGE_HOST, "r", encoding="utf-8") as f:
        spark_benchmarks = json.load(f)

    # 4. Vérification de la stricte conformité des résultats
    is_valid = verify_results_equality(native_benchmarks, spark_benchmarks)

    # 5. Écriture du fichier results/spark_vs_native.csv
    # Colonnes demandées : requete, methode, temps_ms, nb_resultats
    csv_rows = []
    for q in ["A16", "A17", "A20"]:
        # Ligne Native
        csv_rows.append([
            q,
            "natif",
            f"{native_benchmarks[q]['temps_ms']:.2f}",
            native_benchmarks[q]["nb_resultats"]
        ])
        # Lignes Spark (lecture, calcul, total)
        csv_rows.append([
            q,
            "spark_lecture",
            f"{spark_benchmarks[q]['lecture_ms']:.2f}",
            spark_benchmarks[q]["nb_resultats"]
        ])
        csv_rows.append([
            q,
            "spark_calcul",
            f"{spark_benchmarks[q]['calcul_ms']:.2f}",
            spark_benchmarks[q]["nb_resultats"]
        ])
        csv_rows.append([
            q,
            "spark_total",
            f"{spark_benchmarks[q]['total_ms']:.2f}",
            spark_benchmarks[q]["nb_resultats"]
        ])

    os.makedirs(os.path.dirname(OUTPUT_CSV_FILE), exist_ok=True)
    with open(OUTPUT_CSV_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["requete", "methode", "temps_ms", "nb_resultats"])
        for row in csv_rows:
            writer.writerow(row)

    print(f"[+] Fichier CSV généré : {OUTPUT_CSV_FILE}")

    # 6. Affichage du tableau comparatif complet
    print("\n" + "=" * 105)
    print(f"{'TABLEAU COMPARATIF : MONGODB NATIF vs APACHE SPARK':^105}")
    print("=" * 105)
    print(f"{'Requête':<8} | {'Natif (ms)':<12} | {'Spark Lect (ms)':<16} | {'Spark Calc (ms)':<16} | {'Spark Total (ms)':<16} | {'Ratio Total/Nat':<15} | {'Résultats':<10}")
    print("-" * 105)

    for q in ["A16", "A17", "A20"]:
        nat_t = native_benchmarks[q]["temps_ms"]
        spk_read = spark_benchmarks[q]["lecture_ms"]
        spk_calc = spark_benchmarks[q]["calcul_ms"]
        spk_tot = spark_benchmarks[q]["total_ms"]
        nb_res = native_benchmarks[q]["nb_resultats"]
        ratio = spk_tot / nat_t if nat_t > 0 else 0.0

        print(
            f"{q:<8} | "
            f"{nat_t:>12.2f} | "
            f"{spk_read:>16.2f} | "
            f"{spk_calc:>16.2f} | "
            f"{spk_tot:>16.2f} | "
            f"{ratio:>14.2f}x | "
            f"{nb_res:>10}"
        )
    print("=" * 105 + "\n")

    # Nettoyage fichier temporaire
    try:
        os.remove(TEMP_EXCHANGE_HOST)
    except Exception:
        pass


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--spark-worker":
        # Mode worker exécuté à l'intérieur du conteneur Spark
        start_arg = sys.argv[2]
        end_arg = sys.argv[3]
        run_spark_worker(start_arg, end_arg)
    else:
        # Mode coordinateur exécuté depuis la machine hôte
        main_coordinator()
