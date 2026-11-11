"""
Script d'analyse globale Spark : Exécution séquentielle de S26 à S30.
Mesure séparément pour chaque requête :
  - Le temps de lecture (chargement des collections MongoDB + mise en cache .cache() + .count())
  - Le temps de calcul (transformations, jointures, agrégations + .collect())
  - Le temps total (lecture + calcul)
  - Le nombre de résultats retournés
Enregistre les résultats dans results/spark_timings.csv (ne touche JAMAIS à results/timings.csv).
"""

import os
import sys
import time
import csv
from pyspark.sql.functions import col, count, when, round as spark_round, desc

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import get_spark, read_collection
from s26_brute_force import compute_s26
from s27_impossible_travel import compute_s27
from s29_blacklist_hosts import compute_s29_dst
from s30_risk_score import compute_s30


def compute_s28_from_dfs(auth_df, users_df):
    """Calcul S28 à partir des DataFrames déjà chargés et mis en cache."""
    joined_df = auth_df.join(
        users_df.select("user_id", "department", "role"),
        on="user_id",
        how="inner"
    )

    result_df = (
        joined_df
        .groupBy("department", "role")
        .agg(
            count("*").alias("total_authentications"),
            count(when(col("result") == "failure", 1)).alias("failed_authentications"),
            count(when(col("result") == "success", 1)).alias("successful_authentications"),
            spark_round(
                count(when(col("result") == "failure", 1)) / count("*"),
                4
            ).alias("failure_rate")
        )
        .orderBy(desc("failure_rate"), desc("total_authentications"))
    )
    return result_df


def save_spark_timings(timings: list) -> str:
    """
    Enregistre les temps de calcul Spark dans results/spark_timings.csv.
    ATTENTION : N'écrit JAMAIS dans results/timings.csv.
    """
    if os.path.exists("/opt/results"):
        output_dir = "/opt/results"
    else:
        output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")

    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, "spark_timings.csv")

    with open(filepath, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["requete", "lecture_ms", "calcul_ms", "total_ms", "nb_resultats"])
        for row in timings:
            writer.writerow([
                row["requete"],
                f"{row['lecture_ms']:.2f}",
                f"{row['calcul_ms']:.2f}",
                f"{row['total_ms']:.2f}",
                row["nb_resultats"]
            ])

    return filepath


def run_analysis():
    spark = get_spark("SIEM-Spark-Analysis-S26-S30")

    print("\n" + "=" * 90)
    print("       BENCHMARK SPARK GLOBAL : MESURE SÉPARÉE LECTURE / CALCUL (S26 à S30)")
    print("=" * 90)

    timings = []

    # ==========================================================================
    # S26 : FORCE BRUTE (Fenêtre glissante 5 min)
    # ==========================================================================
    print("\n>>> Exécution S26 : Détection de force brute...")
    spark.catalog.clearCache()

    # 1. Lecture MongoDB + cache
    t_start_read = time.perf_counter()
    auth_df = read_collection(spark, "authentications").cache()
    _ = auth_df.count()  # Action forçant le chargement en mémoire depuis MongoDB
    lecture_s26_ms = (time.perf_counter() - t_start_read) * 1000.0

    # 2. Calcul
    t_start_calc = time.perf_counter()
    s26_df = compute_s26(auth_df)
    s26_rows = s26_df.collect()
    calcul_s26_ms = (time.perf_counter() - t_start_calc) * 1000.0

    total_s26_ms = lecture_s26_ms + calcul_s26_ms
    nb_s26 = len(s26_rows)
    print(f"  [S26] Lecture: {lecture_s26_ms:.2f} ms | Calcul: {calcul_s26_ms:.2f} ms | Total: {total_s26_ms:.2f} ms | Résultats: {nb_s26}")

    timings.append({
        "requete": "S26",
        "lecture_ms": lecture_s26_ms,
        "calcul_ms": calcul_s26_ms,
        "total_ms": total_s26_ms,
        "nb_resultats": nb_s26
    })

    # ==========================================================================
    # S27 : VOYAGE IMPOSSIBLE (< 1h, pays différent)
    # ==========================================================================
    print("\n>>> Exécution S27 : Voyage impossible...")
    spark.catalog.clearCache()

    # 1. Lecture MongoDB + cache
    t_start_read = time.perf_counter()
    auth_df = read_collection(spark, "authentications").cache()
    _ = auth_df.count()
    lecture_s27_ms = (time.perf_counter() - t_start_read) * 1000.0

    # 2. Calcul
    t_start_calc = time.perf_counter()
    s27_df = compute_s27(auth_df)
    s27_rows = s27_df.collect()
    calcul_s27_ms = (time.perf_counter() - t_start_calc) * 1000.0

    total_s27_ms = lecture_s27_ms + calcul_s27_ms
    nb_s27 = len(s27_rows)
    print(f"  [S27] Lecture: {lecture_s27_ms:.2f} ms | Calcul: {calcul_s27_ms:.2f} ms | Total: {total_s27_ms:.2f} ms | Résultats: {nb_s27}")

    timings.append({
        "requete": "S27",
        "lecture_ms": lecture_s27_ms,
        "calcul_ms": calcul_s27_ms,
        "total_ms": total_s27_ms,
        "nb_resultats": nb_s27
    })

    # ==========================================================================
    # S28 : TAUX D'ÉCHEC PAR DÉPARTEMENT ET RÔLE (Jointure authentications x users)
    # ==========================================================================
    print("\n>>> Exécution S28 : Taux d'échec département & rôle...")
    spark.catalog.clearCache()

    # 1. Lecture MongoDB + cache (authentications et users)
    t_start_read = time.perf_counter()
    auth_df = read_collection(spark, "authentications").cache()
    users_df = read_collection(spark, "users").cache()
    _ = auth_df.count()
    _ = users_df.count()
    lecture_s28_ms = (time.perf_counter() - t_start_read) * 1000.0

    # 2. Calcul
    t_start_calc = time.perf_counter()
    s28_df = compute_s28_from_dfs(auth_df, users_df)
    s28_rows = s28_df.collect()
    calcul_s28_ms = (time.perf_counter() - t_start_calc) * 1000.0

    total_s28_ms = lecture_s28_ms + calcul_s28_ms
    nb_s28 = len(s28_rows)
    print(f"  [S28] Lecture: {lecture_s28_ms:.2f} ms | Calcul: {calcul_s28_ms:.2f} ms | Total: {total_s28_ms:.2f} ms | Résultats: {nb_s28}")

    timings.append({
        "requete": "S28",
        "lecture_ms": lecture_s28_ms,
        "calcul_ms": calcul_s28_ms,
        "total_ms": total_s28_ms,
        "nb_resultats": nb_s28
    })

    # ==========================================================================
    # S29 : HÔTES CONTACTANT UNE IP EN LISTE NOIRE (Jointure network_flows x blacklist)
    # ==========================================================================
    print("\n>>> Exécution S29 : Hôtes communicant avec ip_blacklist...")
    spark.catalog.clearCache()

    # 1. Lecture MongoDB + cache (network_flows et ip_blacklist)
    t_start_read = time.perf_counter()
    flows_df = read_collection(spark, "network_flows").cache()
    bl_df = read_collection(spark, "ip_blacklist").cache()
    _ = flows_df.count()
    _ = bl_df.count()
    lecture_s29_ms = (time.perf_counter() - t_start_read) * 1000.0

    # 2. Calcul
    t_start_calc = time.perf_counter()
    s29_df = compute_s29_dst(flows_df, bl_df)
    s29_rows = s29_df.collect()
    calcul_s29_ms = (time.perf_counter() - t_start_calc) * 1000.0

    total_s29_ms = lecture_s29_ms + calcul_s29_ms
    nb_s29 = len(s29_rows)
    print(f"  [S29] Lecture: {lecture_s29_ms:.2f} ms | Calcul: {calcul_s29_ms:.2f} ms | Total: {total_s29_ms:.2f} ms | Résultats: {nb_s29}")

    timings.append({
        "requete": "S29",
        "lecture_ms": lecture_s29_ms,
        "calcul_ms": calcul_s29_ms,
        "total_ms": total_s29_ms,
        "nb_resultats": nb_s29
    })

    # ==========================================================================
    # S30 : SCORE DE RISQUE UTILISATEUR TOP 20
    # ==========================================================================
    print("\n>>> Exécution S30 : Score de risque utilisateur (Top 20)...")
    spark.catalog.clearCache()

    # 1. Lecture MongoDB + cache (authentications, users, ip_blacklist)
    t_start_read = time.perf_counter()
    auth_df = read_collection(spark, "authentications").cache()
    users_df = read_collection(spark, "users").cache()
    bl_df = read_collection(spark, "ip_blacklist").cache()
    _ = auth_df.count()
    _ = users_df.count()
    _ = bl_df.count()
    lecture_s30_ms = (time.perf_counter() - t_start_read) * 1000.0

    # 2. Calcul
    t_start_calc = time.perf_counter()
    s30_top20_df, _, _ = compute_s30(spark, auth_df, users_df, bl_df)
    s30_rows = s30_top20_df.collect()
    calcul_s30_ms = (time.perf_counter() - t_start_calc) * 1000.0

    total_s30_ms = lecture_s30_ms + calcul_s30_ms
    nb_s30 = len(s30_rows)
    print(f"  [S30] Lecture: {lecture_s30_ms:.2f} ms | Calcul: {calcul_s30_ms:.2f} ms | Total: {total_s30_ms:.2f} ms | Résultats: {nb_s30}")

    timings.append({
        "requete": "S30",
        "lecture_ms": lecture_s30_ms,
        "calcul_ms": calcul_s30_ms,
        "total_ms": total_s30_ms,
        "nb_resultats": nb_s30
    })

    # ==========================================================================
    # ENREGISTREMENT DANS results/spark_timings.csv
    # ==========================================================================
    csv_file = save_spark_timings(timings)
    print(f"\n[+] Résultats écrits dans : {csv_file}")

    print("\n" + "=" * 90)
    print("                     TABLEAU RÉCAPITULATIF DES TEMPS SPARK")
    print("=" * 90)
    print(f"{'Requête':<10} | {'Lecture (ms)':<15} | {'Calcul (ms)':<15} | {'Total (ms)':<15} | {'Nb Résultats':<12}")
    print("-" * 90)
    for t in timings:
        print(f"{t['requete']:<10} | {t['lecture_ms']:>15.2f} | {t['calcul_ms']:>15.2f} | {t['total_ms']:>15.2f} | {t['nb_resultats']:>12}")
    print("=" * 90 + "\n")

    spark.stop()


if __name__ == "__main__":
    run_analysis()
