"""
Job Spark S28 : Taux d'échec d'authentification par département et rôle.
Jointure explicite authentications x users sur user_id.
Agrégation par department et role, calcul du taux d'échec (échecs / total),
trié par taux d'échec décroissant.
Résultats exportés dans results/spark_outputs/s28.csv.
"""

import os
import sys
from pyspark.sql.functions import col, count, when, round as spark_round, desc

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import get_spark, read_collection, timed, save_csv


def compute_s28(spark):
    auth_df = read_collection(spark, "authentications")
    users_df = read_collection(spark, "users")

    # Jointure explicite sur user_id (pas le champ dénormalisé user_department)
    joined_df = auth_df.join(
        users_df.select("user_id", "department", "role"),
        on="user_id",
        how="inner"
    )

    # Calcul des métriques par département et rôle
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


def main():
    spark = get_spark("SIEM-S28-Failure-Rate")

    print("\n" + "=" * 80)
    print("      JOB S28 : TAUX D'ÉCHEC D'AUTHENTIFICATION PAR DÉPARTEMENT & RÔLE")
    print("=" * 80)

    # Exécution avec mesure de temps
    df, elapsed_ms = timed("Calcul S28", lambda: compute_s28(spark))

    # Collecte des lignes pour affichage et sauvegarde
    rows = df.collect()
    columns = ["department", "role", "total_authentications", "failed_authentications",
               "successful_authentications", "failure_rate"]

    print(f"\n[+] Nombre de groupes (department x role) : {len(rows)}")
    print(f"[+] Temps d'exécution : {elapsed_ms:.2f} ms")

    print("\n--- Aperçu des résultats (Top 10) ---")
    df.show(10, truncate=False)

    # Sauvegarde CSV
    csv_path = save_csv(rows, columns, "s28.csv")
    print(f"[+] Fichier CSV sauvegardé : {csv_path}")

    spark.stop()


if __name__ == "__main__":
    main()
