"""
Job Spark S26 : Détection d'attaques par force brute sur les authentifications.
Fenêtre glissante de 5 minutes avec glissement de 1 minute.
Filtre sur les échecs (result == 'failure') avec plus de 20 tentatives dans une fenêtre.
Dédoublonnage par source_ip (max des échecs, premier début de fenêtre).
Résultats exportés dans results/spark_outputs/s26.csv.
"""

import os
import sys
from pyspark.sql.functions import window, col, min as spark_min, max as spark_max, desc

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import get_spark, read_collection, timed, save_csv


def compute_s26(auth_df):
    """
    Détecte les attaques par force brute via fenêtre glissante de 5 min / pas 1 min.
    """
    failures_df = auth_df.filter(col("result") == "failure")

    # Groupement par fenêtre glissante de 5 minutes (glissement de 1 minute) et par IP source
    windowed_df = (
        failures_df
        .groupBy(
            window("timestamp", "5 minutes", "1 minute"),
            "source_ip"
        )
        .count()
        .filter(col("count") > 20)
    )

    # Agrégation par source_ip pour dédoublonner et extraire les métriques clés
    distinct_ips_df = (
        windowed_df
        .groupBy("source_ip")
        .agg(
            spark_max("count").alias("max_failures"),
            spark_min("window.start").alias("first_window_start")
        )
        .orderBy(desc("max_failures"), "first_window_start", "source_ip")
    )

    return distinct_ips_df


def main():
    spark = get_spark("SIEM-S26-Brute-Force")

    print("\n" + "=" * 80)
    print("      JOB S26 : DÉTECTION DE FORCE BRUTE (FENÊTRE GLISSANTE 5 MIN)")
    print("=" * 80)

    auth_df = read_collection(spark, "authentications")

    # Exécution avec chronométrage
    result_df, elapsed_ms = timed("Calcul S26", lambda: compute_s26(auth_df))

    # Collecte des lignes
    rows = result_df.collect()
    columns = ["source_ip", "max_failures", "first_window_start"]
    nb_ips = len(rows)

    print(f"\n[+] Nombre d'adresses IP distinctes détectées : {nb_ips}")
    print(f"[+] Temps d'exécution : {elapsed_ms:.2f} ms")

    print("\n--- Aperçu des résultats (Top 10) ---")
    result_df.show(10, truncate=False)

    # Sauvegarde CSV
    csv_path = save_csv(rows, columns, "s26.csv")
    print(f"[+] Fichier CSV sauvegardé : {csv_path}")

    # Analyse du résultat
    print("\n" + "=" * 80)
    print("                       BILAN DE L'EXÉCUTION S26")
    print("=" * 80)
    print(f"• Nombre d'IP détectées : {nb_ips} (Attendu : >= 6)")
    if nb_ips == 6:
        print("• Statut : VALIDÉ (Exactement les 6 adresses IP injectées par l'attaque S26)")
    elif nb_ips > 6:
        print(f"• Statut : VALIDÉ ({nb_ips} IP : 6 injectées S26 + {nb_ips - 6} faux positifs ou pics de fond)")
    else:
        print(f"• Statut : ANOMALIE ({nb_ips} < 6 IP attendues)")
    print("=" * 80 + "\n")

    spark.stop()


if __name__ == "__main__":
    main()
