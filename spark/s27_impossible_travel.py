"""
Job Spark S27 : Détection d'anomalies de type "Voyage Impossible" (Impossible Travel).
Recherche les utilisateurs dont deux connexions réussies consécutives proviennent de
pays différents avec un écart temporel strictement inférieur à 1 heure (3600 secondes).
Résultats exportés dans results/spark_outputs/s27.csv.
"""

import os
import sys
from pyspark.sql.window import Window
from pyspark.sql.functions import (
    col,
    lag,
    when,
    countDistinct,
    count,
    lit,
    desc
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import get_spark, read_collection, timed, save_csv


def compute_s27(auth_df):
    """
    Détecte les voyages impossibles sur les authentifications réussies.
    
    Justification du filtrage sur result == 'success' :
    1. Légitimité et criticité : Une authentification réussie prouve qu'une session active
       valide a été ouverte avec les identifiants de l'utilisateur. Deux connexions réussies
       dans des zones géographiques distantes en moins d'une heure révèlent une compromission
       avérée de compte (vol de session, tokens partagés ou identifiants exfiltrés).
    2. Distinction avec les attaques externes : Les tentatives en échec (result == 'failure')
       depuis l'étranger sont typiques d'attaques par force brute, pulvérisation (password spraying)
       ou botnets mondiaux qui ciblent les comptes sans détenir le mot de passe valide.
       Ces attaques sont détectées et traitées par le job S26 et la surveillance de volume d'échecs,
       et ne doivent pas polluer l'alerte de voyage impossible qui cible la présence physique/logique
       simultanée de sessions légitimes.
    """
    # 1. Filtrage sur les connexions réussies uniquement
    success_df = auth_df.filter(col("result") == "success")

    # 2. Spécification de la fenêtre par utilisateur, ordonnée chronologiquement
    window_user = Window.partitionBy("user_id").orderBy("timestamp")

    # 3. Calcul du pays précédent et du timestamp précédent via lag
    travel_df = (
        success_df
        .withColumn("current_country", col("geo.country"))
        .withColumn("prev_country", lag("geo.country", 1).over(window_user))
        .withColumn("prev_timestamp", lag("timestamp", 1).over(window_user))
        .withColumn(
            "delta_seconds",
            col("timestamp").cast("long") - col("prev_timestamp").cast("long")
        )
        # 4. Conservation des événements où le pays change en moins de 3600 secondes
        .filter(
            col("prev_country").isNotNull() &
            (col("current_country") != col("prev_country")) &
            (col("delta_seconds") < 3600) &
            (col("delta_seconds") >= 0)
        )
        .select(
            "user_id",
            "prev_country",
            "current_country",
            "delta_seconds",
            "prev_timestamp",
            col("timestamp").alias("current_timestamp")
        )
        .orderBy("delta_seconds", "user_id")
    )

    return travel_df


def main():
    spark = get_spark("SIEM-S27-Impossible-Travel")

    print("\n" + "=" * 80)
    print("      JOB S27 : DÉTECTION DE VOYAGE IMPOSSIBLE (< 1 HEURE, PAYS DIFFÉRENT)")
    print("=" * 80)

    auth_df = read_collection(spark, "authentications")

    # Exécution avec chronométrage
    result_df, elapsed_ms = timed("Calcul S27", lambda: compute_s27(auth_df))

    # Persistance en cache pour multiples comptages (distinct users, total events, FR/JP)
    result_df.cache()

    rows = result_df.collect()
    columns = [
        "user_id",
        "prev_country",
        "current_country",
        "delta_seconds",
        "prev_timestamp",
        "current_timestamp"
    ]

    total_events = len(rows)

    # Analyse des utilisateurs distincts
    distinct_users = set(r["user_id"] if isinstance(r, dict) else r.user_id for r in rows)
    nb_distinct_users = len(distinct_users)

    # Analyse de la part des cas FR <-> JP injectés
    fr_jp_events = [
        r for r in rows
        if ((r["prev_country"] if isinstance(r, dict) else r.prev_country) == "FR" and
            (r["current_country"] if isinstance(r, dict) else r.current_country) == "JP") or
           ((r["prev_country"] if isinstance(r, dict) else r.prev_country) == "JP" and
            (r["current_country"] if isinstance(r, dict) else r.current_country) == "FR")
    ]
    nb_fr_jp = len(fr_jp_events)
    fr_jp_users = set(r["user_id"] if isinstance(r, dict) else r.user_id for r in fr_jp_events)
    nb_fr_jp_users = len(fr_jp_users)

    pct_fr_jp_events = (nb_fr_jp / total_events * 100.0) if total_events > 0 else 0.0
    pct_fr_jp_users = (nb_fr_jp_users / nb_distinct_users * 100.0) if nb_distinct_users > 0 else 0.0

    print(f"\n[+] Nombre total d'événements de voyage impossible : {total_events}")
    print(f"[+] Nombre d'utilisateurs distincts concernés : {nb_distinct_users}")
    print(f"[+] Dont cas FR <-> JP injectés : {nb_fr_jp} événements ({nb_fr_jp_users} utilisateurs distincts)")
    print(f"[+] Proportion FR/JP parmi les utilisateurs : {pct_fr_jp_users:.2f}% ({nb_fr_jp_users}/{nb_distinct_users})")
    print(f"[+] Temps d'exécution : {elapsed_ms:.2f} ms")

    print("\n--- Aperçu des résultats (Top 10) ---")
    result_df.show(10, truncate=False)

    # Sauvegarde CSV
    csv_path = save_csv(rows, columns, "s27.csv")
    print(f"[+] Fichier CSV sauvegardé : {csv_path}")

    # Analyse du bilan
    print("\n" + "=" * 80)
    print("                       BILAN DE L'EXÉCUTION S27")
    print("=" * 80)
    print(f"• Utilisateurs distincts détectés : {nb_distinct_users} (Attendu : >= 35)")
    print(f"• Utilisateurs injectés FR <-> JP reconnus : {nb_fr_jp_users} / 35")
    nb_fp_users = nb_distinct_users - nb_fr_jp_users
    if nb_fp_users > 0:
        print(f"• Autres cas (bruit statistique aléatoire multi-pays) : {nb_fp_users} utilisateur(s)")
        print(f"• Taux de détection injectée : {pct_fr_jp_users:.2f}% FR/JP vs {100.0 - pct_fr_jp_users:.2f}% bruit")
    else:
        print("• Bruit statistique : 0 faux positif détecté (100% injectés)")
    print("=" * 80 + "\n")

    spark.stop()


if __name__ == "__main__":
    main()
