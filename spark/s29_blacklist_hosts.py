"""
Job Spark S29 : Détection des hôtes communiquant avec des adresses IP en liste noire.
Jointure network_flows x ip_blacklist avec broadcast() de ip_blacklist (200 documents).
- Jointure principale sur dst_ip : hôtes internes contactant des IP blacklistées (C2, botnets).
- Test comparatif sur src_ip : flux entrants ou hôtes dont la source est blacklistée.
Agrégation par host_id : nombre de flux (flow_count) et volume total (total_bytes).
Résultats exportés dans results/spark_outputs/s29.csv.
"""

import os
import sys
from pyspark.sql.functions import broadcast, col, count, sum as spark_sum, desc

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import get_spark, read_collection, timed, save_csv


def compute_s29_dst(flows_df, bl_df):
    """Jointure sur dst_ip avec broadcast de la liste noire."""
    joined_dst = flows_df.join(
        broadcast(bl_df),
        flows_df.dst_ip == bl_df.ip,
        how="inner"
    )

    hosts_dst_df = (
        joined_dst
        .groupBy("host_id")
        .agg(
            count("*").alias("flow_count"),
            spark_sum("bytes").alias("total_bytes")
        )
        .orderBy(desc("flow_count"), desc("total_bytes"), "host_id")
    )
    return hosts_dst_df


def test_s29_src(flows_df, bl_df):
    """Test de la jointure alternative sur src_ip."""
    joined_src = flows_df.join(
        broadcast(bl_df),
        flows_df.src_ip == bl_df.ip,
        how="inner"
    )

    hosts_src_df = (
        joined_src
        .groupBy("host_id")
        .agg(
            count("*").alias("flow_count"),
            spark_sum("bytes").alias("total_bytes")
        )
    )
    return hosts_src_df


def main():
    spark = get_spark("SIEM-S29-Blacklist-Hosts")

    print("\n" + "=" * 80)
    print("      JOB S29 : HÔTES COMMUNIQUANT AVEC DES IP EN LISTE NOIRE (BROADCAST)")
    print("=" * 80)

    flows_df = read_collection(spark, "network_flows")
    bl_df = read_collection(spark, "ip_blacklist")

    # 1. Calcul principal sur dst_ip
    print("\n[*] Exécution de la jointure sur dst_ip avec broadcast(ip_blacklist)...")
    hosts_dst_df, elapsed_ms = timed("Calcul S29 (dst_ip)", lambda: compute_s29_dst(flows_df, bl_df))

    # Collecte des résultats dst_ip
    rows_dst = hosts_dst_df.collect()
    columns = ["host_id", "flow_count", "total_bytes"]
    nb_hosts_dst = len(rows_dst)

    print(f"\n[+] Nombre d'hôtes distincts détectés (dst_ip) : {nb_hosts_dst}")
    print(f"[+] Temps d'exécution : {elapsed_ms:.2f} ms")

    print("\n--- Aperçu des 5 premières lignes (dst_ip) ---")
    hosts_dst_df.show(5, truncate=False)

    # 2. Test comparatif sur src_ip
    print("\n[*] Test comparatif : jointure sur src_ip avec broadcast(ip_blacklist)...")
    hosts_src_df, elapsed_src_ms = timed("Test S29 (src_ip)", lambda: test_s29_src(flows_df, bl_df))
    nb_hosts_src = hosts_src_df.count()

    print(f"\n[+] Nombre d'hôtes distincts détectés (src_ip) : {nb_hosts_src}")
    print(f"[+] Temps du test src_ip : {elapsed_src_ms:.2f} ms")

    if nb_hosts_src == 0:
        print("  -> Analyse src_ip : 0 hôte trouvé. Les flux réseau modélisent des connexions")
        print("     sortantes initiées par des machines internes (src_ip privées de l'entreprise)")
        print("     vers des destinations externes (dst_ip). Aucun flux ne provient d'une IP blacklistée en source.")
    else:
        print(f"  -> {nb_hosts_src} hôtes trouvés en jointure source.")

    # 3. Sauvegarde CSV (sur dst_ip)
    csv_path = save_csv(rows_dst, columns, "s29.csv")
    print(f"\n[+] Fichier CSV sauvegardé : {csv_path}")

    # 4. Vérification du seuil attendu (au moins 35 hôtes)
    print("\n" + "=" * 80)
    print("                       BILAN DE L'EXÉCUTION S29")
    print("=" * 80)
    print(f"• Hôtes distincts contactant la liste noire (dst_ip) : {nb_hosts_dst} (Attendu : >= 35)")
    if nb_hosts_dst == 35:
        print("• Statut : VALIDÉ (Exactement 35 hôtes injectés par le scénario d'attaque S29)")
    elif nb_hosts_dst > 35:
        print(f"• Statut : VALIDÉ ({nb_hosts_dst} hôtes : 35 injectés + {nb_hosts_dst - 35} flux aléatoires tombés sur la liste noire)")
    else:
        print(f"• Statut : ANOMALIE ({nb_hosts_dst} < 35 hôtes attendus)")
    print("=" * 80 + "\n")

    spark.stop()


if __name__ == "__main__":
    main()
