"""
Script d'inspection des schémas réels détectés par Spark pour les collections MongoDB :
- authentications
- users
- network_flows
- ip_blacklist

Affiche printSchema() et 3 lignes pour chaque collection, puis inspecte :
1. Le type exact du champ timestamp (TimestampType vs StringType).
2. La structure du champ geo (StructType, sous-champs geo.country, etc.).
3. La localisation de l'adresse IP dans ip_blacklist (_id vs champ ip).
"""

import os
import sys

# Assure l'importation de common.py dans le même dossier
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import get_spark, read_collection

COLLECTIONS_TO_INSPECT = [
    "authentications",
    "users",
    "network_flows",
    "ip_blacklist"
]


def main():
    spark = get_spark("SIEM-Inspect-Schemas")

    print("\n" + "=" * 80)
    print("           INSPECTION DES SCHÉMAS ET EXEMPLES DE DONNÉES (SPARK)")
    print("=" * 80)

    inspected_dfs = {}

    for name in COLLECTIONS_TO_INSPECT:
        print("\n" + "#" * 80)
        print(f" COLLECTION : {name.upper()}")
        print("#" * 80)

        df = read_collection(spark, name)
        inspected_dfs[name] = df

        print(f"\n--- Schéma détecté par Spark ({name}) ---")
        df.printSchema()

        print(f"\n--- Échantillon de 3 lignes ({name}) ---")
        df.show(3, truncate=False)

    # Analyse détaillée des points d'attention
    print("\n" + "=" * 80)
    print("                       SYNTHÈSE DE L'INSPECTION")
    print("=" * 80)

    # 1. Type de timestamp
    for col_name in ["authentications", "network_flows"]:
        if col_name in inspected_dfs:
            df = inspected_dfs[col_name]
            fields = {f.name: f.dataType for f in df.schema.fields}
            ts_field = fields.get("timestamp")
            print(f"• [{col_name}] Champ 'timestamp' : type = {ts_field} "
                  f"(Est un vrai TimestampType : {'OUI' if 'TimestampType' in str(ts_field) else 'NON (StringType)'})")

    # 2. Structure de geo dans authentications
    if "authentications" in inspected_dfs:
        auth_fields = {f.name: f.dataType for f in inspected_dfs["authentications"].schema.fields}
        geo_field = auth_fields.get("geo")
        print(f"• [authentications] Champ 'geo' : type = {geo_field}")
        if geo_field and "StructType" in str(geo_field):
            print("  -> Structure imbriquée détectée : accessible via 'geo.country', 'geo.city', etc. : OUI")
        else:
            print("  -> Structure non structurée directement.")

    # 3. Localisation de l'IP dans ip_blacklist
    if "ip_blacklist" in inspected_dfs:
        bl_fields = [f.name for f in inspected_dfs["ip_blacklist"].schema.fields]
        print(f"• [ip_blacklist] Colonnes disponibles : {bl_fields}")
        if "ip" in bl_fields:
            print("  -> Adresse IP présente dans le champ dédié 'ip' : OUI")
        else:
            print("  -> Pas de champ 'ip' dédié. L'adresse IP est stockée dans : '_id'")

    print("=" * 80 + "\n")

    spark.stop()


if __name__ == "__main__":
    main()
