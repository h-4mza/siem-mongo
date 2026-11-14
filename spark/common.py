"""
Module commun pour les jobs Apache Spark (SIEM MongoDB).
Fournit la session Spark configurée, les helpers de lecture de collections,
le chronométrage d'exécution et l'export CSV léger.
"""

import os
import sys
import time
import csv
from pyspark.sql import SparkSession

DEFAULT_MONGO_URI = (
    "mongodb://mongo1:27018,"
    "mongo2:27019,"
    "mongo3:27020/"
    "?replicaSet=rs0"
)

DATABASE_NAME = "siem"

# Répertoire d'export des résultats monté dans le conteneur Docker
CONTAINER_OUTPUT_DIR = "/opt/results/spark_outputs"


def get_output_dir() -> str:
    """Retourne le répertoire de sortie en fonction de l'environnement (conteneur vs hôte)."""
    if os.path.exists("/opt/results") or os.name == "posix":
        return CONTAINER_OUTPUT_DIR
    # Environnement local hôte (hors conteneur)
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_dir, "results", "spark_outputs")


def get_spark(app_name: str = "SIEM-Spark-Job") -> SparkSession:
    """
    Initialise et retourne une SparkSession configurée pour MongoDB.
    L'URI de connexion est lue depuis SPARK_MONGO_URI avec fallback sur le cluster par défaut.
    """
    mongo_uri = os.getenv("SPARK_MONGO_URI", DEFAULT_MONGO_URI)
    return (
        SparkSession.builder
        .appName(app_name)
        .config("spark.mongodb.read.connection.uri", mongo_uri)
        .getOrCreate()
    )


def read_collection(spark: SparkSession, name: str):
    """
    Lit une collection MongoDB via le format 'mongodb' sur la base 'siem'.
    """
    mongo_uri = os.getenv("SPARK_MONGO_URI", DEFAULT_MONGO_URI)
    return (
        spark.read
        .format("mongodb")
        .option("connection.uri", mongo_uri)
        .option("database", DATABASE_NAME)
        .option("collection", name)
        .load()
    )


def timed(label: str, fn):
    """
    Mesure le temps d'exécution d'une fonction et retourne (résultat, durée_en_ms).
    """
    start = time.perf_counter()
    result = fn()
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    print(f"[{label}] Temps d'exécution : {elapsed_ms:.2f} ms")
    return result, elapsed_ms


def save_csv(rows, columns, filename: str) -> str:
    """
    Écrit un petit CSV dans /opt/results/spark_outputs/ (ou ./results/spark_outputs)
    en créant le dossier parent si nécessaire.
    N'utilise pas toPandas : utilise le module standard csv.
    """
    output_dir = get_output_dir()
    os.makedirs(output_dir, exist_ok=True)

    target_name = os.path.basename(filename)
    filepath = os.path.join(output_dir, target_name)

    with open(filepath, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(columns)
        for row in rows:
            if hasattr(row, "asDict"):
                d = row.asDict()
                writer.writerow([d.get(c, "") for c in columns])
            elif isinstance(row, dict):
                writer.writerow([row.get(c, "") for c in columns])
            elif isinstance(row, (list, tuple)):
                writer.writerow(row)
            else:
                writer.writerow([getattr(row, c, "") for c in columns])

    print(f"[save_csv] Fichier généré avec succès : {filepath} ({len(rows)} lignes)")
    return filepath
