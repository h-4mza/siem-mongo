"""
Utilitaire de mesure de performance pour les requêtes SIEM MongoDB.

Fournit :
  - Un décorateur / gestionnaire de mesure calculant la moyenne sur 5 exécutions (en ms)
  - L'enregistrement automatique des temps dans results/timings.csv
    (colonnes : requete, type, temps_ms)
"""

import csv
import functools
import os
import sys
import time
from pathlib import Path

# Configuration de l'encodage console pour Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Emplacement du fichier de résultats CSV
RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
TIMINGS_FILE = RESULTS_DIR / "timings.csv"


def record_timing(requete: str, query_type: str, temps_ms: float):
    """
    Enregistre ou met à jour la mesure d'une requête dans results/timings.csv.
    Format : requete, type, temps_ms
    """
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    rows = []
    updated = False

    if TIMINGS_FILE.exists():
        with open(TIMINGS_FILE, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                if r.get("requete") == requete:
                    r["type"] = query_type
                    r["temps_ms"] = f"{temps_ms:.2f}"
                    updated = True
                rows.append(r)

    if not updated:
        rows.append({
            "requete": requete,
            "type": query_type,
            "temps_ms": f"{temps_ms:.2f}",
        })

    with open(TIMINGS_FILE, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["requete", "type", "temps_ms"])
        writer.writeheader()
        writer.writerows(rows)


def benchmark(query_id: str, query_type: str = "transactional", iterations: int = 5, setup_fn=None):
    """
    Décorateur qui exécute la fonction 'iterations' fois (par défaut 5),
    calcule le temps moyen en millisecondes et enregistre le résultat dans timings.csv.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            timings = []
            last_result = None

            for i in range(iterations):
                if setup_fn:
                    setup_fn()
                start = time.perf_counter()
                last_result = func(*args, **kwargs)
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                timings.append(elapsed_ms)

            avg_ms = sum(timings) / len(timings)
            record_timing(query_id, query_type, avg_ms)
            return last_result, avg_ms
        return wrapper
    return decorator


def measure_execution(query_id: str, func, *args, query_type: str = "transactional", iterations: int = 5, setup_fn=None, **kwargs):
    """
    Fonction helper permettant de mesurer une fonction sans passer par un décorateur fixe.
    Exécute la fonction 'iterations' fois, moyenne les temps en ms et enregistre le résultat.
    """
    timings = []
    last_result = None

    for _ in range(iterations):
        if setup_fn:
            setup_fn()
        start = time.perf_counter()
        last_result = func(*args, **kwargs)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        timings.append(elapsed_ms)

    avg_ms = sum(timings) / len(timings)
    record_timing(query_id, query_type, avg_ms)
    return last_result, avg_ms
