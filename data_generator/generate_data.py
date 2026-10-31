"""
Générateur de données de simulation pour le SIEM (MongoDB & Apache Spark).

Ce script génère des jeux de données volumineux, réalistes et reproductibles
au format JSON Lines (.jsonl) dans le dossier data_generator/output/ :
  - users.jsonl          (10 000 documents)
  - hosts.jsonl          (2 000 documents)
  - authentications.jsonl (≥ 60 000 documents) avec injection d'attaques
  - network_flows.jsonl  (≥ 40 000 documents) avec flux malveillants
  - alerts.jsonl         (≥ 3 000 documents)
  - ip_blacklist.jsonl   (~200 documents)

Attaques spécifiques injectées pour les analyses et détections Spark/SIEM :
  1. Force brute (S26) : 6 IP sources avec 25 échecs en moins de 4 minutes.
  2. Voyage impossible (S27) : 35 utilisateurs avec 2 connexions distantes à < 1h.
  3. Connexions multi-pays en 1 semaine (A22) : 25 utilisateurs avec 4 pays différents.
  4. Connexions nocturnes réussies (A18) : 500 connexions entre 22h et 6h sur divers départements.
  5. Communication avec liste noire (S29) : 35 hôtes internes contactant des IP blacklistées.
  6. Pic d'échecs journalier pour le Top 10 IP (A17) : 10 IP avec 250 échecs sur une même journée.
"""

import json
import os
import random
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from faker import Faker

# Configuration UTF-8 pour la sortie console sous Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ==============================================================================
# CONFIGURATION & REPRODUCTIBILITÉ
# ==============================================================================
RANDOM_SEED = 42
random.seed(RANDOM_SEED)

fake = Faker()
Faker.seed(RANDOM_SEED)

# Répertoire de sortie
OUTPUT_DIR = Path(__file__).resolve().parent / "output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Fenêtre temporelle : date de référence fixe = maintenant au moment de la génération
REF_DATE = datetime.now(timezone.utc).replace(microsecond=0)
BASE_DATE = REF_DATE
START_DATE = REF_DATE - timedelta(days=30)
TOTAL_SECONDS_30D = int((REF_DATE - START_DATE).total_seconds())

# ==============================================================================
# RÉFÉRENTIELS ET DONNÉES DE BASE
# ==============================================================================
DEPARTMENTS = [
    "IT",
    "Finance",
    "RH",
    "R&D",
    "Ventes",
    "Marketing",
    "Direction",
    "Support",
    "Juridique",
    "Opérations",
]

ROLES_BY_DEPT = {
    "IT": ["Admin Système", "Ingénieur Réseau", "DevOps", "Analyste SOC", "Architecte Cloud"],
    "Finance": ["Contrôleur de Gestion", "Comptable", "Auditeur Financier", "Directeur Financier"],
    "RH": ["Chargé de Recrutement", "Gestionnaire Paie", "DRH", "Responsable Formation"],
    "R&D": ["Data Scientist", "Développeur Backend", "Développeur Frontend", "Ingénieur IA"],
    "Ventes": ["Commercial Grands Comptes", "Ingénieur Avant-Vente", "Responsable Régional"],
    "Marketing": ["Chef de Produit", "Responsable Communication", "Community Manager"],
    "Direction": ["Directeur Général", "Directeur des Opérations", "Secrétaire Général"],
    "Support": ["Technicien N1", "Support Client N2", "Coordinateur Incident"],
    "Juridique": ["Juriste d'Entreprise", "DPO (Délégué Protection Données)", "Avocat Conseil"],
    "Opérations": ["Chef de Projet", "Responsable Logistique", "Agent d'Exploitation"],
}

CITIES_GEO = [
    {"country": "FR", "city": "Paris", "lat": 48.8566, "lon": 2.3522},
    {"country": "FR", "city": "Lyon", "lat": 45.7640, "lon": 4.8357},
    {"country": "FR", "city": "Marseille", "lat": 43.2965, "lon": 5.3698},
    {"country": "US", "city": "New York", "lat": 40.7128, "lon": -74.0060},
    {"country": "US", "city": "San Francisco", "lat": 37.7749, "lon": -122.4194},
    {"country": "US", "city": "Chicago", "lat": 41.8781, "lon": -87.6298},
    {"country": "DE", "city": "Berlin", "lat": 52.5200, "lon": 13.4050},
    {"country": "DE", "city": "Francfort", "lat": 50.1109, "lon": 8.6821},
    {"country": "GB", "city": "Londres", "lat": 51.5074, "lon": -0.1278},
    {"country": "JP", "city": "Tokyo", "lat": 35.6762, "lon": 139.6503},
    {"country": "SG", "city": "Singapour", "lat": 1.3521, "lon": 103.8198},
    {"country": "AU", "city": "Sydney", "lat": -33.8688, "lon": 151.2093},
    {"country": "CA", "city": "Montréal", "lat": 45.5017, "lon": -73.5673},
    {"country": "BR", "city": "Sao Paulo", "lat": -23.5505, "lon": -46.6333},
    {"country": "IN", "city": "Mumbai", "lat": 19.0760, "lon": 72.8777},
    {"country": "ES", "city": "Madrid", "lat": 40.4168, "lon": -3.7038},
    {"country": "IT", "city": "Rome", "lat": 41.9028, "lon": 12.4964},
    {"country": "CH", "city": "Genève", "lat": 46.2044, "lon": 6.1432},
    {"country": "BE", "city": "Bruxelles", "lat": 50.8503, "lon": 4.3517},
    {"country": "NL", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041},
]

GEO_BY_COUNTRY = {}
for g in CITIES_GEO:
    GEO_BY_COUNTRY.setdefault(g["country"], []).append(g)

COMMON_PORTS = [80, 443, 22, 3389, 445, 53, 8080, 8443, 3306, 5432, 27017, 88]
ALERT_RULES = [
    "Brute Force Authentication Attempt (S26)",
    "Impossible Travel Detected (S27)",
    "Communication with Blacklisted IP (S29)",
    "Suspicious Off-Hours Access (A18)",
    "Multiple Country Logins in Short Period (A22)",
    "Port Scanning Activity",
    "Privilege Escalation Attempt",
    "Malware Beaconing Detected",
]
ANALYSTS = ["Alice Martin", "Bob Leroy", "Charlie Dubois", "Diane Moreau", "Eric Bernard"]
TAG_POOL = ["auth", "network", "malware", "c2", "bruteforce", "geo_anomaly", "policy_violation", "critical_asset"]

def random_timestamp(start_dt: datetime, end_dt: datetime) -> datetime:
    """Génère un datetime aléatoire uniforme entre start_dt et end_dt."""
    delta_s = int((end_dt - start_dt).total_seconds())
    offset_s = random.randint(0, max(0, delta_s))
    return start_dt + timedelta(seconds=offset_s)

def to_iso(dt: datetime) -> str:
    """Formate un datetime en chaîne ISO 8601 UTC."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def write_jsonl(filepath: Path, records: list):
    """Écrit une liste de dictionnaires au format JSON Lines."""
    with open(filepath, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

# ==============================================================================
# 1. GÉNÉRATION DES UTILISATEURS (10 000)
# ==============================================================================
def generate_users(count: int = 10000) -> list:
    print(f"[*] Génération de {count} utilisateurs...")
    users = []
    countries_list = list(GEO_BY_COUNTRY.keys())

    for i in range(1, count + 1):
        user_id = f"usr_{i:05d}"
        dept = random.choice(DEPARTMENTS)
        role = random.choice(ROLES_BY_DEPT[dept])

        # ~3% de comptes de service
        is_svc = random.random() < 0.03
        if is_svc:
            name = f"svc_{dept.lower()}_{i}"
            role = "Compte de Service Applicatif"
        else:
            name = fake.name()

        # 1 à 3 pays habituels (majoritairement FR / US / DE)
        nb_countries = random.choices([1, 2, 3], weights=[0.75, 0.20, 0.05])[0]
        primary_country = random.choices(["FR", "US", "DE", "GB", "CH"], weights=[0.60, 0.15, 0.10, 0.10, 0.05])[0]
        usual_countries = [primary_country]
        other_countries = [c for c in countries_list if c != primary_country]
        if nb_countries > 1:
            usual_countries.extend(random.sample(other_countries, nb_countries - 1))

        # Statuts : active (94%), locked (3%), disabled (3%)
        status = random.choices(["active", "locked", "disabled"], weights=[0.94, 0.03, 0.03])[0]

        users.append({
            "user_id": user_id,
            "name": name,
            "department": dept,
            "role": role,
            "is_service_account": is_svc,
            "usual_countries": usual_countries,
            "status": status,
            "failed_login_count": 0,
        })

    return users

# ==============================================================================
# 2. GÉNÉRATION DES HÔTES (2 000)
# ==============================================================================
def generate_hosts(count: int = 2000, users: list = None) -> list:
    print(f"[*] Génération de {count} hôtes...")
    hosts = []
    user_ids = [u["user_id"] for u in users] if users else ["usr_00001"]

    os_choices = [
        "Ubuntu 22.04 LTS",
        "Debian 12",
        "RedHat Enterprise Linux 9",
        "Windows Server 2022",
        "Windows Server 2019",
        "Windows 11 Enterprise",
    ]
    env_choices = ["production", "staging", "development", "dmz"]
    dc_choices = ["dc-paris-01", "dc-paris-02", "dc-lyon-01", "dc-cloud-eu"]

    for i in range(1, count + 1):
        host_id = f"host_{i:04d}"
        env = random.choice(env_choices)
        
        # IP privée interne séquentielle et unique (10.x.y.z)
        second_octet = (i // 250) + 1
        third_octet = (i % 250) + 1
        ip = f"10.{second_octet}.{third_octet}.50"

        criticality = random.choices(["low", "medium", "high", "critical"], weights=[0.40, 0.35, 0.15, 0.10])[0]

        hosts.append({
            "host_id": host_id,
            "name": f"srv-{env[:3]}-{i:04d}",
            "ip": ip,
            "os": random.choice(os_choices),
            "criticality": criticality,
            "owner": random.choice(user_ids),
            "metadata": {
                "datacenter": random.choice(dc_choices),
                "rack": f"R-{random.randint(1, 42):02d}",
                "environment": env,
            },
        })

    return hosts

# ==============================================================================
# 3. GÉNÉRATION DE LA LISTE NOIRE D'IP (~200)
# ==============================================================================
def generate_ip_blacklist(count: int = 200) -> list:
    print(f"[*] Génération de {count} adresses IP en liste noire...")
    blacklist = []
    reasons = [
        "Known C2 Server",
        "Botnet Command & Control",
        "Tor Exit Node",
        "Phishing Infrastructure",
        "Mass Scanner / Crawler",
        "Brute-Force Network",
    ]

    for i in range(count):
        # IP publique distincte
        ip = f"198.51.{100 + (i // 250)}.{ (i % 250) + 1 }"
        # Date de création dans les 5 derniers jours (entre REF_DATE - 4.5 jours et REF_DATE)
        created_at = random_timestamp(REF_DATE - timedelta(days=4, hours=12), REF_DATE - timedelta(hours=1))
        # expires_at = created_at + 7 jours (strictement entre REF_DATE + 2.5 jours et REF_DATE + 6.9 jours)
        expires_at = created_at + timedelta(days=7)

        blacklist.append({
            "ip": ip,
            "reason": random.choice(reasons),
            "created_at": to_iso(created_at),
            "expires_at": to_iso(expires_at),
        })

    return blacklist

# ==============================================================================
# 4. GÉNÉRATION DES AUTHENTICATIONS (≥ 60 000) ET INJECTIONS D'ATTAQUES
# ==============================================================================
def generate_authentications(users: list, hosts: list, target_count: int = 60000) -> tuple[list, dict]:
    print(f"[*] Génération des authentications (objectif >= {target_count}) avec injection d'attaques...")
    auths = []
    attack_stats = {}

    user_map = {u["user_id"]: u for u in users}
    user_ids = list(user_map.keys())
    host_ids = [h["host_id"] for h in hosts]
    methods = ["password", "MFA", "SSO"]

    # --------------------------------------------------------------------------
    # Attaque 1 : Force brute (S26)
    # Au moins 5 IP sources avec plus de 20 échecs en moins de 5 minutes.
    # On configure 6 IP avec 25 échecs chacune sur une fenêtre de 3-4 minutes.
    # --------------------------------------------------------------------------
    s26_ips = [f"203.0.113.{50 + i}" for i in range(6)]
    s26_events_count = 0
    for attacker_ip in s26_ips:
        burst_start = random_timestamp(START_DATE + timedelta(days=2), BASE_DATE - timedelta(days=2))
        victim_user = user_map[random.choice(user_ids)]
        target_host = random.choice(host_ids)

        for attempt in range(25):
            t = burst_start + timedelta(seconds=random.randint(0, 240))
            auth_id = f"auth_{len(auths) + 1:06d}"
            geo_info = random.choice(GEO_BY_COUNTRY["US"])
            auths.append({
                "auth_id": auth_id,
                "timestamp": to_iso(t),
                "user_id": victim_user["user_id"],
                "host_id": target_host,
                "source_ip": attacker_ip,
                "result": "failure",
                "method": "password",
                "geo": {
                    "country": geo_info["country"],
                    "city": geo_info["city"],
                    "lat": geo_info["lat"],
                    "lon": geo_info["lon"],
                },
                "user_department": victim_user["department"],
            })
            s26_events_count += 1

    attack_stats["S26_force_brute"] = {
        "nb_ip_sources": len(s26_ips),
        "nb_evenements": s26_events_count,
        "detail": "6 IP avec 25 échecs chacune en moins de 4 minutes",
    }

    # --------------------------------------------------------------------------
    # Attaque 2 : Voyage impossible (S27)
    # Au moins 30 utilisateurs avec 2 connexions de 2 pays différents à moins d'1h.
    # On sélectionne 35 utilisateurs distincts.
    # --------------------------------------------------------------------------
    s27_users = random.sample(user_ids, 35)
    s27_events_count = 0
    for u_id in s27_users:
        u = user_map[u_id]
        t1 = random_timestamp(START_DATE + timedelta(days=3), BASE_DATE - timedelta(days=3))
        # 15 à 45 minutes plus tard (< 1 heure)
        t2 = t1 + timedelta(minutes=random.randint(15, 45))

        geo1 = random.choice(GEO_BY_COUNTRY["FR"])   # France
        geo2 = random.choice(GEO_BY_COUNTRY["JP"])   # Japon (distance irréaliste en < 1h)

        h1 = random.choice(host_ids)
        h2 = random.choice(host_ids)

        # Connexion 1
        auths.append({
            "auth_id": f"auth_{len(auths) + 1:06d}",
            "timestamp": to_iso(t1),
            "user_id": u_id,
            "host_id": h1,
            "source_ip": f"195.154.{random.randint(1, 250)}.{random.randint(1, 250)}",
            "result": "success",
            "method": "SSO",
            "geo": {"country": geo1["country"], "city": geo1["city"], "lat": geo1["lat"], "lon": geo1["lon"]},
            "user_department": u["department"],
        })
        # Connexion 2
        auths.append({
            "auth_id": f"auth_{len(auths) + 1:06d}",
            "timestamp": to_iso(t2),
            "user_id": u_id,
            "host_id": h2,
            "source_ip": f"133.242.{random.randint(1, 250)}.{random.randint(1, 250)}",
            "result": "success",
            "method": "password",
            "geo": {"country": geo2["country"], "city": geo2["city"], "lat": geo2["lat"], "lon": geo2["lon"]},
            "user_department": u["department"],
        })
        s27_events_count += 2

    attack_stats["S27_voyage_impossible"] = {
        "nb_utilisateurs": len(s27_users),
        "nb_evenements": s27_events_count,
        "detail": "35 utilisateurs avec 2 connexions (FR et JP) distantes de 15-45 minutes",
    }

    # --------------------------------------------------------------------------
    # Attaque 3 : Utilisateurs avec plus de 3 pays en une semaine (A22)
    # Au moins 20 utilisateurs. On en injecte 25 avec 4 pays différents.
    # --------------------------------------------------------------------------
    remaining_users = list(set(user_ids) - set(s27_users))
    a22_users = random.sample(remaining_users, 25)
    a22_events_count = 0
    four_countries = ["FR", "US", "DE", "SG"]

    for u_id in a22_users:
        u = user_map[u_id]
        week_start = random_timestamp(START_DATE + timedelta(days=5), BASE_DATE - timedelta(days=8))
        for day_offset, c_code in enumerate(four_countries):
            t = week_start + timedelta(days=day_offset * 1.5, hours=random.randint(1, 10))
            geo_info = random.choice(GEO_BY_COUNTRY[c_code])
            auths.append({
                "auth_id": f"auth_{len(auths) + 1:06d}",
                "timestamp": to_iso(t),
                "user_id": u_id,
                "host_id": random.choice(host_ids),
                "source_ip": f"82.165.{random.randint(1, 250)}.{random.randint(1, 250)}",
                "result": "success",
                "method": "MFA",
                "geo": {"country": geo_info["country"], "city": geo_info["city"], "lat": geo_info["lat"], "lon": geo_info["lon"]},
                "user_department": u["department"],
            })
            a22_events_count += 1

    attack_stats["A22_multi_pays_semaine"] = {
        "nb_utilisateurs": len(a22_users),
        "nb_evenements": a22_events_count,
        "detail": "25 utilisateurs connectés depuis 4 pays distincts (FR, US, DE, SG) en une semaine",
    }

    # --------------------------------------------------------------------------
    # Attaque 4 : Connexions réussies entre 22h et 6h (A18) pour plusieurs départements
    # Injection ciblée de 500 connexions nocturnes réussies.
    # --------------------------------------------------------------------------
    a18_events_count = 0
    target_depts = ["Finance", "RH", "Juridique", "R&D", "Ventes", "Direction"]
    depts_represented = set()

    for _ in range(500):
        u_id = random.choice(user_ids)
        u = user_map[u_id]
        # On force un département cible si besoin
        if u["department"] not in target_depts:
            dept = random.choice(target_depts)
        else:
            dept = u["department"]
        depts_represented.add(dept)

        # Génération d'une heure strictement entre 22h et 5h59 (22, 23, 0, 1, 2, 3, 4, 5)
        night_hour = random.choice([22, 23, 0, 1, 2, 3, 4, 5])
        rand_day = random.randint(0, 29)
        day_date = (START_DATE + timedelta(days=rand_day)).date()
        t = datetime(day_date.year, day_date.month, day_date.day, night_hour,
                     random.randint(0, 59), random.randint(0, 59), tzinfo=timezone.utc)

        geo_info = random.choice(GEO_BY_COUNTRY["FR"])
        auths.append({
            "auth_id": f"auth_{len(auths) + 1:06d}",
            "timestamp": to_iso(t),
            "user_id": u_id,
            "host_id": random.choice(host_ids),
            "source_ip": f"194.254.{random.randint(1, 250)}.{random.randint(1, 250)}",
            "result": "success",
            "method": "password",
            "geo": {"country": geo_info["country"], "city": geo_info["city"], "lat": geo_info["lat"], "lon": geo_info["lon"]},
            "user_department": dept,
        })
        a18_events_count += 1

    attack_stats["A18_connexions_nocturnes"] = {
        "nb_evenements": a18_events_count,
        "departements_concernes": list(depts_represented),
        "detail": f"{a18_events_count} connexions réussies entre 22h et 6h réparties sur {len(depts_represented)} départements",
    }

    # --------------------------------------------------------------------------
    # Attaque 6 : Journée avec beaucoup d'échecs pour le Top 10 IP (A17)
    # On cible une journée fixe (7 jours avant BASE_DATE) et 10 adresses IP attaquantes.
    # 250 échecs par IP sur cette seule journée.
    # --------------------------------------------------------------------------
    target_day = (BASE_DATE - timedelta(days=7)).date()
    top10_attack_ips = [f"185.220.101.{10 + i}" for i in range(10)]
    a17_events_count = 0

    for ip in top10_attack_ips:
        for _ in range(250):
            t = datetime(target_day.year, target_day.month, target_day.day,
                         random.randint(0, 23), random.randint(0, 59), random.randint(0, 59),
                         tzinfo=timezone.utc)
            u_id = random.choice(user_ids)
            u = user_map[u_id]
            geo_info = random.choice(GEO_BY_COUNTRY["DE"])
            auths.append({
                "auth_id": f"auth_{len(auths) + 1:06d}",
                "timestamp": to_iso(t),
                "user_id": u_id,
                "host_id": random.choice(host_ids),
                "source_ip": ip,
                "result": "failure",
                "method": "password",
                "geo": {"country": geo_info["country"], "city": geo_info["city"], "lat": geo_info["lat"], "lon": geo_info["lon"]},
                "user_department": u["department"],
            })
            a17_events_count += 1

    attack_stats["A17_top10_echecs_journee"] = {
        "date_cible": target_day.isoformat(),
        "nb_ip": len(top10_attack_ips),
        "nb_evenements": a17_events_count,
        "detail": f"10 IP avec chacune 250 échecs le {target_day} (total {a17_events_count} échecs)",
    }

    # --------------------------------------------------------------------------
    # 7. Authentications sur les dernières 24 heures pour 20 utilisateurs identifiés
    # Au moins 200 authentications dont 40 échecs (2 échecs et 8 succès par utilisateur)
    # --------------------------------------------------------------------------
    identified_users = [f"usr_{idx:05d}" for idx in range(1, 21)]
    recent_24h_auths_count = 0
    recent_24h_failures_count = 0

    for u_id in identified_users:
        u = user_map[u_id]
        # 2 échecs par utilisateur répartis sur les 24h
        for _ in range(2):
            offset_seconds = random.randint(60, 85000)
            t_fail = REF_DATE - timedelta(seconds=offset_seconds)
            geo_info = random.choice(GEO_BY_COUNTRY["FR"])
            auths.append({
                "auth_id": f"auth_{len(auths) + 1:06d}",
                "timestamp": to_iso(t_fail),
                "user_id": u_id,
                "host_id": random.choice(host_ids),
                "source_ip": f"194.214.{random.randint(1, 254)}.{random.randint(1, 254)}",
                "result": "failure",
                "method": "password",
                "geo": {"country": geo_info["country"], "city": geo_info["city"], "lat": geo_info["lat"], "lon": geo_info["lon"]},
                "user_department": u["department"],
            })
            recent_24h_auths_count += 1
            recent_24h_failures_count += 1

        # 8 succès par utilisateur (total 10 connexions/user -> 200 sur 20 users)
        for _ in range(8):
            offset_seconds = random.randint(60, 85000)
            t_succ = REF_DATE - timedelta(seconds=offset_seconds)
            geo_info = random.choice(GEO_BY_COUNTRY["FR"])
            auths.append({
                "auth_id": f"auth_{len(auths) + 1:06d}",
                "timestamp": to_iso(t_succ),
                "user_id": u_id,
                "host_id": random.choice(host_ids),
                "source_ip": f"194.214.{random.randint(1, 254)}.{random.randint(1, 254)}",
                "result": "success",
                "method": random.choice(methods),
                "geo": {"country": geo_info["country"], "city": geo_info["city"], "lat": geo_info["lat"], "lon": geo_info["lon"]},
                "user_department": u["department"],
            })
            recent_24h_auths_count += 1

    attack_stats["recent_24h_identified_users"] = {
        "nb_utilisateurs": len(identified_users),
        "nb_authentications": recent_24h_auths_count,
        "nb_echecs": recent_24h_failures_count,
        "detail": f"{recent_24h_auths_count} connexions dont {recent_24h_failures_count} échecs sur les 24h pour usr_00001 à usr_00020",
    }

    # --------------------------------------------------------------------------
    # Trafic de fond normal pour atteindre au moins 60 000 événements
    # Taux d'échec standard ~15%.
    # --------------------------------------------------------------------------
    current_count = len(auths)
    needed_baseline = max(0, target_count - current_count)
    # On ajoute une petite marge pour dépasser confortablement 60 000
    total_baseline_to_gen = needed_baseline + 500

    print(f"[*] Génération de {total_baseline_to_gen} événements d'authentification de fond...")
    for _ in range(total_baseline_to_gen):
        u_id = random.choice(user_ids)
        u = user_map[u_id]
        t = random_timestamp(START_DATE, BASE_DATE)

        # Pays géographique : généralement l'un des pays habituels de l'utilisateur
        country = random.choice(u["usual_countries"])
        geo_info = random.choice(GEO_BY_COUNTRY.get(country, GEO_BY_COUNTRY["FR"]))

        # IP source : externe ou VPN d'entreprise
        src_ip = f"194.214.{random.randint(1, 254)}.{random.randint(1, 254)}"
        # ~15% d'échecs normaux
        result = "failure" if random.random() < 0.15 else "success"

        auths.append({
            "auth_id": f"auth_{len(auths) + 1:06d}",
            "timestamp": to_iso(t),
            "user_id": u_id,
            "host_id": random.choice(host_ids),
            "source_ip": src_ip,
            "result": result,
            "method": random.choice(methods),
            "geo": {
                "country": geo_info["country"],
                "city": geo_info["city"],
                "lat": geo_info["lat"],
                "lon": geo_info["lon"],
            },
            "user_department": u["department"],
        })

    return auths, attack_stats

# ==============================================================================
# 5. GÉNÉRATION DES FLUX RÉSEAU (≥ 40 000) ET ATTAQUE S29
# ==============================================================================
def generate_network_flows(hosts: list, blacklist: list, target_count: int = 40000) -> tuple[list, dict]:
    print(f"[*] Génération des flux réseau (objectif >= {target_count}) avec injection S29...")
    flows = []
    attack_stats = {}

    host_map = {h["host_id"]: h for h in hosts}
    host_ids = list(host_map.keys())
    blacklist_ips = [b["ip"] for b in blacklist]
    protocols = ["TCP", "UDP", "ICMP"]
    protocol_weights = [0.82, 0.15, 0.03]

    # --------------------------------------------------------------------------
    # Attaque 5 : Au moins 30 hôtes ayant des flux vers des IP en liste noire (S29)
    # On sélectionne 35 hôtes internes et on génère 3 flux par hôte vers la blacklist.
    # --------------------------------------------------------------------------
    s29_hosts = random.sample(host_ids, 35)
    s29_events_count = 0
    for h_id in s29_hosts:
        h = host_map[h_id]
        for _ in range(3):
            t = random_timestamp(START_DATE + timedelta(days=2), BASE_DATE - timedelta(days=1))
            c2_ip = random.choice(blacklist_ips)
            port = random.choice([443, 8080, 4444, 8443, 9001])
            flows.append({
                "flow_id": f"flow_{len(flows) + 1:06d}",
                "timestamp": to_iso(t),
                "src_ip": h["ip"],
                "dst_ip": c2_ip,
                "dst_port": port,
                "protocol": "TCP",
                "bytes": random.randint(1024, 25000000),
                "host_id": h_id,
            })
            s29_events_count += 1

    attack_stats["S29_flux_liste_noire"] = {
        "nb_hotes_concernes": len(s29_hosts),
        "nb_flux_injectes": s29_events_count,
        "detail": "35 hôtes internes émettant des flux vers des IP de la liste noire",
    }

    # --------------------------------------------------------------------------
    # Trafic réseau légitime de fond
    # --------------------------------------------------------------------------
    current_count = len(flows)
    needed_baseline = max(0, target_count - current_count)
    total_baseline_to_gen = needed_baseline + 500

    print(f"[*] Génération de {total_baseline_to_gen} flux réseau normaux...")
    public_destinations = [
        "8.8.8.8", "1.1.1.1", "9.9.9.9", "142.250.74.206",
        "13.107.42.16", "52.96.166.130", "151.101.1.140",
    ]

    for _ in range(total_baseline_to_gen):
        h_id = random.choice(host_ids)
        h = host_map[h_id]
        t = random_timestamp(START_DATE, BASE_DATE)

        # Destination : soit un autre serveur interne (inter-DC), soit une adresse publique saine
        if random.random() < 0.40:
            dst_ip = host_map[random.choice(host_ids)]["ip"]
        else:
            dst_ip = random.choice(public_destinations)

        port = random.choice(COMMON_PORTS)
        proto = random.choices(protocols, weights=protocol_weights)[0]
        flow_bytes = random.randint(64, 45000000)

        flows.append({
            "flow_id": f"flow_{len(flows) + 1:06d}",
            "timestamp": to_iso(t),
            "src_ip": h["ip"],
            "dst_ip": dst_ip,
            "dst_port": port,
            "protocol": proto,
            "bytes": flow_bytes,
            "host_id": h_id,
        })

    return flows, attack_stats

# ==============================================================================
# 6. GÉNÉRATION DES ALERTES (≥ 3 000)
# ==============================================================================
def generate_alerts(count: int = 3200, auths: list = None, flows: list = None) -> list:
    print(f"[*] Génération de {count} alertes SIEM...")
    alerts = []

    auth_ids = [a["auth_id"] for a in auths] if auths else ["auth_000001"]
    flow_ids = [f["flow_id"] for f in flows] if flows else ["flow_000001"]

    severities = ["low", "medium", "high", "critical"]
    sev_weights = [0.35, 0.40, 0.18, 0.07]
    statuses = ["open", "in_progress", "resolved", "closed"]
    status_weights = [0.25, 0.20, 0.35, 0.20]

    for i in range(1, count + 1):
        alert_id = f"alt_{i:05d}"
        rule = random.choice(ALERT_RULES)
        severity = random.choices(severities, weights=sev_weights)[0]
        status = random.choices(statuses, weights=status_weights)[0]

        # Analyste assigné si en cours ou résolue
        if status in ["in_progress", "resolved", "closed"]:
            analyst = random.choice(ANALYSTS)
        else:
            analyst = random.choice(ANALYSTS) if random.random() < 0.3 else None

        # Événements reliés (1 à 4 auth_id ou flow_id)
        related_events = []
        if "Authentication" in rule or "Travel" in rule or "Hours" in rule:
            related_events.extend(random.sample(auth_ids, random.randint(1, 3)))
        elif "Communication" in rule or "Flow" in rule or "Scanning" in rule:
            related_events.extend(random.sample(flow_ids, random.randint(1, 3)))
        else:
            related_events.append(random.choice(auth_ids))
            related_events.append(random.choice(flow_ids))

        # Tags uniques avec répartition contrôlée pour les tests d'index (A25)
        nb_tags = random.randint(1, 3)
        tag_set = set(random.sample(TAG_POOL, nb_tags))

        # Tag très fréquent (~50% des alertes, ~1600 alertes)
        if random.random() < 0.50:
            tag_set.add("auth")

        # Tag rare (< 2% des alertes : exactement 40 alertes sur 3200 = 1.25%)
        if i <= 40:
            tag_set.add("zero_day")
        else:
            tag_set.discard("zero_day")

        tags = list(tag_set)

        # Dates de création et de résolution
        created_at = random_timestamp(START_DATE, BASE_DATE - timedelta(hours=2))
        if status in ["resolved", "closed"]:
            # Résolution toujours postérieure à la création (+15 min à 4 jours)
            resolution_delay = timedelta(minutes=random.randint(15, 5760))
            resolved_dt = min(created_at + resolution_delay, BASE_DATE)
            # S'assurer que resolved_dt > created_at
            if resolved_dt <= created_at:
                resolved_dt = created_at + timedelta(minutes=20)
            resolved_at = to_iso(resolved_dt)
        else:
            resolved_at = None

        alerts.append({
            "alert_id": alert_id,
            "rule": rule,
            "severity": severity,
            "status": status,
            "analyst": analyst,
            "related_events": related_events,
            "tags": tags,
            "created_at": to_iso(created_at),
            "resolved_at": resolved_at,
        })

    return alerts

# ==============================================================================
# POINT D'ENTRÉE PRINCIPAL
# ==============================================================================
def main():
    start_time = time.time()
    print("======================================================================")
    print("      DÉMARRAGE DE LA GÉNÉRATION DES DONNÉES SIEM (SEED FIXE 42)      ")
    print("======================================================================")

    # 1. Users
    users = generate_users(10000)
    write_jsonl(OUTPUT_DIR / "users.jsonl", users)

    # 2. Hosts
    hosts = generate_hosts(2000, users)
    write_jsonl(OUTPUT_DIR / "hosts.jsonl", hosts)

    # 3. IP Blacklist
    blacklist = generate_ip_blacklist(200)
    write_jsonl(OUTPUT_DIR / "ip_blacklist.jsonl", blacklist)

    # 4. Authentications (avec attaques S26, S27, A22, A18, A17)
    authentications, auth_attacks = generate_authentications(users, hosts, target_count=60000)
    write_jsonl(OUTPUT_DIR / "authentications.jsonl", authentications)

    # 5. Network Flows (avec attaque S29)
    flows, flow_attacks = generate_network_flows(hosts, blacklist, target_count=40000)
    write_jsonl(OUTPUT_DIR / "network_flows.jsonl", flows)

    # 6. Alerts
    alerts = generate_alerts(3200, authentications, flows)
    write_jsonl(OUTPUT_DIR / "alerts.jsonl", alerts)

    elapsed = time.time() - start_time

    # ==========================================================================
    # RÉSUMÉ DE LA GÉNÉRATION
    # ==========================================================================
    print("\n======================================================================")
    print("                        RÉSUMÉ DE LA GÉNÉRATION                       ")
    print("======================================================================")
    print(f"Durée totale d'exécution : {elapsed:.2f} secondes")
    print(f"Dossier de sortie        : {OUTPUT_DIR}\n")

    print("--- Volumes de documents générés ---")
    print(f"  - users.jsonl          : {len(users):>7} documents")
    print(f"  - hosts.jsonl          : {len(hosts):>7} documents")
    print(f"  - ip_blacklist.jsonl   : {len(blacklist):>7} documents")
    print(f"  - authentications.jsonl: {len(authentications):>7} documents  (seuil: >= 60 000)")
    print(f"  - network_flows.jsonl  : {len(flows):>7} documents  (seuil: >= 40 000)")
    print(f"  - alerts.jsonl         : {len(alerts):>7} documents  (seuil: >=  3 000)")

    print("\n--- Scénarios d'attaques injectés ---")
    print(f"  1. Force brute (S26)                  : {auth_attacks['S26_force_brute']['nb_ip_sources']} IP sources ({auth_attacks['S26_force_brute']['nb_evenements']} échecs injectés)")
    print(f"  2. Voyage impossible (S27)            : {auth_attacks['S27_voyage_impossible']['nb_utilisateurs']} utilisateurs ({auth_attacks['S27_voyage_impossible']['nb_evenements']} connexions à < 1h)")
    print(f"  3. Multi-pays en 1 semaine (A22)      : {auth_attacks['A22_multi_pays_semaine']['nb_utilisateurs']} utilisateurs ({auth_attacks['A22_multi_pays_semaine']['nb_evenements']} connexions sur 4 pays)")
    print(f"  4. Connexions nocturnes 22h-6h (A18)  : {auth_attacks['A18_connexions_nocturnes']['nb_evenements']} connexions réussies sur {len(auth_attacks['A18_connexions_nocturnes']['departements_concernes'])} départements")
    print(f"  5. Flux vers IP blacklistées (S29)    : {flow_attacks['S29_flux_liste_noire']['nb_hotes_concernes']} hôtes internes ({flow_attacks['S29_flux_liste_noire']['nb_flux_injectes']} flux)")
    print(f"  6. Top 10 IP échecs sur 1 jour (A17)  : {auth_attacks['A17_top10_echecs_journee']['nb_ip']} IP ({auth_attacks['A17_top10_echecs_journee']['nb_evenements']} échecs le {auth_attacks['A17_top10_echecs_journee']['date_cible']})")
    print(f"  7. Dernières 24h (20 users cibles T5) : {auth_attacks['recent_24h_identified_users']['nb_authentications']} connexions ({auth_attacks['recent_24h_identified_users']['nb_echecs']} échecs sur {auth_attacks['recent_24h_identified_users']['nb_utilisateurs']} utilisateurs)")
    print("======================================================================\n")

if __name__ == "__main__":
    main()
