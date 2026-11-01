"""
Initialisation du schéma MongoDB pour le SIEM distribué.

Ce script :
  1. Se connecte au cluster MongoDB via la variable d'environnement MONGO_URI
     (valeur par défaut : mongodb://localhost:27017/?replicaSet=rs0)
  2. Crée les collections avec validation stricte par schéma ($jsonSchema)
  3. Crée les index optimisés pour les requêtes T (Transactionnelles),
     A (Analytiques/Agrégation) et S (Sécurité/Spark)
"""

import os
import sys
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import CollectionInvalid, OperationFailure

# Configuration de l'encodage console pour Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ==============================================================================
# CONNEXION MONGODB
# ==============================================================================
DEFAULT_MONGO_URI = "mongodb://mongo1:27018,mongo2:27019,mongo3:27020/?replicaSet=rs0"
DB_NAME = "siem"

def get_mongo_client():
    """Établit la connexion MongoDB avec gestion du fallback standalone local si nécessaire."""
    uri = os.getenv("MONGO_URI", DEFAULT_MONGO_URI)
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=3000)
        client.admin.command("ping")
        print(f"[+] Connexion réussie à MongoDB via : {uri}")
        return client
    except Exception as e:
        # Fallback si le replicaSet local rs0 n'est pas encore initialisé
        if "replicaSet" in uri and "MONGO_URI" not in os.environ:
            fallback_uri = uri.split("?")[0]
            print(f"[!] Replica Set inaccessible ({uri}). Tentative de repli standalone sur : {fallback_uri}")
            try:
                client = MongoClient(fallback_uri, serverSelectionTimeoutMS=3000)
                client.admin.command("ping")
                print(f"[+] Connexion réussie à MongoDB (standalone local) : {fallback_uri}")
                return client
            except Exception as e2:
                print(f"[-] Échec de la connexion à {fallback_uri} : {e2}")
                raise e2
        print(f"[-] Échec de la connexion MongoDB : {e}")
        raise e

# ==============================================================================
# DÉFINITION DES SCHÉMAS JSON ($jsonSchema)
# ==============================================================================
SCHEMAS = {
    # --------------------------------------------------------------------------
    # 1. USERS : usual_countries en tableau, validation des rôles et statuts
    # --------------------------------------------------------------------------
    "users": {
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["user_id", "name", "department", "role", "is_service_account", "usual_countries", "status", "failed_login_count"],
            "properties": {
                "user_id": {
                    "bsonType": "string",
                    "description": "Identifiant unique de l'utilisateur (ex: usr_00001)"
                },
                "name": {
                    "bsonType": "string",
                    "description": "Nom complet de l'utilisateur"
                },
                "department": {
                    "bsonType": "string",
                    "description": "Département de rattachement"
                },
                "role": {
                    "bsonType": "string",
                    "description": "Rôle / fonction professionnelle"
                },
                "is_service_account": {
                    "bsonType": "bool",
                    "description": "Indicateur de compte applicatif ou humain"
                },
                "usual_countries": {
                    "bsonType": "array",
                    "items": {"bsonType": "string"},
                    "description": "Tableau des pays de connexion habituels (codes ISO)"
                },
                "status": {
                    "enum": ["active", "locked", "disabled"],
                    "description": "Statut du compte"
                },
                "failed_login_count": {
                    "bsonType": ["int", "long"],
                    "minimum": 0,
                    "description": "Compteur de tentatives d'authentification échouées consécutives"
                }
            }
        }
    },

    # --------------------------------------------------------------------------
    # 2. HOSTS : metadata en sous-document imbriqué
    # --------------------------------------------------------------------------
    "hosts": {
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["host_id", "name", "ip", "os", "criticality", "owner", "metadata"],
            "properties": {
                "host_id": {
                    "bsonType": "string",
                    "description": "Identifiant unique de l'hôte (ex: host_0001)"
                },
                "name": {
                    "bsonType": "string",
                    "description": "Nom DNS ou hostname"
                },
                "ip": {
                    "bsonType": "string",
                    "description": "Adresse IP privée de la machine"
                },
                "os": {
                    "bsonType": "string",
                    "description": "Système d'exploitation installé"
                },
                "criticality": {
                    "enum": ["low", "medium", "high", "critical"],
                    "description": "Niveau de criticité pour le SIEM"
                },
                "owner": {
                    "bsonType": "string",
                    "description": "user_id du propriétaire / responsable"
                },
                "metadata": {
                    "bsonType": "object",
                    "required": ["datacenter", "rack", "environment"],
                    "properties": {
                        "datacenter": {"bsonType": "string"},
                        "rack": {"bsonType": "string"},
                        "environment": {"bsonType": "string"}
                    },
                    "description": "Sous-document contenant l'infrastructure d'hébergement"
                }
            }
        }
    },

    # --------------------------------------------------------------------------
    # 3. AUTHENTICATIONS : geo en sous-document, user_id/host_id en référence,
    #    user_department dénormalisé (optimisation pour A18)
    # --------------------------------------------------------------------------
    "authentications": {
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["auth_id", "timestamp", "user_id", "host_id", "source_ip", "result", "method", "geo", "user_department"],
            "properties": {
                "auth_id": {
                    "bsonType": "string",
                    "description": "Identifiant de l'événement d'authentification"
                },
                "timestamp": {
                    "bsonType": "date",
                    "description": "Horodatage précis de l'événement (BSON Date)"
                },
                "user_id": {
                    "bsonType": "string",
                    "description": "Référence vers users.user_id"
                },
                "host_id": {
                    "bsonType": "string",
                    "description": "Référence vers hosts.host_id"
                },
                "source_ip": {
                    "bsonType": "string",
                    "description": "Adresse IP cliente / source de connexion"
                },
                "result": {
                    "enum": ["success", "failure"],
                    "description": "Résultat de la tentative de connexion"
                },
                "method": {
                    "enum": ["password", "MFA", "SSO"],
                    "description": "Méthode d'authentification employée"
                },
                "geo": {
                    "bsonType": "object",
                    "required": ["country", "city", "lat", "lon"],
                    "properties": {
                        "country": {"bsonType": "string"},
                        "city": {"bsonType": "string"},
                        "lat": {"bsonType": ["double", "int"]},
                        "lon": {"bsonType": ["double", "int"]}
                    },
                    "description": "Sous-document de géolocalisation IP"
                },
                "user_department": {
                    "bsonType": "string",
                    "description": "Département dénormalisé de l'utilisateur pour accélération requête A18"
                }
            }
        }
    },

    # --------------------------------------------------------------------------
    # 4. NETWORK_FLOWS : flux de communication réseau
    # --------------------------------------------------------------------------
    "network_flows": {
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["flow_id", "timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "bytes", "host_id"],
            "properties": {
                "flow_id": {
                    "bsonType": "string",
                    "description": "Identifiant du flux réseau"
                },
                "timestamp": {
                    "bsonType": "date",
                    "description": "Horodatage de la session"
                },
                "src_ip": {
                    "bsonType": "string",
                    "description": "Adresse IP source"
                },
                "dst_ip": {
                    "bsonType": "string",
                    "description": "Adresse IP destination"
                },
                "dst_port": {
                    "bsonType": ["int", "long"],
                    "description": "Port de destination du service"
                },
                "protocol": {
                    "enum": ["TCP", "UDP", "ICMP"],
                    "description": "Protocole de transport"
                },
                "bytes": {
                    "bsonType": ["int", "long"],
                    "minimum": 0,
                    "description": "Volume d'octets échangés"
                },
                "host_id": {
                    "bsonType": "string",
                    "description": "Référence vers hosts.host_id"
                }
            }
        }
    },

    # --------------------------------------------------------------------------
    # 5. ALERTS : tags et related_events en tableaux
    # --------------------------------------------------------------------------
    "alerts": {
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["alert_id", "rule", "severity", "status", "related_events", "tags", "created_at"],
            "properties": {
                "alert_id": {
                    "bsonType": "string",
                    "description": "Identifiant de l'alerte SIEM"
                },
                "rule": {
                    "bsonType": "string",
                    "description": "Règle de détection déclenchée"
                },
                "severity": {
                    "enum": ["low", "medium", "high", "critical"],
                    "description": "Niveau de sévérité"
                },
                "status": {
                    "enum": ["open", "in_progress", "resolved", "closed"],
                    "description": "État du cycle de vie de l'alerte"
                },
                "analyst": {
                    "bsonType": ["string", "null"],
                    "description": "Nom ou ID de l'analyste SOC assigné"
                },
                "related_events": {
                    "bsonType": "array",
                    "items": {"bsonType": "string"},
                    "description": "Tableau des identifiants d'événements déclencheurs (auth_id / flow_id)"
                },
                "tags": {
                    "bsonType": "array",
                    "items": {"bsonType": "string"},
                    "description": "Tableau de tags de classification de sécurité"
                },
                "created_at": {
                    "bsonType": "date",
                    "description": "Horodatage de création de l'alerte"
                },
                "resolved_at": {
                    "bsonType": ["date", "null"],
                    "description": "Horodatage de résolution de l'alerte (null si non résolue)"
                }
            }
        }
    },

    # --------------------------------------------------------------------------
    # 6. IP_BLACKLIST : _id = adresse IP, index TTL sur expires_at
    # --------------------------------------------------------------------------
    "ip_blacklist": {
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["_id", "reason", "created_at", "expires_at"],
            "properties": {
                "_id": {
                    "bsonType": "string",
                    "description": "Adresse IP malveillante utilisée comme clé primaire _id"
                },
                "ip": {
                    "bsonType": "string",
                    "description": "Champ miroir d'adresse IP pour lisibilité"
                },
                "reason": {
                    "bsonType": "string",
                    "description": "Motif du blocage / source de la menace"
                },
                "created_at": {
                    "bsonType": "date",
                    "description": "Horodatage d'inscription en liste noire"
                },
                "expires_at": {
                    "bsonType": "date",
                    "description": "Horodatage d'expiration pour l'index TTL"
                }
            }
        }
    }
}

# ==============================================================================
# CONFIGURATION DES INDEX
# ==============================================================================
def create_indexes_for_collection(db, collection_name: str):
    """Crée l'ensemble des index préconisés pour une collection donnée."""
    coll = db[collection_name]

    if collection_name == "users":
        # Index unique sur user_id et index sur department
        coll.create_index([("user_id", ASCENDING)], unique=True, name="idx_users_user_id_unique")
        coll.create_index([("department", ASCENDING)], name="idx_users_department")

    elif collection_name == "hosts":
        # Index unique sur host_id
        coll.create_index([("host_id", ASCENDING)], unique=True, name="idx_hosts_host_id_unique")
        coll.create_index([("ip", ASCENDING)], name="idx_hosts_ip")

    elif collection_name == "authentications":
        # Index demandés :
        # - (user_id, timestamp desc) pour T4
        coll.create_index([("user_id", ASCENDING), ("timestamp", DESCENDING)], name="idx_auth_user_time_desc")
        # - (user_id, result, timestamp) pour T5
        coll.create_index([("user_id", ASCENDING), ("result", ASCENDING), ("timestamp", ASCENDING)], name="idx_auth_user_res_time")
        # - (host_id, timestamp) pour T6
        coll.create_index([("host_id", ASCENDING), ("timestamp", ASCENDING)], name="idx_auth_host_time")
        # - (source_ip, timestamp) pour S26 (force brute) et A17 (top 10 IP)
        coll.create_index([("source_ip", ASCENDING), ("timestamp", ASCENDING)], name="idx_auth_srcip_time")
        # - (timestamp) pour A16
        coll.create_index([("timestamp", ASCENDING)], name="idx_auth_timestamp")
        # - (result, timestamp) pour A17 optimisation
        coll.create_index([("result", ASCENDING), ("timestamp", ASCENDING)], name="idx_auth_res_time")
        # Index unique d'intégrité sur auth_id
        coll.create_index([("auth_id", ASCENDING)], unique=True, name="idx_auth_auth_id_unique")

    elif collection_name == "network_flows":
        # Index demandés :
        # - (host_id, timestamp)
        coll.create_index([("host_id", ASCENDING), ("timestamp", ASCENDING)], name="idx_flows_host_time")
        # - (src_ip)
        coll.create_index([("src_ip", ASCENDING)], name="idx_flows_src_ip")
        # - (dst_ip)
        coll.create_index([("dst_ip", ASCENDING)], name="idx_flows_dst_ip")
        # - (dst_port)
        coll.create_index([("dst_port", ASCENDING)], name="idx_flows_dst_port")
        # Index unique d'intégrité sur flow_id
        coll.create_index([("flow_id", ASCENDING)], unique=True, name="idx_flows_flow_id_unique")

    elif collection_name == "alerts":
        # Index demandés :
        # - tags en tableau : index multikey sur tags pour A25
        coll.create_index([("tags", ASCENDING)], name="idx_alerts_tags_multikey")
        # - (severity, status, created_at desc) pour T14
        coll.create_index([("severity", ASCENDING), ("status", ASCENDING), ("created_at", DESCENDING)], name="idx_alerts_sev_stat_time_desc")
        # - (analyst, status)
        coll.create_index([("analyst", ASCENDING), ("status", ASCENDING)], name="idx_alerts_analyst_status")
        # Index unique d'intégrité sur alert_id
        coll.create_index([("alert_id", ASCENDING)], unique=True, name="idx_alerts_alert_id_unique")

    elif collection_name == "ip_blacklist":
        # Index TTL sur expires_at (expireAfterSeconds: 0) pour T10
        coll.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0, name="idx_ip_blacklist_ttl")


# ==============================================================================
# INITIALISATION COMPLÈTE DU SCHÉMA
# ==============================================================================
def init_schema():
    """Initialise l'ensemble des collections et leurs index dans la base 'siem'."""
    client = get_mongo_client()
    db = client[DB_NAME]
    print(f"\n--- Initialisation de la base de données '{DB_NAME}' ---")

    for coll_name, schema_def in SCHEMAS.items():
        print(f"\n[*] Configuration de la collection '{coll_name}'...")
        
        # Si la collection existe, on la réinitialise pour garantir un état propre
        existing_colls = db.list_collection_names()
        if coll_name in existing_colls:
            print(f"    - Suppression de la collection existante '{coll_name}'")
            db[coll_name].drop()

        # Création de la collection avec validation JSON Schema stricte
        db.create_collection(
            coll_name,
            validator=schema_def,
            validationLevel="strict",
            validationAction="error"
        )
        print(f"    - Validation $jsonSchema activée (strict / error)")

        # Création des index
        create_indexes_for_collection(db, coll_name)
        indexes = db[coll_name].index_information()
        print(f"    - {len(indexes)} index configurés : {list(indexes.keys())}")

    print("\n[✓] Schéma et index initialisés avec succès dans la base 'siem' !")
    client.close()

if __name__ == "__main__":
    init_schema()
