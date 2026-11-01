# SIEM Distribué avec MongoDB & Apache Spark

Projet universitaire implémentant une architecture SIEM (Security Information and Event Management) distribuée s'appuyant sur un Replica Set MongoDB (3 nœuds) et Apache Spark pour l'analyse et la corrélation de logs de sécurité.

---

## Démarrage rapide

1. Une fois par PC, ajouter dans le fichier hosts (droits admin) :
   `127.0.0.1 mongo1 mongo2 mongo3`
2. `docker compose up -d`  (attendre ~45 s, les 3 mongo doivent être "healthy")
3. `python data_generator/generate_data.py`
4. `python schema/create_schema.py`   (réinitialise les collections)
5. `python schema/load_data.py`       (à lancer UNE fois après create_schema)
6. `python schema/verify_db.py`

URI par défaut : mongodb://mongo1:27018,mongo2:27019,mongo3:27020/?replicaSet=rs0
(utilisable aussi depuis les conteneurs Spark)

## 📁 Structure du projet

```text
siem-mongo/
├── docker-compose.yml        # Déploiement de l'infrastructure (MongoDB RS + Spark) - Géré par l'équipier
├── requirements.txt          # Dépendances Python du projet
├── README.md                 # Guide de déploiement et d'utilisation
├── data_generator/           # Scripts de génération et d'ingestion de logs de sécurité (Faker)
├── schema/                   # Définition du schéma MongoDB, validation et indexation
├── queries/                  # Requêtes analytiques et pipelines d'agrégation de sécurité
├── spark/                    # Traitements distribués et jobs d'analyse Spark
├── dashboard/                # Interface de visualisation des alertes et métriques
└── report/                   # Documentation technique et livrables universitaires
```

---

## ⚙️ Prérequis

- **Python 3.10+**
- **pip** (gestionnaire de paquets Python)
- **MongoDB** en replica set (`rs0`) actif (déployé via Docker Compose)

---

## 📦 Installation des dépendances

À la racine du dossier `siem-mongo` :

```bash
# Création d'un environnement virtuel (recommandé)
python -m venv .venv

# Activation de l'environnement virtuel
# Sur Linux / macOS :
source .venv/bin/activate
# Sur Windows (PowerShell) :
.venv\Scripts\Activate.ps1
# Sur Windows (CMD) :
.venv\Scripts\activate.bat

# Installation des dépendances
pip install -r requirements.txt
```

---

## 🔧 Configuration de la connexion MongoDB

La connexion à la base de données s'effectue via la variable d'environnement `MONGO_URI`.

- **Valeur par défaut** : `mongodb://localhost:27017/?replicaSet=rs0`
- **Nom de la base de données** : `siem`

### Définir la variable d'environnement (optionnel) :

- **Linux / macOS :**
  ```bash
  export MONGO_URI="mongodb://localhost:27017/?replicaSet=rs0"
  ```
- **Windows (PowerShell) :**
  ```powershell
  $env:MONGO_URI = "mongodb://localhost:27017/?replicaSet=rs0"
  ```
- **Windows (CMD) :**
  ```cmd
  set MONGO_URI=mongodb://localhost:27017/?replicaSet=rs0
  ```

---

## 🚀 Utilisation des scripts

*(Ce guide sera complété au fur et à mesure de l'ajout des composants)*

### 1. Génération des jeux de données de simulation
```bash
python data_generator/generate_data.py
```

### 2. Initialisation du schéma MongoDB, validation et index
```bash
python schema/create_schema.py
```

### 3. Chargement des données dans MongoDB (lots de 5 000)
```bash
python schema/load_data.py
```

### 4. Vérification de la base (comptage et index)
```bash
python schema/verify_db.py
```

### 5. Benchmark des requêtes transactionnelles (T1 à T15)
```bash
python queries/transactional.py
```

### 6. Benchmark des requêtes analytiques (A16 à A25) et expériences d'indexation
```bash
python queries/analytical.py
```

### 7. Expérience de cohérence et durabilité (WriteConcern & ReadConcern / ReadPreference)
```bash
python queries/consistency_experiment.py
```

### 8. Test de basculement automatique et résilience (Failover)
```bash
# Lance une écriture continue toutes les 100 ms avec retryWrites=true
python queries/failover_test.py

# Pour tester le basculement : dans un autre terminal, stoppez le primaire Docker :
# docker stop <nom_du_container_mongo_primaire>
# Le script affichera la détection d'erreur, l'élection et la reprise avec la durée exacte d'indisponibilité.
```

### 9. Jobs Spark
```bash
spark-submit --packages org.mongodb.spark:mongo-spark-connector_2.12:10.x.x spark/spark_analysis.py
```

### 10. Lancement du Dashboard
```bash
streamlit run dashboard/app.py
```
