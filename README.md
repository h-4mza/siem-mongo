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
├── docker-compose.yml        # Cluster MongoDB RS (3 nœuds) + Spark (1 master, 2 workers)
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

- **Valeur par défaut** : `mongodb://mongo1:27018,mongo2:27019,mongo3:27020/?replicaSet=rs0`
- **Nom de la base de données** : `siem`

> **Note** : Prérequis par PC : ajouter 127.0.0.1 mongo1 mongo2 mongo3 au fichier hosts (admin).

### Définir la variable d'environnement (optionnel) :

- **Linux / macOS :**
  ```bash
  export MONGO_URI="mongodb://mongo1:27018,mongo2:27019,mongo3:27020/?replicaSet=rs0"
  ```
- **Windows (PowerShell) :**
  ```powershell
  $env:MONGO_URI = "mongodb://mongo1:27018,mongo2:27019,mongo3:27020/?replicaSet=rs0"
  ```
- **Windows (CMD) :**
  ```cmd
  set MONGO_URI=mongodb://mongo1:27018,mongo2:27019,mongo3:27020/?replicaSet=rs0
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
# docker stop siem-mongo1
# Le script affichera la détection d'erreur, l'élection et la reprise avec la durée exacte d'indisponibilité.
```

### 9. Jobs Spark

L'infrastructure Spark est composée d'un **Spark Master** et de **deux Spark Workers**, connectés au même réseau Docker que le Replica Set MongoDB.

#### Architecture Spark

- Spark Master : `spark-master:7077`
- Spark UI : `http://localhost:8085` *(redirigé vers le port interne 8080 du conteneur master)*
- Worker 1 : 1 cœur, 1 Go de mémoire
- Worker 2 : 1 cœur, 1 Go de mémoire
- Version Apache Spark : `3.5.0`
- MongoDB Spark Connector : `10.3.0`

#### Vérification de la connexion Spark ↔ MongoDB

Le script suivant permet de vérifier que Spark peut lire les collections MongoDB :

```powershell
docker exec siem-spark-master /opt/spark/bin/spark-submit `
  --master spark://spark-master:7077 `
  --packages org.mongodb.spark:mongo-spark-connector_2.12:10.3.0 `
  --conf spark.jars.ivy=/tmp/.ivy2 `
  --conf spark.mongodb.read.connection.uri="mongodb://mongo1:27018,mongo2:27019,mongo3:27020/?replicaSet=rs0" `
  /opt/spark-apps/test_connection.py
```

Le test valide les 6 collections : `users` (10 000), `hosts` (2 000), `authentications` (60 500), `network_flows` (40 500), `alerts` (3 200), `ip_blacklist` (200).

#### Exécution des Jobs d'Analyse de Sécurité (S26 à S30)

Chaque job s'exécute dans le conteneur master via `spark-submit` et exporte ses résultats dans `results/spark_outputs/*.csv` :

```powershell
# S26 : Détection de force brute (fenêtre glissante 5 min, glissement 1 min)
docker exec siem-spark-master /opt/spark/bin/spark-submit `
  --master spark://spark-master:7077 `
  --packages org.mongodb.spark:mongo-spark-connector_2.12:10.3.0 `
  --conf spark.jars.ivy=/tmp/.ivy2 `
  --conf spark.mongodb.read.connection.uri="mongodb://mongo1:27018,mongo2:27019,mongo3:27020/?replicaSet=rs0" `
  /opt/spark-apps/s26_brute_force.py

# S27 : Voyage impossible (2 connexions consécutives réussies dans 2 pays en < 1h)
docker exec siem-spark-master /opt/spark/bin/spark-submit `
  --master spark://spark-master:7077 `
  --packages org.mongodb.spark:mongo-spark-connector_2.12:10.3.0 `
  --conf spark.jars.ivy=/tmp/.ivy2 `
  --conf spark.mongodb.read.connection.uri="mongodb://mongo1:27018,mongo2:27019,mongo3:27020/?replicaSet=rs0" `
  /opt/spark-apps/s27_impossible_travel.py

# S28 : Taux d'échec d'authentification par département et rôle
docker exec siem-spark-master /opt/spark/bin/spark-submit `
  --master spark://spark-master:7077 `
  --packages org.mongodb.spark:mongo-spark-connector_2.12:10.3.0 `
  --conf spark.jars.ivy=/tmp/.ivy2 `
  --conf spark.mongodb.read.connection.uri="mongodb://mongo1:27018,mongo2:27019,mongo3:27020/?replicaSet=rs0" `
  /opt/spark-apps/s28_failure_rate.py

# S29 : Hôtes contactant des IP blacklistées (broadcast join de ip_blacklist)
docker exec siem-spark-master /opt/spark/bin/spark-submit `
  --master spark://spark-master:7077 `
  --packages org.mongodb.spark:mongo-spark-connector_2.12:10.3.0 `
  --conf spark.jars.ivy=/tmp/.ivy2 `
  --conf spark.mongodb.read.connection.uri="mongodb://mongo1:27018,mongo2:27019,mongo3:27020/?replicaSet=rs0" `
  /opt/spark-apps/s29_blacklist_hosts.py

# S30 : Score de risque composite par utilisateur (Top 20)
docker exec siem-spark-master /opt/spark/bin/spark-submit `
  --master spark://spark-master:7077 `
  --packages org.mongodb.spark:mongo-spark-connector_2.12:10.3.0 `
  --conf spark.jars.ivy=/tmp/.ivy2 `
  --conf spark.mongodb.read.connection.uri="mongodb://mongo1:27018,mongo2:27019,mongo3:27020/?replicaSet=rs0" `
  /opt/spark-apps/s30_risk_score.py
```

#### Benchmark Global Spark (S26 à S30)
Pour exécuter les 5 requêtes à la suite et mesurer séparément lecture et calcul dans `results/spark_timings.csv` :
```powershell
docker exec siem-spark-master /opt/spark/bin/spark-submit `
  --master spark://spark-master:7077 `
  --packages org.mongodb.spark:mongo-spark-connector_2.12:10.3.0 `
  --conf spark.jars.ivy=/tmp/.ivy2 `
  --conf spark.mongodb.read.connection.uri="mongodb://mongo1:27018,mongo2:27019,mongo3:27020/?replicaSet=rs0" `
  /opt/spark-apps/spark_analysis.py
```

#### Comparatif de Performance Natif vs Spark (A16, A17, A20)
Pour lancer la comparaison avec vérification de l'égalité stricte des résultats et export dans `results/spark_vs_native.csv` :
```powershell
python spark/compare_native_vs_spark.py
```

---

### 10. Lancement du Dashboard de Supervision

Le dashboard Streamlit intègre les visualisations Plotly (A16, A17, A19, A21) connectées au Replica Set MongoDB et l'onglet de détections Spark (S26, S30) :

```powershell
streamlit run dashboard/app.py
```

Accès à l'application dans le navigateur : `http://localhost:8501`