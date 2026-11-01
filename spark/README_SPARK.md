# Guide Spark — SIEM MongoDB

## 1. Infrastructure

Le projet utilise un cluster Apache Spark connecté au Replica Set MongoDB.

### Versions validées

- **Apache Spark** : `3.5.0`
- **MongoDB** : `7`
- **MongoDB Spark Connector** : `10.3.0`

### Architecture

```text
                 ┌─────────────────┐
                 │  Spark Master   │
                 │ spark-master    │
                 │ Port 7077       │
                 └────────┬────────┘
                          │
              ┌───────────┴───────────┐
              │                       │
       ┌──────▼──────┐         ┌──────▼──────┐
       │  Worker 1   │         │  Worker 2   │
       │  1 Core     │         │  1 Core     │
       │  1 GiB      │         │  1 GiB      │
       └─────────────┘         └─────────────┘
                          │
                          ▼
                ┌──────────────────┐
                │ MongoDB Replica  │
                │    Set rs0       │
                └──────────────────┘
```

---

## 2. Connexion MongoDB

Les jobs Spark doivent utiliser le Replica Set MongoDB suivant :

```text
mongodb://mongo1:27018,mongo2:27019,mongo3:27020/?replicaSet=rs0
```

### Base de données

```text
siem
```

### Collections disponibles

| Collection | Nombre de documents |
|---|---:|
| `users` | 10 000 |
| `hosts` | 2 000 |
| `authentications` | 60 500 |
| `network_flows` | 40 500 |
| `alerts` | 3 200 |
| `ip_blacklist` | 200 |

**Total : 116 400 documents.**

---

## 3. Exécution d'un job Spark

Les scripts Spark doivent être placés dans le dossier :

```text
spark/
```

Les fichiers de ce dossier sont montés dans le conteneur à l'emplacement :

```text
/opt/spark-apps
```

Pour exécuter un job :

```powershell
docker exec siem-spark-master /opt/spark/bin/spark-submit `
  --master spark://spark-master:7077 `
  --packages org.mongodb.spark:mongo-spark-connector_2.12:10.3.0 `
  --conf spark.jars.ivy=/tmp/.ivy2 `
  --conf spark.mongodb.read.connection.uri="mongodb://mongo1:27018,mongo2:27019,mongo3:27020/?replicaSet=rs0" `
  /opt/spark-apps/<nom_du_script>.py
```

Remplacer :

```text
<nom_du_script>.py
```

par le nom réel du job Spark.

Exemple :

```text
/opt/spark-apps/s26_brute_force.py
```

---

## 4. Vérification de l'infrastructure

Le script suivant permet de vérifier la connexion entre Spark et MongoDB :

```text
spark/test_connection.py
```

Exécution :

```powershell
docker exec siem-spark-master /opt/spark/bin/spark-submit `
  --master spark://spark-master:7077 `
  --packages org.mongodb.spark:mongo-spark-connector_2.12:10.3.0 `
  --conf spark.jars.ivy=/tmp/.ivy2 `
  --conf spark.mongodb.read.connection.uri="mongodb://mongo1:27018,mongo2:27019,mongo3:27020/?replicaSet=rs0" `
  /opt/spark-apps/test_connection.py
```

La validation a confirmé que Spark peut lire les six collections MongoDB.

---

## 5. Types et structure des données

Avant de développer les jobs Spark, il est recommandé d'exécuter :

```text
spark/test_connection.py
```

afin d'afficher les schémas réellement détectés par Spark avec :

```python
df.printSchema()
```

Pour les jobs d'analyse :

- Vérifier le type réel de la colonne `timestamp`.
- Vérifier la structure réelle du champ `geo`.
- Utiliser les champs imbriqués avec la notation appropriée, par exemple :

```text
geo.country
```

Les jobs doivent être basés sur le schéma réellement affiché par `printSchema()`.

---

## 6. Particularité de `ip_blacklist`

Dans la collection `ip_blacklist`, l'adresse IP est stockée dans le champ :

```text
_id
```

Les jobs Spark qui utilisent la liste noire doivent donc tenir compte de cette structure lors des jointures ou des comparaisons avec les adresses IP présentes dans les autres collections.

---

## 7. Résultats des jobs

Le dossier local :

```text
results/
```

est monté dans les conteneurs Spark à l'emplacement :

```text
/opt/results
```

Les jobs Spark peuvent donc écrire leurs résultats dans :

```text
/opt/results
```

afin qu'ils soient également disponibles dans le dossier `results/` du projet sur la machine hôte.

---

## 8. Interface Spark

L'interface Web du Spark Master est accessible à l'adresse :

```text
http://localhost:8080
```

Elle permet de vérifier :

- l'état des Workers ;
- les applications en cours ;
- les applications terminées ;
- les ressources utilisées par le cluster.

Pour l'infrastructure validée, les deux Workers doivent apparaître avec l'état :

```text
ALIVE
```

---

## 9. Cache des dépendances

Le cache Ivy est monté depuis :

```text
./spark/.ivy2
```

vers :

```text
/tmp/.ivy2
```

Cela permet de conserver les packages téléchargés avec `--packages`, notamment le MongoDB Spark Connector.

La commande suivante doit utiliser la version validée :

```text
org.mongodb.spark:mongo-spark-connector_2.12:10.3.0
```

---

## 10. Problèmes rencontrés et solutions

### Les scripts Spark ne sont pas visibles dans le conteneur

Vérifier que le volume suivant est présent dans `docker-compose.yml` :

```yaml
volumes:
  - ./spark:/opt/spark-apps
```

### Le connecteur MongoDB doit être téléchargé

Utiliser :

```text
--packages org.mongodb.spark:mongo-spark-connector_2.12:10.3.0
```

Le cache Ivy permet de conserver les dépendances téléchargées.

### Connexion MongoDB depuis Spark

Ne pas utiliser `localhost` depuis les conteneurs Spark.

Utiliser les noms des services Docker :

```text
mongo1
mongo2
mongo3
```

avec l'URI :

```text
mongodb://mongo1:27018,mongo2:27019,mongo3:27020/?replicaSet=rs0
```