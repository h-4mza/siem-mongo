# Notes d'infrastructure — SIEM Distribué

## 1. Architecture générale

L'infrastructure du projet repose sur une architecture distribuée composée de deux parties principales :

1. Un Replica Set MongoDB composé de trois nœuds.
2. Un cluster Apache Spark composé d'un Master et de deux Workers.

L'ensemble des services communique à travers le réseau Docker :

```text
                     ┌─────────────────────────────┐
                     │      Réseau Docker          │
                     │       siem-network          │
                     └──────────────┬──────────────┘
                                    │
          ┌─────────────────────────┼─────────────────────────┐
          │                         │                         │
          ▼                         ▼                         ▼
   ┌─────────────┐           ┌─────────────┐           ┌─────────────┐
   │   mongo1    │           │   mongo2    │           │   mongo3    │
   │   PRIMARY   │           │ SECONDARY   │           │ SECONDARY   │
   │ Port 27018  │           │ Port 27019  │           │ Port 27020  │
   │ Priority 2  │           │ Priority 1  │           │ Priority 1  │
   └─────────────┘           └─────────────┘           └─────────────┘
          │                         │                         │
          └─────────────────────────┼─────────────────────────┘
                                    │
                             Replica Set rs0
                                    │
                                    ▼
                           ┌───────────────────┐
                           │   Spark Master    │
                           │ Port 7077         │
                           │ UI Port 8080      │
                           └─────────┬─────────┘
                                     │
                        ┌────────────┴────────────┐
                        │                         │
                        ▼                         ▼
                 ┌─────────────┐           ┌─────────────┐
                 │  Worker 1   │           │  Worker 2   │
                 │   1 Core    │           │   1 Core    │
                 │   1 GiB     │           │   1 GiB     │
                 └─────────────┘           └─────────────┘

## 2. MongoDB Replica Set

Le stockage distribué repose sur MongoDB 7 configuré sous la forme d'un Replica Set nommé `rs0`.

Les trois nœuds sont :

| Nœud | Adresse Docker | Port |
|---|---|---:|
| mongo1 | mongo1 | 27018 |
| mongo2 | mongo2 | 27019 |
| mongo3 | mongo3 | 27020 |

La configuration attribue une priorité supérieure à `mongo1` :

- `mongo1` : priorité 2
- `mongo2` : priorité 1
- `mongo3` : priorité 1

Ainsi, `mongo1` est privilégié lors des élections lorsqu'il est disponible.

## 3. Healthchecks et initialisation

Chaque conteneur MongoDB possède un healthcheck utilisant :

```text
db.adminCommand('ping')
```

Le service `mongo-init-replica` attend que les trois nœuds soient opérationnels avant d'initialiser le Replica Set.

Le Replica Set est configuré avec les membres :

```text
mongo1:27018
mongo2:27019
mongo3:27020
```

## 4. Ports et accès

Les ports MongoDB exposés sur la machine hôte sont :

```text
27018
27019
27020
```

Le port MongoDB standard `27017` n'est volontairement pas utilisé afin d'éviter un conflit avec une éventuelle installation locale de MongoDB sur l'ordinateur hôte.

Depuis la machine hôte, la connexion au Replica Set utilise l'URI :

```text
mongodb://mongo1:27018,mongo2:27019,mongo3:27020/?replicaSet=rs0
```

Pour permettre la résolution des noms `mongo1`, `mongo2` et `mongo3` depuis la machine hôte, l'entrée suivante doit être ajoutée au fichier `hosts` avec les droits administrateur :

```text
127.0.0.1 mongo1 mongo2 mongo3
```

Cette configuration est nécessaire pour les scripts Python exécutés directement sur la machine hôte.

En revanche, aucun fichier `hosts` supplémentaire n'est nécessaire entre les conteneurs Docker. Les services présents sur le réseau Docker `siem-network` peuvent communiquer directement en utilisant leurs noms de service :

```text
mongo1
mongo2
mongo3
spark-master
spark-worker-1
spark-worker-2
```

## 5. Infrastructure Apache Spark

Le projet utilise Apache Spark `3.5.0` afin de permettre l'exécution de traitements distribués sur les données de sécurité stockées dans MongoDB.

Le cluster Spark est composé de :

- 1 Spark Master ;
- 2 Spark Workers.

Le Spark Master est accessible à l'intérieur du réseau Docker à l'adresse :

```text
spark://spark-master:7077
```

Son interface Web est accessible depuis la machine hôte à l'adresse :

```text
http://localhost:8080
```

Les deux Workers sont configurés avec les ressources suivantes :

```text
SPARK_WORKER_CORES=1
SPARK_WORKER_MEMORY=1g
```

Chaque Worker dispose donc d'un cœur CPU et de 1 GiB de mémoire.

Cette limitation volontaire permet d'éviter de saturer les ressources d'un ordinateur portable pendant les démonstrations et les expérimentations du projet.

## 6. Volumes Spark

Les répertoires nécessaires à l'exécution des applications Spark sont montés dans le conteneur Spark Master ainsi que dans les deux Spark Workers.

Les volumes utilisés sont :

```text
./spark       → /opt/spark-apps
./results     → /opt/results
./spark/.ivy2 → /tmp/.ivy2
```

Le répertoire `/opt/spark-apps` contient les scripts Spark du projet.

Le répertoire `/opt/results` est destiné au stockage des résultats générés par les traitements Spark.

Le répertoire `/tmp/.ivy2` contient le cache Ivy utilisé par Spark pour stocker les dépendances téléchargées avec l'option `--packages`.

Ce cache permet notamment de conserver le connecteur MongoDB Spark afin d'éviter un nouveau téléchargement à chaque lancement du cluster ou d'une application. Cela améliore également la fiabilité des démonstrations lorsque la connexion Internet est limitée ou indisponible après un premier téléchargement réussi.

## 7. Validation de la connexion Spark ↔ MongoDB

La communication entre Apache Spark et MongoDB a été validée à l'aide du script :

```text
spark/test_connection.py
```

Le connecteur utilisé est :

```text
org.mongodb.spark:mongo-spark-connector_2.12:10.3.0
```

Cette version a été testée avec succès avec Apache Spark `3.5.0`.

La commande utilisée pour exécuter le test est :

```powershell
docker exec siem-spark-master /opt/spark/bin/spark-submit `
  --master spark://spark-master:7077 `
  --packages org.mongodb.spark:mongo-spark-connector_2.12:10.3.0 `
  --conf spark.jars.ivy=/tmp/.ivy2 `
  --conf spark.mongodb.read.connection.uri="mongodb://mongo1:27018,mongo2:27019,mongo3:27020/?replicaSet=rs0" `
  /opt/spark-apps/test_connection.py
```

Spark se connecte au Replica Set MongoDB `rs0` à travers le réseau Docker.

La base de données utilisée est :

```text
siem
```

Les collections suivantes ont été validées :

| Collection | Nombre de documents |
|---|---:|
| users | 10 000 |
| hosts | 2 000 |
| authentications | 60 500 |
| network_flows | 40 500 |
| alerts | 3 200 |
| ip_blacklist | 200 |

Le nombre total de documents validés est donc :

```text
116 400 documents
```

Le script affiche le schéma Spark de chaque collection ainsi que son nombre de documents.

Pour la collection `authentications`, un traitement supplémentaire est effectué :

```text
groupBy("result").count()
```

Cela permet également de vérifier que Spark peut effectuer une opération d'agrégation sur les données MongoDB.

L'exécution a été validée dans l'interface Spark avec les résultats suivants :

- 2 Workers dans l'état `ALIVE` ;
- l'application `SIEM-MongoDB-Connection-Test` correctement soumise au cluster ;
- état final de l'application : `FINISHED`.

La capture correspondante est disponible dans :

```text
report/img/spark_ui.png
```

Cette validation confirme que le cluster Spark est opérationnel et prêt à être utilisé pour les traitements distribués et les jobs d'analyse de la prochaine phase du projet.

## 8. Connectivité et utilisation par les jobs Spark

Les futurs jobs Spark peuvent accéder aux données MongoDB en utilisant directement les noms des services Docker.

L'URI utilisée à l'intérieur des conteneurs est :

```text
mongodb://mongo1:27018,mongo2:27019,mongo3:27020/?replicaSet=rs0
```

Le Replica Set est accessible depuis le Spark Master et les Spark Workers grâce au réseau Docker partagé.

Les scripts Spark sont accessibles dans les conteneurs via :

```text
/opt/spark-apps
```

Les résultats peuvent être écrits dans :

```text
/opt/results
```

Cette infrastructure permet donc aux futurs traitements Spark d'exécuter des analyses distribuées directement sur les collections MongoDB sans avoir besoin d'installer MongoDB ou Spark directement sur la machine hôte.

## 9. Limites de l'environnement

L'infrastructure présente volontairement certaines limites liées au contexte universitaire et aux ressources disponibles.

### Un seul hôte physique

Tous les conteneurs MongoDB et Spark sont exécutés sur un seul ordinateur physique.

L'architecture est donc distribuée au niveau logique grâce aux conteneurs Docker, mais les nœuds ne sont pas répartis sur plusieurs machines physiques.

### Simulation des pannes

Une panne de nœud est simulée en arrêtant un conteneur Docker.

Par exemple :

```powershell
docker stop siem-mongo1
```

Cette simulation permet d'observer le mécanisme d'élection automatique du Replica Set sans nécessiter plusieurs serveurs physiques.

### Absence d'authentification MongoDB

MongoDB n'utilise pas d'authentification dans cette infrastructure de démonstration.

Ce choix simplifie le déploiement et les expérimentations dans le cadre universitaire, mais ne constitue pas une configuration adaptée à un environnement de production.

### Ressources Spark limitées

Chaque Spark Worker est volontairement limité à :

```text
1 cœur CPU
1 GiB de mémoire
```

Cette configuration permet d'exécuter le cluster sur un ordinateur portable sans monopoliser l'ensemble des ressources disponibles.

### Environnement de démonstration

Cette architecture ne doit pas être considérée comme une configuration de production.

Dans un environnement réel, il serait notamment nécessaire de prévoir :

- une répartition des nœuds sur plusieurs machines physiques ;
- l'authentification et le contrôle des accès MongoDB ;
- le chiffrement des communications ;
- une gestion plus avancée des ressources Spark ;
- une supervision et une journalisation centralisées de l'infrastructure.

## 10. Relecture du test de bascule MongoDB

La procédure de test de bascule documentée dans la partie du projet consacrée à MongoDB est cohérente avec l'architecture du Replica Set `rs0`.

Le test consiste à effectuer des opérations pendant l'arrêt du nœud Primary afin d'observer :

1. la détection de l'indisponibilité du nœud ;
2. l'élection automatique d'un nouveau Primary parmi les nœuds disponibles ;
3. la reprise des opérations après l'élection.

Le Replica Set MongoDB est configuré avec trois membres, ce qui permet de maintenir une majorité disponible lorsqu'un seul nœud devient indisponible.

La priorité supérieure attribuée à `mongo1` signifie que ce nœud est privilégié lors des élections lorsqu'il est disponible. Toutefois, lorsqu'il est arrêté ou indisponible, un autre membre éligible du Replica Set peut être élu Primary.

La procédure de test de bascule décrite par P2 correspond donc au comportement attendu de l'architecture MongoDB configurée dans ce projet.

Il est important de noter que, dans cet environnement universitaire, la panne est simulée par l'arrêt d'un conteneur Docker. Le mécanisme d'élection reste néanmoins celui d'un véritable Replica Set MongoDB.

## 11. Conclusion

L'infrastructure du projet est composée d'un Replica Set MongoDB à trois nœuds et d'un cluster Apache Spark composé d'un Master et de deux Workers.

Le Replica Set `rs0` assure la réplication des données et permet de tester les mécanismes de haute disponibilité et de basculement automatique.

Le cluster Apache Spark a été configuré et validé avec succès pour communiquer avec MongoDB à l'aide du MongoDB Spark Connector `10.3.0`.

La validation a confirmé :

- la disponibilité des 3 nœuds MongoDB ;
- la disponibilité des 2 Spark Workers ;
- la lecture des 6 collections MongoDB ;
- la validation de 116 400 documents ;
- l'exécution réussie de l'application `SIEM-MongoDB-Connection-Test`.

L'infrastructure est désormais prête pour l'exécution des futurs jobs Spark dédiés à l'analyse distribuée et à la corrélation des événements de sécurité.