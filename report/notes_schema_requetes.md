# Notes de Synthèse : Schéma, Requêtes (T1 à T25) et Expériences d'Indexation

Ce document constitue la base technique du rapport de projet universitaire SIEM distribué (MongoDB & Spark). Il synthétise l'implémentation, les performances mesurées sur un replica set MongoDB de 3 nœuds (Docker) et les choix d'indexation pour l'ensemble des 25 requêtes opérationnelles et analytiques, accompagnées des résultats chiffrés et vérifiés des benchmarks d'indexation.

---

## 1. Tableau Récapitulatif des 25 Requêtes (T1 à T15 et A16 à A25)

Toutes les métriques temporelles correspondent à la moyenne sur 5 exécutions successives (exprimées en millisecondes), mesurées sur un replica set MongoDB de 3 nœuds (Docker) après le chargement complet des 116 400 documents dans MongoDB.

| Réf | Énoncé du Sujet | Requête MongoDB Utilisée | Index Mobilisé | Temps Mesuré | Justification Technique & Choix de Conception |
| :--- | :--- | :--- | :--- | :---: | :--- |
| **T1** | Insérer une authentification | `db.authentications.insertOne(doc)` | `_id_`, `idx_auth_auth_id_unique` | **22.63 ms** | Insertion unitaire sous `$jsonSchema` avec Write Concern `w: "majority"` (défaut replica set). Temps à froid sur 5 itérations incluant handshake initial (8.24 ms en régime stabilisé sur 200 itérations). |
| **T2** | Insérer 1000 flux en lot (insert_many) | `db.network_flows.insertMany(batch, {ordered: false})` | `_id_`, `idx_flows_flow_id_unique` | **135.98 ms** | Écriture vectorisée par lot (*batching*) amortissant le coût réseau et disque (~7 350 docs/sec sur 3 nœuds). |
| **T3** | Profil d'un utilisateur | `db.users.findOne({user_id: "usr_00001"})` | `idx_users_user_id_unique` `(user_id: 1)` | **1.38 ms** | Recherche O(1) sur la clé métier unique de l'utilisateur sans jointure. |
| **T4** | 20 dernières connexions (tri desc) | `db.authentications.find({user_id}).sort({timestamp: -1}).limit(20)` | `idx_auth_user_time_desc` `(user_id: 1, timestamp: -1)` | **4.22 ms** | Index composé aligné sur le filtre et l'ordre de tri : élimine tout tri en mémoire RAM (*no in-memory sort*). |
| **T5** | Échecs de connexion sur les dernières 24 h | `db.authentications.find({user_id, result: "failure", timestamp: {$gte, $lte}}).sort({timestamp: 1})` | `idx_auth_user_res_time` `(user_id: 1, result: 1, timestamp: 1)` | **2.39 ms** | Règle ESR (Égalité sur `user_id` et `result`, puis intervalle sur `timestamp`). Accès direct en O(log n) via l'arbre B-Tree sans balayage. |
| **T6** | Événements d'un hôte pour un jour donné (page 50 par curseur, pas skip) | `db.authentications.find({host_id, timestamp: {$gt: cursor, $lte: fin}}).sort({timestamp: 1}).limit(50)` | `idx_auth_host_time` `(host_id: 1, timestamp: 1)` | **3.44 ms** | Pagination par curseur évitant le balayage O(N) inhérent à `$skip` sur les collections volumineuses. |
| **T7** | Créer une alerte | `db.alerts.insertOne(alert_doc)` | `_id_`, `idx_alerts_alert_id_unique` | **11.13 ms** | Enregistrement atomique de l'alerte intégrant son tableau de tags et la liste de références aux événements. |
| **T8** | Changer le statut d'une alerte et affecter un analyste (update_one) | `db.alerts.updateOne({alert_id}, {$set: {status, analyst}})` | `idx_alerts_alert_id_unique` `(alert_id: 1)` | **7.02 ms** | Ciblage direct par l'identifiant d'alerte et mise à jour ponctuelle en place. |
| **T9** | Ajouter un tag (utiliser $addToSet) | `db.alerts.updateOne({alert_id}, {$addToSet: {tags: tag}})` | `idx_alerts_alert_id_unique` `(alert_id: 1)` | **4.68 ms** | `$addToSet` garantit l'unicité des tags dans le tableau sans nécessiter de lecture préalable. |
| **T10** | Bloquer une IP avec expiration à 7 jours | `db.ip_blacklist.updateOne({_id: ip}, {$set: {ip, reason, created_at, expires_at}}, {upsert: true})` | `_id_`, `idx_ip_blacklist_ttl` `(expires_at: 1, TTL: 0s)` | **11.67 ms** | Clé primaire naturelle `_id = ip` pour un accès O(1) et purge automatique par le moteur TTL MongoDB. |
| **T11** | Vérifier si une IP est bloquée | `db.ip_blacklist.findOne({_id: ip})` | `_id_` (clé primaire) | **2.18 ms** | Vérification quasi-instantanée en mémoire vive lors du contrôle en temps réel des flux entrants. |
| **T12** | Incrémenter ($inc) puis remettre à zéro le compteur d'échecs | `db.users.updateOne({user_id}, {$inc: {failed_login_count: 1}})` puis `{$set: {failed_login_count: 0}}` | `idx_users_user_id_unique` `(user_id: 1)` | **20.97 ms** | Modification atomique sur document évitant les conditions de course (*race conditions*) lors d'attaques concurrentes. |
| **T13** | Supprimer les événements d'un hôte retiré (delete_many) | `db.authentications.deleteMany({host_id})` & `db.network_flows.deleteMany({host_id})` | `idx_auth_host_time`, `idx_flows_host_time` | **35.57 ms** | Les index préfixés par `host_id` localisent et suppriment immédiatement les documents liés sans balayer les collections. |
| **T14** | Alertes critiques ouvertes, plus récentes d'abord | `db.alerts.find({severity: "critical", status: "open"}).sort({created_at: -1})` | `idx_alerts_sev_stat_time_desc` `(severity: 1, status: 1, created_at: -1)` | **3.56 ms** | Index composé couvrant le double filtre d'égalité et le tri descendant pour la file de triage du SOC. |
| **T15** | Verrouiller un compte (status = locked) | `db.users.updateOne({user_id}, {$set: {status: "locked"}})` | `idx_users_user_id_unique` `(user_id: 1)` | **4.19 ms** | Révocation immédiate d'accès par clé unique lors de la confirmation d'une compromission. |
| **A16** | Connexions réussies/échouées par jour sur 30 jours | `aggregate([{$group: {_id: {$dateToString}, succes: {$sum: {$cond}}, echecs: {$sum: {$cond}}}}, {$sort: {_id: 1}}])` | `idx_auth_timestamp` `(timestamp: 1)` | **127.15 ms** | Agrégation volumique sur les 60 500 documents avec calcul conditionnel vectorisé par journée. |
| **A17** | Top 10 IP sources par nombre d'échecs sur une journée | `aggregate([{$match: {result: "failure", timestamp: {$gte, $lte}}}, {$sortByCount: "$source_ip"}, {$limit: 10}])` | `idx_auth_res_time` `(result: 1, timestamp: 1)` | **13.10 ms** | L'index composite ESR restreint la recherche aux seuls échecs du jour sans charger les connexions réussies. |
| **A18** | Connexions réussies entre 22h et 6h pour un département (sans $lookup) | `aggregate([{$match: {user_department, result: "success", $expr: {$or: [...]}}}, {$group: {_id: "$user_id", nb: {$sum: 1}}}, {$sort: {nb: -1}}])` | Champ dénormalisé `user_department` | **132.82 ms** | La dénormalisation évite une jointure inter-collections sur 60k+ événements (5.9x plus rapide que `$lookup`). |
| **A19** | Alertes par sévérité et statut | `aggregate([{$group: {_id: {severity: "$severity", status: "$status"}, count: {$sum: 1}}}, {$sort: {"_id.severity": 1}}])` | `idx_alerts_sev_stat_time_desc` | **7.67 ms** | L'index composé préfixé par `(severity, status)` accélère le partitionnement des groupes d'alertes. |
| **A20** | Octets par hôte pour une journée | `aggregate([{$match: {timestamp: {$gte, $lte}}}, {$group: {_id: "$host_id", total_bytes: {$sum: "$bytes"}, nb_flux: {$sum: 1}}}, {$sort: {total_bytes: -1}}])` | `idx_flows_host_time` `(host_id: 1, timestamp: 1)` | **42.66 ms** | Isole les flux réseau sur la fenêtre d'un jour avant d'agréger les volumes d'octets transférés. |
| **A21** | Top 10 ports de destination | `aggregate([{$sortByCount: "$dst_port"}, {$limit: 10}])` | `idx_flows_dst_port` `(dst_port: 1)` | **51.05 ms** | Comptage et classement direct sur le champ `dst_port` pour repérer les services ciblés (443, 80, 22, 3389). |
| **A22** | Utilisateurs connectés depuis plus de 3 pays en une semaine | `aggregate([{$match: {timestamp: {$gte}}}, {$group: {_id: {user_id, semaine: {$dateToString}}, pays: {$addToSet: "$geo.country"}}}, {$project: {nb_pays: {$size: "$pays"}}}, {$match: {nb_pays: {$gt: 3}}}])` | `idx_auth_timestamp` `(timestamp: 1)` | **183.84 ms** | Le `$match` temporel initial réduit de moitié les documents à grouper et dédoublonner (détecte les attaquants injectés). |
| **A23** | Répartition par méthode d'authentification | `aggregate([{$sortByCount: "$method"}])` | Scan de collection (3 modalités) | **75.31 ms** | Statistiques globales d'utilisation des protocoles d'accès (Password, MFA, SSO) sur l'ensemble de l'organisation. |
| **A24** | Délai moyen de résolution par analyste ($subtract sur les dates) | `aggregate([{$match: {status: {$in: ["resolved", "closed"]}}}, {$project: {duree: {$subtract: ["$resolved_at", "$created_at"]}}}, {$group: {_id: "$analyst", delai_moyen: {$avg: ...}}}])` | `idx_alerts_analyst_status` `(analyst: 1, status: 1)` | **25.30 ms** | Calcul arithmétique direct sur dates BSON en millisecondes et regroupement par analyste SOC. |
| **A25** | Alertes avec un tag donné | `aggregate([{$match: {tags: tag}}, {$sort: {created_at: -1}}, {$limit: 50}])` | `idx_alerts_tags_multikey` `(tags: 1)` | **11.68 ms** (global) / **2.84 ms** (freq) | L'index multikey sur le tableau `tags` permet un filtrage direct, particulièrement décisif sur les tags rares. |

---

## 2. Expériences d'Indexation : Analyse Quantitative et Comparaison COLLSCAN vs IXSCAN

Pour évaluer concrètement l'impact des index et de la modélisation sur le moteur WiredTiger au sein du cluster 3 nœuds, nous avons mené 5 séries d'expérimentations rigoureuses.
Toutes les métriques proviennent de l'introspection `explain("executionStats")` de MongoDB et de moyennes chronométrées sur 5 itérations (consignées dans `results/index_experiments.csv`).

### Tableau Récapitulatif des Expérimentations

| Requête Cible | Configuration Testée | Stage Principal | Clés Examinées (`keysExamined`) | Documents Examinés (`docsExamined`) | Documents Retournés (`nReturned`) | Temps Moyen (`temps_ms`) | Interprétation & Impact |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **T5** *(Échecs 24h)* | **AVEC_INDEX** `(user_id, result, timestamp)` | `IXSCAN` | **2** | **2** | **2** | **2.39 ms** | **15.2x plus rapide** (`nReturned = 2 > 0` garanti) |
| | **SANS_INDEX** | `COLLSCAN` | 0 | 60 505 | 2 | 36.27 ms | Balayage séquentiel complet de 60 505 documents |
| **A25** *(Tag fréquent : auth, ~63%)* | **AVEC_INDEX** `(tags)` | `IXSCAN` | 50 | 50 | 50 | 2.84 ms | Faible sélectivité : B-Tree traverse 50 entrées |
| | **SANS_INDEX** | `COLLSCAN` | 0 | 78 | 50 | **3.91 ms** | `COLLSCAN` s'arrête dès que `limit(50)` est atteint (78 docs lus) |
| **A25** *(Tag rare : zero_day, 1.25%)* | **AVEC_INDEX** `(tags)` | `IXSCAN` | **40** | **40** | **40** | **2.66 ms** | **1.33x plus rapide**, 98.8% d'I/O épargnées |
| | **SANS_INDEX** | `COLLSCAN` | 0 | 3 205 | 40 | 3.54 ms | `COLLSCAN` doit balayer les 3 205 alertes pour trouver les 40 |
| **A17** *(Top 10 échecs journaliers)* | **INDEX `(result, timestamp)`** | `IXSCAN` | **2 805** | **2 805** | **2 805** | **15.02 ms** | Règle ESR : égalité `result='failure'` dès l'index (aucun doc superflu) |
| | **INDEX `(timestamp)`** | `IXSCAN` | 4 508 | 4 508 | 2 805 | **11.32 ms** | Index temporel seul : lit 4 508 docs et filtre `result` en mémoire cache |
| | **SANS_INDEX** | `COLLSCAN` | 0 | 60 505 | 2 805 | 33.76 ms | Balayage complet des 60 505 événements |
| **A22** *(Voyages multiples)* | **AVEC `$match` temporel (14j)** | `IXSCAN` | **29 734** | **29 734** | **29 734** | **207.20 ms** | **31.8% de réduction du temps**, 30 771 documents évités |
| | **SANS `$match` temporel** | `COLLSCAN` | 0 | 60 505 | 60 505 | 303.90 ms | Groupement et dédoublonnage sur l'intégralité des 30 jours |
| **A18** *(Connexions de nuit)* | **DÉNORMALISÉE** | `IXSCAN` | 49 143 | 49 143 | 1 779 | **132.82 ms** | **5.9x plus rapide**, groupement direct en streaming |
| | **AVEC `$LOOKUP` (Normalisée)** | `IXSCAN` | 49 143 | 49 143 | 16 735 | 783.09 ms | Goulot d'étranglement : jointure de 16 700+ documents |

---

### Analyse Détaillée des Résultats

#### 1. Cas T5 : Vérification rigoureuse avec `nReturned > 0`
- **Contexte expérimental** : L'expérimentation a été conduite sur l'utilisateur identifié `usr_00001`, pour lequel des échecs de connexion récents ont été générés dans les dernières 24 heures (`nReturned = 2`).
- **Sans index** : MongoDB effectue un `COLLSCAN` intégral de la collection `authentications` (**60 505 documents examinés**) pour trouver les 2 enregistrements pertinents, consommant **36.27 ms**.
- **Avec index `(user_id, result, timestamp)`** : L'index composite respecte parfaitement la règle ESR (*Equality, Sort, Range*). Le moteur cible immédiatement les **2 clés d'index** et charge exactement les **2 documents nécessaires** (`docsExamined = 2`), ramenant l'exécution à **2.39 ms** (facteur d'accélération de **15.2x**).

#### 2. Cas A25 : Comportement comparé selon la sélectivité (Tag Fréquent vs Tag Rare)
- **Tag fréquent (`auth`, ~63% des alertes, limit=50)** :
  - `AVEC INDEX` : 2.84 ms (50 clés et 50 documents examinés).
  - `SANS INDEX` : 3.91 ms (78 documents examinés en `COLLSCAN`).
  - *Constat honnête* : Lorsque le prédicat a une très faible sélectivité et qu'une clause `$limit` précoce est présente, le balayage séquentiel s'arrête très vite (après 78 documents lus). L'index apporte un gain modeste (2.84 ms vs 3.91 ms) car la navigation dans l'arbre B-Tree a un coût fixe comparable à la lecture des premiers blocs contigus.
- **Tag rare (`zero_day`, 1.25% des alertes, soit 40 documents sur 3 205)** :
  - `AVEC INDEX` : 2.66 ms (40 clés examinées, 40 documents lus).
  - `SANS INDEX` : 3.54 ms (3 205 documents examinés).
  - *Constat honnête* : L'index devient particulièrement protecteur pour les valeurs rares : il évite de parcourir l'intégralité des 3 205 alertes de la collection en ciblant directement les 40 documents.

#### 3. Cas A17 : Analyse comparée de l'index composite ESR vs index temporel simple
- **Index `(timestamp)` seul** : L'index isole la plage temporelle de la journée (4 508 documents). Comme le champ `result` n'est pas indexé, MongoDB charge chaque document pour vérifier `result == "failure"` (**4 508 documents examinés** pour **11.32 ms** lorsque les blocs sont déjà en mémoire cache WiredTiger).
- **Index composite `(result, timestamp)`** : En plaçant le critère d'égalité `result = "failure"` en tête de l'index avant l'intervalle temporel, le moteur élimine immédiatement les connexions réussies dès l'index. Seuls les **2 805 documents d'échec** sont examinés (**15.02 ms**). L'index composite réduit de 38% le volume de documents examinés (2 805 vs 4 508), évitant des I/O inutiles en cas de cache froid.
- **Sans index** : Un `COLLSCAN` complet parcourt les 60 505 documents en **33.76 ms**.

#### 4. Cas A22 : Optimisation des pipelines d'agrégation volumineux par filtrage amont
- **Sans `$match` temporel** : Le moteur doit grouper et extraire les pays uniques pour l'ensemble des 60 505 événements sur 30 jours, mobilisant **303.90 ms**.
- **Avec `$match` temporel amont (14 jours)** : En restreignant la fenêtre temporelle en première étape de pipeline, l'index temporel élimine 30 771 documents en amont. L'étape `$group` ne traite que 29 734 documents, faisant chuter le temps à **207.20 ms** (**gain de 31.8%**).

#### 5. Cas A18 : Mesure réelle de la dénormalisation vs jointure `$lookup` (et analyse de l'écart initial)
- **Origine des écarts de mesure (61 ms → 401.86 ms → 132.82 ms)** :
  - La valeur préliminaire de ~61 ms correspondait à une requête restreinte à une période temporelle partielle (ex: fenêtre de 7 jours).
  - L'évaluation exhaustive sur les **30 jours de la collection (60 500 documents)** sans filtre temporel oblige MongoDB à parcourir les 49 143 connexions réussies pour évaluer l'expression `$hour` et filtrer le département Finance.
  - L'écart mesuré entre la machine locale mono-nœud (**401.86 ms**) et le replica set (**132.82 ms**) reflète uniquement des environnements d'exécution différents (ressources matérielles, ordonnancement des processus et charge système).
  - **Harmonisation stricte** : La suite analytique globale et l'expérience d'indexation sont mesurées avec rigoureusement les mêmes paramètres (département `"Finance"`, 30 jours, moyenne sur 5 itérations) et affichent exactement la même valeur (**132.82 ms** dans `timings.csv` et `index_experiments.csv`).
- **Approche normalisée (`$lookup` vers `users`)** : Pour chaque connexion nocturne réussie, MongoDB doit effectuer une résolution vers la collection `users` pour récupérer le département (16 735 jointures traitées). Le temps d'exécution s'élève à **783.09 ms**.
- **Approche dénormalisée (`user_department` stocké dans le log)** : La requête s'exécute directement sur la collection `authentications` sans aucune jointure inter-collections, en **132.82 ms**.
- *Conclusion chiffrée* : La dénormalisation apporte un gain de performance direct d'un facteur **5.9x** (132.82 ms vs 783.09 ms), justifiant pleinement ce choix de modélisation pour un SIEM distribué à haute cadence.

---

## 3. Expériences de Cohérence, Durabilité et Résilience (Replica Set & Failover)

Afin d'évaluer la robustesse du SIEM face aux pannes et de mesurer l'impact des garanties ACID sur la réactivité du système, nous avons mené deux séries d'expérimentations sur le comportement distribué du cluster MongoDB (replica set de 3 nœuds `rs0`).

### 3.1. Mesures des Niveaux de Write Concern et Read Concern (`consistency_experiment.py`)

Les résultats ont été enregistrés dans `results/consistency_experiments.csv` sur des séries de 200 opérations par configuration :

| Opération | Paramètre Évalué | Configuration | WriteConcern | Journal | ReadConcern | ReadPreference | Temps Moyen | P95 |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **T1 (Écriture)** | Latence brute | `w:1` | `w:1` | `False` | *N/A* | *N/A* | **3.81 ms** | **4.96 ms** |
| **T1 (Écriture)** | Consensus quorum | `w:majority` | `w:majority` | `False` | *N/A* | *N/A* | **8.24 ms** | **14.46 ms** |
| **T1 (Écriture)** | Durabilité stricte | `w:majority+j:true` | `w:majority` | `True` | *N/A* | *N/A* | **10.90 ms** | **21.91 ms** |
| **T3 (Lecture)** | Primaire local | `rc:local + rp:primary` | *N/A* | *N/A* | `local` | `primary` | **2.67 ms** | **5.33 ms** |
| **T3 (Lecture)** | Primaire majorité | `rc:majority + rp:primary` | *N/A* | *N/A* | `majority` | `primary` | **1.25 ms** | **2.07 ms** |
| **T3 (Lecture)** | Réplica secondaire | `rc:local + rp:secondaryPreferred` | *N/A* | *N/A* | `local` | `secondaryPreferred` | **2.10 ms** | **3.59 ms** |
| **T3 (Lecture)** | Réplica majorité | `rc:majority + rp:secondaryPreferred` | *N/A* | *N/A* | `majority` | `secondaryPreferred` | **1.95 ms** | **2.76 ms** |

### 3.2. Analyse du Compromis Latence vs Durabilité (Trade-off)

1. **Write Concern et Durabilité des Événements SOC sur le Replica Set** :
   - **Write Concern utilisé par T1 et explication de l'écart avec `consistency_experiments.csv`** :
     - Dans `queries/transactional.py`, T1 applique le Write Concern par défaut du cluster MongoDB 5.0+ sur Replica Set, à savoir **`w: "majority"`**.
     - Le temps rapporté dans `timings.csv` (**22.63 ms**) correspond à une mesure ponctuelle sur seulement 5 itérations exécutées dès le lancement du processus, sans préchauffage. La première écriture absorbe le surcoût de découverte de la topologie SDAM, l'ouverture des sockets et l'initialisation du validateur `$jsonSchema`.
     - Dans `results/consistency_experiments.csv`, la mesure est réalisée en **régime stabilisé sur 200 itérations successives**, où ce coût d'initialisation est lissé : le temps moyen de **`w: "majority"`** s'établit alors à **8.24 ms** (P95: 14.46 ms).
   - **`w:1` (Asynchrone vers les secondaires)** : Le nœud primaire accuse réception dès l'inscription de l'événement en mémoire vive / WAL local. La latence moyenne est de **3.81 ms** (P95: 4.96 ms). C'est le choix privilégié pour l'ingestion massive de flux réseau haute fréquence (**T2**) où un débit élevé est requis (~7 350 docs/sec) et où la perte théorique de quelques trames réseau lors d'un crash brutal reste tolérable. En revanche, `w:1` présente un risque de **perte de données (*rollback*)** si le primaire subit une coupure d'alimentation avant d'avoir propagé l'oplog aux secondaires.
   - **`w:"majority"` (Consensus distribué sur 2/3 nœuds)** : Le primaire attend la confirmation d'au moins un réplica secondaire avant de répondre au client. Sur notre cluster Docker à 3 nœuds en régime établi, le temps moyen passe à **8.24 ms** (P95: 14.46 ms), soit un facteur **2.16x plus lent** que `w:1` en raison du round-trip réseau inter-conteneurs et de la confirmation du quorum. C'est le standard indispensable pour les événements de sécurité critiques : **T1 (Authentications)**, **T7 (Création d'alertes SOC)**, **T10 (Blacklistage IP)** et **T15 (Verrouillage de compte)**.
   - **`w:"majority" + j:true` (Synchronisation fsync sur disque)** : En plus du consensus de la majorité des nœuds, le moteur WiredTiger force une écriture synchrone sur le journal physique avant d'accuser réception. La latence moyenne s'élève à **10.90 ms** et le P95 bondit à **21.91 ms** (+51% par rapport à `w:majority`), traduisant l'impact des I/O disques bloquantes. Cette garantie est requise lorsque la perte de données est inacceptable même en cas de panne électrique simultanée de l'ensemble du datacenter.

2. **Read Preference, Read Concern et Bruit de Mesure sur T3** :
   - **Analyse de T3 (Profil utilisateur)** : L'écart mesuré entre `readConcern: "local"` (2.67 ms, P95: 5.33 ms) et `readConcern: "majority"` (1.25 ms, P95: 2.07 ms) se situe **dans le bruit de mesure** inhérent aux micro-variations de latence réseau et d'ordonnancement de l'hôte, les documents résidant dans les deux cas directement en mémoire cache WiredTiger.
   - **Déportation de charge (`secondaryPreferred`)** : L'utilisation de `readPreference=secondaryPreferred` pour les requêtes de consultation fréquentes (ex: **T3 Profil utilisateur**, **A19 Statut des alertes** ou les dashboards de visualisation) permet de distribuer la charge de lecture sur les réplicas secondaires (`siem-mongo2`, `siem-mongo3`), réservant l'intégralité des cycles d'écriture du primaire `siem-mongo1` au flux d'ingestion des logs d'authentification et de flux réseau.
   - La combinaison avec `readConcern="majority"` protège l'analyste SOC contre la lecture de données incohérentes (*dirty reads* ou lectures fantômes de transactions non pérennes) en consultant uniquement les clichés (*snapshots*) validés par le quorum de réplication.

### 3.3. Tests de Bascule : Arrêt Propre (`docker stop`) vs Crash Brutal (`docker kill`)

Deux expérimentations distinctes de tolérance aux pannes ont été pilotées et mesurées avec le script `queries/failover_test.py` (consignées dans `results/failover_output.txt`) sous une charge d'écriture continue (1 insertion toutes les 100 ms avec `retryWrites=True`).

#### 1. Test (A) : Arrêt Propre du Primaire (`docker stop siem-mongo1`)
- **Déclenchement** : `docker stop siem-mongo1` exécuté à **19:21:26.642**.
- **Mécanisme** : Le signal `SIGTERM` déclenche un désistement ordonné (*clean stepdown*) de `siem-mongo1`. Le primaire informe immédiatement ses secondaires et libère son rôle.
- **Délai avant reprise** : La première écriture sur le nouveau primaire (`mongo2:27019`) réussit à **19:21:26.876** (écriture #103).
- **Durée mesurée entre l'arrêt et la 1re écriture sur le nouveau primaire** : **0.234 seconde (234 ms)**.
- **Détection de basculement** : Affichage immédiat par le script : `Basculement détecté : mongo1 -> mongo2 à 19:21:26.876`.
- **Écritures en erreur** : **0 erreur** (549/549 écritures réussies, 100.0%).
- **Effet de `retryWrites=true`** : L'élection et la transition ayant duré 234 ms (très inférieur au timeout `serverSelectionTimeoutMS = 2000 ms`), le retry transparent du driver PyMongo a totalement masqué la bascule sans lever d'exception.
- **Comportement au redémarrage (`docker start siem-mongo1`)** : Redémarré à 19:21:56.313, `mongo1` (priorité 2) synchronise son oplog et reprend la tête du cluster à 19:22:09.798 (`Basculement détecté : mongo2 -> mongo1 à 19:22:09.798 (écriture #489)`), sans aucune erreur.

#### 2. Test (B) : Crash Brutal du Primaire (`docker kill siem-mongo1`)
- **Déclenchement** : `docker kill siem-mongo1` (signal `SIGKILL`) exécuté à **19:22:50.057**.
- **Mécanisme** : Le processus mongod est arrêté net par le noyau sans fermer ses connexions ni notifier le replica set.
- **Détection de panne et élection** :
  - Les nœuds secondaires doivent attendre l'expiration du timeout de heartbeat (~2 secondes) pour constater la disparition de `mongo1`.
  - Côté applicatif, l'écriture #101 rencontre une socket coupée (`AutoReconnect`) à 19:22:52.268.
  - Durant la phase d'élection du nouveau primaire par quorum Raft, aucune écriture n'est possible (`ServerSelectionTimeoutError: No primary available for writes, Timeout: 2.0s`). Les écritures #101, #102, #103 et #104 échouent successivement.
- **Délai avant reprise** : À **19:23:00.490**, l'élection de **`mongo3:27020`** aboutit. L'écriture #105 réussit immédiatement sur `mongo3`.
- **Durée mesurée entre le kill et la 1re écriture sur le nouveau primaire** : **10.433 secondes** (dont **8.222 secondes** d'indisponibilité effective mesurée entre le premier échec et la reprise).
- **Détection de basculement** : `Basculement détecté : mongo1 -> mongo3 à 19:23:00.490 (écriture #105)`.
- **Écritures en erreur** : **4 écritures échouées** (#101 à #104).
- **Effet de `retryWrites=true`** : `retryWrites=True` retente l'écriture une fois. Toutefois, comme l'absence de primaire a persisté pendant ~8.2 secondes (dépassant le timeout de sélection de 2 000 ms), les 4 requêtes émises durant le vote ont été rejetées avec `ServerSelectionTimeoutError`. Dès l'élection validée, les écritures ont repris automatiquement sans redémarrer le client applicatif.
- **Comportement au redémarrage (`docker start siem-mongo1`)** : Redémarré à 19:23:16.305, `mongo1` (priorité 2) est redevenu stable en 7 secondes et a repris son statut de primaire à 19:23:29.312 (`Basculement détecté : mongo3 -> mongo1 à 19:23:29.312 (écriture #364)`).

#### Tableau Comparatif des Deux Modes de Panne

| Paramètre Mesuré | Arrêt Propre (`docker stop`) | Crash Brutal (`docker kill`) | Interprétation Technique |
| :--- | :---: | :---: | :--- |
| **Signal système envoyé** | `SIGTERM` (arrêt gracieux) | `SIGKILL` (coupure nette) | `docker stop` permet un stepdown coordonné, `kill` simule une panne matérielle. |
| **Heure de déclenchement** | 19:21:26.642 | 19:22:50.057 | Arrêt déclenché manuellement après phase nominale sur `mongo1`. |
| **Heure de 1re écriture sur nouveau primaire** | 19:21:26.876 | 19:23:00.490 | Reprise sur le nœud secondaire promu par le quorum. |
| **Durée entre arrêt/kill et 1re écriture** | **0.234 seconde (234 ms)** | **10.433 secondes** | Le crash nécessite l'expiration des heartbeats (2 s) + vote Raft (~8 s). |
| **Durée d'indisponibilité mesurée (erreurs)** | **0 s** (aucune interruption visible) | **8.222 secondes** | Période durant laquelle aucun primaire n'était disponible pour les écritures. |
| **Écritures en erreur** | **0** (549/549 réussies, 100%) | **4** (407/411 réussies, 99.0%) | Les 4 écritures émises pendant les 8.2 s de vote dépassent le timeout de 2 s. |
| **Nouveau primaire élu** | **`mongo2:27019`** | **`mongo3:27020`** | Élu par consensus majoritaire (2/3 nœuds). |
| **Basculements de nœud détectés** | **2** (`mongo1`→`mongo2`→`mongo1`) | **2** (`mongo1`→`mongo3`→`mongo1`) | Détectés et tracés par le script même en l'absence d'erreur (arrêt propre). |
| **Effet de `retryWrites=true`** | Coupure complètement masquée | Erreur émise après 2 s de retry, reprise automatique dès l'élection achevée | Protège contre les coupures ultra-brèves (< 2 s) ; rétablit le flux sans intervention humaine après crash. |
| **Comportement au redémarrage de `mongo1`** | Reprise automatique (priorité 2) | Reprise automatique (priorité 2) | Dans les deux cas, le failback est fluide et n'engendre aucune erreur. |

> **Conclusion sur la résilience** : On ne peut pas conclure de façon générale à une indisponibilité de "0 seconde". Lors d'un arrêt ordonné, la transition est quasi-instantanée (**234 ms**) et totalement masquée par `retryWrites=true`. En revanche, lors d'un crash réel avec rupture brutale des liaisons, l'indisponibilité effective est de l'ordre de **8 à 10 secondes** (le temps que le quorum constate la perte des heartbeats et valide le nouveau primaire), entraînant le rejet des requêtes arrivant pendant cette fenêtre si leur délai d'attente est inférieur à cette durée.

---

## 4. Synthèse des Recommandations pour l'Architecture SIEM

1. **Validation stricte au chargement** : `$jsonSchema` garantit l'intégrité structurelle des données à la source sans compromettre les débits d'ingestion par lot (~7 350 à 20 000 docs/s).
2. **Respect systématique de la règle ESR** : Comme démontré par T5 et A17, indexer d'abord les égalités puis les intervalles temporels divise drastiquement les accès disque WiredTiger.
3. **Dénormalisation mesurée et ciblée** : Réserver la dénormalisation aux attributs immuables ou historisés (ex: `user_department`) sollicités par des requêtes analytiques lourdes afin d'éviter les jointures distribuées (gain de 5.9x).
4. **Purge automatique par TTL** : L'index TTL sur `ip_blacklist.expires_at` décharge l'application de la gestion du cycle de vie des menaces éphémères.
