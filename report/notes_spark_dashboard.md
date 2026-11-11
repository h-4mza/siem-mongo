# Notes Techniques : Traitements Distribués Spark & Dashboard SIEM

Ce document consigne l'ensemble des résultats mesurés, la méthodologie et l'analyse technique des traitements distribués Apache Spark (jobs S26 à S30), du comparatif de performance avec MongoDB natif, ainsi que du dashboard de supervision.

> **Règle méthodologique** : L'intégralité des données chiffrées présentées dans ce rapport provient exclusivement des exécutions réelles réalisées sur le cluster Docker (Replica Set MongoDB à 3 nœuds et cluster Spark à 2 workers).

---

## 1. Jobs Spark (S26 à S30) : Méthodologie, Logique & Mesures

Chaque job a été implémenté en PySpark (API DataFrames), exécuté en mode distribué via `spark-submit` sur le master `spark://spark-master:7077`, et mesuré de manière isolée via `spark/spark_analysis.py` avec dissociation stricte du temps de chargement/mise en cache (`lecture_ms`) et du temps d'exécution des transformations/actions (`calcul_ms`).

### Récapitulatif des temps mesurés (`results/spark_timings.csv`)

| Requête | Description | Lecture (ms) | Calcul (ms) | Total (ms) | Nb Résultats |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **S26** | Détection d'attaques par force brute (fenêtre 5 min) | 23 944,06 | 5 498,63 | 29 442,69 | 6 |
| **S27** | Détection d'anomalies de voyage impossible (< 1h) | 12 245,16 | 2 534,46 | 14 779,62 | 73 |
| **S28** | Taux d'échec par département et rôle (jointure) | 6 885,03 | 2 000,85 | 8 885,88 | 45 |
| **S29** | Hôtes contactant des IP en liste noire (broadcast) | 3 679,98 | 1 581,29 | 5 261,27 | 35 |
| **S30** | Score de risque composite par utilisateur (Top 20) | 3 683,14 | 5 479,02 | 9 162,16 | 20 |

---

### Détail par job Spark

#### S26 : Détection de force brute sur fenêtre glissante
- **Énoncé** : Identifier les adresses IP sources générant plus de 20 échecs d'authentification sur une fenêtre temporelle glissante de 5 minutes avec un pas de glissement de 1 minute.
- **Logique Spark** :
  1. Filtrage sur `result == 'failure'`.
  2. `groupBy(window("timestamp", "5 minutes", "1 minute"), "source_ip").count()`.
  3. Filtrage des fenêtres avec `count > 20`.
  4. Agrégation finale par `source_ip` : `max(count)` (pic d'échecs) et `min(window.start)` (horodatage du début d'attaque).
- **Résultats trouvés vs attendus** :
  - **Trouvé** : Exactement **6 adresses IP** (`203.0.113.50` à `203.0.113.55`).
  - **Attendu** : Au moins 6 IP.
  - **Conformité** : 100 % (chacune des 6 IP injectées présente un pic mesuré de 25 échecs dans sa première fenêtre à `2026-10-31 03:00:00`). Les 250 échecs de l'attaque A17, dilués sur 24 heures (~10 échecs/h), ne dépassent jamais le seuil de 20 échecs en 5 minutes.
- **Fichier généré** : `results/spark_outputs/s26.csv`.

#### S27 : Voyage impossible (Impossible Travel)
- **Énoncé** : Détecter les utilisateurs dont deux connexions consécutives réussies proviennent de deux pays différents en moins de 3 600 secondes (1 heure).
- **Justification du filtre `result == 'success'`** :
  Un échec d'authentification distant (`failure`) caractérise une attaque externe (spray, force brute, botnet) sans détention des identifiants valides. L'anomalie de "Voyage Impossible" cible spécifiquement la compromission avérée de compte ou le détournement de session active (présence simultanée ou déplacement physiquement irréaliste d'un utilisateur authentifié dans deux pays).
- **Logique Spark** :
  1. Filtre strict `result == 'success'`.
  2. Fenêtrage : `Window.partitionBy("user_id").orderBy("timestamp")`.
  3. Calculs via fonctions analytiques : `lag("geo.country", 1)` et `lag("timestamp", 1)`.
  4. Filtre de voyage : `prev_country.isNotNull() AND current_country != prev_country AND delta_seconds < 3600 AND delta_seconds >= 0`.
- **Résultats trouvés vs attendus** :
  - **Nombre total d'événements** : 73 événements.
  - **Utilisateurs distincts détectés** : **70 utilisateurs** (attendu : ≥ 35).
  - **Part des cas injectés FR <-> JP** : **36 utilisateurs** (soit les 35 utilisateurs ciblés par le générateur + 1 cas FR/JP généré aléatoirement), représentant **51,43 %** du total.
  - **Part du bruit statistique (faux positifs)** : **34 utilisateurs** (soit **48,57 %**). Cette proportion s'explique mathématiquement par la distribution aléatoire de 1 à 3 pays habituels (`usual_countries`) parmi 10 000 utilisateurs réalisant 60 500 authentifications sur 30 jours.
- **Fichier généré** : `results/spark_outputs/s27.csv`.

#### S28 : Taux d'échec par département et rôle
- **Énoncé** : Calculer le taux d'échec global d'authentification (`échecs / total`) pour chaque combinaison département x rôle via une jointure explicite.
- **Logique Spark** :
  1. Jointure inner explicite `authentications.join(users.select("user_id", "department", "role"), on="user_id")` (sans utiliser le champ dénormalisé `user_department`).
  2. `groupBy("department", "role")`.
  3. Agrégations : `count(*)` total, `count(when(result == 'failure'))`, ratio arrondi à 4 décimales.
- **Résultats trouvés vs attendus** :
  - **Trouvé** : **45 groupes distincts** (9 départements × 5 rôles).
  - **Attendu** : 45 groupes.
  - **Mesure clé** : Taux d'échec moyen oscillant entre 17,8 % et 20,1 % selon les rôles.
- **Fichier généré** : `results/spark_outputs/s28.csv`.

#### S29 : Hôtes communicant avec la liste noire (Broadcast Join)
- **Énoncé** : Identifier les machines internes contactant des adresses IP malveillantes via jointure `network_flows x ip_blacklist`.
- **Logique Spark** :
  1. Optimisation par diffusion : `flows_df.join(broadcast(bl_df), flows_df.dst_ip == bl_df.ip)`. La table de liste noire (200 lignes, ~15 Ko) est diffusée sur tous les exécuteurs pour supprimer le shuffle de la collection de flux (40 500 lignes).
  2. `groupBy("host_id").agg(count("*"), sum("bytes"))`.
  3. Test comparatif alternatif sur `src_ip`.
- **Résultats trouvés vs attendus** :
  - **Jointure sur `dst_ip`** : Exactement **35 hôtes distincts** (attendu : ≥ 35), totalisant 105 flux malveillants vers les IP de C2 et botnets.
  - **Jointure sur `src_ip`** : **0 hôte trouvé**.
  - **Explication de l'écart** : Dans un réseau d'entreprise, les flux réseau modélisent des connexions sortantes initiées depuis des adresses IP sources privées internes vers des serveurs de commande externes (`dst_ip`). Aucune communication ne présente d'adresse IP blacklistée en source sur les flux sortants.
- **Fichier généré** : `results/spark_outputs/s29.csv`.

---

## 2. Job S30 : Score de Risque Composite par Utilisateur

### Formule mathématique et normalisation

Chaque signal unitaire est normalisé par son maximum global observé sur la base de données :

$$\text{score\_brut} = 1.0 \times \frac{\text{échecs}}{\max(\text{échecs})} + 2.0 \times \frac{\text{nocturnes}}{\max(\text{nocturnes})} + 3.0 \times \frac{\text{pays\_extra}}{\max(\text{pays\_extra})} + 10.0 \times \frac{\text{voyage}}{\max(\text{voyage})} + 8.0 \times \frac{\text{blacklist}}{\max(\text{blacklist})}$$

$$\text{score\_final} = \text{score\_brut} \times (1.5 \text{ si } \text{is\_service\_account} == \text{True} \text{ sinon } 1.0)$$

### Maximums mesurés sur les 10 000 utilisateurs

- $\max(\text{échecs})$ : **27**
- $\max(\text{nocturnes})$ (22h-6h) : **9**
- $\max(\text{pays\_extra})$ (pays distincts au-delà de 1) : **5**
- $\max(\text{voyage})$ (événements voyage impossible) : **2**
- $\max(\text{blacklist})$ (authentications depuis IP blacklistée) : **0** *(aucune injection sur authentications)*

### Dictionnaire des poids et justifications techniques

| Signal | Poids | Justification technique |
| :--- | :---: | :--- |
| **`failures`** | **1.0** | Les échecs isolés sont fréquents (erreurs de frappe légitimes d'utilisateurs distraits) et présentent une criticité unitaire faible, sauf cumul massif. |
| **`nocturnal`** | **2.0** | Les accès hors heures ouvrées (22h-6h) constituent une anomalie modérée par rapport au comportement nominal des collaborateurs. |
| **`extra_countries`** | **3.0** | L'accès depuis de multiples pays (> 1) reflète une dispersion géographique atypique augmentant la surface d'exposition de l'identité. |
| **`impossible_travel`** | **10.0** | Indicateur critique d'usurpation de session ou de compte compromis : deux connexions distantes réussies en < 1 heure sont physiquement impossibles. |
| **`ip_blacklist`** | **8.0** | Authentification initiée depuis une infrastructure offensive connue (C2, botnet, nœud Tor) avec une forte présomption de malveillance. |
| **`is_service_account`** | **× 1.5** | Un compte de service dispose de privilèges techniques élevés et d'accès automatisés sensibles ; une compromission entraîne un risque d'élévation décuplé. |

---

### Top 20 mesuré (`results/spark_outputs/s30.csv`)

| Rang | User ID | Département | Rôle / Type | Svc Acc | Échecs | Nocturnes | Pays+ (>1) | Voyage Imposs. | Blacklist | Score |
| :---: | :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **1** | `usr_07694` | Finance | Auditeur Financier | non | 5 | 5 | 3 | 2 | 0 | **13.0963** |
| **2** | `usr_00007` | Direction | Directeur Général | non | 2 | 6 | 2 | 2 | 0 | **12.6074** |
| **3** | `usr_07123` | Juridique | Juriste d'Entreprise | non | 2 | 5 | 2 | 2 | 0 | **12.3852** |
| **4** | `usr_07098` | Juridique | Compte de Service Applicatif | **OUI** | 0 | 2 | 2 | 1 | 0 | **9.9667** |
| **5** | `usr_06411` | Direction | Compte de Service Applicatif | **OUI** | 2 | 1 | 2 | 1 | 0 | **9.7444** |
| **6** | `usr_09790` | Support | Compte de Service Applicatif | **OUI** | 1 | 1 | 2 | 1 | 0 | **9.6889** |
| **7** | `usr_07612` | RH | Compte de Service Applicatif | **OUI** | 0 | 3 | 1 | 1 | 0 | **9.4000** |
| **8** | `usr_09990` | Finance | Directeur Financier | non | 3 | 6 | 2 | 1 | 0 | **7.6444** |
| **9** | `usr_01393` | Direction | Secrétaire Général | non | 1 | 3 | 3 | 1 | 0 | **7.5037** |
| **10** | `usr_08456` | Ventes | Commercial Grands Comptes | non | 1 | 3 | 3 | 1 | 0 | **7.5037** |
| **11** | `usr_09072` | Juridique | Avocat Conseil | non | 1 | 3 | 3 | 1 | 0 | **7.5037** |
| **12** | `usr_02442` | Opérations | Agent d'Exploitation | non | 0 | 3 | 3 | 1 | 0 | **7.4667** |
| **13** | `usr_03860` | Marketing | Chef de Produit | non | 0 | 3 | 3 | 1 | 0 | **7.4667** |
| **14** | `usr_06260` | Support | Support Client N2 | non | 0 | 5 | 2 | 1 | 0 | **7.3111** |
| **15** | `usr_04648` | Finance | Comptable | non | 0 | 2 | 3 | 1 | 0 | **7.2444** |
| **16** | `usr_01022` | Finance | Directeur Financier | non | 1 | 4 | 2 | 1 | 0 | **7.1259** |
| **17** | `usr_08557` | Direction | Directeur Général | non | 1 | 4 | 2 | 1 | 0 | **7.1259** |
| **18** | `usr_03931` | Finance | Contrôleur de Gestion | non | 3 | 3 | 2 | 1 | 0 | **6.9778** |
| **19** | `usr_08870` | R&D | Développeur Backend | non | 2 | 3 | 2 | 1 | 0 | **6.9407** |
| **20** | `usr_03182` | IT | Admin Système | non | 1 | 3 | 2 | 1 | 0 | **6.9037** |

---

### Analyse critique du Top 20 et proposition d'ajustement

1. **Sur-représentation du voyage impossible** :
   - **14 des 20 utilisateurs (70 %)** proviennent directement des 35 comptes ciblés par l'attaque S27 (pattern injecté FR <-> JP).
   - Les 6 autres utilisateurs du Top 20 ont tous au moins 1 voyage impossible issu du bruit statistique multi-pays.
   - **100 % des membres du Top 20 possèdent au moins un voyage impossible.**

2. **Éviction totale des victimes de force brute (S26)** :
   - **0 utilisateur parmi les 6 victimes de force brute S26** (`usr_00472`, `usr_02104`, `usr_02982`, `usr_05113`, `usr_08478`, `usr_08846`) n'apparaît dans le Top 20.
   - Pourtant, ces comptes subissent entre 25 et 27 échecs massifs (les maxima absolus de la base de données).
   - **Cause mathématique** :
     - Pour le voyage impossible, $\max = 2$. Un seul événement rapporte $10.0 \times (1 / 2) = \mathbf{5,0}$ **points**. Deux événements rapportent **10,0 points**.
     - Pour les échecs, $\max = 27$. Subir 27 échecs violents ne rapporte que $1.0 \times (27 / 27) = \mathbf{1,0}$ **point** !
     - Le score total d'une victime de force brute culmine à **~2,87**, ce qui la place très en dessous du 20ᵉ seuil du Top 20 (fixé à **6,9037**).
   - Par ailleurs, le signal `ip_blacklist` est inactif ($\max = 0$) car injecté sur la couche réseau et non sur les authentifications.

3. **Proposition d'ajustement des poids** :
   - Augmenter le poids de `failures` à **6.0** (un pic de force brute rapportera ~5,5 à 6,0 points).
   - Ajuster `impossible_travel` à **7.0** (1 événement = 3,5 points, 2 événements = 7,0 points).
   - Réduire `extra_countries` à **2.0** pour ne pas sur-pénaliser les collaborateurs mobiles légitimes.
   - *Impact calculé* : Une victime de 27 échecs avec 3 accès nocturnes obtiendrait $6.0 \times 1.0 + 2.0 \times (3/9) + 2.0 \times (2/5) = \mathbf{7,47}$, la propulsant immédiatement dans le **Top 10**, assurant un équilibre sain entre détection d'attaques sur les identifiants et détournements de session.

---

## 3. Comparatif de Performance : MongoDB Natif vs Apache Spark

Mesures moyennes issues de [`results/spark_vs_native.csv`](file:///C:/Users/HP/Desktop/Big%20data/siem-mongo/results/spark_vs_native.csv) :
- **Natif** : 5 itérations pymongo sur l'hôte.
- **Spark** : 6 itérations distribuées dans le conteneur, avec première itération (cold start) systématiquement écartée.

| Requête | Natif MongoDB (ms) | Spark Lecture (ms) | Spark Calcul (ms) | Spark Total (ms) | Ratio Total / Natif | Nb Résultats | Concordance des Données |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **A16** (Auths journalières) | **107,40** | 3 273,24 | 1 168,44 | 4 441,68 | **41,36x** | 31 | **Parfaite (31/31 jours)** |
| **A17** (Top 10 IP échecs 24h) | **18,97** | 1 508,25 | 483,61 | 1 991,87 | **104,98x** | 10 | **Parfaite (10/10 IP)** |
| **A20** (Octets/hôte 24h) | **27,68** | 833,68 | 450,19 | 1 283,87 | **46,39x** | 20 | **Parfaite (20/20 hôtes)** |

### Analyse prudente des écarts de temps

1. **Surcoût d'ingestion et sérialisation (`lecture_ms`)** :
   L'extraction des collections MongoDB via le connecteur Java représente **65 % à 76 % du temps total de Spark** (de 833 ms à 3 273 ms pour 40 500 à 60 500 documents). MongoDB traite les données directement en mémoire (WiredTiger) sans conversion BSON → Java Object → Catalyst Rows.
2. **Coût incompressible d'orchestration distribuée (`calcul_ms`)** :
   Même avec les DataFrames préalablement mis en cache (`.cache()`), l'instanciation du DAG, la sérialisation des closures et la collecte finale (`.collect()`) introduisent un plancher de latence de **450 ms à 1 170 ms**.
3. **Indexation native MongoDB** :
   Sur A17, MongoDB bénéficie de l'index composé `(result, timestamp)` qui filtre instantanément les 250 échecs de la journée en **18,97 ms**, alors que Spark doit scanner l'ensemble des partitions.
4. **Ce qui n'a pas été mesuré dans ce benchmark** :
   - Le passage à l'échelle sur plusieurs dizaines de gigaoctets ou téraoctets (où MongoDB saturerait sa RAM tandis que Spark paralléliserait horizontalement).
   - Le comportement sur des clusters physiques distincts avec latence réseau inter-serveurs (ici tous les conteneurs partagent le CPU et le bus mémoire de l'hôte WSL2).

---

## 4. Comportement du Cluster Spark

- **Nœuds actifs** :
  - `spark-master` : coordinateur autonome (port 7077).
  - `spark-worker-1` (`172.25.0.7`) : état **ALIVE**, 1 cœur, 1 024 MiB de RAM.
  - `spark-worker-2` (`172.25.0.8`) : état **ALIVE**, 1 cœur, 1 024 MiB de RAM.
- **Connecteur MongoDB Spark** : version validée `10.3.0` (driver officiel `mongodb-driver-sync:4.8.2` et `bson:4.8.2`).
- **Gestion des dépendances et cache** :
  - Les dépendances Maven sont persistées dans le volume monté `/tmp/.ivy2`.
  - L'utilisation directe de l'argument `--jars /tmp/.ivy2/jars/...` permet d'exécuter les jobs en circuit fermé sans dépendre d'une résolution DNS externe vers Maven Central.
- **Interface Spark Web UI** :
  - Configurée sur le port hôte **`http://localhost:8085`** (redirigée vers le port interne 8080 du conteneur master, le port 8080 hôte étant alloué par le système Windows au service Oracle Listener).
  - 10 applications Spark répertoriées avec statut `FINISHED` sans aucun échec d'exécuteur.

---

## 5. Limites Identifiées du Système

1. **Taux de faux positifs dans la détection spatiale (S27)** :
   Le taux de faux positifs atteint **48,57 %** (34 utilisateurs sur 70). En l'absence de géolocalisation continue ou d'analyse contextuelle de la vitesse moyenne de déplacement (formule de haversine en km/h plutôt qu'un simple changement de code pays), un tirage aléatoire de pays habituels produit naturellement des alertes non pertinentes.
2. **Volume de données modeste** :
   Avec 60 500 authentifications et 40 500 flux réseau, le jeu de données loge intégralement dans le cache mémoire de MongoDB (WiredTiger configuré à 1,5 Go). Ce volume met en valeur la vitesse du moteur C++ de MongoDB et pénalise Spark qui n'atteint son seuil de rentabilité qu'à partir de plusieurs millions de documents.
3. **Environnement mono-hôte (Docker sous Windows / WSL2)** :
   L'ensemble des services (3 nœuds MongoDB, 1 master Spark, 2 workers Spark) se partagent le même processeur hôte (CPU i7/i5 partagé) et la même pile réseau virtuelle Docker. Les gains théoriques du partitionnement distribué sont donc limités par la contention sur les ressources locales de la machine hôte.
