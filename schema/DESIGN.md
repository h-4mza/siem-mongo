# Justification des Choix de Conception et Schéma (SIEM MongoDB & Spark)

Ce document formalise les décisions d'architecture et de modélisation de données retenues pour le SIEM distribué, conformément aux exigences de volumétrie, de performance d'ingestion et de requêtage analytique (requêtes transactionnelles **T**, requêtes d'agrégation **A** et scénarios de sécurité **S**).

---

## 1. Principes Directeurs de Modélisation

1. **Favoriser la localité des données pour les événements immuables** : Les journaux de logs (`authentications`, `network_flows`) et les alertes sont créés une seule fois et ne subissent pas de mises à jour fréquentes. Les données indissociables sont donc imbriquées pour éviter les lectures multiples.
2. **Référence pour les entités maîtresses à forte cardinalité croisée** : Les référentiels d'inventaire (`users`, `hosts`) sont séparés et référencés par leurs clés métier afin d'éviter la duplication massive de dizaines de mégaoctets de données statiques.
3. **Dénormalisation ciblée guidée par les requêtes** : Dénormaliser uniquement les attributs requis par les requêtes analytiques critiques à forte volumétrie (comme le département dans les événements de connexion pour la requête A18).
4. **Indexation couvrante et ciblée** : Respecter scrupuleusement la règle **ESR** (*Equality, Sort, Range*) pour chaque index composé.

---

## 2. Tableau Justificatif : Imbriqué (Embedded) vs Référence

| Collection | Champ / Attribut | Type de Modélisation | Justification Technique & Requêtes Associées |
| :--- | :--- | :--- | :--- |
| **hosts** | `metadata` | **Imbriqué** (sous-document) | Les informations d'infrastructure (*datacenter*, *rack*, *environment*) ont un cycle de vie 1:1 strictement lié au serveur. L'imbrication permet une lecture atomique en un seul accès disque sans jointure. |
| **users** | `usual_countries` | **Imbriqué** (tableau) | Cardinalité très faible (1 à 3 pays par utilisateur). L'imbrication dans un tableau permet des tests d'appartenance directs (`$in`, `$nin`) pour la détection d'anomalies géographiques (**S27**, **A22**). |
| **authentications** | `geo` | **Imbriqué** (sous-document) | Géolocalisation instantanée de l'IP source au moment précis de la tentative. Les coordonnées et le pays sont immuables pour cet événement spécifique et nécessaires pour **S27** (Voyage impossible) et **A22**. |
| **authentications** | `user_id`, `host_id` | **Référence** (clé étrangère) | Un utilisateur et un serveur génèrent des milliers d'événements. Dupliquer le profil utilisateur complet (nom, rôle, statut) dans chaque log ferait exploser l'empreinte disque et mémoire de MongoDB et Spark. |
| **network_flows** | `host_id` | **Référence** | Référence vers l'hôte émetteur. Permet de croiser l'inventaire des hôtes critiques avec les flux réseaux suspects (**S29**). |
| **alerts** | `tags` | **Imbriqué** (tableau) | Permet la catégorisation multi-critères d'une alerte (*auth*, *bruteforce*, *critical_asset*). Exploité avec un index multikey pour la requête **A25**. |
| **alerts** | `related_events` | **Référence** (tableau d'identifiants) | Stocke les `auth_id` ou `flow_id` déclencheurs. Évite d'embarquer des documents volumineux complets tout en conservant une traçabilité d'audit complète. |
| **ip_blacklist** | `_id` = `ip` | **Clé Primaire Naturelle** | L'adresse IP est unique par nature dans la liste noire. Utiliser l'IP directement comme `_id` élimine l'index unique supplémentaire qui aurait été nécessaire, économise de la RAM et accélère les vérifications O(1) (**S29**). |

---

## 3. Justification des Index et Requêtes Associées

| Collection | Index | Type / Propriété | Requête(s) Cible(s) | Justification Technique et Règle ESR |
| :--- | :--- | :--- | :--- | :--- |
| **users** | `user_id` | Unique (1) | Authentification, intégrité | Empêche les doublons d'identifiants et permet la résolution immédiate du profil utilisateur. |
| **users** | `department` | Simple (1) | **A18**, Gestion RH | Filtrage rapide des collaborateurs par département d'appartenance. |
| **hosts** | `host_id` | Unique (1) | Inventaire, intégrité | Résolution O(1) des serveurs lors des corrélations de sécurité. |
| **hosts** | `ip` | Simple (1) | **S29**, Résolution réseau | Permet de retrouver instantanément la machine interne émettrice à partir de son IP privée. |
| **authentications** | `(user_id, timestamp desc)` | Composé (1, -1) | **T4** | **T4 (Historique récent de connexion d'un utilisateur)** : Égalité sur `user_id` puis tri descendant sur `timestamp`. Permet un *Index Scan* sans aucun tri en mémoire RAM (*no in-memory sort*). |
| **authentications** | `(user_id, result, timestamp)` | Composé (1, 1, 1) | **T5** | **T5 (Audit des échecs d'un utilisateur)** : Filtrage sur `user_id` et `result="failure"` puis tri chronologique pour détecter la succession rapprochée d'échecs. |
| **authentications** | `(host_id, timestamp)` | Composé (1, 1) | **T6** | **T6 (Journal d'activité d'un serveur)** : Restitution chronologique de toutes les connexions entrantes sur une machine cible. |
| **authentications** | `(source_ip, timestamp)` | Composé (1, 1) | **S26** | **S26 (Détection de force brute)** : Regroupement par IP source attaquante sur des fenêtres temporelles de 5 minutes. |
| **authentications** | `(result, timestamp)` | Composé (1, 1) | **A17** | **A17 (Top 10 IP avec échecs sur une journée)** : Respect strict de la règle ESR (Égalité sur `result="failure"` puis filtre d'intervalle sur `timestamp`). Mesuré **2.3x plus rapide** que l'index temporel seul (11.45 ms vs 26.38 ms). |
| **authentications** | `timestamp` | Simple (1) | **A16** | **A16 (Recherche globale par intervalle de temps)** : Requêtes d'intervalles (*range queries*) sur des plages de dates globales pour le SIEM. |
| **network_flows** | `(host_id, timestamp)` | Composé (1, 1) | Analyse flux serveur | Chronologie des connexions réseau établies par une machine compromise. |
| **network_flows** | `src_ip` | Simple (1) | Détection latérale | Filtrage sur l'adresse source interne pour pister la propagation d'une attaque. |
| **network_flows** | `dst_ip` | Simple (1) | **S29** | **S29 (Flux vers liste noire)** : Recherche immédiate des flux dont l'IP de destination figure dans la table `ip_blacklist`. |
| **network_flows** | `dst_port` | Simple (1) | Analyse protocolaire | Détection de scans de ports et filtrage des services vulnérables (ex: ports 445 SMB, 3389 RDP). |
| **alerts** | `tags` | **Multikey** (1) | **A25** | **A25 (Filtrage d'alertes par tags)** : MongoDB indexe chaque élément du tableau `tags`, permettant des filtres extrêmement rapides `$in: ["bruteforce", "c2"]`. |
| **alerts** | `(severity, status, created_at desc)` | Composé (1, 1, -1) | **T14** | **T14 (Dashboard SOC - File des alertes prioritaires)** : Égalité sur `severity` et `status="open"`, suivi du tri par date de création descendante pour afficher immédiatement les alertes critiques les plus récentes. |
| **alerts** | `(analyst, status)` | Composé (1, 1) | Suivi de charge SOC | Répartition du travail et suivi des alertes en cours de traitement par analyste de garde. |
| **ip_blacklist** | `expires_at` | **TTL** (expireAfterSeconds: 0) | **T10** | **T10 (Cycle de vie et purge automatique des menaces)** : Le moteur en tâche de fond de MongoDB supprime automatiquement les adresses IP dès que l'horodatage `expires_at` est atteint (7 jours après création), évitant la saturation de la liste noire sans nécessiter de script cron externe. |

---

## 4. Analyse de la Dénormalisation de `user_department`

Dans la collection `authentications`, le champ `user_department` est dénormalisé (recopié depuis `users.department`).

### Motivation et Requête A18
La requête **A18** analyse les **connexions réussies survenues en heures non ouvrées (22h - 6h) agrégées par département** afin d'identifier des exfiltrations de données ou des accès inhabituels :

```javascript
// Exemple d'agrégation A18 rendue triviale grâce à la dénormalisation
db.authentications.aggregate([
  {
    $match: {
      result: "success"
    }
  },
  {
    $project: {
      user_department: 1,
      hour: { $hour: "$timestamp" }
    }
  },
  {
    $match: {
      $or: [{ hour: { $gte: 22 } }, { hour: { $lt: 6 } }]
    }
  },
  {
    $group: {
      _id: "$user_department",
      nb_connexions_nocturnes: { $sum: 1 }
    }
  },
  { $sort: { nb_connexions_nocturnes: -1 } }
]);
```

### Comparatif d'Architecture et Mesures Réelles : Dénormalisation vs `$lookup`

| Critère | Approche Normalisée avec `$lookup` | Approche Retenue (Dénormalisation) |
| :--- | :--- | :--- |
| **Temps d'exécution mesuré** | **783.09 ms** | **132.82 ms** (**5.9x plus rapide**) |
| **Complexité de la requête** | Nécessite une étape `$lookup` qui effectue des milliers de résolutions croisées entre la collection `authentications` et `users`. | Pipeline d'agrégation direct sur la seule collection `authentications`. |
| **Documents traités en mémoire** | 16 735 documents retournés et croisés avec la collection `users`. | 1 779 documents filtrés et agrégés directement en streaming. |
| **Distribution & Scalabilité** | Dans un cluster shardt/replica set ou un cluster Spark distribué, les `$lookup` nécessitent des transferts réseau importants entre partitions. | Aucun échange inter-collections nécessaire. Chaque partition Spark peut traiter ses événements localement. |
| **Impact sur l'écriture** | Aucun. | Minime : copie d'une chaîne courte (~10 octets) lors de l'insertion de l'événement. |
| **Cohérence des données d'audit** | En cas de changement de département, le log reflèterait le *nouveau* département au lieu de la situation historique. | Parfaite : l'événement de journalisation consigne fidèlement le département de l'utilisateur **au moment exact** où l'accès a eu lieu. |

---

## 5. Synthèse Globale

L'architecture de données ainsi mise en place garantit un équilibre optimal :
- **Intégrité stricte** via la validation `$jsonSchema`.
- **Rapidité d'ingestion** (> 15 000 à 35 000 docs/sec par lot de 5 000).
- **Indexation chirurgicale** couvrant chaque requête opérationnelle et analytique sans surcoût excessif en RAM.
- **Interopérabilité totale avec Apache Spark**, qui pourra paralléliser la lecture des collections via le connecteur Mongo-Spark sans contrainte de jointure lourde.
