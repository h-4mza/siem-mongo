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