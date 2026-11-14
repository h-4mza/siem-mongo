"""
Application Dashboard SIEM & Détections Spark (Streamlit + Plotly).
Se connecte au replica set MongoDB (variable MONGO_URI) pour les requêtes analytiques natives
et lit les exports CSV pour les détections distribuées Spark (sans jamais appeler Spark directement).
"""

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# ==============================================================================
# CONFIGURATION STREAMLIT & CHEMINS
# ==============================================================================
st.set_page_config(
    page_title="SIEM Dashboard — MongoDB & Spark Analytics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

BASE_DIR = Path(__file__).resolve().parent.parent
QUERIES_DIR = BASE_DIR / "queries"
RESULTS_DIR = BASE_DIR / "results"
SPARK_OUTPUTS_DIR = RESULTS_DIR / "spark_outputs"

# Import des fonctions analytiques sans réécrire les pipelines d'agrégation
sys.path.insert(0, str(QUERIES_DIR))
try:
    from analytical import (
        get_database,
        a16_daily_auth_stats,
        a17_top10_failed_ips_daily,
        a19_alerts_by_severity_status,
        a21_top10_dst_ports,
        DEFAULT_MONGO_URI
    )
except ImportError as e:
    st.error(f"Erreur d'importation de `queries/analytical.py` : {e}")
    st.stop()


# ==============================================================================
# GESTION DE LA CONNEXION MONGODB & CACHE STREAMLIT
# ==============================================================================
MONGO_URI = os.getenv("MONGO_URI", DEFAULT_MONGO_URI)
os.environ["MONGO_URI"] = MONGO_URI


@st.cache_resource
def init_mongo_connection():
    """Initialise et met en cache la connexion au replica set MongoDB."""
    try:
        return get_database()
    except Exception as exc:
        st.error(f"Impossible de se connecter au replica set MongoDB ({MONGO_URI}) : {exc}")
        return None


@st.cache_data(ttl=300)
def load_a16():
    """Charge les statistiques journalières d'authentification (A16)."""
    db = init_mongo_connection()
    if db is None:
        return []
    return a16_daily_auth_stats(db)


@st.cache_data(ttl=300)
def load_a17(target_date_str: str):
    """Charge le top 10 des IP en échec pour une journée (A17)."""
    db = init_mongo_connection()
    if db is None:
        return []
    target_dt = datetime.strptime(target_date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return a17_top10_failed_ips_daily(db, target_dt)


@st.cache_data(ttl=300)
def load_a19():
    """Charge les alertes par sévérité et statut (A19)."""
    db = init_mongo_connection()
    if db is None:
        return []
    return a19_alerts_by_severity_status(db)


@st.cache_data(ttl=300)
def load_a21():
    """Charge le top 10 des ports de destination réseau (A21)."""
    db = init_mongo_connection()
    if db is None:
        return []
    return a21_top10_dst_ports(db)


# ==============================================================================
# EN-TÊTE DU DASHBOARD
# ==============================================================================
st.title("🛡️ SIEM Dashboard — Supervision de Sécurité & Big Data")
st.caption("Plateforme d'analyse distribuée combinant MongoDB Replica Set (3 nœuds) et Apache Spark")

# Sidebar : état du cluster et informations
with st.sidebar:
    st.header("⚙️ Configuration & Cluster")
    st.markdown(f"**URI MongoDB :**\n`{MONGO_URI}`")
    db_conn = init_mongo_connection()
    if db_conn is not None:
        st.success("Connecté au Replica Set MongoDB (siem)")
    else:
        st.error("Déconnecté de MongoDB")

    st.markdown("---")
    st.markdown("**Architecture :**")
    st.markdown("- **BDD :** MongoDB 3-Node RS (`rs0`)")
    st.markdown("- **Calcul Distribué :** Apache Spark 3.5.0")
    st.markdown("- **Visualisation :** Streamlit + Plotly")

    st.markdown("---")
    if st.button("🔄 Rafraîchir le cache des données"):
        st.cache_data.clear()
        st.rerun()


# ==============================================================================
# ONGLETS DU DASHBOARD
# ==============================================================================
tab_a16, tab_a17, tab_a19, tab_a21, tab_spark = st.tabs([
    "📈 1. Connexions Journalières (A16)",
    "🎯 2. Top IP en Échec (A17)",
    "⚠️ 3. Alertes Sécurité (A19)",
    "🌐 4. Ports de Destination (A21)",
    "⚡ Détection Spark (S26 & S30)"
])


# ------------------------------------------------------------------------------
# 1) CONNEXIONS RÉUSSIES ET ÉCHOUÉES PAR JOUR (A16) - COURBE
# ------------------------------------------------------------------------------
with tab_a16:
    st.subheader("A16 : Connexions réussies et échouées par jour sur 30 jours")
    st.markdown("Supervision temporelle des volumes d'authentifications pour détecter les anomalies de trafic et pics d'échecs.")

    raw_a16 = load_a16()
    if not raw_a16:
        st.warning("Aucune donnée retournée par la requête A16.")
    else:
        df_a16 = pd.DataFrame([
            {
                "date": r["_id"],
                "total_succes": r.get("total_succes", 0),
                "total_echecs": r.get("total_echecs", 0),
                "total_connexions": r.get("total_connexions", 0)
            }
            for r in raw_a16
        ]).sort_values("date")

        # Métriques de synthèse
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Jours observés", len(df_a16))
        col2.metric("Total Connexions", f"{df_a16['total_connexions'].sum():,}")
        col3.metric("Total Succès", f"{df_a16['total_succes'].sum():,}")
        col4.metric("Total Échecs", f"{df_a16['total_echecs'].sum():,}")

        # Graphique Plotly (Courbe)
        fig_a16 = go.Figure()
        fig_a16.add_trace(go.Scatter(
            x=df_a16["date"],
            y=df_a16["total_succes"],
            mode="lines+markers",
            name="Connexions Réussies",
            line=dict(color="#10b981", width=2.5),
            marker=dict(size=6)
        ))
        fig_a16.add_trace(go.Scatter(
            x=df_a16["date"],
            y=df_a16["total_echecs"],
            mode="lines+markers",
            name="Connexions Échouées",
            line=dict(color="#ef4444", width=2.5),
            marker=dict(size=6)
        ))

        fig_a16.update_layout(
            title="Évolution temporelle quotidienne des authentifications (Succès vs Échecs)",
            xaxis_title="Date",
            yaxis_title="Nombre d'authentifications",
            hovermode="x unified",
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            template="plotly_white",
            height=450
        )
        st.plotly_chart(fig_a16, use_container_width=True)


# ------------------------------------------------------------------------------
# 2) TOP 10 DES IP EN ÉCHEC SUR UNE JOURNÉE (A17) - BARRES
# ------------------------------------------------------------------------------
with tab_a17:
    st.subheader("A17 : Top 10 des IP sources par nombre d'échecs sur une journée")
    st.markdown("Identification ciblée des adresses IP effectuant des tentatives massives de connexion infructueuses.")

    # Choix de la journée : date par défaut = 7 jours avant aujourd'hui (injection attaque A17)
    default_date = (datetime.now(timezone.utc) - timedelta(days=7)).date()

    # Si A16 est chargé, on propose les dates disponibles
    available_dates = [r["_id"] for r in raw_a16] if raw_a16 else []
    selected_date_str = None

    col_date, col_info = st.columns([1, 2])
    with col_date:
        if available_dates:
            default_index = 0
            def_str = default_date.strftime("%Y-%m-%d")
            if def_str in available_dates:
                default_index = available_dates.index(def_str)
            selected_date_str = st.selectbox(
                "📅 Sélectionner la journée d'analyse :",
                options=available_dates,
                index=default_index
            )
        else:
            sel_date = st.date_input("📅 Sélectionner la journée :", value=default_date)
            selected_date_str = sel_date.strftime("%Y-%m-%d")

    with col_info:
        st.info(f"Analyse des échecs d'authentification pour la date du **{selected_date_str}**.")

    raw_a17 = load_a17(selected_date_str)
    if not raw_a17:
        st.warning(f"Aucun échec d'authentification enregistré le {selected_date_str}.")
    else:
        df_a17 = pd.DataFrame([
            {"source_ip": r["_id"], "nombre_echecs": r.get("count", 0)}
            for r in raw_a17
        ]).sort_values("nombre_echecs", ascending=True)

        fig_a17 = px.bar(
            df_a17,
            x="nombre_echecs",
            y="source_ip",
            orientation="h",
            text="nombre_echecs",
            title=f"Top 10 IP les plus actives en échec ({selected_date_str})",
            labels={"source_ip": "Adresse IP Source", "nombre_echecs": "Nombre d'échecs"},
            color="nombre_echecs",
            color_continuous_scale="Reds",
            template="plotly_white",
            height=450
        )
        fig_a17.update_traces(textposition="outside")
        fig_a17.update_layout(coloraxis_showscale=False)
        st.plotly_chart(fig_a17, use_container_width=True)


# ------------------------------------------------------------------------------
# 3) ALERTES PAR SÉVÉRITÉ ET STATUT (A19) - BARRES EMPILÉES
# ------------------------------------------------------------------------------
with tab_a19:
    st.subheader("A19 : Répartition des alertes par sévérité et statut")
    st.markdown("Vue synthétique sur le cycle de vie des alertes du SOC selon leur niveau de sévérité.")

    raw_a19 = load_a19()
    if not raw_a19:
        st.warning("Aucune donnée d'alerte disponible (A19).")
    else:
        df_a19 = pd.DataFrame([
            {
                "severity": r["_id"].get("severity", "UNKNOWN"),
                "status": r["_id"].get("status", "UNKNOWN"),
                "nb_alertes": r.get("nb_alertes", 0)
            }
            for r in raw_a19
        ])

        # Filtre sur la sévérité
        all_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        present_severities = [s for s in all_severities if s in df_a19["severity"].unique()]
        other_severities = [s for s in df_a19["severity"].unique() if s not in all_severities]
        avail_sevs = present_severities + other_severities

        selected_sevs = st.multiselect(
            "Filtrer par niveau de sévérité :",
            options=avail_sevs,
            default=avail_sevs
        )

        filtered_a19 = df_a19[df_a19["severity"].isin(selected_sevs)]

        if filtered_a19.empty:
            st.info("Aucune alerte ne correspond aux sévérités sélectionnées.")
        else:
            fig_a19 = px.bar(
                filtered_a19,
                x="severity",
                y="nb_alertes",
                color="status",
                barmode="stack",
                title="Alertes de sécurité : Distribution par sévérité (barres empilées par statut)",
                labels={"severity": "Sévérité", "nb_alertes": "Nombre d'alertes", "status": "Statut"},
                category_orders={"severity": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                color_discrete_map={
                    "open": "#3b82f6",
                    "in_progress": "#f59e0b",
                    "resolved": "#10b981",
                    "closed": "#6b7280"
                },
                template="plotly_white",
                height=450
            )
            fig_a19.update_layout(legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1))
            st.plotly_chart(fig_a19, use_container_width=True)


# ------------------------------------------------------------------------------
# 4) TOP 10 DES PORTS DE DESTINATION (A21) - BARRES
# ------------------------------------------------------------------------------
with tab_a21:
    st.subheader("A21 : Top 10 des ports de destination (Flux Réseau)")
    st.markdown("Cartographie des services réseaux les plus ciblés ou sollicités sur l'infrastructure.")

    raw_a21 = load_a21()
    if not raw_a21:
        st.warning("Aucune donnée de flux réseau disponible (A21).")
    else:
        # Dictionnaire des services usuels pour enrichir l'affichage
        SERVICE_NAMES = {
            80: "HTTP (80)",
            443: "HTTPS (443)",
            22: "SSH (22)",
            53: "DNS (53)",
            3389: "RDP (3389)",
            445: "SMB (445)",
            8080: "HTTP-Alt (8080)",
            8443: "HTTPS-Alt (8443)",
            3306: "MySQL (3306)",
            5432: "PostgreSQL (5432)",
            4444: "Metasploit / C2 (4444)",
            9001: "Tor / Custom C2 (9001)"
        }

        df_a21 = pd.DataFrame([
            {
                "port": str(r["_id"]),
                "port_label": SERVICE_NAMES.get(r["_id"], f"Port {r['_id']}"),
                "nb_flux": r.get("count", 0)
            }
            for r in raw_a21
        ]).sort_values("nb_flux", ascending=False)

        fig_a21 = px.bar(
            df_a21,
            x="port_label",
            y="nb_flux",
            text="nb_flux",
            title="Top 10 des ports de destination par volume de flux réseau",
            labels={"port_label": "Port de destination / Service", "nb_flux": "Nombre de flux"},
            color="nb_flux",
            color_continuous_scale="Blues",
            template="plotly_white",
            height=450
        )
        fig_a21.update_traces(textposition="outside")
        fig_a21.update_layout(coloraxis_showscale=False)
        st.plotly_chart(fig_a21, use_container_width=True)


# ------------------------------------------------------------------------------
# 5) ONGLET "DÉTECTION SPARK" (S26 & S30 DEPUIS CSV)
# ------------------------------------------------------------------------------
with tab_spark:
    st.subheader("⚡ Résultats des Détections Analytiques Spark")
    st.markdown("Visualisation des résultats générés par les jobs distribués Apache Spark, exportés sous format CSV.")

    # --- S26 : Force Brute ---
    st.markdown("### 🚨 S26 : Attaques par Force Brute (Fenêtre glissante 5 min)")
    s26_csv_path = SPARK_OUTPUTS_DIR / "s26.csv"
    if not s26_csv_path.exists():
        st.warning(
            "⚠️ **Fichier introuvable :** `results/spark_outputs/s26.csv`\n\n"
            "Le job Spark S26 n'a pas encore exporté ses résultats. "
            "Veuillez exécuter : `docker exec siem-spark-master /opt/spark/bin/spark-submit ... /opt/spark-apps/s26_brute_force.py`."
        )
    else:
        try:
            df_s26 = pd.read_csv(s26_csv_path)
            st.success(f"Résultats chargés avec succès depuis `{s26_csv_path.name}` ({len(df_s26)} IP détectées).")

            col_m1, col_m2 = st.columns(2)
            col_m1.metric("Adresses IP attaquantes", len(df_s26))
            col_m2.metric("Tentatives max / fenêtre 5 min", int(df_s26["max_failures"].max()))

            st.dataframe(
                df_s26,
                column_config={
                    "source_ip": st.column_config.TextColumn("Adresse IP Source"),
                    "max_failures": st.column_config.NumberColumn("Tentatives max (échecs)"),
                    "first_window_start": st.column_config.DatetimeColumn("Début de première fenêtre")
                },
                use_container_width=True,
                hide_index=True
            )
        except Exception as e:
            st.error(f"Erreur lors de la lecture de `s26.csv` : {e}")

    st.markdown("---")

    # --- S30 : Score de Risque ---
    st.markdown("### 📊 S30 : Top 20 des Utilisateurs à Risque (Score composite)")
    s30_csv_path = SPARK_OUTPUTS_DIR / "s30.csv"
    if not s30_csv_path.exists():
        st.warning(
            "⚠️ **Fichier introuvable :** `results/spark_outputs/s30.csv`\n\n"
            "Le job Spark S30 n'a pas encore exporté ses résultats. "
            "Veuillez exécuter : `docker exec siem-spark-master /opt/spark/bin/spark-submit ... /opt/spark-apps/s30_risk_score.py`."
        )
    else:
        try:
            df_s30 = pd.read_csv(s30_csv_path)
            st.success(f"Résultats chargés avec succès depuis `{s30_csv_path.name}` (Top {len(df_s30)} utilisateurs).")

            col_s1, col_s2, col_s3 = st.columns(3)
            col_s1.metric("Utilisateur le plus à risque", str(df_s30.iloc[0]["user_id"]))
            col_s2.metric("Score maximal", f"{df_s30.iloc[0]['risk_score']:.4f}")
            col_s3.metric("Comptes de service concernés", int(df_s30["is_service_account"].sum()))

            st.dataframe(
                df_s30,
                column_config={
                    "user_id": st.column_config.TextColumn("Identifiant User"),
                    "department": st.column_config.TextColumn("Département"),
                    "role": st.column_config.TextColumn("Rôle"),
                    "is_service_account": st.column_config.CheckboxColumn("Compte Service"),
                    "nb_failures": st.column_config.NumberColumn("Échecs"),
                    "nb_nocturnal": st.column_config.NumberColumn("Nocturnes (22h-6h)"),
                    "extra_countries": st.column_config.NumberColumn("Pays suppl. (>1)"),
                    "nb_impossible_travel": st.column_config.NumberColumn("Voyages Impossibles"),
                    "nb_blacklist": st.column_config.NumberColumn("IP Blacklist"),
                    "risk_score": st.column_config.NumberColumn("Score de Risque", format="%.4f")
                },
                use_container_width=True,
                hide_index=True
            )
        except Exception as e:
            st.error(f"Erreur lors de la lecture de `s30.csv` : {e}")
