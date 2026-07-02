"""
Network Guardian - Dashboard
------------------------------
Visualizes Pi-hole activity: blocked domains, top offending devices,
and flagged violators, with one-click guidance on how to block a
device via your router's own admin panel.

Run with:
    streamlit run dashboard.py
"""

import json
import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st

DB_PATH = "./etc-pihole/pihole-FTL.db"
VIOLATIONS_LOG = "violations.json"
BLOCKED_STATUSES = (1, 4, 5, 6, 7, 8, 9, 10, 11)

st.set_page_config(page_title="Network Guardian", layout="wide")
st.title("🛡️ Network Guardian")
st.caption("Monitoring devices on your home WiFi for illegal / unsafe site access.")

if not Path(DB_PATH).exists():
    st.error(
        f"Pi-hole database not found at `{DB_PATH}`. Make sure Pi-hole is running "
        f"(`docker compose up -d`) and this dashboard is run from the same folder "
        f"as your docker-compose.yml."
    )
    st.stop()


@st.cache_data(ttl=15)
def load_recent_queries(limit=2000):
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query(
        f"""
        SELECT client, domain, timestamp, status
        FROM queries
        ORDER BY timestamp DESC
        LIMIT {limit}
        """,
        conn,
    )
    conn.close()
    df["time"] = pd.to_datetime(df["timestamp"], unit="s")
    df["blocked"] = df["status"].isin(BLOCKED_STATUSES)
    return df


def load_violations():
    if Path(VIOLATIONS_LOG).exists():
        with open(VIOLATIONS_LOG) as f:
            return pd.DataFrame(json.load(f))
    return pd.DataFrame(columns=["client_ip", "blocked_attempts_in_window", "last_domain", "flagged_at"])


df = load_recent_queries()
violations_df = load_violations()

col1, col2, col3 = st.columns(3)
col1.metric("Total queries (recent)", len(df))
col2.metric("Blocked queries", int(df["blocked"].sum()))
col3.metric("Devices flagged", violations_df["client_ip"].nunique() if not violations_df.empty else 0)

st.subheader("🚨 Flagged devices")
if violations_df.empty:
    st.success("No devices have been flagged for repeated illegal/unsafe site access.")
else:
    st.dataframe(violations_df.sort_values("flagged_at", ascending=False), use_container_width=True)
    st.info(
        "To block a flagged device: open your router's admin page "
        "(commonly `http://192.168.1.1` or `http://192.168.0.1`), log in, "
        "and look for **Parental Controls**, **Access Control**, or "
        "**Device Manager** — then block the device by its IP/MAC address. "
        "This step is intentionally manual: it uses your router's own "
        "security features rather than any network-attack technique."
    )

st.subheader("🔎 Top blocked domains")
blocked = df[df["blocked"]]
if not blocked.empty:
    top_domains = blocked["domain"].value_counts().head(15)
    st.bar_chart(top_domains)
else:
    st.write("No blocked queries yet.")

st.subheader("📋 Recent blocked activity by device")
if not blocked.empty:
    per_client = blocked.groupby("client")["domain"].count().sort_values(ascending=False)
    st.bar_chart(per_client)

st.subheader("🕒 Full recent query log")
st.dataframe(
    df[["time", "client", "domain", "blocked"]].sort_values("time", ascending=False),
    use_container_width=True,
    height=400,
)
