"""MalMap - Ultra Minimal Dashboard (red/black theme, no filters)."""

from __future__ import annotations

from datetime import datetime

import pandas as pd
import plotly.graph_objects as go
import requests
import streamlit as st
import streamlit.components.v1 as components

import os
from dotenv import load_dotenv
from database import get_all_iocs, get_stats, init_database, upsert_iocs_batch

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY")



st.set_page_config(
    page_title="MalMap",
    layout="wide",
    initial_sidebar_state="collapsed",
    menu_items={"Get help": None, "Report a bug": None, "About": None},
)


def fmt_time(ts) -> str:
    if not ts:
        return "Never"
    try:
        dt = datetime.fromisoformat(str(ts))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


def refresh_from_malwarebazaar(limit: int = 250) -> int:
    """
    Pull recent samples from MalwareBazaar and upsert as hash IOCs.
    """
    url = "https://mb-api.abuse.ch/api/v1/"
    try:
        headers = {"User-Agent": "MalMap/1.0"}
        resp = requests.post(
            url, 
            data={"query": "get_recent", "selector": str(limit)}, 
            headers=headers,
            timeout=30
        )
        if resp.status_code == 401:
            st.info("⚠️ MalwareBazaar: API requires authentication. Using fallback approach...")
            return 0
        resp.raise_for_status()
        payload = resp.json()
        entries = payload.get("data") or []

        now = datetime.now().isoformat()
        iocs = []
        for e in entries:
            sha256 = e.get("sha256_hash")
            if not sha256:
                continue
            iocs.append(
                {
                    "value": sha256,
                    "type": "hash",
                    "source": "bazaar",
                    "tags": e.get("tags") or [],
                    "mitre_id": "Unknown",
                    "mitre_name": e.get("signature") or "Unclassified",
                    "risk_score": 75,
                    "first_seen": now,
                    "last_seen": now,
                }
            )
        return upsert_iocs_batch(iocs) if iocs else 0
    except requests.exceptions.RequestException as e:
        st.info(f"ℹ️ MalwareBazaar: {str(e)[:60]}... (API limit or connectivity issue)")
        return 0
    except Exception as e:
        st.warning(f"MalwareBazaar Refresh Error: {e}")
        return 0


def refresh_from_abuseipdb(limit: int = 100) -> int:
    """
    Pull recent malicious IPs from AbuseIPDB with rate limiting.
    """
    if not ABUSEIPDB_API_KEY:
        st.info("ℹ️ AbuseIPDB API key missing - skipping.")
        return 0
    
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
    params = {"limit": min(limit, 100), "maxAgeInDays": 7}  # Reduce limit, cache recent only
    
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        
        if resp.status_code == 429:
            st.info("⚠️ AbuseIPDB: Rate limit reached. Try again in a moment.")
            return 0
        elif resp.status_code == 401:
            st.error("❌ AbuseIPDB: Invalid API key.")
            return 0
            
        resp.raise_for_status()
        payload = resp.json()
        entries = payload.get("data") or []

        now = datetime.now().isoformat()
        iocs = []
        for e in entries:
            ip = e.get("ipAddress")
            if not ip:
                continue
            iocs.append(
                {
                    "value": ip,
                    "type": "ip",
                    "source": "abuseipdb",
                    "tags": [],
                    "mitre_id": "Unknown",
                    "mitre_name": "Suspicious IP",
                    "risk_score": e.get("abuseConfidenceScore", 50),
                    "first_seen": now,
                    "last_seen": now,
                }
            )
        added = upsert_iocs_batch(iocs) if iocs else 0
        if added > 0:
            st.success(f"✅ AbuseIPDB: Added {added} IPs")
        return added
    except requests.exceptions.ConnectionError:
        st.info("ℹ️ AbuseIPDB: Connection timeout - try again later.")
        return 0
    except Exception as e:
        st.info(f"ℹ️ AbuseIPDB: {str(e)[:50]}...")
        return 0


def refresh_from_alienvault(limit: int = 100) -> int:
    """
    Pull recent pulses from AlienVault OTX with improved error handling.
    """
    if not ALIENVAULT_API_KEY:
        st.info("ℹ️ AlienVault API key missing - skipping.")
        return 0
    
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": ALIENVAULT_API_KEY}
    
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        
        if resp.status_code == 429:
            st.info("⚠️ AlienVault OTX: Rate limit reached.")
            return 0
        elif resp.status_code == 401:
            st.error("❌ AlienVault OTX: Invalid API key.")
            return 0
            
        resp.raise_for_status()
        payload = resp.json()
        pulses = payload.get("results") or []

        now = datetime.now().isoformat()
        iocs = []
        for p in pulses:
            indicators = p.get("indicators") or []
            pulse_tags = p.get("tags") or []
            pulse_name = p.get("name", "Unknown Pulse")
            
            for ind in indicators[:20]:  # Limit indicators per pulse for performance
                val = ind.get("indicator")
                type_map = {
                    "IPv4": "ip",
                    "IPv6": "ip",
                    "domain": "domain",
                    "hostname": "domain",
                    "FileHash-SHA256": "hash",
                    "URL": "url"
                }
                ioc_type = type_map.get(ind.get("type"), "unknown")
                if ioc_type == "unknown":
                    continue
                
                iocs.append(
                    {
                        "value": val,
                        "type": ioc_type,
                        "source": "otx",
                        "tags": pulse_tags,
                        "mitre_id": "Unknown",
                        "mitre_name": pulse_name,
                        "risk_score": 60,
                        "first_seen": now,
                        "last_seen": now,
                    }
                )
        added = upsert_iocs_batch(iocs) if iocs else 0
        if added > 0:
            st.success(f"✅ AlienVault OTX: Added {added} indicators")
        return added
    except requests.exceptions.ConnectionError:
        st.info("ℹ️ AlienVault OTX: Connection timeout - try again later.")
        return 0
    except Exception as e:
        st.info(f"ℹ️ AlienVault OTX: {str(e)[:50]}...")
        return 0



st.markdown(
    """
<style>
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}

:root{
  --bg: #060606;
  --panel: rgba(10,10,10,0.72);
  --panel-2: rgba(12,12,12,0.82);
  --text: #f2f2f2;
  --muted: rgba(242,242,242,0.72);
  --border: rgba(255,255,255,0.10);
  --red: #ff2a2a;
  --red2: #b40000;
}

/* Put Vanta behind everything */
#vanta-bg {
  position: fixed;
  inset: 0;
  z-index: 0;
}
#vanta-bg canvas {
  position: absolute;
  inset: 0;
}

/* Make Streamlit layers transparent so background shows */
html, body, .stApp {
  background: transparent !important;
  color: var(--text) !important;
}

/* Ensure Streamlit content is above the Vanta layer */
.stApp > header {background: transparent;}
section.main {position: relative; z-index: 2;}

.main {
  padding: 1.5rem 2rem;
}

h1, h2, h3, h4, h5, h6 {color: var(--text) !important;}
h1 {font-size: 1.6em; margin: 0 0 1rem 0; font-weight: 900;}
h2 {font-size: 1.1em; margin: 1.5rem 0 0.8rem 0; font-weight: 900;}
.stCaption {color: var(--muted) !important; font-size: 0.85em;}
.stDivider {margin: 1.5rem 0; border-top: 1px solid var(--border) !important;}

/* Give the whole page a subtle readable overlay panel */
[data-testid="stAppViewContainer"]{
  background: linear-gradient(180deg, rgba(0,0,0,0.52), rgba(0,0,0,0.72));
}

/* Inputs */
.stTextInput input {
  border: 1px solid var(--border) !important;
  padding: 0.55rem 0.65rem;
  border-radius: 16px;
  background: rgba(0,0,0,0.55) !important;
  color: var(--text) !important;
}
.stButton > button {
  background: linear-gradient(135deg, #ff2a2a 0%, #cc1111 100%) !important;
  color: #ffffff !important;
  border: 1px solid rgba(255,42,42,0.8) !important;
  padding: 0.35rem 0.75rem !important;
  border-radius: 8px !important;
  font-weight: 700 !important;
  font-size: 0.9em !important;
  height: auto !important;
}
.stButton > button:hover {
  background: linear-gradient(135deg, #ff5050 0%, #dd2222 100%) !important;
  border-color: rgba(255,100,100,0.9) !important;
  box-shadow: 0 4px 15px rgba(255,42,42,0.4) !important;
}

/* Curved "data tiles" (Streamlit metrics) */
.stMetric {
  background: var(--panel);
  padding: 1rem;
  border-radius: 28px;
  border: 1px solid var(--border);
  box-shadow: 0 18px 50px rgba(0,0,0,0.50);
}
.stMetric label {color: var(--muted) !important; font-size: 0.85em;}
.stMetric [data-testid="metricValue"] {color: var(--text) !important; font-size: 1.8em; font-weight: 950;}

/* Curved hero "tiles" */
#hero {
  position: relative;
  border-radius: 34px;
  overflow: hidden;
  border: 1px solid rgba(255,42,42,0.20);
  background: rgba(0,0,0,0.25);
  box-shadow: 0 30px 90px rgba(0,0,0,0.55);
}
.tiles {
  display: grid;
  gap: 14px;
  width: 100%;
  max-width: 1200px;
  padding: 18px;
  grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
}
.tile {
  background: var(--panel-2);
  border: 1px solid rgba(255,255,255,0.12);
  border-radius: 34px;
  padding: 14px 22px;
  text-align:center;
  box-shadow: 0 18px 55px rgba(0,0,0,0.45);
}
.tile .label {color: var(--muted) !important; font-size: 0.85em; margin-bottom:6px; font-weight: 800;}
.tile .value {color: var(--text) !important; font-weight: 950; font-size: 1.6em;}
.tile .value.accent {color: var(--red) !important;}

/* Dataframe container curved */
.stDataFrame {border-radius: 28px; overflow: hidden; border: 1px solid var(--border);}

</style>
""",
    unsafe_allow_html=True,
)


try:
    init_database()
except Exception:
    pass


try:
    top_left, top_mid, top_right = st.columns([6, 2, 2], vertical_alignment="center")
    with top_left:
        st.title("MalMap")
    with top_right:
        if st.button("Refresh All", use_container_width=True):
            with st.spinner("🔄 Syncing threat intelligence from all sources..."):
                added_mb = refresh_from_malwarebazaar(limit=100)
                added_adb = refresh_from_abuseipdb(limit=100)
                added_av = refresh_from_alienvault(limit=50)
                total_added = added_mb + added_adb + added_av
            if total_added > 0:
                st.success(f"✅ Sync complete! Added {total_added} new threat indicators.")
            else:
                st.info("ℹ️ No new indicators found or all sources blocked.")
            st.rerun()

    stats = get_stats()
    all_iocs = get_all_iocs()

    # --- Sidebar Filters ---
    st.sidebar.title("Filters")
    with st.sidebar:
        st.markdown("### IOC Type")
        unique_types = sorted(all_iocs["type"].unique().tolist()) if not all_iocs.empty else []
        selected_types = st.multiselect("Select Type", unique_types, default=unique_types) if unique_types else []
        
        st.markdown("### Source")
        unique_sources = sorted(all_iocs["source"].unique().tolist()) if not all_iocs.empty else []
        selected_sources = st.multiselect("Select Source", unique_sources, default=unique_sources) if unique_sources else []
        
        st.markdown("### Risk Level")
        risk_min, risk_max = st.slider("Risk Score Range", 0, 100, (0, 100))
        
        st.divider()
        st.markdown("### API Status")
        if ABUSEIPDB_API_KEY:
            st.success("AbuseIPDB: Connected", icon="✅")
        else:
            st.error("AbuseIPDB: Key Missing", icon="❌")
            
        if ALIENVAULT_API_KEY:
            st.success("AlienVault: Connected", icon="✅")
        else:
            st.error("AlienVault: Key Missing", icon="❌")
            
        st.info("MalwareBazaar: Public Access", icon="🔓")
        
        st.divider()
        if st.button("Clear DB", type="secondary", use_container_width=True):
            import sqlite3
            from database import DB_PATH
            try:
                conn = sqlite3.connect(DB_PATH)
                conn.execute("DELETE FROM iocs")
                conn.commit()
                conn.close()
                st.toast("Database cleared successfully!", icon="🗑️")
                st.rerun()
            except Exception as e:
                st.error(f"Failed to clear DB: {e}")

        st.divider()
        with st.expander("ℹ️ About MalMap"):
            st.markdown("""
            **MalMap** is a high-performance threat intelligence dashboard designed for security analysts.
            
            - **Data Sources**: MalwareBazaar, AbuseIPDB, AlienVault OTX.
            - **Features**: Global heatmaps, risk-based filtering, MITRE ATT&CK integration, and one-click analysis.
            - **Privacy**: No telemetry is collected. API keys are stored locally in `.env`.
            """)

    # Filter data
    filtered_iocs = all_iocs.copy()
    if not filtered_iocs.empty:
        if selected_types:
            filtered_iocs = filtered_iocs[filtered_iocs["type"].isin(selected_types)]
        if selected_sources:
            filtered_iocs = filtered_iocs[filtered_iocs["source"].isin(selected_sources)]
        filtered_iocs = filtered_iocs[(filtered_iocs["risk_score"] >= risk_min) & (filtered_iocs["risk_score"] <= risk_max)]

    # Full-page Vanta background (red/black)
    vanta_bg = """
<div id="vanta-bg"></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r134/three.min.js"></script>
<script src="https://unpkg.com/vanta@latest/dist/vanta.dots.min.js"></script>
<script>
  (function () {
    if (typeof VANTA === 'undefined' || !VANTA.DOTS) return;
    try {
      if (window.__MALMAP_VANTA_BG) return;
      window.__MALMAP_VANTA_BG = VANTA.DOTS({
        el: "#vanta-bg",
        mouseControls: true,
        touchControls: true,
        gyroControls: false,
        minHeight: 200.0,
        minWidth: 200.0,
        scale: 1.0,
        scaleMobile: 1.0,
        color: 0xff2a2a,
        color2: 0x000000,
        backgroundColor: 0x000000
      });
    } catch (e) {}
  })();
</script>
"""
    components.html(vanta_bg, height=1)

    st.markdown("## Global Threat Intelligence")
    
    # Custom Metric Layout using the CSS tiles
    st.markdown(f"""
    <div class="tiles">
        <div class="tile">
            <div class="label">TOTAL IOCs</div>
            <div class="value">{len(filtered_iocs):,}</div>
        </div>
        <div class="tile">
            <div class="label">HIGH RISK</div>
            <div class="value accent">{(filtered_iocs['risk_score'] >= 75).sum() if not filtered_iocs.empty else 0}</div>
        </div>
        <div class="tile">
            <div class="label">ACTIVE SOURCES</div>
            <div class="value">{len(filtered_iocs['source'].unique()) if not filtered_iocs.empty else 0}</div>
        </div>
        <div class="tile">
            <div class="label">LAST SYNC</div>
            <div class="value" style="font-size: 1.1em; padding-top: 5px;">{fmt_time(stats.get('last_updated'))}</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")


    st.markdown("## Global Threat Map")
    if not filtered_iocs.empty and "source" in filtered_iocs.columns:
        # NOTE: We don't have real per-IOC geolocation in the dataset, so we spread
        # points by sampling "threat regions" and applying jitter around each region.
        import random

        threat_regions = {
            "otx": {"lat": 40.7128, "lon": -74.0060, "name": "OTX Network", "jitter": 22},
            "bazaar": {"lat": 47.3744, "lon": 8.5410, "name": "Malware Bazaar", "jitter": 18},
            "abuseipdb": {"lat": 34.0522, "lon": -118.2437, "name": "AbuseIPDB", "jitter": 25},
        }

        # Cap the number of points for performance, but still show spread.
        max_points = 900
        df_pts = filtered_iocs.copy()
        if len(df_pts) > max_points:
            df_pts = df_pts.sample(n=max_points, random_state=7)

        rng = random.Random(7)
        lats: list[float] = []
        lons: list[float] = []
        sizes: list[float] = []
        colors: list[str] = []
        hovers: list[str] = []

        def clamp(v: float, lo: float, hi: float) -> float:
            return max(lo, min(hi, v))

        for _, row in df_pts.iterrows():
            source = str(row.get("source", "")).lower()
            region = threat_regions.get(source)
            if not region:
                continue

            j = float(region["jitter"])
            # Triangular distribution keeps density near the region center.
            lat = float(region["lat"]) + rng.triangular(-j, j, 0.0)
            lon = float(region["lon"]) + rng.triangular(-j, j, 0.0)
            lat = clamp(lat, -80.0, 80.0)
            lon = ((lon + 180.0) % 360.0) - 180.0

            risk = float(row.get("risk_score", 0) or 0)
            size = 6.0 + (risk / 100.0) * 10.0

            # Risk -> red intensity
            if risk >= 75:
                c = "#ff2a2a"
            elif risk >= 50:
                c = "#ff5c5c"
            else:
                c = "#ff9a9a"

            lats.append(lat)
            lons.append(lon)
            sizes.append(size)
            colors.append(c)
            hovers.append(
                "<b>IOC</b>: "
                + str(row.get("value", ""))[:90]
                + "<br><b>Type</b>: "
                + str(row.get("type", ""))
                + "<br><b>Source</b>: "
                + str(row.get("source", ""))
                + "<br><b>Risk</b>: "
                + str(int(risk))
            )

        if lats:
            fig_map = go.Figure()
            fig_map.add_trace(
                go.Scattergeo(
                    lon=lons,
                    lat=lats,
                    text=hovers,
                    mode="markers",
                    marker=dict(
                        size=sizes,
                        color=colors,
                        opacity=0.75,
                        line=dict(width=0.6, color="rgba(255,255,255,0.22)"),
                    ),
                    hovertemplate="%{text}<extra></extra>",
                )
            )

            fig_map.update_layout(
                geo=dict(
                    projection_type="natural earth",
                    showland=True,
                    landcolor="#0d0d0d",
                    coastlinecolor="#1f1f1f",
                    showocean=True,
                    oceancolor="#000000",
                    bgcolor="rgba(0,0,0,0)",
                ),
                height=500,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#f2f2f2", size=11),
                showlegend=False,
                margin=dict(l=0, r=0, t=0, b=0),
            )
            st.plotly_chart(fig_map, use_container_width=True)
        else:
            st.info("No threat data to display")
    else:
        st.info("No threat data to display")

    st.markdown("## Threat Distribution")
    dist1, dist2 = st.columns(2)
    
    if not filtered_iocs.empty:
        with dist1:
            type_counts = filtered_iocs['type'].value_counts()
            fig_type = go.Figure(data=[go.Pie(labels=type_counts.index, values=type_counts.values, hole=.4, marker=dict(colors=["#ff2a2a", "#b40000", "#3a0000", "#1a1a1a"]))])
            fig_type.update_layout(title="IOC Types", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#f2f2f2"), showlegend=True, height=350, margin=dict(l=0, r=0, t=30, b=0))
            st.plotly_chart(fig_type, use_container_width=True)
            
        with dist2:
            source_counts = filtered_iocs['source'].value_counts()
            fig_source = go.Figure(data=[go.Bar(x=source_counts.index, y=source_counts.values, marker_color="#ff2a2a")])
            fig_source.update_layout(title="Top Sources", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#f2f2f2"), height=350, margin=dict(l=0, r=0, t=30, b=0))
            st.plotly_chart(fig_source, use_container_width=True)
    else:
        st.info("No distribution data available.")

    st.divider()

    st.markdown("## IOC Repository")
    
    col_search, col_export = st.columns([8, 2], vertical_alignment="bottom")
    with col_search:
        search = st.text_input("Search IOCs", placeholder="Value, type, source, MITRE...", label_visibility="collapsed")
    with col_export:
        if not filtered_iocs.empty:
            csv = filtered_iocs.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="Export CSV",
                data=csv,
                file_name=f"malmap_iocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime='text/csv',
                use_container_width=True
            )


    if search and not filtered_iocs.empty:
        q = search.lower().strip()
        mask = (
            filtered_iocs["value"].astype(str).str.lower().str.contains(q, na=False)
            | filtered_iocs["type"].astype(str).str.lower().str.contains(q, na=False)
            | filtered_iocs["source"].astype(str).str.lower().str.contains(q, na=False)
            | filtered_iocs["mitre_name"].astype(str).str.lower().str.contains(q, na=False)
        )
        df = filtered_iocs.loc[mask].copy()

    else:
        df = filtered_iocs.head(100).copy()

    if not df.empty:
        # Prepare display columns with more details
        display = df[["value", "type", "source", "risk_score", "mitre_id", "mitre_name", "tags", "first_seen", "last_seen"]].copy()
        display.columns = ["IOC", "Type", "Source", "Risk", "MITRE ID", "Threat Category", "Tags", "First Seen", "Last Seen"]
        display["Risk"] = display["Risk"].astype(int)
        display["First Seen"] = display["First Seen"].apply(fmt_time)
        display["Last Seen"] = display["Last Seen"].apply(fmt_time)
        # Convert tags to string for display
        display["Tags"] = display["Tags"].apply(lambda x: ", ".join(x) if isinstance(x, list) and x else "-")


        def style_risk(val: int) -> str:
            if val >= 75:
                return "background-color: #b40000; color: #fff; font-weight: 900; text-align: center;"
            if val >= 50:
                return "background-color: #3a0000; color: #fff; font-weight: 850; text-align: center;"
            return "background-color: #151515; color: #f2f2f2; font-weight: 850; text-align: center;"

        # Add a column for External Links
        def make_link(row):
            val = row['IOC']
            typ = row['Type']
            if typ == 'hash':
                return f"https://www.virustotal.com/gui/file/{val}"
            elif typ == 'ip':
                return f"https://www.abuseipdb.com/check/{val}"
            elif typ == 'domain':
                return f"https://urlhaus.abuse.ch/browse.php?search={val}"
            return ""

        display["Analyze"] = display.apply(make_link, axis=1)

        # Reorder columns
        cols = ["Risk", "IOC", "Type", "Source", "MITRE ID", "Threat Category", "Tags", "First Seen", "Last Seen", "Analyze"]
        display = display[cols]

        st.dataframe(
            display.style.map(style_risk, subset=["Risk"]),
            use_container_width=True,
            height=600,
            column_config={
                "Analyze": st.column_config.LinkColumn("Analyze", help="Click to investigate on external platforms"),
                "Risk": st.column_config.NumberColumn("Risk", format="%d"),
                "IOC": st.column_config.TextColumn("IOC", width="medium"),
                "Type": st.column_config.TextColumn("Type", width="small"),
                "Source": st.column_config.TextColumn("Source", width="small"),
                "MITRE ID": st.column_config.TextColumn("MITRE ID", width="small"),
                "Threat Category": st.column_config.TextColumn("Threat Category", width="medium"),
                "Tags": st.column_config.TextColumn("Tags", width="medium"),
                "First Seen": st.column_config.TextColumn("First Seen", width="medium"),
                "Last Seen": st.column_config.TextColumn("Last Seen", width="medium"),
            },
            hide_index=True
        )


        st.caption(f"{len(df)} of {len(filtered_iocs)} total")
    else:
        st.info("No IOCs to display")

    st.divider()
    st.caption("n4cr0t1c • github.com/n4cr0t1c/malmap")

except Exception as e:
    st.error(f"Error: {e}")

