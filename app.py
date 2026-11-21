"""Interactive dashboard. Run with:  streamlit run app.py"""
import json

import pandas as pd
import plotly.express as px
import streamlit as st

from scanner import storage
from scanner.config import LAB_TARGETS, InvalidTarget, is_local, normalize_url
from scanner.orchestrator import FULL, MODES, NotVerified, cancel_scan, start_scan_async
from scanner.report import build_pdf
from scanner.scoring import SEVERITY_ORDER
from scanner.ui_theme import apply_theme, hero, status_dot
from scanner.verify import is_verified, token_for, verification_url
from scanner.zap_client import ZapScanner

SEV_COLORS = {"Critical": "#ff3b5c", "High": "#ff7a45", "Medium": "#ffc53d", "Low": "#40a9ff", "Info": "#a0aec0"}


def style_fig(fig):
    """Transparent chart backgrounds so charts sit on the glass panels."""
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      font_color="#dbe7f7", margin=dict(t=50, l=10, r=10, b=10))
    return fig


st.set_page_config(page_title="Threat Scanner", page_icon=":material/shield:", layout="wide")
apply_theme()

with st.sidebar:
    st.markdown("### :material/radar: Threat scanner")
    page = st.radio("Navigate", ["New scan", "Results", "Scan history"],
                    captions=["Scan a website", "Findings and fixes", "Past scans"], label_visibility="collapsed",
                    key="nav")
    st.divider()
    zap_ok = ZapScanner().is_up()
    status_dot(zap_ok)
    if not zap_ok:
        st.caption("Start it with `docker compose up -d`. Quick scans work without ZAP.")

# ---------------------------------------------------------------- New scan
if page == "New scan":
    hero("Threat <span>Scanner</span>", "Paste a website address to check its security.")

    def _use_demo(url):
        st.session_state["url_input"] = url

    with st.container(border=True, key="panel_scan"):
        st.markdown("**Demo targets** · deliberately vulnerable apps in the local Docker lab")
        with st.container(horizontal=True):
            for name, cfg in LAB_TARGETS.items():
                st.button(name, key=f"demo_{name}", icon=":material/target:", on_click=_use_demo,
                          args=(cfg["url"],), help=f"Fill in {cfg['url']}")

        raw = st.text_input("Enter URL", placeholder="https://example.com", key="url_input",
                            help="Paste the address of the website you want to check, or pick a demo target "
                                 "above. https:// is added if missing.")
        target = None
        if raw.strip():
            try:
                target = normalize_url(raw)
            except InvalidTarget as e:
                st.error(str(e), icon=":material/error:")
        if target and target != raw.strip():
            st.caption(f"Will scan: `{target}`")

        mode = st.radio("Scan mode", list(MODES), index=0, horizontal=True,
                        captions=["Headers, cookies, HTTPS, exposed files, info leaks. Safe for any site.",
                                  "Also crawls the site with OWASP ZAP and inspects every page. Read-only.",
                                  "Sends attack test requests (SQL injection, XSS...). Only for sites you own."])

        verified = True
        if target and mode == FULL and not is_local(target):
            verified = is_verified(target)
            if verified:
                st.success("Ownership verified for this domain.", icon=":material/verified:")
            else:
                st.warning(f"1. Create a text file containing the token below.\n"
                           f"2. Publish it at `{verification_url(target)}`\n"
                           f"3. Click **Check verification**.",
                           title="Full scans need proof that you own this website", icon=":material/lock:")
                st.code(token_for(target), language=None)
                if st.button("Check verification", icon=":material/refresh:"):
                    st.rerun()

        consent = st.checkbox("I own this website or have the owner's permission to scan it.")

        current = st.session_state.get("scan_id")
        busy = bool(current) and (storage.get_scan(current) or {}).get("status") == "running"
        ready = bool(target) and consent and verified and not busy
        # A fixed key keeps this one widget across reruns.
        if st.button("Start scan", type="primary", disabled=not ready, key="start_scan", icon=":material/bolt:"):
            if MODES[mode]["zap"] and not zap_ok:
                st.error("The ZAP engine is not running. Start it or choose Quick mode.")
            else:
                try:
                    st.session_state["scan_id"] = start_scan_async(target, mode)
                except (InvalidTarget, NotVerified) as e:
                    st.error(str(e))

    @st.fragment(run_every=2)
    def scan_progress():
        """Refreshes only this box while a scan runs (the rest of the page, and the
        animated background, stay untouched)."""
        sid = st.session_state.get("scan_id")
        if not sid:
            return
        scan = storage.get_scan(sid)
        with st.container(border=True, key="panel_progress"):
            st.progress(scan["progress"] / 100, text=f"Scan #{sid}: {scan['message']}")
            if scan["status"] == "running":
                if st.button("Cancel scan", key="cancel_scan", icon=":material/stop_circle:"):
                    cancel_scan(sid)
                    st.rerun(scope="fragment")
            elif scan["status"] == "completed":
                st.success(f"Scan #{sid} finished: {scan['message']} in {scan['duration_s']} s. Open **Results**.",
                           icon=":material/task_alt:")
                st.session_state["view_id"] = sid
            elif scan["status"] == "cancelled":
                st.warning(f"Scan #{sid} was cancelled.")
            else:
                st.error(f"Scan failed: {scan['message']}")

    scan_progress()

# ---------------------------------------------------------------- Results
elif page == "Results":
    hero("Scan <span>Results</span>", "Findings, severity and how to fix each one.")
    scans = [s for s in storage.list_scans() if s["status"] == "completed"]
    if not scans:
        st.info("No completed scans yet.")
        st.stop()
    labels = {s["id"]: f"#{s['id']} · {s['target']} · {s['mode']} · {s['started_at']}" for s in scans}
    default = st.session_state.get("view_id", scans[0]["id"])
    ids = list(labels)
    sid = st.selectbox("Scan", ids, index=ids.index(default) if default in ids else 0, format_func=labels.get)
    df = pd.DataFrame(storage.get_findings(sid))
    if df.empty:
        st.success("No findings for this scan.")
        st.stop()

    cols = st.columns(5)
    for c, sev in zip(cols, SEVERITY_ORDER):
        with c.container(key=f"sev_{sev}"):
            st.metric(sev, int((df["severity"] == sev).sum()))

    c1, c2 = st.columns(2)
    with c1.container(border=True, key="panel_pie"):
        sev_counts = df["severity"].value_counts().reindex(SEVERITY_ORDER).dropna().reset_index()
        sev_counts.columns = ["severity", "count"]
        st.plotly_chart(style_fig(px.pie(sev_counts, names="severity", values="count", hole=0.55,
                                         title="By severity", color="severity", color_discrete_map=SEV_COLORS)))
    with c2.container(border=True, key="panel_owasp"):
        ow = df.groupby("owasp").size().reset_index(name="count").sort_values("count")
        st.plotly_chart(style_fig(px.bar(ow, x="count", y="owasp", orientation="h",
                                         title="By OWASP Top 10 category")))

    df["engine"] = df["source"].str.split(":").str[0]
    with st.container(border=True, key="panel_engine"):
        st.plotly_chart(style_fig(px.histogram(df, x="engine", color="severity", barmode="stack",
                                               title="ZAP vs custom checks",
                                               category_orders={"severity": SEVERITY_ORDER},
                                               color_discrete_map=SEV_COLORS)))

    with st.container(border=True, key="panel_findings"):
        f1, f2, f3 = st.columns(3)
        sev_f = f1.multiselect("Severity", SEVERITY_ORDER, default=SEVERITY_ORDER)
        src_f = f2.multiselect("Source", sorted(df["engine"].unique()), default=sorted(df["engine"].unique()))
        q = f3.text_input("Search title / URL", icon=":material/search:")
        view = df[df["severity"].isin(sev_f) & df["engine"].isin(src_f)]
        if q:
            view = view[view["title"].str.contains(q, case=False) | view["url"].str.contains(q, case=False)]
        st.dataframe(view[["severity", "risk_score", "title", "owasp", "cwe", "url", "param", "source"]],
                     hide_index=True)

    st.subheader("Finding details and remediation")
    for _, f in view.iterrows():
        with st.expander(f"[{f['severity']}] {f['title']} — {f['url']}"):
            st.markdown(f"**OWASP:** {f['owasp']} · **CWE:** {f['cwe']} · **Risk:** {f['risk_score']}/9 · "
                        f"**Confidence:** {f['confidence']} · **Source:** {f['source']}")
            if f["param"]:
                st.markdown(f"**Parameter:** `{f['param']}`")
            urls = json.loads(f["extra"] or "{}").get("urls", [f["url"]])
            if len(urls) > 1:
                st.markdown(f"**Affected URLs ({len(urls)}):**")
                st.code("\n".join(urls[:30]) + ("\n..." if len(urls) > 30 else ""))
            if f["description"]:
                st.markdown(f"**Issue:** {f['description']}")
            if f["evidence"]:
                st.code(f["evidence"])
            st.markdown("**How to fix:**")
            st.markdown(f["remediation"])

    if st.button("Generate PDF report", icon=":material/picture_as_pdf:"):
        path = build_pdf(sid)
        with open(path, "rb") as fh:
            st.download_button("Download PDF", fh, file_name=f"scan_{sid}.pdf", mime="application/pdf",
                               icon=":material/download:")

# ---------------------------------------------------------------- History
else:
    hero("Scan <span>History</span>", "Every scan this scanner has run.")
    scans = storage.list_scans()
    if not scans:
        st.info("No scans yet.")
        st.stop()
    with st.container(border=True, key="panel_history"):
        hist = pd.DataFrame(scans)[["id", "target", "mode", "status", "started_at", "duration_s", "message"]]
        st.dataframe(hist, hide_index=True)
    rows = []
    for s in scans:
        for f in storage.get_findings(s["id"]):
            rows.append({"scan": f"#{s['id']}", "severity": f["severity"]})
    if rows:
        with st.container(border=True, key="panel_hist_chart"):
            st.plotly_chart(style_fig(px.histogram(pd.DataFrame(rows), x="scan", color="severity",
                                                   title="Findings per scan",
                                                   category_orders={"severity": SEVERITY_ORDER},
                                                   color_discrete_map=SEV_COLORS)))
