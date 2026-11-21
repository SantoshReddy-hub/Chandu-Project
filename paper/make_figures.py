"""Builds the research-paper figures from the scanner's real results.

Usage:  .venv/bin/python paper/make_figures.py <dvwa_scan_id> <juice_scan_id>
Writes PNGs to paper/figures/ and the numbers used to paper/results.json.
"""
import json
import os
import sys
from collections import Counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from evaluate import GT_PATH, evaluate  # noqa: E402
from scanner import storage  # noqa: E402
from scanner.scoring import SEVERITY_ORDER  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "figures")
os.makedirs(OUT, exist_ok=True)
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.spines.top": False,
                     "axes.spines.right": False, "figure.dpi": 200})
BLUE, ORANGE, GREEN, RED, GREY = "#2563eb", "#d97706", "#059669", "#dc2626", "#6b7280"
SEV_COL = {"Critical": "#7f1d1d", "High": "#dc2626", "Medium": "#ea8a00", "Low": "#2563eb", "Info": "#9ca3af"}


def save(fig, name):
    fig.savefig(os.path.join(OUT, name), bbox_inches="tight", facecolor="white")
    plt.close(fig)


# ------------------------------------------------------------------ diagrams
def box(ax, x, y, w, h, title, body, edge, fill):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.01,rounding_size=0.015",
                                linewidth=1.6, edgecolor=edge, facecolor=fill))
    ax.text(x + 0.025, y + h - 0.025, title, fontsize=10, fontweight="bold", color=edge, va="top")
    for i, line in enumerate(body):
        ax.text(x + 0.025, y + h - 0.065 - i * 0.034, line, fontsize=8.5, color="#111827", va="top")


def fig_architecture():
    fig, ax = plt.subplots(figsize=(7.5, 8.2))
    ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")
    ax.text(0.5, 0.985, "SYSTEM ARCHITECTURE", ha="center", fontsize=13, fontweight="bold")
    ax.text(0.5, 0.958, "Automated web-application vulnerability scanner", ha="center", fontsize=9, color=GREY)
    rows = [
        ("USER", ["Pastes a URL or picks a demo target (DVWA, Juice Shop)",
                  "in the Streamlit dashboard (app.py) or the CLI (scan.py)"], "#2563eb", "#dbeafe"),
        ("ORCHESTRATOR", ["Validates the URL, checks domain ownership for Full scans,",
                          "queues ZAP scans, reports progress, supports cancel"], "#059669", "#d1fae5"),
        ("SCANNING ENGINES", ["OWASP ZAP 2.17 (Docker): spider, AJAX spider, passive + active rules",
                              "Custom checks: headers, cookies, exposed files, info leaks, HTTPS"], "#d97706", "#fef3c7"),
        ("PROCESSING PIPELINE", ["Merge duplicates across pages and engines",
                                 "Risk = likelihood x impact -> severity; fix guidance by CWE"], "#7c3aed", "#ede9fe"),
        ("RESULTS", ["SQLite storage; dashboard charts, filters and history;",
                     "PDF report per scan"], "#dc2626", "#fee2e2"),
    ]
    h, gap, y = 0.135, 0.045, 0.925 - 0.135
    for title, body, edge, fill in rows:
        box(ax, 0.12, y, 0.76, h, title, body, edge, fill)
        if title != "RESULTS":
            ax.annotate("", xy=(0.5, y - gap + 0.004), xytext=(0.5, y - 0.004),
                        arrowprops=dict(arrowstyle="->", color="#374151", lw=1.2))
        y -= h + gap
    save(fig, "fig_architecture.png")


def fig_pipeline():
    steps = ["Input\nURL", "Normalise\n+ validate", "Ownership\ncheck (Full)", "ZAP crawl\n+ scan",
             "Custom\nchecks", "Merge\nduplicates", "Risk\nscore", "Fix\nguidance"]
    cols = ["#dbeafe", "#fef3c7", "#fef3c7", "#ede9fe", "#ede9fe", "#d1fae5", "#d1fae5", "#d1fae5"]
    fig, ax = plt.subplots(figsize=(9, 1.6))
    ax.set_xlim(0, len(steps) + 1.2); ax.set_ylim(0, 1); ax.axis("off")
    for i, (s, c) in enumerate(zip(steps, cols)):
        ax.add_patch(FancyBboxPatch((i + 0.08, 0.2), 0.8, 0.6, boxstyle="round,pad=0.02",
                                    linewidth=1, edgecolor="#374151", facecolor=c))
        ax.text(i + 0.48, 0.5, s, ha="center", va="center", fontsize=7)
        ax.annotate("", xy=(i + 1.08, 0.5), xytext=(i + 0.9, 0.5),
                    arrowprops=dict(arrowstyle="->", color="#374151", lw=1))
    ax.text(len(steps) + 0.15, 0.5, "Report", ha="left", va="center", fontsize=10, fontweight="bold")
    save(fig, "fig_pipeline.png")


# ------------------------------------------------------------------ results
def load(scan_id, name, gt):
    scan = storage.get_scan(scan_id)
    findings = storage.get_findings(scan_id)
    zap = evaluate(findings, gt, {"ZAP"})
    comb = evaluate(findings, gt, {"ZAP", "Custom"})
    raw = sum(len(json.loads(f["extra"] or "{}").get("urls", [f["url"]])) for f in findings)
    return {"name": name, "scan_id": scan_id, "duration_s": scan["duration_s"], "findings": len(findings),
            "raw_instances": raw,
            "severity": dict(Counter(f["severity"] for f in findings)),
            "owasp": dict(Counter((f["owasp"] or "Other").split(" ", 1)[0] for f in findings)),
            "engines": dict(Counter(("Both" if "+" in f["source"] else f["source"].split(":")[0]) for f in findings)),
            "zap_only": {k: zap[k] for k in ("TP", "FN", "FP*", "Precision", "Recall", "F1")},
            "combined": {k: comb[k] for k in ("TP", "FN", "FP*", "Precision", "Recall", "F1")},
            "per_vuln": [{"name": g["name"], "owasp": g["owasp"], "zap": zap["detected"][g["id"]],
                          "combined": comb["detected"][g["id"]]} for g in gt],
            "fp_titles": [f["title"] for f in comb["fp_list"]]}


def fig_accuracy(res):
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.4), sharey=True)
    for ax, r in zip(axes, res):
        metrics = ["Precision", "Recall", "F1"]
        z = [r["zap_only"][m] for m in metrics]; c = [r["combined"][m] for m in metrics]
        xs = range(len(metrics))
        b1 = ax.bar([x - 0.18 for x in xs], z, 0.36, color="#93c5fd", label="ZAP only")
        b2 = ax.bar([x + 0.18 for x in xs], c, 0.36, color=BLUE, label="ZAP + custom checks")
        for b in list(b1) + list(b2):
            ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.02, f"{b.get_height():.2f}",
                    ha="center", fontsize=8)
        ax.set_xticks(list(xs)); ax.set_xticklabels(metrics); ax.set_ylim(0, 1.15)
        ax.set_title(f"{r['name']} ({len(r['per_vuln'])} known issues)", fontsize=10)
    axes[0].set_ylabel("Score"); axes[0].legend(frameon=False, fontsize=8, loc="upper left")
    fig.suptitle("Detection accuracy: ZAP alone vs ZAP + custom checks", fontsize=11, y=1.04)
    save(fig, "fig_accuracy.png")


def fig_severity(res):
    fig, ax = plt.subplots(figsize=(7, 2.6))
    for i, r in enumerate(res):
        left = 0
        for s in SEVERITY_ORDER:
            n = r["severity"].get(s, 0)
            if n:
                ax.barh(i, n, left=left, color=SEV_COL[s], label=s if i == 0 else None)
                ax.text(left + n / 2, i, str(n), ha="center", va="center", fontsize=8,
                        color="white" if s != "Info" else "black")
                left += n
    ax.set_yticks(range(len(res))); ax.set_yticklabels([r["name"] for r in res])
    ax.set_xlabel("Findings after merging"); ax.invert_yaxis()
    handles = [plt.Rectangle((0, 0), 1, 1, color=SEV_COL[s]) for s in SEVERITY_ORDER]
    ax.legend(handles, SEVERITY_ORDER, ncol=5, frameon=False, fontsize=8, loc="lower center",
              bbox_to_anchor=(0.5, 1.0))
    save(fig, "fig_severity.png")


def fig_owasp(res):
    cats = sorted({c for r in res for c in r["owasp"]})
    fig, ax = plt.subplots(figsize=(7, 3))
    ys = range(len(cats))
    for j, (r, col) in enumerate(zip(res, [BLUE, ORANGE])):
        ax.barh([y + (j - 0.5) * 0.38 for y in ys], [r["owasp"].get(c, 0) for c in cats], 0.38,
                color=col, label=r["name"])
    ax.set_yticks(list(ys)); ax.set_yticklabels(cats); ax.invert_yaxis()
    ax.set_xlabel("Findings"); ax.legend(frameon=False, fontsize=8)
    ax.set_title("Findings by OWASP Top 10 (2021) category", fontsize=10)
    save(fig, "fig_owasp.png")


def fig_dedup(res):
    fig, ax = plt.subplots(figsize=(6, 2.8))
    xs = range(len(res))
    raw = [r["raw_instances"] for r in res]; merged = [r["findings"] for r in res]
    b1 = ax.bar([x - 0.18 for x in xs], raw, 0.36, color="#fca5a5", label="Raw alert instances")
    b2 = ax.bar([x + 0.18 for x in xs], merged, 0.36, color=RED, label="Findings after merging")
    for b in list(b1) + list(b2):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 1, str(int(b.get_height())), ha="center", fontsize=8)
    ax.set_xticks(list(xs)); ax.set_xticklabels([r["name"] for r in res]); ax.set_ylabel("Count")
    ax.legend(frameon=False, fontsize=8); ax.set_title("Effect of cross-page and cross-engine merging", fontsize=10)
    save(fig, "fig_dedup.png")


VALIDATION = [  # manual validation against live responses (Section 6.4 of the report)
    {"site": "Google (Quick)", "before": {"correct": 6, "false_pos": 2, "missed": 1}, "after": {"correct": 8, "false_pos": 0, "missed": 0}},
    {"site": "Instagram (Quick)", "before": {"correct": 2, "false_pos": 3, "missed": 2}, "after": {"correct": 5, "false_pos": 0, "missed": 0}},
]


def fig_validation():
    fig, axes = plt.subplots(1, 2, figsize=(9, 3), sharey=True)
    for ax, v in zip(axes, VALIDATION):
        cats = ["correct", "false_pos", "missed"]; labels = ["Correct", "False positives", "Missed"]
        cols = [GREEN, RED, ORANGE]
        for k, (stage, alpha) in enumerate([("before", 0.45), ("after", 1.0)]):
            vals = [v[stage][c] for c in cats]
            bars = ax.bar([x + (k - 0.5) * 0.38 for x in range(3)], vals, 0.38, color=cols, alpha=alpha,
                          edgecolor="black", linewidth=0.4)
            for b in bars:
                ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.1, str(int(b.get_height())), ha="center", fontsize=8)
        ax.set_xticks(range(3)); ax.set_xticklabels(labels, fontsize=8); ax.set_title(v["site"], fontsize=10)
    axes[0].set_ylabel("Findings")
    axes[0].text(0.02, 0.95, "light = first report, dark = after fixes", transform=axes[0].transAxes, fontsize=7.5, color=GREY, va="top")
    fig.suptitle("Manual validation on real websites: before and after fixes", fontsize=11, y=1.04)
    save(fig, "fig_validation.png")


def fig_modes(res, quick_s, standard_s):
    labels = ["Quick", "Standard"] + [f"Full ({r['name']})" for r in res]
    vals = [quick_s, standard_s] + [r["duration_s"] for r in res]
    fig, ax = plt.subplots(figsize=(6.5, 2.6))
    bars = ax.barh(labels, vals, color=[GREEN, BLUE, ORANGE, ORANGE][:len(vals)])
    for b in bars:
        ax.text(b.get_width() * 1.15, b.get_y() + b.get_height() / 2, f"{b.get_width():.0f} s", va="center", fontsize=8)
    ax.set_xscale("log"); ax.set_xlim(1, max(vals) * 4); ax.invert_yaxis(); ax.set_xlabel("Scan time (seconds, log scale)"); ax.set_title("Scan time by mode", fontsize=10)
    save(fig, "fig_modes.png")


if __name__ == "__main__":
    fig_architecture(); fig_pipeline(); fig_validation()
    if len(sys.argv) >= 3:
        gt = json.load(open(GT_PATH))
        res = [load(int(sys.argv[1]), "DVWA", gt["DVWA"]), load(int(sys.argv[2]), "OWASP Juice Shop", gt["OWASP Juice Shop"])]
        quick = float(sys.argv[3]) if len(sys.argv) > 3 else 2.4
        standard = float(sys.argv[4]) if len(sys.argv) > 4 else 38.7
        fig_accuracy(res); fig_severity(res); fig_owasp(res); fig_dedup(res); fig_modes(res, quick, standard)
        json.dump({"results": res, "validation": VALIDATION}, open(os.path.join(os.path.dirname(__file__), "results.json"), "w"), indent=2)
    print("figures:", sorted(os.listdir(OUT)))
