"""PDF report generation with fpdf2."""
import json
import os
from collections import Counter

from fpdf import FPDF

from . import storage
from .config import REPORT_DIR
from .scoring import SEVERITY_ORDER

SEV_COLORS = {"Critical": (127, 29, 29), "High": (220, 38, 38), "Medium": (234, 138, 0),
              "Low": (37, 99, 235), "Info": (100, 116, 139)}


def _t(s):
    """Core PDF fonts are Latin-1 only."""
    return (s or "").encode("latin-1", "replace").decode("latin-1")


class Report(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(100)
        self.cell(0, 8, "Automated Web-Application Vulnerability Scanner - Y23-HTE-PROJECT-150", align="R")
        self.ln(10)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(130)
        self.cell(0, 8, f"Page {self.page_no()} - Authorized lab testing only", align="C")


def build_pdf(scan_id):
    scan = storage.get_scan(scan_id)
    findings = storage.get_findings(scan_id)
    os.makedirs(REPORT_DIR, exist_ok=True)
    path = os.path.abspath(os.path.join(REPORT_DIR, f"scan_{scan_id}.pdf"))

    pdf = Report()
    pdf.set_auto_page_break(True, 15)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(20)
    pdf.cell(0, 10, "Vulnerability Assessment Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    for label, val in [("Target", scan["target"]), ("Scan ID", scan_id), ("Mode", scan["mode"]),
                       ("Started", scan["started_at"]), ("Duration", f"{scan['duration_s']} s"),
                       ("Total findings", len(findings))]:
        pdf.cell(35, 6, f"{label}:")
        pdf.cell(0, 6, _t(str(val)), new_x="LMARGIN", new_y="NEXT")

    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, "Executive summary", new_x="LMARGIN", new_y="NEXT")
    counts = Counter(f["severity"] for f in findings)
    pdf.set_font("Helvetica", "B", 10)
    for sev in SEVERITY_ORDER:
        pdf.set_fill_color(*SEV_COLORS[sev])
        pdf.set_text_color(255)
        pdf.cell(36, 10, f"{sev}: {counts.get(sev, 0)}", fill=True, align="C")
        pdf.cell(2, 10, "")
    pdf.ln(14)

    pdf.set_text_color(20)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, "Findings", new_x="LMARGIN", new_y="NEXT")
    for i, f in enumerate(findings, 1):
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(*SEV_COLORS.get(f["severity"], (0, 0, 0)))
        pdf.multi_cell(0, 6, _t(f"{i}. [{f['severity']}] {f['title']}"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(40)
        pdf.set_font("Helvetica", "", 9)
        meta = f"{f['owasp']} | CWE-{f['cwe']} | Risk {f['risk_score']}/9 | Confidence {f['confidence']} | {f['source']}"
        pdf.multi_cell(0, 5, _t(meta), new_x="LMARGIN", new_y="NEXT")
        urls = json.loads(f["extra"] or "{}").get("urls", [f["url"]])
        more = f"  (+{len(urls) - 1} more URLs)" if len(urls) > 1 else ""
        pdf.multi_cell(0, 5, _t(f"URL: {f['url']}{more}" + (f"  Param: {f['param']}" if f['param'] else "")),
                       new_x="LMARGIN", new_y="NEXT")
        if f["description"]:
            pdf.multi_cell(0, 5, _t("Issue: " + f["description"][:600]), new_x="LMARGIN", new_y="NEXT")
        if f["evidence"]:
            pdf.multi_cell(0, 5, _t("Evidence: " + f["evidence"][:300]), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "I", 9)
        pdf.multi_cell(0, 5, _t("Fix: " + f["remediation"][:900]), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

    pdf.output(path)
    return path
