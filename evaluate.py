"""Measures scanner accuracy against the known vulnerabilities of a lab target.

Usage:
    python evaluate.py <scan_id>            # target is detected from the scan
    python evaluate.py <scan_id> --csv out.csv

Prints, for "ZAP only" and for "ZAP + custom checks":
    TP (known issues detected), FN (known issues missed),
    FP candidates (non-Info findings not on the known list; confirm manually),
    Precision, Recall, F1.
"""
import argparse
import csv
import json
import os

from scanner import storage
from scanner.config import LAB_TARGETS

GT_PATH = os.path.join(os.path.dirname(__file__), "lab", "ground_truth.json")


def _matches(gt, finding):
    urls = json.loads(finding["extra"] or "{}").get("urls", [finding["url"]])
    title = finding["title"].lower()
    return any(gt["path"] in u for u in urls) and any(k in title for k in gt["keywords"])


def _engines(finding):
    found_by = json.loads(finding["extra"] or "{}").get("found_by", [finding["source"]])
    return {s.split(":")[0] for s in found_by}


def evaluate(findings, ground_truth, engines):
    subset = [f for f in findings if _engines(f) & engines]
    detected = {g["id"]: any(_matches(g, f) for f in subset) for g in ground_truth}
    tp = sum(detected.values())
    fn = len(ground_truth) - tp
    fp_list = [f for f in subset if f["severity"] != "Info"
               and not any(_matches(g, f) for g in ground_truth)]
    fp = len(fp_list)
    p = tp / (tp + fp) if tp + fp else 0
    r = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * p * r / (p + r) if p + r else 0
    return {"TP": tp, "FN": fn, "FP*": fp, "Precision": p, "Recall": r, "F1": f1,
            "detected": detected, "fp_list": fp_list}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scan_id", type=int)
    ap.add_argument("--csv")
    args = ap.parse_args()

    scan = storage.get_scan(args.scan_id)
    name = next(n for n, t in LAB_TARGETS.items() if scan["target"].startswith(t["url"]))
    gt = json.load(open(GT_PATH))[name]
    findings = storage.get_findings(args.scan_id)

    print(f"\nScan #{args.scan_id} - {name} - {scan['mode']} - {scan['duration_s']} s - {len(findings)} findings")
    print(f"Known vulnerabilities in ground truth: {len(gt)}\n")

    rows = []
    results = {"ZAP only": evaluate(findings, gt, {"ZAP"}),
               "ZAP + custom": evaluate(findings, gt, {"ZAP", "Custom"})}
    print(f"{'Configuration':<15}{'TP':>4}{'FN':>4}{'FP*':>5}{'Precision':>11}{'Recall':>8}{'F1':>7}")
    for label, m in results.items():
        print(f"{label:<15}{m['TP']:>4}{m['FN']:>4}{m['FP*']:>5}{m['Precision']:>11.2f}{m['Recall']:>8.2f}{m['F1']:>7.2f}")
        rows.append({"config": label, **{k: m[k] for k in ("TP", "FN", "FP*")},
                     **{k: round(m[k], 3) for k in ("Precision", "Recall", "F1")}})

    print("\nPer known vulnerability:")
    print(f"  {'Vulnerability':<38}{'ZAP only':>10}{'Combined':>10}")
    for g in gt:
        a = "yes" if results["ZAP only"]["detected"][g["id"]] else "-"
        b = "yes" if results["ZAP + custom"]["detected"][g["id"]] else "-"
        print(f"  {g['name']:<38}{a:>10}{b:>10}")

    fps = results["ZAP + custom"]["fp_list"]
    if fps:
        print("\nFP* = findings not on the known list. Check each by hand; some are real extra issues:")
        for f in fps:
            print(f"  [{f['severity']}] {f['title']} ({f['source']})")

    if args.csv:
        with open(args.csv, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=rows[0].keys())
            w.writeheader()
            w.writerows(rows)
        print("\nSaved", args.csv)


if __name__ == "__main__":
    main()
