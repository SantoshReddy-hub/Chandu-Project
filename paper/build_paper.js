// Builds the research paper (.docx) in the same journal layout as the team's
// deepfake paper. Numbers come from paper/results.json (made by make_figures.py).
// Usage: node paper/build_paper.js
const fs = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, ImageRun, Table, TableRow, TableCell, AlignmentType,
  WidthType, ShadingType, BorderStyle, Header, Footer, PageNumber, LevelFormat, TabStopType,
} = require("docx");

const HERE = __dirname;
const R = JSON.parse(fs.readFileSync(path.join(HERE, "results.json"), "utf8"));
const [D, J] = R.results; // DVWA, Juice Shop
const FONT = "Cambria";
const W = 9638; // A4 text width in DXA with 2 cm margins
const f2 = (x) => x.toFixed(2);
const pct = (x) => `${(x * 100).toFixed(1)}%`;

// ---------------------------------------------------------------- helpers
const run = (t, o = {}) => new TextRun({ text: t, font: FONT, size: o.size || 20, bold: o.bold, italics: o.italics, color: o.color, smallCaps: o.smallCaps });
// Inline **bold** support in body text.
const rich = (t, o = {}) => t.split(/(\*\*[^*]+\*\*)/).filter(Boolean).map((s) =>
  s.startsWith("**") ? run(s.slice(2, -2), { ...o, bold: true }) : run(s, o));
const P = (t, o = {}) => new Paragraph({ children: rich(t, o), alignment: o.align || AlignmentType.JUSTIFIED, spacing: { after: 120, line: 264 } });
const H1 = (t) => new Paragraph({ children: [run(t, { size: 26, bold: true })], spacing: { before: 300, after: 140 }, keepNext: true,
  border: { top: { style: BorderStyle.SINGLE, size: 12, color: "A6A6A6", space: 10 } } });
const H2 = (t) => new Paragraph({ children: [run(t, { size: 21, bold: true })], spacing: { before: 180, after: 80 }, keepNext: true });
const H3i = (t) => new Paragraph({ children: [run(t, { italics: true, size: 21 })], spacing: { before: 140, after: 60 }, keepNext: true });
const bullet = (t) => new Paragraph({ children: rich(t), numbering: { reference: "bullets", level: 0 }, alignment: AlignmentType.JUSTIFIED, spacing: { after: 60, line: 264 } });
const eq = (t) => new Paragraph({ children: [run(t, { italics: true, size: 21 })], alignment: AlignmentType.CENTER, spacing: { before: 80, after: 120 } });

const border = { style: BorderStyle.SINGLE, size: 4, color: "000000" };
const cellBorders = { top: border, bottom: border, left: border, right: border };
function table(caption, header, rows, widths) {
  const total = widths.reduce((a, b) => a + b, 0);
  const cw = widths.map((w) => Math.round((w / total) * W));
  cw[cw.length - 1] += W - cw.reduce((a, b) => a + b, 0);
  const mk = (cells, head) => new TableRow({ tableHeader: head, children: cells.map((c, i) => new TableCell({
    borders: cellBorders, width: { size: cw[i], type: WidthType.DXA },
    shading: head ? { fill: "F2F2F2", type: ShadingType.CLEAR, color: "auto" } : undefined,
    margins: { top: 50, bottom: 50, left: 90, right: 90 },
    children: [new Paragraph({ children: [run(String(c), { size: 17, bold: head })] })] })) });
  return [
    new Paragraph({ children: [run(caption.split(" ").slice(0, 2).join(" ") + " ", { bold: true }), run(caption.split(" ").slice(2).join(" "))], spacing: { before: 160, after: 80 }, keepNext: true }),
    new Table({ width: { size: W, type: WidthType.DXA }, columnWidths: cw, rows: [mk(header, true), ...rows.map((r) => mk(r, false))] }),
    new Paragraph({ children: [], spacing: { after: 80 } }),
  ];
}

const imgSize = (file) => { // read PNG/JPEG pixel size
  const b = fs.readFileSync(file);
  if (b[0] === 0x89) return [b.readUInt32BE(16), b.readUInt32BE(20)];
  let i = 2; while (i < b.length) { const m = b[i + 1]; const len = b.readUInt16BE(i + 2);
    if (m >= 0xc0 && m <= 0xc3) return [b.readUInt16BE(i + 7), b.readUInt16BE(i + 5)]; i += 2 + len; }
  return [800, 600];
};
function figure(file, caption, widthPx = 600) {
  const full = path.join(HERE, "figures", file);
  const [w, h] = imgSize(full);
  const boxed = { style: BorderStyle.SINGLE, size: 8, color: "000000", space: 6 };
  return [
    new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 160, after: 80 }, keepNext: true,
      border: { top: boxed, bottom: boxed, left: boxed, right: boxed },
      children: [new ImageRun({ type: file.endsWith(".png") ? "png" : "jpg", data: fs.readFileSync(full),
        transformation: { width: widthPx, height: Math.round((widthPx * h) / w) } })] }),
    new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 160 },
      children: [run(caption.split(" ").slice(0, 2).join(" ") + " ", { bold: true }), run(caption.split(" ").slice(2).join(" "))] }),
  ];
}

// ---------------------------------------------------------------- numbers
const dz = D.zap_only, dc = D.combined, jz = J.zap_only, jc = J.combined;
const sev = (r, s) => r.severity[s] || 0;
const yes = (b) => (b ? "Yes" : "-");
const extraD = dc.TP - dz.TP, extraJ = jc.TP - jz.TP;
// Wording that stays true whatever the numbers are.
const change = (a, b) => (b > a ? `rose from ${f2(a)} to ${f2(b)}` : b < a ? `fell from ${f2(a)} to ${f2(b)}` : `was ${f2(b)} in both configurations`);
const both = extraD > 0 && extraJ > 0;

// ---------------------------------------------------------------- content
const body = [
  new Paragraph({ children: [run("(RESEARCH ARTICLE)", { smallCaps: true })], spacing: { after: 200 } }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 240 }, children: [run(
    "Automated Web-Application Vulnerability Scanning: Combining OWASP ZAP with Content-Verified Custom Checks, Risk Scoring and Ownership-Gated Active Testing", { size: 32 })] }),
  P("Santosh Reddy, [Team member names]", { align: AlignmentType.LEFT }),
  P("[Department of Computer Science and Engineering (Cybersecurity & Blockchain Technology), Institution name, City, India.]", { italics: true, align: AlignmentType.LEFT }),
  P("[Journal name, Year, Volume(Issue), pages]", { align: AlignmentType.LEFT }),
  P("Publication history: [Received on __; revised on __; accepted on __]", { align: AlignmentType.LEFT }),
  P("Article DOI: [to be assigned]", { align: AlignmentType.LEFT }),

  H1("Abstract"),
  P("Web applications are exposed to the internet by design, and configuration mistakes and unvalidated input remain the most common causes of compromise. Free dynamic scanners such as OWASP ZAP detect many of these weaknesses, but they report one alert per page, mix ratings across rules, miss several configuration issues and place no limit on who may be attack-tested. In this paper we present an automated web-application vulnerability scanner that drives OWASP ZAP through its API and adds five content-verified custom checks for security headers, cookie flags, exposed files, information disclosure and transport security. Findings from both engines are merged across pages and engines, rated as likelihood × impact into five severity levels and matched to remediation guidance by CWE. Read-only scans are allowed on any URL, while active attack testing runs only after the user proves domain ownership with a published token."),
  P(`We evaluated the scanner in an isolated Docker lab against two deliberately vulnerable applications with known ground truth. On OWASP Juice Shop (${J.per_vuln.length} known issues) recall ${change(jz.Recall, jc.Recall)} when the custom checks were added to ZAP (F1 ${change(jz.F1, jc.F1).replace(/^(rose|fell|was) (from )?/, '')}); on DVWA (${D.per_vuln.length} known issues) recall ${change(dz.Recall, dc.Recall)}. Merging reduced ${D.raw_instances} raw DVWA alert instances to ${D.findings} findings. Manual validation of reports against the live responses of google.com and instagram.com exposed eleven accuracy defects, including catch-all routes mistaken for exposed files and cookies hidden by a shared session; after correction every reported finding on both sites matched the live response.`),
  new Paragraph({ children: [run("Keywords: ", { bold: true }), run("Web Application Security; Vulnerability Scanning; DAST; OWASP ZAP; OWASP Top 10; Risk Scoring; False Positives")], spacing: { after: 200 } }),

  H1("1. Introduction"),
  H2("1.1. Context and Motivation"),
  P("Almost every public service is now delivered as a web application, from banking to university portals. Each one is reachable by anyone on the internet, so a single mistake, such as an unescaped input field, a missing security header or a forgotten backup file, can expose user data. The OWASP Top 10 [1] ranks the most critical of these risks and is the reference most organisations use to prioritise web security work."),
  P("Manual penetration testing finds such weaknesses reliably but needs specialists, takes days per application and is rarely repeated after every change. Automated dynamic application security testing (DAST) tools test the running application from outside, as an attacker would, and can be repeated at no cost. Their weaknesses are equally well documented: limited crawling, noisy reports and false positives [13], [14], [16]."),
  H2("1.2. Problem Statement"),
  P("OWASP ZAP [2] is the most widely used free DAST engine, but in its raw form it is difficult for a non-specialist to act on. It reports the same issue once per page, so one baseline scan of DVWA produced 126 raw alerts for about 30 distinct issues. It covers several configuration weaknesses only partially, its ratings cannot be compared with those of other tools, and it will actively attack any address it is given. A student or small team therefore needs a scanner that keeps ZAP's detection power while producing a short, consistently rated, actionable report, and that cannot be misused against sites the user does not own."),
  H2("1.3. Research Contributions"),
  P("This research makes the following contributions:"),
  bullet("A complete, reproducible scanner from URL input to PDF report, combining automated OWASP ZAP scanning with five custom checks, in a dashboard that accepts any URL."),
  bullet("Content verification for every custom finding (file signatures, first-visit cookie collection, report-only CSP handling) to keep false positives low on real sites."),
  bullet("A cross-engine merging and likelihood × impact scoring model that keeps one engine's rating instead of mixing ratings."),
  bullet("Ownership-gated active testing with HMAC domain tokens, so attack tests run only on sites the user controls."),
  bullet("A quantitative evaluation against known vulnerabilities in DVWA and OWASP Juice Shop, comparing ZAP alone with ZAP plus the custom checks, and a manual validation on two high-traffic websites that documents eleven defects found and fixed."),

  H1("2. Related Work"),
  P("Black-box web scanners have been evaluated repeatedly. Fonseca et al. injected realistic vulnerabilities into web applications and found that commercial scanners missed many SQL injection and XSS flaws while reporting a high number of false positives [16]. Bau et al. evaluated eight leading scanners and found good detection of simple reflected XSS but weak detection of stored XSS and second-order SQL injection [14]. Doupé et al. built a purpose-made vulnerable application and showed that crawling, rather than attack payloads, is the main limitation of black-box scanners: flaws on pages the crawler never reaches are never tested [13]. Khoury et al. reached a similar conclusion for stored SQL injection [15]."),
  P("Later work used standard benchmarks. Mburano and Si compared OWASP ZAP and Arachni on the OWASP Benchmark project and reported that each tool led on different vulnerability classes, which supports combining engines rather than trusting one [17]. On the configuration side, Weichselbaum et al. analysed Content Security Policies deployed on the web and found that most could be bypassed, mainly because of permissive source lists and 'unsafe-inline'; they proposed nonce-based policies with 'strict-dynamic' [12]. Online header checkers such as Mozilla Observatory grade any URL quickly but stop at response headers. None of these works combines engine output with a single risk model, remediation guidance and a safeguard against testing sites the user does not own."),

  H1("3. Literature Review"),
  H2("3.1. Manual Testing and Penetration Testing"),
  P("A manual penetration test follows a methodology such as the OWASP Testing Guide and relies on the tester's judgement. It finds business-logic flaws that no scanner can, but its cost and duration mean it is usually performed once before release rather than after every change."),
  H2("3.2. Automated DAST Scanners"),
  P("DAST scanners crawl an application, then run passive rules that inspect responses and active rules that send crafted inputs. Passive scanning is harmless; active scanning can change data and is legal only with the owner's permission. Coverage depends first on the crawler [13], and accuracy on how carefully each rule confirms what it reports [16]."),
  H2("3.3. Configuration and Header Checkers"),
  P("A large share of the OWASP Top 10, especially A05 Security Misconfiguration and A02 Cryptographic Failures, can be detected from response headers, cookies and reachable files without any attack. Header checkers do this quickly, but they do not verify findings against page content, and therefore misreport sites that answer every path with an ordinary page."),
  H2("3.4. Risk Rating"),
  P("CVSS [4] rates individual vulnerabilities on many base metrics, while the OWASP Risk Rating Methodology [5] multiplies likelihood by impact. For a scanner that merges findings from different engines, a simple and transparent likelihood × impact model makes ratings comparable across engines and explainable to non-specialists."),

  H1("4. System Architecture"),
  H2("4.1. Architectural Overview"),
  P("The system follows a five-layer design (Figure 1). A user enters a URL in the Streamlit dashboard or the command line. The orchestrator validates the address, enforces the ownership rule for active scans, queues work for the single ZAP engine and reports progress. Two engines scan the target: OWASP ZAP 2.17 running in Docker, and the custom checks written in Python. A processing pipeline merges, scores and annotates the findings, which are stored in SQLite and presented as dashboard charts and a PDF report."),
  ...figure("fig_architecture.png", "Figure 1 System architecture diagram", 430),
  H2("4.2. Scan Modes"),
  ...table("Table 1 Scan modes and the rule that governs each", ["Mode", "Engines", "Typical time", "Allowed on"], [
    ["Quick", "Custom checks only", "about 3–10 s", "Any URL"],
    ["Standard", "ZAP spider + passive scan, custom checks", "about 40–100 s", "Any URL"],
    ["Full", "Standard + ZAP active scan", "up to about 15 min", "Verified domains and the local lab only"],
  ], [1.2, 3, 1.6, 2.6]),
  H2("4.3. Risk Scoring Model"),
  P("Every finding receives a likelihood L and an impact I, each from 1 to 3. ZAP's own risk levels are mapped to (L, I) pairs; custom checks set them per issue, for example impact 3 for a session cookie and 1 for a preference cookie. Findings with low confidence lose one point:"),
  eq("Risk = L × I − c,   c = 1 if confidence is low, otherwise 0"),
  P("A score of 9 is Critical, 6–8 High, 3–4 Medium, 2 Low and 0–1 Info. When both engines report the same issue, the merged finding keeps the (L, I) pair of whichever engine scored it higher. Taking the larger likelihood from one engine and the larger impact from the other would invent ratings neither engine gave."),
  H2("4.4. Ownership-Gated Active Testing"),
  P("Active scanning without permission is an offence under Sections 43 and 66 of India's Information Technology Act, 2000 [11]. For a Full scan the scanner computes a token as HMAC-SHA256 of the domain name under a server secret, and the owner publishes it at /.well-known/vulnscanner-verify.txt. The Start button remains disabled until the token is found. Read-only modes need no token, and the local lab counts as owned."),
  ...figure("fig_pipeline.png", "Figure 2 Scan pipeline flowchart", 600),

  H1("5. Implementation Methodology"),
  P("The scanner is about 1,600 lines of Python in 21 files plus a Docker Compose lab. It works in four stages: input handling, scanning, processing and reporting."),
  H2("5.1. Input Handling"),
  P("A pasted address is trimmed, given a scheme when missing (https for public hosts, http for localhost) and rejected when it has no valid host or uses a scheme other than http or https. A reachability check runs before any long scan, so an unreachable site fails within seconds with a clear message."),
  H2("5.2. ZAP Automation"),
  P("For each scan the ZAP client opens a fresh session, applies exclusions, crawls with the spider (depth 5, 2–5 minutes) and, for single-page applications, with the AJAX spider in one headless Firefox. It then waits for the passive scanner and, in Full mode, runs the active scan with a 2-minute limit per rule and 15 minutes overall. On a time limit or a user cancel it stops ZAP's own scan, so no work keeps running inside the engine. DVWA pages sit behind a login, so the scanner logs in and injects the session cookie into every ZAP request; Juice Shop's API routes are invisible to a link crawler, so known routes are seeded."),
  H2("5.3. Content-Verified Custom Checks"),
  ...table("Table 2 Custom checks and how each avoids false positives", ["Check", "Detects", "Verification"], [
    ["Security headers", "Missing CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy; weak CSP", "Report-only CSP rated separately; 'unsafe-inline' ignored when a nonce, hash or 'strict-dynamic' is present"],
    ["Cookie flags", "Missing HttpOnly, Secure, SameSite", "Fresh first-visit session; attributes parsed one by one; deleted cookies skipped; CSRF-token cookies exempt from HttpOnly"],
    ["Exposed files", ".git, .env, phpinfo, config backups, archives, open directories, server-status, robots.txt", "Content must prove the type: ZIP signature, Git reference, PHP info table, directory listing; catch-all pages compared by title"],
    ["Information disclosure", "Version numbers in headers; stack traces", "Version pattern required"],
    ["Transport security", "Plain HTTP, login form over HTTP, invalid certificate, missing HSTS", "Final URL after redirects"],
  ], [1.4, 3.2, 4]),
  H2("5.4. Merging and Remediation"),
  P("Findings are grouped by CWE and parameter. Aliases merge ZAP's and the custom checks' wording of the same issue; cookie findings are grouped per cookie; alerts whose parameter is a URL, such as one per external script, are grouped into one finding listing every item. Each merged finding keeps all affected URLs and all engines that found it, and receives fix guidance from a library keyed by CWE."),
  H2("5.5. Technical Stack"),
  ...table("Table 3 Technology stack", ["Layer", "Technology (version)", "Role"], [
    ["Language", "Python 3.11", "All scanner code"],
    ["Scanning engine", "OWASP ZAP 2.17 (zaproxy/zap-stable, Docker; 2 GB Java heap)", "Spider, AJAX spider, passive and active rules"],
    ["Engine client", "python-owasp-zap-v2.4 0.0.21", "ZAP API from Python"],
    ["HTTP", "requests", "Custom checks, logins, ownership checks"],
    ["Interface", "Streamlit, Plotly, pandas", "Dashboard and charts"],
    ["Storage and reports", "SQLite, fpdf2", "Scan history, PDF reports"],
    ["Lab", "Docker Compose: DVWA, OWASP Juice Shop", "Vulnerable targets bound to 127.0.0.1"],
  ], [1.5, 3.6, 3.2]),
  ...figure("fig_ui_newscan.jpg", "Figure 3 Web application interface (New scan page with demo targets)", 560),

  H1("6. Experimental Result"),
  H2("6.1. Ground Truth"),
  P(`DVWA [8] and OWASP Juice Shop [7] contain documented vulnerabilities. We listed ${D.per_vuln.length} known issues for DVWA and ${J.per_vuln.length} for Juice Shop (Table 5). A finding counts as a detection when its affected URL contains the issue's path and its title contains one of the issue's keywords.`),
  H2("6.2. Performance Measurement"),
  P("With a known issue as the positive class, TP is a known issue the scanner found and FN a known issue it missed. FP* counts non-Info findings that are not on the known list; because a scanner can find real issues the list omits, each FP* was also reviewed by hand."),
  eq("Precision = TP / (TP + FP),   Recall = TP / (TP + FN),   F1 = 2·P·R / (P + R)"),
  H2("6.3. Evaluation Environment"),
  P("All scans ran on an Apple Mac (arm64, 7.7 GB available to Docker) with OWASP ZAP 2.17.0. Both applications were scanned in Full mode, so the ZAP active scan, the passive scan and all custom checks contributed. Every reported number was recomputed from the stored findings by the evaluation script."),
  H2("6.4. Quantitative Analysis"),
  ...table("Table 4 Detection accuracy against known vulnerabilities (Full scans)", ["Application", "Configuration", "TP", "FN", "FP*", "Precision", "Recall", "F1"], [
    ["DVWA", "ZAP only", dz.TP, dz.FN, dz["FP*"], f2(dz.Precision), f2(dz.Recall), f2(dz.F1)],
    ["DVWA", "ZAP + custom", dc.TP, dc.FN, dc["FP*"], f2(dc.Precision), f2(dc.Recall), f2(dc.F1)],
    ["OWASP Juice Shop", "ZAP only", jz.TP, jz.FN, jz["FP*"], f2(jz.Precision), f2(jz.Recall), f2(jz.F1)],
    ["OWASP Juice Shop", "ZAP + custom", jc.TP, jc.FN, jc["FP*"], f2(jc.Precision), f2(jc.Recall), f2(jc.F1)],
  ], [2, 1.8, 0.7, 0.7, 0.7, 1.1, 1, 0.8]),
  P(`Adding the custom checks detected ${extraJ} more known issue${extraJ === 1 ? "" : "s"} on Juice Shop and ${extraD} more on DVWA. Recall ${change(jz.Recall, jc.Recall)} on Juice Shop and ${change(dz.Recall, dc.Recall)} on DVWA (Figure 4).`),
  ...figure("fig_accuracy.png", "Figure 4 Detection accuracy of ZAP alone and ZAP with the custom checks", 600),
  ...table("Table 5 Detection of each known vulnerability", ["Application", "Known vulnerability", "OWASP", "ZAP only", "ZAP + custom"],
    [...D.per_vuln.map((v) => ["DVWA", v.name, v.owasp, yes(v.zap), yes(v.combined)]),
     ...J.per_vuln.map((v) => ["Juice Shop", v.name, v.owasp, yes(v.zap), yes(v.combined)])],
    [1.3, 3.6, 0.9, 1, 1.2]),
  P(`Manual review of the FP* findings showed that ${D.fp_titles.filter((t) => t.includes("Cross Site Scripting")).length} of the ${dz["FP*"]} DVWA FP* items are reflected XSS on DVWA pages outside the listed XSS modules (for example its SQL injection and brute-force pages): real vulnerabilities that the ground-truth list does not name. Measured precision is therefore a lower bound.`),
  H2("6.5. Severity and Category Distribution"),
  P(`After merging, the DVWA scan reported ${D.findings} findings (${sev(D, "Critical")} Critical, ${sev(D, "High")} High, ${sev(D, "Medium")} Medium, ${sev(D, "Low")} Low, ${sev(D, "Info")} Info) and the Juice Shop scan ${J.findings} findings (${sev(J, "Critical")} Critical, ${sev(J, "High")} High, ${sev(J, "Medium")} Medium, ${sev(J, "Low")} Low, ${sev(J, "Info")} Info). Figures 5 and 6 show the distribution by severity and by OWASP category. Injection (A03) leads on DVWA and Security Misconfiguration (A05) on Juice Shop.`),
  ...figure("fig_severity.png", "Figure 5 Findings by severity after merging", 560),
  ...figure("fig_owasp.png", "Figure 6 Findings by OWASP Top 10 (2021) category", 560),
  H2("6.6. Effect of Merging"),
  P(`ZAP reports each issue once per affected page. Merging across pages and engines reduced ${D.raw_instances} raw alert instances to ${D.findings} findings on DVWA (${pct(1 - D.findings / D.raw_instances)} fewer items to read) and ${J.raw_instances} to ${J.findings} on Juice Shop (Figure 7). No information is lost: each finding lists every affected URL.`),
  ...figure("fig_dedup.png", "Figure 7 Raw alert instances and findings after merging", 480),
  H2("6.7. Scan Time"),
  P(`A Quick scan finished in a few seconds, a Standard scan of example.com in about 39 s, and the Full scans took ${Math.round(D.duration_s)} s on DVWA and ${Math.round(J.duration_s)} s on Juice Shop, bounded by the per-rule and overall limits (Figure 8).`),
  ...figure("fig_modes.png", "Figure 8 Scan time by mode", 500),

  H1("7. Discussion and comparative study"),
  H2("7.1. Contribution of the Custom Checks"),
  P("Where they add detections, the custom checks do so mainly in A05 Security Misconfiguration and A02 Cryptographic Failures: exposed phpinfo pages and directories, logins over plain HTTP, and missing Permissions-Policy and Referrer-Policy headers. ZAP's passive rules either do not test these or test them on only some responses. The injection classes (SQL injection, XSS, command injection) remain ZAP's domain, which is why both engines are needed."),
  H2("7.2. Manual Validation on Real Websites"),
  P("Lab applications have known flaws but unrealistic responses. We therefore ran Quick scans on google.com and instagram.com and compared each finding with the live HTTP response (Table 6, Figure 9). Read-only modes only were used on these sites."),
  ...table("Table 6 Manual validation of Quick-mode reports against live responses", ["Site", "Report", "Correct", "False positives", "Missed"], [
    ["google.com", "First", 6, 2, 1], ["google.com", "After fixes", 8, 0, 0],
    ["instagram.com", "First", 2, 3, 2], ["instagram.com", "After fixes", 5, 0, 0],
  ], [2, 1.6, 1, 1.4, 1]),
  ...figure("fig_validation.png", "Figure 9 Manual validation on real websites before and after fixes", 600),
  H2("7.3. Defects Found by Validation"),
  ...table("Table 7 Accuracy defects found by manual validation and their fixes", ["No.", "Defect", "Effect", "Fix"], [
    [1, "Deleted (expired, empty) cookies checked", "False positives", "Skip deletion cookies"],
    [2, "Report-only CSP treated as missing", "Over-rated (High)", "Separate Medium finding"],
    [3, "Different cookies merged into one", "Missed findings", "Group per cookie"],
    [4, "'__Secure-' cookie name read as the Secure flag", "Missed findings", "Parse attributes individually"],
    [5, "'unsafe-inline' with a nonce flagged as weak", "False positive", "Respect nonce, hash, 'strict-dynamic'"],
    [6, "Catch-all routes taken as exposed files", "False positives", "Verify file content"],
    [7, "Shared session hid cookies", "Missed findings", "First-visit session"],
    [8, "CSRF-token cookies flagged for HttpOnly", "False positive", "Exempt by design"],
    [9, "ZAP PII rule flagging internal IDs", "False Critical", "Cap at Medium, mark for review"],
    [10, "Ratings mixed when merging engines", "Over-rated", "Keep one engine's pair"],
    [11, "One finding per external script", "Noise", "Group into one finding"],
  ], [0.5, 3.4, 1.6, 2.6]),
  P("The most instructive case is Instagram, where every path is a potential username: /backup.zip is the profile page of an account called \"backup.zip\". A check that trusts the HTTP 200 status reports a leaked archive; a check that demands a ZIP signature does not. Similarly, a cookie check that shares a session with earlier checks sees no cookies at all, because the server sends a cookie only once. These defects are invisible in lab applications, which supports validating scanners on real sites as well as benchmarks."),
  H2("7.4. Comparison with Existing Tools"),
  ...table("Table 8 Qualitative comparison with existing tools", ["Capability", "ZAP alone", "Header checkers", "Commercial DAST", "This work"], [
    ["Crawling and injection testing", "Yes", "No", "Yes", "Yes (ZAP)"],
    ["Content-verified configuration checks", "Partial", "Headers only", "Yes", "Yes"],
    ["Merging across pages and engines", "No", "-", "Yes", "Yes"],
    ["Single risk model with remediation", "Per rule", "Grade only", "Yes", "Yes"],
    ["Ownership check before active tests", "No", "-", "Yes", "Yes"],
    ["Cost", "Free", "Free", "Paid", "Free"],
  ], [3, 1.3, 1.5, 1.5, 1.3]),
  H2("7.5. Engineering Challenges"),
  bullet("**Shared engine.** Two scans on one ZAP instance reset each other's session; a file lock now queues scans and each can be cancelled."),
  bullet("**Memory.** The active scan was killed by Docker twice for exceeding memory: once in the time-based SQL injection rules, once in the browser-based DOM XSS rule. A 2 GB Java heap, a 2-minute per-rule limit and disabling the DOM XSS rule fixed it."),
  bullet("**Crawling.** DVWA needed an authenticated crawl, and ZAP's crawler once submitted DVWA's change-password form and locked itself out; Juice Shop needed the AJAX spider and seeded API routes."),
  H2("7.6. Advantages of the Proposed Methodology"),
  P(`The approach has three practical advantages. First, it keeps ZAP's injection testing while adding verified configuration checks, which raised recall ${both ? 'on both applications' : "where ZAP's passive rules left gaps"}. Second, merging and a single scoring model turn hundreds of alerts into a short report a non-specialist can act on. Third, the ownership gate makes the tool safe to offer for any URL, because attack tests are limited to sites the user controls.`),
  H3i("Limitations"),
  P("The ground truth lists only documented vulnerabilities, so FP* may include real issues and recall depends on the list's scope. Each application was scanned once; scan-to-scan variation was not measured. The DOM XSS rule was disabled for memory reasons, so DOM-based XSS is not tested. Business-logic flaws and multi-role access control remain out of reach of black-box scanning. Real-world validation covered two sites in read-only modes."),
  H3i("Future Scope"),
  P("Planned extensions are authenticated scanning with user-supplied credentials, multi-role access-control tests, a larger benchmark such as the OWASP Benchmark project, and running scans in CI/CD pipelines. Given the team's specialization, report hashes could also be anchored on a blockchain to give tamper-evident audit trails of each assessment."),

  H1("8. Conclusion"),
  P(`This research developed an automated web-application vulnerability scanner that combines OWASP ZAP with five content-verified custom checks, a cross-engine merging and scoring model, remediation guidance and ownership-gated active testing. On known vulnerabilities, recall ${change(jz.Recall, jc.Recall)} on OWASP Juice Shop and ${change(dz.Recall, dc.Recall)} on DVWA when the custom checks were added, and merging cut raw DVWA alerts by ${pct(1 - D.findings / D.raw_instances)}.`),
  P("Manual validation on google.com and instagram.com showed that lab benchmarks alone hide important defects: catch-all routes, cookie sessions and report-only policies all produced errors that DVWA and Juice Shop never would. After eleven fixes, every finding on both sites matched the live response. Future scanners should be evaluated both on benchmarks with known flaws and on real sites against their live behaviour."),

  H1("Compliance with ethical standards"),
  H3i("Acknowledgement"),
  P("The authors thank their mentor, Dr. Ganta Jacob Victor, Department of Experiential Learning & Global Engagement, for guidance throughout this project."),
  H3i("Disclosure of conflict of interest"),
  P("No conflict of interest to be disclosed."),
  H3i("Statement of ethical testing"),
  P("Active scans were run only against deliberately vulnerable applications in an isolated local lab. Public websites were examined only with read-only requests equivalent to an ordinary visit."),

  H1("References"),
  ...[
    "OWASP Foundation, \"OWASP Top 10:2021,\" 2021. [Online]. Available: https://owasp.org/Top10/",
    "OWASP ZAP Project, \"Zed Attack Proxy Documentation.\" [Online]. Available: https://www.zaproxy.org/docs/",
    "MITRE Corporation, \"Common Weakness Enumeration (CWE).\" [Online]. Available: https://cwe.mitre.org/",
    "FIRST, \"Common Vulnerability Scoring System v3.1: Specification Document,\" 2019.",
    "OWASP Foundation, \"OWASP Risk Rating Methodology.\" [Online]. Available: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology",
    "OWASP Foundation, \"OWASP Cheat Sheet Series.\" [Online]. Available: https://cheatsheetseries.owasp.org/",
    "B. Kimminich, \"OWASP Juice Shop.\" [Online]. Available: https://owasp.org/www-project-juice-shop/",
    "DVWA Project, \"Damn Vulnerable Web Application.\" [Online]. Available: https://github.com/digininja/DVWA",
    "A. Barth, \"HTTP State Management Mechanism,\" RFC 6265, IETF, 2011.",
    "J. Hodges, C. Jackson, and A. Barth, \"HTTP Strict Transport Security (HSTS),\" RFC 6797, IETF, 2012.",
    "Government of India, \"The Information Technology Act, 2000,\" Sections 43 and 66.",
    "L. Weichselbaum, M. Spagnuolo, S. Lekies, and A. Janc, \"CSP Is Dead, Long Live CSP! On the Insecurity of Whitelists and the Future of Content Security Policy,\" in Proc. ACM Conf. on Computer and Communications Security (CCS), 2016.",
    "A. Doupé, M. Cova, and G. Vigna, \"Why Johnny Can't Pentest: An Analysis of Black-Box Web Vulnerability Scanners,\" in Proc. Detection of Intrusions and Malware, and Vulnerability Assessment (DIMVA), 2010.",
    "J. Bau, E. Bursztein, D. Gupta, and J. Mitchell, \"State of the Art: Automated Black-Box Web Application Vulnerability Testing,\" in Proc. IEEE Symp. on Security and Privacy, 2010.",
    "N. Khoury, P. Zavarsky, D. Lindskog, and R. Ruhl, \"An Analysis of Black-Box Web Application Security Scanners against Stored SQL Injection,\" in Proc. IEEE Int. Conf. on Privacy, Security, Risk and Trust (PASSAT), 2011.",
    "J. Fonseca, M. Vieira, and H. Madeira, \"Testing and Comparing Web Vulnerability Scanning Tools for SQL Injection and XSS Attacks,\" in Proc. IEEE Pacific Rim Int. Symp. on Dependable Computing (PRDC), 2007.",
    "B. Mburano and W. Si, \"Evaluation of Web Vulnerability Scanners Based on OWASP Benchmark,\" in Proc. Int. Conf. on Systems Engineering (ICSEng), 2018.",
  ].map((r, i) => new Paragraph({ children: [run(`[${i + 1}]`), run(`\t${r}`)], spacing: { after: 80 },
    tabStops: [{ type: TabStopType.LEFT, position: 600 }], indent: { left: 600, hanging: 600 }, alignment: AlignmentType.JUSTIFIED })),
  P("Corresponding author: Santosh Reddy", { size: 17, align: AlignmentType.LEFT }),
];

const doc = new Document({
  creator: "Santosh Reddy",
  title: "Automated Web-Application Vulnerability Scanning",
  styles: { default: { document: { run: { font: FONT, size: 20 } } } },
  numbering: { config: [{ reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT,
    style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] }] },
  sections: [{
    properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1134, bottom: 1134, left: 1134, right: 1134 } } },
    headers: { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [run("Automated Web-Application Vulnerability Scanning, 2026", { size: 18 })] })] }) },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 18 })] })] }) },
    children: body,
  }],
});

Packer.toBuffer(doc).then((buf) => {
  const out = path.join(HERE, "Vulnerability_Scanner_Research_Paper.docx");
  fs.writeFileSync(out, buf);
  console.log("wrote", out);
});
