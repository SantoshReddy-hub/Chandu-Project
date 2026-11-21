"""Remediation library: practical fix guidance keyed by CWE."""

REMEDIATION = {
    89: "Use parameterised queries / prepared statements for every database call; never build SQL by "
        "string concatenation. Use an ORM where possible, apply least-privilege DB accounts and validate input types.\n"
        "Example (Python): cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
    79: "Encode all untrusted output for its context (HTML, attribute, JS, URL). Use a templating engine with "
        "auto-escaping, add a strict Content-Security-Policy, and sanitise any HTML users can submit.",
    78: "Avoid passing user input to shell commands. Use language APIs instead of the shell, or pass arguments "
        "as a list with an allowlist of permitted values.",
    22: "Resolve the requested path and verify it stays inside the allowed base directory. Reject '..' and "
        "absolute paths; map user choices to fixed IDs instead of file names.",
    352: "Add anti-CSRF tokens to every state-changing form, set SameSite=Lax or Strict on session cookies, "
         "and require re-authentication for sensitive actions.",
    639: "Check on the server that the logged-in user owns or may access every object requested by ID. "
         "Deny by default and use indirect or random identifiers.",
    693: "Add the missing security header in the web server or framework config, e.g. "
         "Content-Security-Policy: default-src 'self'; X-Content-Type-Options: nosniff; "
         "Permissions-Policy: camera=(), microphone=(), geolocation=()",
    1021: "Send X-Frame-Options: DENY (or SAMEORIGIN) or CSP frame-ancestors 'none' to prevent clickjacking.",
    200: "Remove or restrict access to the resource. Set Referrer-Policy: strict-origin-when-cross-origin and "
         "make sure no secrets appear in URLs.",
    1004: "Set the HttpOnly flag on session and authentication cookies so JavaScript cannot read them.",
    1275: "Set SameSite=Lax (or Strict) on cookies to limit cross-site sending.",
    614: "Set the Secure flag so cookies are only sent over HTTPS.",
    319: "Serve the whole site over HTTPS with a valid certificate, redirect HTTP to HTTPS, and send "
         "Strict-Transport-Security: max-age=31536000; includeSubDomains",
    295: "Install a valid certificate from a trusted authority (e.g. free from Let's Encrypt), include the full "
         "certificate chain, and renew before expiry.",
    538:"Remove the file from the web root, block dot-files in the web server config, and rotate any "
         "secrets it contained.",
    530: "Delete backup files from the web root and keep backups in storage that is not publicly served.",
    548: "Disable directory listing (Apache: Options -Indexes; Nginx: autoindex off) and require "
         "authentication for file areas.",
    497: "Hide version details: Apache 'ServerTokens Prod' and 'ServerSignature Off', PHP 'expose_php = Off', "
         "remove X-Powered-By in the framework.",
    209: "Show generic error pages in production, log details on the server only, and turn off debug mode.",
    1104: "Upgrade the outdated component to a supported version and track dependencies with a tool such as "
          "OWASP Dependency-Check.",
    287: "Enforce strong authentication: rate-limit logins, use multi-factor authentication and secure "
         "password storage (bcrypt/argon2).",
}

GENERIC = ("Review the finding, confirm it manually, and apply the relevant OWASP Cheat Sheet "
           "(https://cheatsheetseries.owasp.org).")


def attach_remediation(findings):
    for f in findings:
        guide = REMEDIATION.get(f.cwe)
        if guide:
            # Keep ZAP's own advice as well when it exists.
            f.remediation = guide + (f"\n\nZAP advice: {f.remediation}" if f.remediation else "")
        elif not f.remediation:
            f.remediation = GENERIC
    return findings
