"""
Pak-CyberPulse attack-pattern registry.

Every pattern the SIEM understands lives here as DATA, not code:
  - id / name / OWASP Top-10 (2021) mapping / PISF control mapping
  - kind: "signature" (regex match on the log line) or "behavioral" (stateful correlation)
  - severity, human description, analyst indicators
  - mitigation: ordered SOAR playbook steps the engine executes automatically
  - soar_action: block_ip | kill_session | quarantine | alert

Adding a new attack = appending one dict. The engine, UI table, test
vectors and docs all render from this single source of truth.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Signature-based patterns (matched against the event message / URL line)
# ---------------------------------------------------------------------------
SIGNATURE_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "SQLI",
        "name": "SQL Injection",
        "owasp": "A03:2021 Injection",
        "pisf": "PISF-04.1",
        "kind": "signature",
        "severity": "Critical",
        "signatures": [
            r"(?i)('\s*or\s+'?1'?\s*=\s*'?1|union\s+select|drop\s+table|insert\s+into|sleep\s*\(|xp_cmdshell|information_schema|select\s+.+\s+from\s+)",
        ],
        "description": "Attacker injects SQL into input fields or URL parameters to read, modify or destroy database content.",
        "indicators": ["' OR '1'='1", "UNION SELECT", "SLEEP(", "information_schema"],
        "mitigation": [
            "Block attacker source IP at the firewall (SOAR).",
            "Kill all active sessions originating from the IP (Zero-Trust).",
            "Flag input vector; recommend parameterized queries to app owner.",
            "Snapshot air-gapped DB backup; attach SHA-256 evidence to incident PDF.",
        ],
        "soar_action": "block_ip",
    },
    {
        "id": "XSS",
        "name": "Cross-Site Scripting",
        "owasp": "A03:2021 Injection",
        "pisf": "PISF-04.1",
        "kind": "signature",
        "severity": "High",
        "signatures": [
            r"(?i)(<script|javascript:|onerror\s*=|onload\s*=|<img\s+src=|document\.cookie|alert\s*\()",
        ],
        "description": "Attacker injects browser-executable script to hijack sessions or deface the portal.",
        "indicators": ["<script>", "javascript:", "onerror=", "document.cookie"],
        "mitigation": [
            "Block attacker source IP at the firewall (SOAR).",
            "Purge cached page containing the payload if served from cache.",
            "Recommend output encoding + Content-Security-Policy to app owner.",
        ],
        "soar_action": "block_ip",
    },
    {
        "id": "CMDI",
        "name": "OS Command Injection",
        "owasp": "A03:2021 Injection",
        "pisf": "PISF-04.1",
        "kind": "signature",
        "severity": "Critical",
        "signatures": [
            r"(?i)(;\s*(cat|ls|whoami|id|nc|wget|curl)\b|\|\s*(sh|bash)\b|\$\(|\bwget\s+http|;\s*rm\s+-rf)",
        ],
        "description": "Attacker chains OS commands after a legitimate input to execute shell on the host.",
        "indicators": ["; cat /etc/passwd", "| sh", "$(whoami)", "wget http"],
        "mitigation": [
            "Block attacker source IP immediately (SOAR).",
            "Isolate host: kill web-worker process tree serving the request.",
            "Trigger air-gapped backup; verify binary integrity of web root.",
        ],
        "soar_action": "block_ip",
    },
    {
        "id": "SSTI",
        "name": "Server-Side Template Injection",
        "owasp": "A03:2021 Injection",
        "pisf": "PISF-04.1",
        "kind": "signature",
        "severity": "Critical",
        "signatures": [
            r"(\{\{\s*7\s*\*\s*7\s*\}\}|\{\{.*__class__.*\}\}|\$\{.*\.class.*\}|<%=.*%>)",
        ],
        "description": "Attacker injects template syntax ({{7*7}}) to achieve remote code execution via the template engine.",
        "indicators": ["{{7*7}}", "{{''.__class__}}", "${...}"],
        "mitigation": [
            "Block attacker source IP (SOAR).",
            "Disable template rendering of user input; sandbox the engine.",
            "Review rendered pages for prior successful exploitation.",
        ],
        "soar_action": "block_ip",
    },
    {
        "id": "LOG4SHELL",
        "name": "Log4Shell / JNDI Injection",
        "owasp": "A06:2021 Vulnerable Components",
        "pisf": "PISF-04.1",
        "kind": "signature",
        "severity": "Critical",
        "signatures": [
            r"(?i)(\$\{\s*jndi\s*:|\$\{\s*lower\s*:j\}|\$\{\s*::-j\})",
        ],
        "description": "CVE-2021-44228 probe: JNDI lookup strings smuggled in headers/inputs to trigger remote class loading.",
        "indicators": ["${jndi:ldap://", "${jndi:dns://"],
        "mitigation": [
            "Block attacker source IP (SOAR).",
            "Egress-block LDAP/RMI/DNS to untrusted hosts at the firewall.",
            "Verify log4j >= 2.17.1 on all Java hosts; scan for prior exploitation in logs.",
        ],
        "soar_action": "block_ip",
    },
    {
        "id": "SSRF",
        "name": "Server-Side Request Forgery",
        "owasp": "A10:2021 SSRF",
        "pisf": "PISF-04.1",
        "kind": "signature",
        "severity": "High",
        "signatures": [
            r"(?i)(url\s*=\s*https?://(169\.254\.169\.254|127\.0\.0\.1|localhost|metadata\.google\.internal|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+))",
        ],
        "description": "Attacker makes the server fetch internal URLs — cloud metadata service or intranet hosts.",
        "indicators": ["url=http://169.254.169.254/", "url=http://localhost:"],
        "mitigation": [
            "Block attacker source IP (SOAR).",
            "Deny cloud-metadata IP 169.254.169.254 at egress firewall.",
            "Enforce allow-list on server-side fetch destinations.",
        ],
        "soar_action": "block_ip",
    },
    {
        "id": "LFI_TRAVERSAL",
        "name": "Path Traversal / Local File Inclusion",
        "owasp": "A01:2021 Broken Access Control",
        "pisf": "PISF-04.1",
        "kind": "signature",
        "severity": "High",
        "signatures": [
            r"(\.\./\.\.|%2e%2e|/etc/passwd|/etc/shadow|boot\.ini|win\.ini)",
        ],
        "description": "Attacker walks out of the web root with ../ sequences to read OS files.",
        "indicators": ["../../etc/passwd", "%2e%2e%2f"],
        "mitigation": [
            "Block attacker source IP (SOAR).",
            "Chroot / jail the web process; canonicalize all file paths.",
            "Audit file-access logs for successful reads before the block.",
        ],
        "soar_action": "block_ip",
    },
    {
        "id": "MISCONFIG_PROBE",
        "name": "Security Misconfiguration Probe",
        "owasp": "A05:2021 Misconfiguration",
        "pisf": "PISF-10.1",
        "kind": "signature",
        "severity": "Medium",
        "signatures": [
            r"(?i)(/\.git/|/\.env|/server-status|/server-info|/phpinfo|/actuator/env|/\.ds_store|/debug)",
        ],
        "description": "Reconnaissance for exposed config, VCS metadata, debug endpoints and status pages.",
        "indicators": ["/.git/HEAD", "/.env", "/server-status"],
        "mitigation": [
            "Rate-limit then block the scanning IP (SOAR).",
            "Remove/disable the exposed endpoint; rotate any leaked secrets.",
            "Add WAF rule for the probed path family.",
        ],
        "soar_action": "block_ip",
    },
    {
        "id": "DESERIAL",
        "name": "Insecure Deserialization",
        "owasp": "A08:2021 Integrity Failures",
        "pisf": "PISF-04.1",
        "kind": "signature",
        "severity": "Critical",
        "signatures": [
            r"(rO0AB|H4sIAAAAAAAA|KGRvYmplY3Q=|java\.io\.ObjectInputStream|__reduce__|pickle\.loads)",
        ],
        "description": "Serialized object payloads (Java serialization magic bytes, pickle) aimed at RCE on deserialization.",
        "indicators": ["rO0AB (Java ser magic)", "pickle __reduce__"],
        "mitigation": [
            "Block attacker source IP (SOAR).",
            "Reject serialized-object content types at the WAF.",
            "Migrate endpoints to JSON schema-validated DTOs.",
        ],
        "soar_action": "block_ip",
    },
    {
        "id": "SECRET_IN_URL",
        "name": "Cryptographic Failure — Secret in URL",
        "owasp": "A02:2021 Cryptographic Failures",
        "pisf": "PISF-06.1",
        "kind": "signature",
        "severity": "Medium",
        "signatures": [
            r"(?i)(\?(.*&)?(password|passwd|secret|api[_-]?key|token)\s*=[^&\s]{3,})",
        ],
        "description": "Credentials or API keys transmitted in the URL — logged by proxies, cached by browsers, visible in referers.",
        "indicators": ["?password=...", "&api_key=..."],
        "mitigation": [
            "Alert only (no IP block — usually the legitimate client at fault).",
            "Force credential rotation for the exposed secret.",
            "Move secrets to Authorization headers / POST bodies over TLS.",
        ],
        "soar_action": "alert",
    },
    {
        "id": "BAC_PROBE",
        "name": "Broken Access Control Probe",
        "owasp": "A01:2021 Broken Access Control",
        "pisf": "PISF-05.1",
        "kind": "signature",
        "severity": "High",
        "signatures": [
            r"(?i)(/admin|/config|/wp-admin|/phpmyadmin|/backup|/console|/actuator|/env|/debug|/swagger|/api/v1/admin|/internal|/api/user/\d+)",
        ],
        "description": "Forced browsing of admin/config endpoints or direct object references (/api/user/124) without authorization checks.",
        "indicators": ["/admin", "/api/user/124 (IDOR)", "/actuator/env"],
        "mitigation": [
            "Block attacker source IP (SOAR).",
            "Kill the probing session (Zero-Trust).",
            "Enforce server-side authorization on every object reference.",
        ],
        "soar_action": "block_ip",
    },
    {
        "id": "BUSINESS_LOGIC_ABUSE",
        "name": "Business-Logic Abuse (Insecure Design)",
        "owasp": "A04:2021 Insecure Design",
        "pisf": "PISF-04.1",
        "kind": "signature",
        "severity": "Medium",
        "signatures": [
            r"(?i)(quantity\s*=\s*-|price\s*=\s*0[^\d]|coupon=[^&\s]+.*coupon=|/reset-password\?.*email=)",
        ],
        "description": "Abuse of legitimate workflows: negative quantities, price tampering, coupon replay, mass password-reset harvesting.",
        "indicators": ["quantity=-1", "coupon replay", "mass /reset-password"],
        "mitigation": [
            "Alert + rate-limit the session (SOAR).",
            "Enforce server-side price/quantity validation and coupon single-use.",
            "Review orders placed through the abused workflow.",
        ],
        "soar_action": "alert",
    },
]

# ---------------------------------------------------------------------------
# Behavioral patterns (stateful correlation across events)
# ---------------------------------------------------------------------------
BEHAVIORAL_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "BRUTEFORCE",
        "name": "Brute-Force Login (sliding window)",
        "owasp": "A07:2021 Auth Failures",
        "pisf": "PISF-05.2",
        "kind": "behavioral",
        "severity": "Critical",
        "description": "10 failed authentications for one (source IP, user) inside a 60-second sliding window.",
        "indicators": ["10 AUTH_FAIL / 60s, same IP+user"],
        "mitigation": [
            "Firewall-block the source IP (real iptables when privileged).",
            "Lock the targeted account for 15 minutes.",
            "Air-gapped DB snapshot; PKCERT incident PDF with SHA-256.",
        ],
        "soar_action": "block_ip",
    },
    {
        "id": "PASSWORD_SPRAY",
        "name": "Password Spraying",
        "owasp": "A07:2021 Auth Failures",
        "pisf": "PISF-05.2",
        "kind": "behavioral",
        "severity": "High",
        "description": "One IP tries a few common passwords across MANY users — evades per-user brute-force windows.",
        "indicators": ["1 IP, >=5 distinct users, <=2 fails each, inside 120s"],
        "mitigation": [
            "Firewall-block the spraying IP (SOAR).",
            "Force password reset for all targeted users.",
            "Enable MFA enrollment campaign for affected accounts.",
        ],
        "soar_action": "block_ip",
    },
    {
        "id": "DISTRIBUTED_BRUTEFORCE",
        "name": "Distributed Low-and-Slow Brute Force",
        "owasp": "A07:2021 Auth Failures",
        "pisf": "PISF-05.2",
        "kind": "behavioral",
        "severity": "High",
        "description": "Many source IPs attack ONE user slowly — each IP stays under the per-IP window.",
        "indicators": [">=5 distinct IPs, >=10 total fails, one user, inside 300s"],
        "mitigation": [
            "Block all participating IPs (SOAR bulk contain).",
            "Lock the targeted account; notify the user out-of-band.",
            "Tighten WAF rate limits on the login endpoint.",
        ],
        "soar_action": "block_ip",
    },
    {
        "id": "IMPOSSIBLE_TRAVEL",
        "name": "Impossible Travel / Credential Sharing",
        "owasp": "A07:2021 Auth Failures",
        "pisf": "PISF-05.3",
        "kind": "behavioral",
        "severity": "High",
        "description": "Same user logs in from two far-apart networks within minutes — impossible for one human. HEURISTIC — /16 network change within 15 min, no GeoIP (no geolocation database; distance is inferred from network prefix only).",
        "indicators": ["same user, 2 public IPs in different /16, <15 min apart"],
        "mitigation": [
            "Kill all sessions for the user (Zero-Trust session revoke).",
            "Force re-authentication + MFA challenge.",
            "Alert only — do not auto-block; could be VPN egress change.",
        ],
        "soar_action": "kill_session",
    },
    {
        "id": "UEBA_ANOMALY",
        "name": "Behavioral Anomaly (UEBA-lite)",
        "owasp": "A07:2021 Auth Failures",
        "pisf": "PISF-05.3",
        "kind": "behavioral",
        "severity": "Medium",
        "description": "Login from a never-seen IP (NEW_IP) or at an unusual hour (OFF_HOURS, <10% of user's logins) after baseline training.",
        "indicators": ["NEW_IP", "OFF_HOURS"],
        "mitigation": [
            "Step-up authentication (MFA challenge) on next login.",
            "Keep IP under watch-list for 24h; correlate with other patterns.",
        ],
        "soar_action": "alert",
    },
    {
        "id": "EXFILTRATION",
        "name": "Data Exfiltration Behavior",
        "owasp": "A01:2021 Broken Access Control",
        "pisf": "PISF-06.1",
        "kind": "behavioral",
        "severity": "Critical",
        "description": "Burst of successful reads on export/download endpoints or oversized responses from one session.",
        "indicators": [">=20 hits on /export|/download|/backup in 120s, or response >10MB x5"],
        "mitigation": [
            "Kill the session immediately (Zero-Trust).",
            "Block the source IP; quarantine the host.",
            "DLP review: what left the building? Scope in incident PDF.",
        ],
        "soar_action": "kill_session",
    },
    {
        "id": "TELEMETRY_GAP",
        "name": "Logging/Monitoring Failure (Telemetry Gap)",
        "owasp": "A09:2021 Logging Failures",
        "pisf": "PISF-10.1",
        "kind": "behavioral",
        "severity": "Medium",
        "description": "Sudden collapse of ingested event rate — the logging pipeline itself may be down, throttled, or tampered with. Attacks hide in the silence.",
        "indicators": ["event rate drops >90% vs 5-min baseline for 60s"],
        "mitigation": [
            "Alert the SOC immediately (no IP to block).",
            "Fail over to redundant log shipper; verify log-file integrity.",
            "Treat the gap window as unmonitored: retro-hunt afterwards.",
        ],
        "soar_action": "alert",
    },
]

PATTERNS: list[dict[str, Any]] = SIGNATURE_PATTERNS + BEHAVIORAL_PATTERNS
PATTERN_BY_ID: dict[str, dict[str, Any]] = {p["id"]: p for p in PATTERNS}


def owasp_coverage() -> dict[str, list[str]]:
    """OWASP category -> pattern ids covering it (for the UI/docs matrix)."""
    cov: dict[str, list[str]] = {}
    for p in PATTERNS:
        cov.setdefault(p["owasp"], []).append(p["id"])
    return cov
