"""
monitor.py
──────────
Automatically monitors your localhost website and sends suspicious
activity to Sentinel-Ops for AI threat analysis.

HOW IT WORKS:
  1. Acts as a proxy/middleware sitting between the internet and your app
  2. Watches every request coming into your website
  3. Detects suspicious patterns (brute force, SQL injection, XSS, etc.)
  4. Automatically submits alerts to Sentinel-Ops at localhost:8000

USAGE:
  python monitor.py --target http://localhost:3000 --port 9000

  Then visit YOUR website at: http://localhost:9000
  (monitor sits in between and watches all traffic)

  OR if you just want to simulate attacks without a proxy:
  python monitor.py --simulate

  Control simulation speed:
  python monitor.py --simulate --interval 10   # 10s between attacks (default: 5)

REQUIREMENTS:
  pip install httpx flask flask-cors
"""

import argparse
import time
import threading
import re
import json
import httpx
from datetime import datetime
from collections import defaultdict

# ── Sentinel-Ops config ────────────────────────────────────────────────────
SENTINEL_URL = "http://localhost:8000"

# ── Attack detection patterns ──────────────────────────────────────────────
ATTACK_PATTERNS = {
    "SQL Injection": [
        r"(\bUNION\b.*\bSELECT\b)",
        r"(\bSELECT\b.*\bFROM\b)",
        r"(--|#|/\*.*\*/)",
        r"(\bDROP\b.*\bTABLE\b)",
        r"(\bOR\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?)",
        r"(\bINSERT\b.*\bINTO\b)",
        r"(;.*\bEXEC\b)",
    ],
    "XSS Attack": [
        r"(<script.*?>)",
        r"(javascript\s*:)",
        r"(onerror\s*=)",
        r"(onload\s*=)",
        r"(<img.*?src.*?=.*?javascript)",
        r"(alert\s*\()",
        r"(document\.cookie)",
    ],
    "Path Traversal": [
        r"(\.\./){2,}",
        r"(%2e%2e%2f)",
        r"(\.\.\\){2,}",
        r"(/etc/passwd)",
        r"(/windows/system32)",
    ],
    "Command Injection": [
        r"(;\s*ls\s)",
        r"(;\s*cat\s)",
        r"(\|\s*whoami)",
        r"(`.*`)",
        r"(\$\(.*\))",
        r"(;\s*rm\s+-rf)",
        r"(&&\s*wget\s)",
    ],
    "Brute Force": None,  # handled separately via rate tracking
    "Scanner/Bot": [
        r"(nikto)",
        r"(sqlmap)",
        r"(nmap)",
        r"(masscan)",
        r"(dirbuster)",
        r"(gobuster)",
        r"(burpsuite)",
        r"(python-requests.*scan)",
    ],
}

# ── State tracking ─────────────────────────────────────────────────────────
request_counts   = defaultdict(list)   # ip -> [timestamps]
failed_auth      = defaultdict(int)    # ip -> count
submitted_alerts = set()               # dedupe alerts

# ── Thresholds ─────────────────────────────────────────────────────────────
RATE_LIMIT_WINDOW   = 60    # seconds
RATE_LIMIT_MAX      = 30    # requests per window before alert
BRUTE_FORCE_MAX     = 5     # failed logins before alert


def now():
    return datetime.now().strftime("%H:%M:%S")


def log(msg, level="INFO"):
    colors = {"INFO": "\033[36m", "WARN": "\033[33m", "ALERT": "\033[31m", "OK": "\033[32m"}
    reset = "\033[0m"
    c = colors.get(level, "")
    print(f"{c}[{now()}] [{level}] {msg}{reset}")


# ── Sentinel-Ops integration ───────────────────────────────────────────────
def submit_to_sentinel(problem_statement: str, dedupe_key: str = None):
    """Push alert to Sentinel-Ops queue — frontend will auto-fill and submit."""

    if dedupe_key and dedupe_key in submitted_alerts:
        return
    if dedupe_key:
        submitted_alerts.add(dedupe_key)

    log(f"Pushing to Sentinel-Ops queue: {problem_statement[:80]}...", "ALERT")

    try:
        resp = httpx.post(
            f"{SENTINEL_URL}/api/v1/queue",
            json={"problem_statement": problem_statement},
            timeout=5,
        )
        if resp.status_code == 202:
            log(f"✓ Alert queued — will appear in dashboard at {SENTINEL_URL}", "OK")
        else:
            log(f"Sentinel-Ops returned {resp.status_code}", "WARN")
    except httpx.ConnectError:
        log("Cannot reach Sentinel-Ops. Is it running on port 8000?", "WARN")


def poll_result(job_id: str):
    """Poll job until complete and print the threat report."""
    for _ in range(30):
        time.sleep(2)
        try:
            r = httpx.get(f"{SENTINEL_URL}/api/v1/jobs/{job_id}", timeout=5)
            data = r.json()
            status = data.get("status")

            if status == "complete":
                fact = data.get("fact_sheet", {})
                severity = fact.get("severity", "UNKNOWN") if fact else "UNKNOWN"
                markdown = fact.get("raw_markdown", "") if fact else ""
                log(f"── Threat Report for job {job_id[:8]} ──────────────────", "OK")
                log(f"Severity: {severity}", "OK")
                if markdown:
                    preview = markdown[:500].replace("\n", " | ")
                    log(f"Report: {preview}...", "OK")
                log(f"Full report: {SENTINEL_URL} → click the job in the dashboard", "OK")
                return

            elif status == "failed":
                log(f"Job {job_id[:8]} failed: {data.get('error')}", "WARN")
                return

        except Exception:
            pass


# ── Request analyzer ───────────────────────────────────────────────────────
def analyze_request(method: str, path: str, headers: dict,
                    body: str, client_ip: str):
    """
    Analyze an incoming request for threats.
    Call this from your web framework middleware.
    """
    full_request = f"{method} {path} body={body} headers={json.dumps(headers)}"
    user_agent   = headers.get("user-agent", headers.get("User-Agent", ""))
    timestamp    = time.time()

    # ── 1. Rate limiting / brute force detection ───────────────────────────
    window_start = timestamp - RATE_LIMIT_WINDOW
    request_counts[client_ip] = [
        t for t in request_counts[client_ip] if t > window_start
    ]
    request_counts[client_ip].append(timestamp)
    count = len(request_counts[client_ip])

    if count == RATE_LIMIT_MAX:
        submit_to_sentinel(
            f"Possible brute force / DDoS from {client_ip}. "
            f"{count} requests in {RATE_LIMIT_WINDOW}s to {path}. "
            f"User-Agent: {user_agent}",
            dedupe_key=f"ratelimit:{client_ip}"
        )

    # ── 2. Failed auth tracking ────────────────────────────────────────────
    if path in ("/login", "/admin", "/auth", "/signin", "/wp-login.php"):
        failed_auth[client_ip] += 1
        if failed_auth[client_ip] == BRUTE_FORCE_MAX:
            submit_to_sentinel(
                f"Brute force login attack from {client_ip}. "
                f"{failed_auth[client_ip]} failed attempts on {path}. "
                f"User-Agent: {user_agent}",
                dedupe_key=f"bruteforce:{client_ip}"
            )

    # ── 3. Pattern-based attack detection ─────────────────────────────────
    for attack_type, patterns in ATTACK_PATTERNS.items():
        if patterns is None:
            continue
        for pattern in patterns:
            if re.search(pattern, full_request, re.IGNORECASE):
                submit_to_sentinel(
                    f"{attack_type} detected from {client_ip}. "
                    f"Method: {method}, Path: {path}. "
                    f"Payload snippet: {(path + ' ' + body)[:200]}. "
                    f"User-Agent: {user_agent}",
                    dedupe_key=f"{attack_type}:{client_ip}:{path}"
                )
                break

    # ── 4. Sensitive path access ───────────────────────────────────────────
    sensitive_paths = [
        "/admin", "/.env", "/config", "/backup",
        "/phpinfo", "/.git", "/wp-admin", "/database",
        "/secret", "/private", "/api/keys"
    ]
    for sp in sensitive_paths:
        if path.lower().startswith(sp):
            submit_to_sentinel(
                f"Sensitive path access attempt from {client_ip}. "
                f"Path: {path}. Method: {method}. "
                f"User-Agent: {user_agent}",
                dedupe_key=f"sensitive:{client_ip}:{path}"
            )
            break


# ── Flask proxy middleware ─────────────────────────────────────────────────
def run_proxy(target_url: str, listen_port: int):
    """
    Run a reverse proxy that sits in front of your website.
    All traffic goes through here so we can inspect it.
    """
    try:
        from flask import Flask, request, Response
        import flask_cors
    except ImportError:
        log("Installing required packages...", "INFO")
        import subprocess
        subprocess.run(["pip", "install", "flask", "flask-cors", "--quiet"])
        from flask import Flask, request, Response
        import flask_cors

    app = Flask(__name__)
    flask_cors.CORS(app)

    log(f"Starting monitor proxy on port {listen_port}", "INFO")
    log(f"Forwarding traffic to: {target_url}", "INFO")
    log(f"Sentinel-Ops dashboard: {SENTINEL_URL}", "INFO")
    log("─" * 60, "INFO")
    log(f"Visit YOUR website at: http://localhost:{listen_port}", "OK")
    log("All requests will be monitored for threats.", "OK")
    log("─" * 60, "INFO")

    @app.route("/", defaults={"path": ""}, methods=["GET","POST","PUT","DELETE","PATCH","OPTIONS"])
    @app.route("/<path:path>",             methods=["GET","POST","PUT","DELETE","PATCH","OPTIONS"])
    def proxy(path):
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        body      = request.get_data(as_text=True)
        headers   = dict(request.headers)

        log(f"{request.method} /{path} from {client_ip}")

        analyze_request(
            method=request.method,
            path="/" + path,
            headers=headers,
            body=body,
            client_ip=client_ip,
        )

        try:
            url = f"{target_url}/{path}"
            if request.query_string:
                url += "?" + request.query_string.decode()

            fwd_headers = {
                k: v for k, v in headers.items()
                if k.lower() not in ("host", "content-length")
            }

            resp = httpx.request(
                method=request.method,
                url=url,
                headers=fwd_headers,
                content=body.encode() if body else b"",
                timeout=10,
                follow_redirects=True,
            )

            if resp.status_code in (401, 403) and "/" + path in ("/login", "/admin", "/auth"):
                failed_auth[client_ip] += 1

            return Response(
                resp.content,
                status=resp.status_code,
                headers=dict(resp.headers),
            )

        except httpx.ConnectError:
            log(f"Cannot reach target {target_url}. Is your website running?", "WARN")
            return Response(
                f"<h1>Monitor Error</h1><p>Cannot reach {target_url}. "
                f"Make sure your website is running.</p>",
                status=502,
                mimetype="text/html"
            )

    app.run(host="0.0.0.0", port=listen_port, debug=False, threaded=True)


# ── Attack simulator (for testing) ────────────────────────────────────────
def run_simulator(interval: int = 5):
    """
    Simulate various attacks against the monitor proxy for testing.
    interval: seconds to wait between each attack (default 5).
    """
    import httpx

    TARGET = "http://localhost:9000"

    attacks = [
        ("Normal request",          "GET",  "/",             ""),
        ("SQL Injection in URL",    "GET",  "/search?q=1' UNION SELECT * FROM users--", ""),
        ("XSS in body",             "POST", "/comment",      '{"text": "<script>alert(document.cookie)</script>"}'),
        ("Path traversal",          "GET",  "/../../etc/passwd", ""),
        ("Admin brute force 1",     "POST", "/admin",        "user=admin&pass=password1"),
        ("Admin brute force 2",     "POST", "/admin",        "user=admin&pass=password2"),
        ("Admin brute force 3",     "POST", "/admin",        "user=admin&pass=password3"),
        ("Admin brute force 4",     "POST", "/admin",        "user=admin&pass=password4"),
        ("Admin brute force 5",     "POST", "/admin",        "user=admin&pass=password5"),
        ("Sensitive path access",   "GET",  "/.env",         ""),
        ("Sensitive path access",   "GET",  "/.git/config",  ""),
        ("Command injection",       "POST", "/ping",         "host=127.0.0.1; cat /etc/passwd"),
        ("Scanner user agent",      "GET",  "/",             ""),
    ]

    log("Starting attack simulation...", "WARN")
    log(f"Targeting: {TARGET}", "WARN")
    log(f"Interval between attacks: {interval}s", "INFO")
    log("─" * 60)

    client = httpx.Client(timeout=3)

    for desc, method, path, body in attacks:
        log(f"Simulating: {desc}")
        try:
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            if "Scanner" in desc:
                headers["User-Agent"] = "Mozilla/5.0 (nikto scanner)"

            client.request(method, TARGET + path,
                           content=body.encode(), headers=headers)
        except Exception:
            pass
        time.sleep(interval)   # ← configurable interval

    log("─" * 60)
    log("Simulation complete! Check Sentinel-Ops dashboard for alerts.", "OK")
    log(f"Dashboard: {SENTINEL_URL}", "OK")


# ── Entry point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Sentinel-Ops Website Monitor"
    )
    parser.add_argument(
        "--target", default="http://localhost:3000",
        help="Your website URL (default: http://localhost:3000)"
    )
    parser.add_argument(
        "--port", type=int, default=9000,
        help="Port to run the monitor proxy on (default: 9000)"
    )
    parser.add_argument(
        "--simulate", action="store_true",
        help="Run attack simulation instead of proxy"
    )
    parser.add_argument(
        "--interval", type=int, default=5,
        help="Seconds between simulated attacks (default: 5)"
    )
    args = parser.parse_args()

    if args.simulate:
        run_simulator(interval=args.interval)
    else:
        run_proxy(args.target, args.port)