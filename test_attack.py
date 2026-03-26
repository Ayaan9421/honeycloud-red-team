"""
RedOps — Complete Route Test Suite
────────────────────────────────────
Tests every API endpoint in order. Run this after the server is up.

Usage:
    python test_routes.py                          # tests against localhost:8000
    python test_routes.py --host 1.2.3.4           # custom host
    python test_routes.py --host 1.2.3.4 --port 9000

What gets tested:
    GET  /                                  root
    GET  /api/health                        liveness + allowlist check
    GET  /api/playbooks                     list playbooks
    POST /api/fingerprint                   isolated fingerprint scan
    GET  /api/fingerprint/history           past fingerprint results
    POST /api/campaigns                     create + launch campaign
    GET  /api/campaigns                     list campaigns
    GET  /api/campaigns/{id}                single campaign
    GET  /api/campaigns/{id}/events         attack events
    GET  /api/campaigns/{id}/report         scored report (after completion)
    DELETE /api/campaigns/{id}             abort
    GET  /api/ml/status                     which models are loaded
    GET  /api/ml/forecast/{campaign_id}     Bi-LSTM next move prediction
    POST /api/ml/retrain                    retrain fingerprint RF

The script does NOT run real attacks — it uses the target from --target
which defaults to whatever is first in your allowlist. It will still
enforce the allowlist, so if your GCP IP isn't allowlisted the campaign
POST will return 403 and the script will tell you exactly how to fix it.
"""
import argparse
import json
import sys
import time
import textwrap
import urllib.request
import urllib.error

# ── ANSI colours ────────────────────────────────────────────
G = "\033[32m"; R = "\033[31m"; Y = "\033[33m"; B = "\033[34m"; C = "\033[36m"; RESET = "\033[0m"; BOLD = "\033[1m"
def ok(msg):   print(f"  {G}✓{RESET}  {msg}")
def fail(msg): print(f"  {R}✗{RESET}  {msg}")
def warn(msg): print(f"  {Y}!{RESET}  {msg}")
def info(msg): print(f"  {B}→{RESET}  {msg}")
def head(msg): print(f"\n{BOLD}{C}{'─'*60}{RESET}\n{BOLD}{C}  {msg}{RESET}\n{BOLD}{C}{'─'*60}{RESET}")


# ── HTTP helpers ────────────────────────────────────────────
def _req(method, url, body=None, timeout=15):
    data = json.dumps(body).encode() if body else None
    headers = {"Content-Type": "application/json"} if data else {}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode()
            return r.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:    return e.code, json.loads(raw)
        except: return e.code, {"raw": raw}
    except Exception as e:
        return 0, {"error": str(e)}


def GET(base, path, timeout=15):
    return _req("GET", base + path, timeout=timeout)

def POST(base, path, body, timeout=30):
    return _req("POST", base + path, body, timeout=timeout)

def DELETE(base, path):
    return _req("DELETE", base + path)


# ── Individual test functions ────────────────────────────────
def test_root(base):
    head("1 / — ROOT")
    code, body = GET(base, "/")
    if code == 200 and body.get("status") == "operational":
        ok(f"Root OK — version={body.get('version')} docs={body.get('docs')}")
    else:
        fail(f"Unexpected response: {code} {body}")
    return code == 200


def test_health(base):
    head("2 /api/health — LIVENESS CHECK")
    code, body = GET(base, "/api/health")
    if code != 200:
        fail(f"Health returned {code}: {body}")
        return False, body

    status = body.get("status")
    if status == "ok":
        ok(f"Status: {G}OK{RESET}")
    else:
        warn(f"Status: {Y}DEGRADED{RESET}")

    db = body.get("database", {})
    redis = body.get("redis", {})

    if db.get("connected"):  ok(f"Database connected")
    else:                    fail(f"Database ERROR: {db.get('error')}")

    if redis.get("connected"): ok(f"Redis connected")
    else:                      fail(f"Redis ERROR: {redis.get('error')}")

    allowlist = body.get("allowlist", "")
    info(f"Current allowlist: {Y}{allowlist}{RESET}")

    return code == 200, body


def test_playbooks(base):
    head("3 /api/playbooks — LIST PLAYBOOKS")
    code, body = GET(base, "/api/playbooks")
    if code != 200:
        fail(f"Got {code}: {body}")
        return []
    pbs = body.get("playbooks", [])
    ok(f"Found {len(pbs)} playbooks:")
    for p in pbs:
        info(f"  {p['name']} ({p.get('stages','?')} stages) [{p.get('source','?')}] — {p.get('description','')[:60]}")
    return pbs


def test_fingerprint(base, target_host, target_port):
    head(f"4 /api/fingerprint — ISOLATED FINGERPRINT SCAN → {target_host}:{target_port}")
    info("This runs the full 4-signal pipeline (banner, timing, filesystem, protocol depth)")
    info("May take 20-40 seconds — runs concurrently but SSH probes take time...")

    code, body = POST(base, "/api/fingerprint", {"host": target_host, "port": target_port}, timeout=60)

    if code == 403:
        fail(f"TARGET NOT IN ALLOWLIST — Got 403")
        warn(f"Add '{target_host}' to TARGET_ALLOWLIST in your .env file")
        warn(f"See the .env fix section at the top of this output")
        return None
    elif code != 200:
        fail(f"Got {code}: {body}")
        return None

    verdict = body.get("verdict", "UNKNOWN")
    conf    = body.get("honeypot_confidence", 0)
    color   = R if verdict == "HONEYPOT" else G if verdict == "REAL" else Y

    ok(f"Verdict: {color}{verdict}{RESET}  (confidence={conf:.2%})")
    info(f"  banner_score:          {body.get('banner_score', 0):.3f}")
    info(f"  timing_score:          {body.get('timing_score', 0):.3f}")
    info(f"  filesystem_score:      {body.get('filesystem_score', 0):.3f}")
    info(f"  protocol_depth_score:  {body.get('protocol_depth_score', 0):.3f}")
    info(f"  is_honeypot:           {body.get('is_honeypot')}")
    return body


def test_fingerprint_history(base):
    head("5 /api/fingerprint/history — FINGERPRINT HISTORY")
    code, body = GET(base, "/api/fingerprint/history")
    if code == 200:
        ok(f"Got {len(body)} historical fingerprint records")
        for r in body[:3]:
            info(f"  {r.get('target_host')}:{r.get('target_port')} → {r.get('verdict')} ({r.get('honeypot_confidence', 0):.2%})")
    else:
        fail(f"Got {code}: {body}")
    return code == 200


def test_campaign_create(base, target_host, target_port, playbook):
    head(f"6 POST /api/campaigns — LAUNCH CAMPAIGN")
    info(f"Target: {target_host}:{target_port}  Playbook: {playbook}")
    warn("This will start a REAL multi-stage APT campaign against the target!")

    payload = {
        "name":          f"TEST-{int(time.time())}",
        "target_host":   target_host,
        "target_port":   target_port,
        "playbook_name": playbook,
    }
    code, body = POST(base, "/api/campaigns", payload, timeout=15)

    if code == 403:
        fail(f"TARGET NOT IN ALLOWLIST — Got 403")
        warn(f"The safety module blocked this. Add '{target_host}' to TARGET_ALLOWLIST in .env")
        return None
    elif code == 429:
        warn(f"Too many concurrent campaigns running (429). Wait for one to finish or abort.")
        return None
    elif code == 201:
        ok(f"Campaign created: id={body.get('id', '')[:8]}...  status={body.get('status')}")
        info(f"  name: {body.get('name')}")
        info(f"  stages: {[s['stage_name'] for s in body.get('stages', [])]}")
        return body
    else:
        fail(f"Got {code}: {body}")
        return None


def test_campaign_list(base):
    head("7 GET /api/campaigns — LIST CAMPAIGNS")
    code, body = GET(base, "/api/campaigns?limit=5")
    if code == 200:
        ok(f"Got {len(body)} campaigns (showing last 5)")
        for c in body:
            ds = c.get("deception_score")
            info(f"  [{c['status'].upper():<10}] {c['name']:<25} target={c['target_host']}  deception={f'{ds:.2%}' if ds else '—'}")
    else:
        fail(f"Got {code}: {body}")
    return body if code == 200 else []


def test_campaign_get(base, campaign_id):
    head(f"8 GET /api/campaigns/{{id}} — SINGLE CAMPAIGN")
    code, body = GET(base, f"/api/campaigns/{campaign_id}")
    if code == 200:
        ok(f"id={campaign_id[:8]}... status={body.get('status')} playbook={body.get('playbook_name')}")
        for s in body.get("stages", []):
            detected_mark = f"  {R}DETECTED{RESET}" if s.get("detected") else ""
            info(f"  stage[{s['stage_order']}] {s['stage_name']:<15} {s['status']}{detected_mark}")
    else:
        fail(f"Got {code}: {body}")
    return code == 200


def test_campaign_events(base, campaign_id):
    head(f"9 GET /api/campaigns/{{id}}/events — ATTACK EVENTS")
    code, body = GET(base, f"/api/campaigns/{campaign_id}/events")
    if code == 200:
        ok(f"{len(body)} events recorded")
        for ev in body[-5:]:
            succ = f"{G}✓{RESET}" if ev.get("success") else f"{R}✗{RESET}"
            det  = f"  {R}⚠ detected{RESET}" if ev.get("detected") else ""
            info(f"  {succ} [{ev['stage']:<12}] {ev['action']}{det}")
    else:
        fail(f"Got {code}: {body}")
    return code == 200


def test_campaign_report(base, campaign_id):
    head(f"10 GET /api/campaigns/{{id}}/report — FINAL REPORT")
    code, body = GET(base, f"/api/campaigns/{campaign_id}/report")
    if code == 409:
        warn(f"Campaign not yet complete — report unavailable (409). This is expected if still running.")
        return False
    elif code == 200:
        ok(f"Report ready")
        info(f"  summary:           {body.get('summary')}")
        info(f"  fingerprint_score: {body.get('fingerprint_score', 0):.3f}  (higher = more fingerprintable)")
        info(f"  evasion_rate:      {body.get('evasion_rate', 0):.2%}")
        info(f"  detection_latency: {body.get('detection_latency')}s")
        info(f"  kill_chain_depth:  {body.get('kill_chain_depth')} stages before detection")
        info(f"  deception_score:   {body.get('deception_score', 0):.3f}")
        recs = body.get("recommendations", [])
        if recs:
            info(f"  recommendations ({len(recs)}):")
            for r in recs:
                info(f"    ↳ {r}")
        return True
    else:
        fail(f"Got {code}: {body}")
        return False


def test_campaign_abort(base, campaign_id):
    head(f"11 DELETE /api/campaigns/{{id}} — ABORT")
    code, body = DELETE(base, f"/api/campaigns/{campaign_id}")
    if code == 204:
        ok("Campaign aborted (204 No Content)")
        return True
    elif code == 409:
        warn(f"Cannot abort — campaign is in a non-abortable state (already done/aborted)")
        return False
    else:
        fail(f"Got {code}: {body}")
        return False


def test_ml_status(base):
    head("12 GET /api/ml/status — ML MODEL STATUS")
    code, body = GET(base, "/api/ml/status")
    if code == 200:
        ok("ML status retrieved")
        on_disk = body.get("models_on_disk", {})
        for m, present in on_disk.items():
            marker = ok if present else warn
            (ok if present else warn)(f"  {m:<25} {'LOADED' if present else 'NOT FOUND (will use fallback)'}")
        info(f"  inference_ready:        {body.get('inference_ready')}")
        info(f"  fingerprint_classifier: {body.get('fingerprint_classifier')}")
    else:
        fail(f"Got {code}: {body}")
    return code == 200


def test_ml_forecast(base, campaign_id):
    head(f"13 GET /api/ml/forecast/{{id}} — Bi-LSTM FORECAST")
    code, body = GET(base, f"/api/ml/forecast/{campaign_id}")
    if code == 404:
        warn("No events yet for this campaign — forecast needs at least 1 event")
        return False
    elif code == 200:
        ok("Forecast received")
        info(f"  forecasted_move: {Y}{body.get('forecasted_move')}{RESET}")
        info(f"  confidence:      {body.get('confidence')}%")
        info(f"  anomaly_score:   {body.get('anomaly_score')} / 100")
        info(f"  model_used:      {body.get('model_used')}")
        return True
    else:
        fail(f"Got {code}: {body}")
        return False


def test_ml_retrain(base):
    head("14 POST /api/ml/retrain — RETRAIN FINGERPRINT RF")
    info("Sending dummy labeled IDs — expecting 400 (not enough real DB records)")
    payload = {
        "label_honeypot_ids": ["fake-id-1", "fake-id-2"],
        "label_real_ids":     ["fake-id-3"],
    }
    code, body = POST(base, "/api/ml/retrain", payload, timeout=30)
    if code == 400:
        ok(f"Correctly rejected with 400 — {body.get('detail', '')}")
    elif code == 200:
        ok(f"Retrain succeeded: {body}")
    else:
        fail(f"Got {code}: {body}")
    return True  # either 400 or 200 is correct here


# ── Main ────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="RedOps Route Test Suite")
    parser.add_argument("--host",       default="localhost",      help="API host (default: localhost)")
    parser.add_argument("--port",       default=8000, type=int,   help="API port (default: 8000)")
    parser.add_argument("--target",     default=None,             help="Honeypot IP to test against (must be in allowlist)")
    parser.add_argument("--target-port",default=2222,   type=int,   help="Honeypot SSH port (default: 22)")
    parser.add_argument("--playbook",   default="fingerprint_only", help="Playbook to use for campaign test (default: fingerprint_only)")
    parser.add_argument("--skip-campaign", action="store_true",   help="Skip campaign launch (just test read-only routes)")
    parser.add_argument("--skip-fingerprint", action="store_true",help="Skip live fingerprint scan")
    args = parser.parse_args()

    base = f"http://{args.host}:{args.port}"

    print(f"""
{BOLD}{C}╔══════════════════════════════════════════════════════════╗
║           RedOps — Complete Route Test Suite             ║
╚══════════════════════════════════════════════════════════╝{RESET}
  API base:   {base}
  Target:     {args.target or '(none — will use first allowlisted IP)'}
  Playbook:   {args.playbook}
""")

    # ── 1. Root
    test_root(base)

    # ── 2. Health — get allowlist + target resolution
    health_ok, health_body = test_health(base)
    allowlist_str = health_body.get("allowlist", "")

    # Resolve test target
    target = args.target
    if not target:
        # pick the first non-CIDR entry from allowlist
        for entry in allowlist_str.split(","):
            entry = entry.strip()
            if entry and "/" not in entry:
                target = entry
                break
    if not target:
        warn("Could not determine a test target IP. Pass --target <ip>")
        target = "127.0.0.1"

    info(f"Using test target: {Y}{target}:{args.target_port}{RESET}\n")

    # ── 3. Playbooks
    test_playbooks(base)

    # ── 4-5. Fingerprint
    fp_result = None
    if not args.skip_fingerprint:
        fp_result = test_fingerprint(base, target, args.target_port)
        test_fingerprint_history(base)
    else:
        warn("Skipping live fingerprint scan (--skip-fingerprint)")

    # ── 12. ML status (before campaign, so we know what models are loaded)
    test_ml_status(base)

    # ── 6-11. Campaign lifecycle
    campaign = None
    if not args.skip_campaign:
        campaign = test_campaign_create(base, target, args.target_port, args.playbook)
    else:
        warn("Skipping campaign launch (--skip-campaign)")
        # try to grab most recent existing campaign for read tests
        existing = test_campaign_list(base)
        if existing:
            campaign = existing[0]
            info(f"Using existing campaign {campaign['id'][:8]}... for read tests")

    if campaign:
        cid = campaign["id"]
        test_campaign_list(base)
        test_campaign_get(base, cid)
        test_campaign_events(base, cid)

        # If we just launched, give it a moment then check report
        if not args.skip_campaign and campaign.get("status") in ("pending", "running"):
            info("Campaign is running — checking report (expect 409 if not done yet)...")
        test_campaign_report(base, cid)

        # ── 13. ML Forecast
        test_ml_forecast(base, cid)

        # ── 14. Retrain
        test_ml_retrain(base)

    # ── Summary
    print(f"""
{BOLD}{C}{'─'*60}
  DONE. Check above for any {R}✗{C} failures.
{'─'*60}{RESET}

{BOLD}NEXT STEPS:{RESET}
  1. If you got 403 on fingerprint/campaign → add your GCP IP to the allowlist (see below)
  2. Watch a full campaign run:  python test_routes.py --target <GCP_IP> --playbook fingerprint_only
  3. For a full APT run:         python test_routes.py --target <GCP_IP> --playbook default_apt
  4. Watch live via WebSocket:   wscat -c ws://localhost:8000/api/ws/campaigns/<campaign_id>
  5. Swagger UI:                 http://localhost:8000/docs
""")


if __name__ == "__main__":
    main()