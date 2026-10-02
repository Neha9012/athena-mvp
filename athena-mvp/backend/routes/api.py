import datetime as dt
from functools import wraps
from flask import Blueprint, request, jsonify, current_app, Response
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from services import detection, store

api = Blueprint("api", __name__, url_prefix="/api")
USERS = {"admin": {"role": "Admin", "name": "Administrator"}}  # SOC Analyst / User roles: add here

def _ser(): return URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
def err(msg, code): return jsonify({"error": msg}), code

def auth(f):
    @wraps(f)
    def w(*a, **k):
        tok = request.headers.get("Authorization", "").replace("Bearer ", "")
        try: request.user = _ser().loads(tok, max_age=8 * 3600)
        except (BadSignature, SignatureExpired): return err("Authentication required or session expired.", 401)
        return f(*a, **k)
    return w

def admin_only(f):
    @wraps(f)
    def w(*a, **k):
        if request.user["role"] != "Admin": return err("Admin role required.", 403)
        return f(*a, **k)
    return w

@api.get("/health")
def health(): return {"status": "ok"}

@api.post("/login")
def login():
    d = request.get_json(silent=True) or {}
    u, p = d.get("username", ""), d.get("password", "")
    if not u or not p: return err("Username and password are required.", 400)
    if u not in USERS or p != current_app.config["ADMIN_PASSWORD"]: return err("Invalid username or password.", 401)
    user = {"username": u, **USERS[u]}
    return {"token": _ser().dumps(user), "user": user}

@api.get("/dashboard")
@auth
def dashboard(): return store.dashboard()

@api.get("/alerts")
@auth
def alerts(): return {"alerts": store.state["alerts"]}

@api.delete("/alerts")
@auth
@admin_only
def clear():
    store.clear_alerts(); return {"cleared": True}

@api.patch("/alerts/<int:aid>")
@auth
def alert_status(aid):
    st = (request.get_json(silent=True) or {}).get("status")
    if st not in ("New", "Investigating", "Resolved"): return err("Invalid status.", 400)
    for a in store.state["alerts"]:
        if a["id"] == aid: a["status"] = st; return a
    return err("Alert not found.", 404)

@api.get("/network-events")
@auth
def events(): return {"events": store.state["events"]}

REPORTS = [("daily", "Daily Threat Summary", "Alert volume and severity over the last 24 hours."),
           ("network", "Network Behavior Analysis", "Protocol mix and traffic outliers."),
           ("anomaly", "Anomaly Detection Report", "Anomaly scores from the ML engine."),
           ("model", "Model Performance Report", "Model confidence and status.")]

@api.get("/reports")
@auth
def reports(): return {"reports": [{"id": i, "title": t, "description": d} for i, t, d in REPORTS]}

@api.get("/reports/<rid>/download")
@auth
def report_dl(rid):
    r = next((x for x in REPORTS if x[0] == rid), None)
    if not r: return err("Report not found.", 404)
    d = store.dashboard()
    body = (f"ATHENA - {r[1]}\nGenerated: {dt.datetime.utcnow().isoformat()}Z\n"
            "NOTE: Simulated demo data, not a production security engine.\n\n"
            f"Overall threat score: {d['threat_score']}/100\nCritical alerts: {d['critical_alerts']}\n"
            f"Anomalies: {d['anomalies']}\nEvents processed: {d['events_processed']}\n"
            f"Model confidence: {d['model_confidence']}%\n")
    return Response(body, mimetype="text/plain", headers={"Content-Disposition": f"attachment; filename={rid}-report.txt"})

@api.get("/model-status")
@auth
def model_status():
    s = store.state
    return {"models": [{"name": "Isolation Forest", "status": "Online", "confidence": 94},
                       {"name": "STMP (statistical)", "status": "Online", "confidence": 91},
                       {"name": "Zero-Day Lab", "status": "Online", "confidence": 88}],
            "engine_enabled": s["engine_enabled"], "last_refreshed": s["model_refreshed"], "simulated": True}

@api.post("/analyze")
@auth
def analyze():
    if not store.state["engine_enabled"]: return err("Detection engine is disabled. Enable it in Admin.", 409)
    try: res = detection.analyze(request.get_json(silent=True))
    except detection.ValidationError as e: return err(str(e), 400)
    store.state["events_processed"] += 1
    alert = None
    if res["threat_score"] >= 40:  # alert generation stage
        alert = store.make_alert("Analyzer: " + res["prediction"], "Anomalous Traffic",
                                 res["threat_score"], res["input"]["source_ip"])
        store.add_alert(alert)
    return {**res, "alert": alert}

@api.post("/generate-alert")
@auth
def gen_alert():
    a = store.make_alert(score=store.R.randint(60, 98)); store.add_alert(a); return a, 201

@api.get("/admin/status")
@auth
def admin_status():
    s = store.state
    return {"api": "Healthy", "database": "In-memory (demo)", "models": "Online (simulated)", "health": 97,
            "active_users": 1, "engine_enabled": s["engine_enabled"], "alerts": len(s["alerts"])}

@api.post("/admin/engine")
@auth
@admin_only
def toggle():
    store.state["engine_enabled"] = bool((request.get_json(silent=True) or {}).get("enabled"))
    return {"engine_enabled": store.state["engine_enabled"]}

@api.post("/admin/refresh-models")
@auth
@admin_only
def refresh():
    store.state["model_refreshed"] = dt.datetime.utcnow().isoformat() + "Z"; return model_status()
