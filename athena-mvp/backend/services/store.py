"""In-memory data layer seeded with simulated data. Swap for SQLite/Postgres later."""
import random, datetime as dt, itertools
from services.detection import severity_for

R = random.Random(7)
NOW = lambda: dt.datetime.utcnow()
TYPES = [("Brute-force login pattern", "Credential Attack"), ("Unusual outbound traffic", "Data Exfiltration"),
         ("Repeated DNS anomaly", "DNS Tunneling"), ("Privilege escalation signal", "Privilege Escalation"),
         ("Rare protocol sequence", "Zero-Day Candidate"), ("Abnormal request burst", "DoS Behavior")]
_ids = itertools.count(1001)
state = {"engine_enabled": True, "alerts": [], "events": [], "events_processed": 18492,
         "model_refreshed": NOW().isoformat() + "Z"}

def rip(): return f"{R.choice([192, 10, 172])}.{R.randint(16, 168)}.{R.randint(0, 254)}.{R.randint(2, 250)}"

def make_alert(name=None, ttype=None, score=None, ip=None, ts=None):
    if not name: name, ttype = R.choice(TYPES)
    score = score if score is not None else R.randint(22, 96)
    return {"id": next(_ids), "name": name, "source_ip": ip or rip(), "timestamp": (ts or NOW()).isoformat() + "Z",
            "threat_type": ttype, "severity": severity_for(score), "threat_score": score,
            "status": R.choice(["New", "Investigating", "Resolved"]) if ts else "New"}

def seed():
    state["alerts"] = sorted((make_alert(ts=NOW() - dt.timedelta(minutes=R.randint(2, 900))) for _ in range(18)),
                             key=lambda a: a["timestamp"], reverse=True)
    protos = [("TCP", 443), ("TCP", 22), ("UDP", 53), ("ICMP", 0), ("TCP", 3389), ("UDP", 123), ("TCP", 80)]
    ev = []
    for _ in range(40):
        p, port = R.choice(protos); pk = R.randint(20, 900)
        an = round(min(0.99, pk / 1000 + R.uniform(0, .25)), 2)
        ev.append({"source_ip": rip(), "destination_ip": f"10.0.0.{R.randint(2, 40)}", "protocol": p, "port": port,
                   "packet_count": pk, "volume_kb": round(pk * R.uniform(.6, 1.4), 1), "anomaly_score": an,
                   "risk": "High" if an > .7 else "Medium" if an > .4 else "Low"})
    state["events"] = ev
seed()

def clear_alerts(): state["alerts"] = []
def add_alert(a): state["alerts"].insert(0, a)

def dashboard():
    al = state["alerts"]
    crit = sum(a["severity"] == "Critical" for a in al)
    avg = round(sum(a["threat_score"] for a in al) / len(al)) if al else 0
    overall = min(100, round(avg * 0.7 + crit * 6)) if al else 0
    rr = random.Random(7)
    threat = [35 + (i % 5) * 6 + rr.randint(-8, 8) for i in range(12)]
    threat[-1] = overall
    hours = [f"{h:02d}:00" for h in range(0, 24, 2)]
    return {"threat_score": overall, "anomalies": sum(a["threat_score"] >= 40 for a in al) + 6, "critical_alerts": crit,
            "events_processed": state["events_processed"], "model_confidence": 94,
            "activity": [{"time": h, "threat": t, "anomalies": t // 6 + rr.randint(0, 3)} for h, t in zip(hours, threat)],
            "severity_distribution": [{"name": s, "value": sum(a["severity"] == s for a in al)}
                                      for s in ("Critical", "High", "Medium", "Low")],
            "recent_alerts": al[:5], "engine_enabled": state["engine_enabled"]}
