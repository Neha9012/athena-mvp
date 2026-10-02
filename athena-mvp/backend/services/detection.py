"""Mock pipeline: preprocess -> ML engine -> anomaly -> zero-day -> threat score."""
import ipaddress
from models.detectors import IsolationForestSim, STMPSim, ZeroDayLabSim

IF, STMP, ZD = IsolationForestSim(), STMPSim(), ZeroDayLabSim()
PROTOCOLS = {"TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS", "SSH"}

class ValidationError(ValueError):
    pass

def preprocess(p):
    """Request validation + normalisation."""
    if not p:
        raise ValidationError("Request body is empty.")
    try:
        for k in ("source_ip", "destination_ip"):
            ipaddress.ip_address(str(p.get(k, "")))
    except ValueError:
        raise ValidationError("source_ip and destination_ip must be valid IP addresses.")
    proto = str(p.get("protocol", "")).upper()
    if proto not in PROTOCOLS:
        raise ValidationError(f"protocol must be one of {sorted(PROTOCOLS)}.")
    try:
        pc = int(p.get("packet_count"))
        assert 0 < pc <= 1_000_000
    except (TypeError, ValueError, AssertionError):
        raise ValidationError("packet_count must be an integer between 1 and 1,000,000.")
    return {"source_ip": p["source_ip"], "destination_ip": p["destination_ip"], "protocol": proto, "packet_count": pc}

def severity_for(s):
    return "Critical" if s >= 85 else "High" if s >= 70 else "Medium" if s >= 40 else "Low"

def analyze(payload):
    e = preprocess(payload)
    a_if, a_st = IF.score(e), STMP.score(e)
    anomaly = round(0.65 * a_if + 0.35 * a_st, 2)
    patterns = ZD.patterns(e, anomaly)
    threat = min(100, round(anomaly * 85 + patterns * 1.8))
    pred = "Malicious Pattern" if threat >= 85 else "Suspicious Activity" if threat >= 55 else "Normal Behavior"
    return {"anomaly_score": anomaly, "threat_score": threat, "severity": severity_for(threat), "prediction": pred,
            "confidence": round(0.88 + a_if * 0.08, 2),
            "details": {"isolation_forest": a_if, "stmp": a_st, "zero_day_patterns": patterns},
            "input": e, "simulated": True}
