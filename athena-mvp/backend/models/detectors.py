"""Simulated detectors. Each exposes score(event)->float in [0,1].
Replace the bodies with real models (e.g. scikit-learn IsolationForest via joblib)
and keep the same interface; nothing else needs to change."""
import random, zlib

def _rng(e):
    key = f"{e.get('source_ip')}{e.get('destination_ip')}{e.get('protocol')}{e.get('packet_count')}"
    return random.Random(zlib.crc32(key.encode()))  # deterministic noise per input

class IsolationForestSim:
    name = "Isolation Forest"
    def score(self, e):
        pc = min(e["packet_count"] / 600, 1.0)
        return round(min(0.15 + 0.7 * pc + _rng(e).uniform(0, 0.15), 0.99), 2)

class STMPSim:
    """Placeholder for statistical threat modeling (baseline deviation)."""
    name = "STMP"
    def score(self, e):
        base = {"TCP": 0.35, "UDP": 0.45, "ICMP": 0.55, "DNS": 0.4}.get(e["protocol"], 0.6)
        pc = min(e["packet_count"] / 800, 1.0)
        return round(min(base * 0.5 + pc * 0.5 + _rng(e).uniform(0, 0.1), 0.99), 2)

class ZeroDayLabSim:
    name = "Zero-Day Lab"
    def patterns(self, e, anomaly):
        return max(0, min(int(anomaly * 8 + _rng(e).randint(0, 1)), 9))
