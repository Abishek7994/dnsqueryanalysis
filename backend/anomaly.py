import math
import time
from collections import Counter, defaultdict, deque
from typing import Any

from validator import validate_regex


class AnomalyDetector:
    def __init__(self) -> None:
        self.client_queries: dict[str, deque[float]] = defaultdict(deque)
        self.rate_window_seconds = 10
        self.rate_spike_threshold = 12

    @staticmethod
    def entropy(value: str) -> float:
        if not value:
            return 0.0
        counts = Counter(value.lower())
        length = len(value)
        return -sum(
            (count / length) * math.log2(count / length) for count in counts.values()
        )

    def analyze(self, domain: str, client_ip: str, now: float | None = None) -> dict[str, Any]:
        current_time = now if now is not None else time.monotonic()
        history = self.client_queries[client_ip]
        history.append(current_time)
        while history and current_time - history[0] > self.rate_window_seconds:
            history.popleft()

        valid = validate_regex(domain)["is_valid"]
        labels = domain.rstrip(".").split(".") if domain else []
        subdomains = labels[:-2] if len(labels) > 2 else []
        payload = ".".join(subdomains)
        entropy = round(self.entropy(payload), 3)
        depth = len(subdomains)
        reasons: list[str] = []
        status = "NORMAL"

        if not valid:
            status = "MALFORMED"
            reasons.append("Malformed domain syntax; query would be rejected.")
        if depth > 4:
            reasons.append(f"Unusually deep subdomain ({depth} labels).")
        if len(payload) > 60:
            reasons.append(f"Long subdomain payload ({len(payload)} characters).")
        if payload and entropy > 3.8:
            reasons.append(f"High subdomain entropy ({entropy:.2f} bits); possible DGA or tunneling.")
        if len(history) > self.rate_spike_threshold:
            reasons.append(
                f"Client query rate spike ({len(history)} queries in {self.rate_window_seconds}s)."
            )

        if any("rate spike" in reason for reason in reasons):
            status = "CRITICAL" if valid else "MALFORMED"
        elif valid and reasons:
            status = "SUSPICIOUS"
        if not reasons:
            reasons.append("No anomaly detected.")

        return {
            "status": status,
            "entropy": entropy,
            "anomaly_reason": " ".join(reasons),
            "subdomain_depth": depth,
            "payload_length": len(payload),
            "client_rate": len(history),
        }
