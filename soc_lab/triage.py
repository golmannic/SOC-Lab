"""Alert correlation into incidents, response playbooks, and evaluation against ground truth."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .detections import Alert, severity_for

CORRELATION_WINDOW = timedelta(hours=24)
MATCH_SLACK = timedelta(hours=1)

PLAYBOOKS = {
    "BRUTE_FORCE": ["Block source IP at WAF", "Notify customer of failed login attempts"],
    "BRUTE_FORCE_SUCCESS": ["Lock online banking session and force password reset",
                            "Block source IP at WAF", "Require step-up MFA on next login"],
    "PASSWORD_SPRAY": ["Block source IP / ASN at WAF", "Check targeted accounts for later successful logins",
                       "Confirm rate limiting on login endpoint"],
    "IMPOSSIBLE_TRAVEL": ["Verify recent login with customer through a known channel",
                          "Check whether the IP is a known VPN or proxy exit node"],
    "NEW_PAYEE_HIGH_VALUE": ["Hold or recall the transfer", "Call customer back to confirm the payee"],
    "STRUCTURING": ["Escalate to BSA/AML team for SAR review", "Do not tip off the customer"],
    "CARD_TESTING": ["Block card and reissue", "Dispute fraudulent purchases",
                     "Block source IP for card-not-present traffic"],
    "MONEY_MULE_FANOUT": ["Freeze outbound transfers on account", "Contact originating bank for wire recall",
                          "Escalate to BSA/AML team for SAR review"],
}


@dataclass
class Incident:
    incident_id: str
    entity: str
    alerts: list[Alert] = field(default_factory=list)

    @property
    def first_seen(self) -> datetime:
        return min(a.first_seen for a in self.alerts)

    @property
    def last_seen(self) -> datetime:
        return max(a.last_seen for a in self.alerts)

    @property
    def rules(self) -> list[str]:
        return sorted({a.rule_id for a in self.alerts})

    @property
    def risk(self) -> int:
        # Highest alert score, plus 10 for each additional distinct rule (a chained attack).
        return min(100, max(a.score for a in self.alerts) + 10 * (len(self.rules) - 1))

    @property
    def severity(self) -> str:
        return severity_for(self.risk)

    @property
    def mitre(self) -> list[str]:
        return sorted({t for a in self.alerts for t in a.mitre})

    @property
    def actions(self) -> list[str]:
        seen: list[str] = []
        for a in sorted(self.alerts, key=lambda a: -a.score):
            for step in PLAYBOOKS.get(a.rule_id, []):
                if step not in seen:
                    seen.append(step)
        return seen


def correlate(alerts: list[Alert]) -> list[Incident]:
    """Group alerts on the same entity that occur within 24h of each other."""
    by_entity = defaultdict(list)
    for a in sorted(alerts, key=lambda a: a.first_seen):
        by_entity[a.entity].append(a)

    incidents: list[Incident] = []
    for entity, group in by_entity.items():
        current: Incident | None = None
        for a in group:
            if current and a.first_seen - current.last_seen <= CORRELATION_WINDOW:
                current.alerts.append(a)
            else:
                current = Incident("", entity, [a])
                incidents.append(current)

    incidents.sort(key=lambda i: (-i.risk, i.first_seen))
    for n, inc in enumerate(incidents, 1):
        inc.incident_id = f"INC-{n:04d}"
    return incidents


def _matches(alert: Alert, truth: dict) -> bool:
    return (alert.entity == truth["entity"]
            and alert.first_seen <= truth["end"] + MATCH_SLACK
            and alert.last_seen >= truth["start"] - MATCH_SLACK)


def evaluate(alerts: list[Alert], truth: list[dict]) -> dict:
    """Score alerts against injected ground truth.

    An alert is a true positive if it overlaps a malicious scenario on the same
    entity; otherwise it is a false positive (attributed to a benign scenario if
    one overlaps, else "unlabelled").
    """
    per_rule = defaultdict(lambda: {"tp": 0, "fp": 0})
    false_positives = []
    for a in alerts:
        hit = next((t for t in truth if _matches(a, t)), None)
        if hit and hit["malicious"]:
            per_rule[a.rule_id]["tp"] += 1
        else:
            per_rule[a.rule_id]["fp"] += 1
            false_positives.append({"alert": a, "cause": hit["scenario"] if hit else "unlabelled"})

    scenarios = []
    for t in truth:
        rules = sorted({a.rule_id for a in alerts if _matches(a, t)})
        scenarios.append({**t, "detected_by": rules, "detected": bool(rules)})

    malicious = [s for s in scenarios if s["malicious"]]
    tp = sum(r["tp"] for r in per_rule.values())
    fp = sum(r["fp"] for r in per_rule.values())
    return {
        "per_rule": dict(per_rule),
        "scenarios": scenarios,
        "false_positives": false_positives,
        "scenario_recall": sum(s["detected"] for s in malicious) / len(malicious) if malicious else 0.0,
        "alert_precision": tp / (tp + fp) if tp + fp else 0.0,
    }
