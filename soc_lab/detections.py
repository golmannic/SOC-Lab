"""Detection rules.

Each rule takes the full, time-sorted event list and returns Alerts. Rules only
look at fields a real SIEM would have (no ground-truth labels).
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta


@dataclass
class Alert:
    rule_id: str
    title: str
    score: int
    entity: str
    first_seen: datetime
    last_seen: datetime
    mitre: list[str]
    evidence: dict
    event_ids: list[str] = field(default_factory=list)

    @property
    def severity(self) -> str:
        return severity_for(self.score)


def severity_for(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 6371 * 2 * math.asin(math.sqrt(a))


def _clusters(events: list[dict], gap: timedelta) -> list[list[dict]]:
    """Split time-sorted events into runs where consecutive events are <= gap apart."""
    out: list[list[dict]] = []
    for e in events:
        if out and e["ts"] - out[-1][-1]["ts"] <= gap:
            out[-1].append(e)
        else:
            out.append([e])
    return out


def _logins(events, success=None):
    return [e for e in events if e["event_type"] == "login"
            and (success is None or e["success"] == success)]


def _txns(events, *types):
    return [e for e in events if e["event_type"] == "transaction"
            and (not types or e["txn_type"] in types)]


# --------------------------------------------------------------------- rules
BRUTE_FORCE_THRESHOLD = 5          # failed logins
BRUTE_FORCE_GAP = timedelta(minutes=10)


def brute_force(events: list[dict]) -> list[Alert]:
    """>= 5 failed logins on one account from one IP, optionally followed by success."""
    fails = defaultdict(list)
    for e in _logins(events, success=False):
        fails[(e["user"], e["src_ip"])].append(e)
    successes = defaultdict(list)
    for e in _logins(events, success=True):
        successes[(e["user"], e["src_ip"])].append(e)

    alerts = []
    for (user, ip), evs in fails.items():
        for burst in _clusters(evs, BRUTE_FORCE_GAP):
            if len(burst) < BRUTE_FORCE_THRESHOLD:
                continue
            end = burst[-1]["ts"]
            win = [s for s in successes[(user, ip)] if end <= s["ts"] <= end + timedelta(minutes=30)]
            ids = [e["event_id"] for e in burst]
            if win:
                ids.append(win[0]["event_id"])
                alerts.append(Alert(
                    "BRUTE_FORCE_SUCCESS", "Brute force followed by successful login", 75,
                    user, burst[0]["ts"], win[0]["ts"], ["T1110.001", "T1078"],
                    {"src_ip": ip, "failed_attempts": len(burst), "geo": burst[0]["city"],
                     "user_agent": burst[0]["user_agent"]}, ids))
            else:
                alerts.append(Alert(
                    "BRUTE_FORCE", "Repeated failed logins on one account", 45,
                    user, burst[0]["ts"], end, ["T1110.001"],
                    {"src_ip": ip, "failed_attempts": len(burst)}, ids))
    return alerts


PASSWORD_SPRAY_USERS = 10
PASSWORD_SPRAY_WINDOW = timedelta(minutes=30)


def password_spray(events: list[dict]) -> list[Alert]:
    """One source IP failing against >= 10 distinct accounts within 30 minutes."""
    by_ip = defaultdict(list)
    for e in _logins(events, success=False):
        by_ip[e["src_ip"]].append(e)

    alerts = []
    for ip, evs in by_ip.items():
        for burst in _clusters(evs, PASSWORD_SPRAY_WINDOW):
            users = {e["user"] for e in burst}
            if len(users) >= PASSWORD_SPRAY_USERS:
                alerts.append(Alert(
                    "PASSWORD_SPRAY", "Password spraying from a single IP", 60,
                    ip, burst[0]["ts"], burst[-1]["ts"], ["T1110.003"],
                    {"distinct_accounts": len(users), "attempts": len(burst),
                     "geo": burst[0]["city"], "user_agent": burst[0]["user_agent"]},
                    [e["event_id"] for e in burst]))
    return alerts


MAX_TRAVEL_KMH = 900               # roughly airliner cruise speed
MIN_TRAVEL_KM = 500


def impossible_travel(events: list[dict]) -> list[Alert]:
    """Two successful logins for one user that would require > 900 km/h travel."""
    by_user = defaultdict(list)
    for e in _logins(events, success=True):
        by_user[e["user"]].append(e)

    alerts = []
    for user, evs in by_user.items():
        for a, b in zip(evs, evs[1:]):
            km = haversine_km(a["lat"], a["lon"], b["lat"], b["lon"])
            hours = max((b["ts"] - a["ts"]).total_seconds() / 3600, 1 / 60)
            if km >= MIN_TRAVEL_KM and km / hours > MAX_TRAVEL_KMH:
                alerts.append(Alert(
                    "IMPOSSIBLE_TRAVEL", "Impossible travel between logins", 55,
                    user, a["ts"], b["ts"], ["T1078"],
                    {"from": f"{a['city']} ({a['src_ip']})", "to": f"{b['city']} ({b['src_ip']})",
                     "distance_km": round(km), "implied_kmh": round(km / hours)},
                    [a["event_id"], b["event_id"]]))
    return alerts


NEW_PAYEE_MULTIPLIER = 3
NEW_PAYEE_MIN_AMOUNT = 1000
LEARNING_PERIOD = timedelta(days=7)


def new_payee_high_value(events: list[dict]) -> list[Alert]:
    """Outbound transfer to a never-seen payee that is >= 3x the customer's average transfer."""
    first_seen: dict[str, datetime] = {}
    known = defaultdict(set)
    history = defaultdict(list)
    alerts = []
    for e in _txns(events, "transfer_out"):
        user = e["user"]
        first_seen.setdefault(user, e["ts"])
        payee, amount = e["counterparty"], e["amount"]
        baseline = sum(history[user]) / len(history[user]) if history[user] else 0
        learned = e["ts"] - first_seen[user] >= LEARNING_PERIOD
        if (learned and payee not in known[user]
                and amount >= max(NEW_PAYEE_MIN_AMOUNT, NEW_PAYEE_MULTIPLIER * baseline)):
            alerts.append(Alert(
                "NEW_PAYEE_HIGH_VALUE", "High-value transfer to a new payee", 65,
                user, e["ts"], e["ts"], ["T1657"],
                {"payee": payee, "amount": amount, "avg_transfer": round(baseline, 2),
                 "channel": e["channel"], "src_ip": e["src_ip"], "geo": e["city"]},
                [e["event_id"]]))
        known[user].add(payee)
        history[user].append(amount)
    return alerts


CTR_THRESHOLD = 10_000
STRUCTURING_FLOOR = 8_000
STRUCTURING_COUNT = 3
STRUCTURING_WINDOW = timedelta(hours=72)


def structuring(events: list[dict]) -> list[Alert]:
    """>= 3 cash deposits between $8k and $10k within 72h (BSA/AML structuring)."""
    by_user = defaultdict(list)
    for e in _txns(events, "cash_deposit"):
        if STRUCTURING_FLOOR <= e["amount"] < CTR_THRESHOLD:
            by_user[e["user"]].append(e)

    alerts = []
    for user, evs in by_user.items():
        i = 0
        while i < len(evs):
            win = [e for e in evs[i:] if e["ts"] - evs[i]["ts"] <= STRUCTURING_WINDOW]
            if len(win) >= STRUCTURING_COUNT:
                alerts.append(Alert(
                    "STRUCTURING", "Cash deposits structured below CTR threshold", 70,
                    user, win[0]["ts"], win[-1]["ts"], [],
                    {"deposits": len(win), "total": round(sum(e["amount"] for e in win), 2),
                     "locations": sorted({e["counterparty"] for e in win})},
                    [e["event_id"] for e in win]))
                i += len(win)
            else:
                i += 1
    return alerts


CARD_TEST_MAX_AMOUNT = 5.00
CARD_TEST_COUNT = 5
CARD_TEST_MERCHANTS = 3
CARD_TEST_GAP = timedelta(minutes=10)


def card_testing(events: list[dict]) -> list[Alert]:
    """>= 5 sub-$5 card purchases across >= 3 merchants in quick succession."""
    by_user = defaultdict(list)
    for e in _txns(events, "card_purchase"):
        if e["amount"] < CARD_TEST_MAX_AMOUNT:
            by_user[e["user"]].append(e)
    purchases = defaultdict(list)
    for e in _txns(events, "card_purchase"):
        purchases[e["user"]].append(e)

    alerts = []
    for user, evs in by_user.items():
        for burst in _clusters(evs, CARD_TEST_GAP):
            merchants = {e["counterparty"] for e in burst}
            if len(burst) >= CARD_TEST_COUNT and len(merchants) >= CARD_TEST_MERCHANTS:
                end = burst[-1]["ts"]
                follow = [p for p in purchases[user]
                          if end < p["ts"] <= end + timedelta(hours=1) and p["amount"] >= 500]
                alerts.append(Alert(
                    "CARD_TESTING", "Card testing (micro-transactions)", 85 if follow else 65,
                    user, burst[0]["ts"], (follow[0] if follow else burst[-1])["ts"], ["T1657"],
                    {"micro_txns": len(burst), "merchants": len(merchants),
                     "src_ip": burst[0]["src_ip"], "geo": burst[0]["city"],
                     "cash_out_purchase": follow[0]["amount"] if follow else None},
                    [e["event_id"] for e in burst + follow[:1]]))
    return alerts


MULE_INBOUND_MIN = 10_000
MULE_WINDOW = timedelta(hours=2)
MULE_PAYEES = 3


def money_mule(events: list[dict]) -> list[Alert]:
    """Large inbound credit fanned out to >= 3 distinct payees within 2h, moving >= 50% of it."""
    txns = _txns(events)
    by_user = defaultdict(list)
    for e in txns:
        by_user[e["user"]].append(e)

    alerts = []
    for user, evs in by_user.items():
        for e in evs:
            if e["txn_type"] not in ("wire_in", "transfer_in") or e["amount"] < MULE_INBOUND_MIN:
                continue
            outs = [o for o in evs if o["txn_type"] == "transfer_out"
                    and e["ts"] < o["ts"] <= e["ts"] + MULE_WINDOW]
            payees = {o["counterparty"] for o in outs}
            moved = sum(o["amount"] for o in outs)
            if len(payees) >= MULE_PAYEES and moved >= 0.5 * e["amount"]:
                alerts.append(Alert(
                    "MONEY_MULE_FANOUT", "Inbound funds rapidly fanned out (mule pattern)", 85,
                    user, e["ts"], outs[-1]["ts"], [],
                    {"inbound": e["amount"], "inbound_from": e["counterparty"],
                     "outbound_total": round(moved, 2), "payees": len(payees),
                     "pct_moved": round(100 * moved / e["amount"])},
                    [e["event_id"]] + [o["event_id"] for o in outs]))
    return alerts


RULES = [
    brute_force,
    password_spray,
    impossible_travel,
    new_payee_high_value,
    structuring,
    card_testing,
    money_mule,
]


def run_detections(events: list[dict]) -> list[Alert]:
    alerts = [a for rule in RULES for a in rule(events)]
    return sorted(alerts, key=lambda a: a.first_seen)
