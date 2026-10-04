"""Markdown incident report and JSON export."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from .detections import Alert
from .triage import Incident


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%SZ")


def _json_default(o):
    if isinstance(o, datetime):
        return o.isoformat().replace("+00:00", "Z")
    raise TypeError(type(o))


def alert_dict(a: Alert) -> dict:
    return {**asdict(a), "severity": a.severity}


def incident_dict(i: Incident) -> dict:
    return {
        "incident_id": i.incident_id, "entity": i.entity, "severity": i.severity,
        "risk": i.risk, "first_seen": i.first_seen, "last_seen": i.last_seen,
        "rules": i.rules, "mitre": i.mitre, "recommended_actions": i.actions,
        "alerts": [alert_dict(a) for a in i.alerts],
    }


def write_outputs(out: Path, events, truth, alerts, incidents, metrics, seed) -> None:
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "events.jsonl", "w") as f:
        for e in events:
            f.write(json.dumps(e, default=_json_default) + "\n")
    dump = lambda name, obj: (out / name).write_text(json.dumps(obj, indent=2, default=_json_default))
    dump("ground_truth.json", truth)
    dump("alerts.json", [alert_dict(a) for a in alerts])
    dump("incidents.json", [incident_dict(i) for i in incidents])
    (out / "report.md").write_text(render_report(events, alerts, incidents, metrics, seed))


def render_report(events, alerts, incidents, metrics, seed) -> str:
    n_login = sum(e["event_type"] == "login" for e in events)
    n_txn = len(events) - n_login
    sev_counts = {s: sum(i.severity == s for i in incidents) for s in ("critical", "high", "medium", "low")}

    lines = [
        "# SOC Lab: Incident Report",
        "",
        f"Simulation seed `{seed}`, {_ts(events[0]['ts'])} to {_ts(events[-1]['ts'])}.",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Events ingested | {len(events):,} ({n_login:,} logins, {n_txn:,} transactions) |",
        f"| Alerts raised | {len(alerts)} |",
        f"| Incidents after correlation | {len(incidents)} "
        f"({sev_counts['critical']} critical, {sev_counts['high']} high, "
        f"{sev_counts['medium']} medium, {sev_counts['low']} low) |",
        f"| Attack scenarios detected (recall) | {metrics['scenario_recall']:.0%} |",
        f"| Alert precision | {metrics['alert_precision']:.0%} |",
        "",
        "## Detection performance",
        "",
        "| Rule | True positives | False positives | Precision |",
        "|---|---|---|---|",
    ]
    for rule, c in sorted(metrics["per_rule"].items()):
        total = c["tp"] + c["fp"]
        lines.append(f"| `{rule}` | {c['tp']} | {c['fp']} | {c['tp'] / total:.0%} |")

    lines += ["", "### Injected scenarios", "", "| Scenario | Entity | Malicious | Detected by |", "|---|---|---|---|"]
    for s in metrics["scenarios"]:
        det = ", ".join(f"`{r}`" for r in s["detected_by"])
        if s["malicious"]:
            det = det or "**MISSED**"
        else:
            det = f"{det} (false positive)" if det else "not flagged (correct)"
        lines.append(f"| {s['scenario']} | `{s['entity']}` | {'yes' if s['malicious'] else 'no (benign)'} | {det} |")

    if metrics["false_positives"]:
        lines += ["", "### False positives", ""]
        for fp in metrics["false_positives"]:
            a = fp["alert"]
            lines.append(f"- `{a.rule_id}` on `{a.entity}` at {_ts(a.first_seen)}, caused by "
                         f"**{fp['cause']}**: {json.dumps(a.evidence, default=_json_default)}")

    lines += ["", "## Incidents", ""]
    for inc in incidents:
        lines += [
            f"### {inc.incident_id}: {inc.severity.upper()} (risk {inc.risk}), `{inc.entity}`",
            "",
            f"- **Window:** {_ts(inc.first_seen)} to {_ts(inc.last_seen)}",
            f"- **Rules:** {', '.join(f'`{r}`' for r in inc.rules)}",
            f"- **MITRE ATT&CK:** {', '.join(inc.mitre) or 'n/a (financial-crime typology)'}",
            "",
            "| Time | Alert | Evidence |",
            "|---|---|---|",
        ]
        for a in sorted(inc.alerts, key=lambda a: a.first_seen):
            ev = "; ".join(f"{k}={v}" for k, v in a.evidence.items() if v is not None)
            lines.append(f"| {_ts(a.first_seen)} | {a.title} | {ev} |")
        lines += ["", "**Recommended actions:**", ""]
        lines += [f"{n}. {step}" for n, step in enumerate(inc.actions, 1)]
        lines.append("")
    return "\n".join(lines)
