"""Run the full pipeline: simulate -> detect -> correlate -> evaluate -> report."""

from __future__ import annotations

import argparse
from pathlib import Path

from .detections import run_detections
from .generator import generate
from .report import write_outputs
from .triage import correlate, evaluate


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="soc_lab", description=__doc__)
    p.add_argument("--seed", type=int, default=42, help="random seed (default: 42)")
    p.add_argument("--users", type=int, default=50, help="number of simulated customers (min 30)")
    p.add_argument("--out", type=Path, default=Path("output"), help="output directory")
    args = p.parse_args(argv)

    events, truth = generate(seed=args.seed, n_users=args.users)
    alerts = run_detections(events)
    incidents = correlate(alerts)
    metrics = evaluate(alerts, truth)
    write_outputs(args.out, events, truth, alerts, incidents, metrics, args.seed)

    print(f"Events:     {len(events):,}")
    print(f"Alerts:     {len(alerts)}")
    print(f"Incidents:  {len(incidents)}")
    print(f"Recall:     {metrics['scenario_recall']:.0%} of attack scenarios detected")
    print(f"Precision:  {metrics['alert_precision']:.0%} of alerts were true positives")
    print()
    for inc in incidents:
        print(f"  {inc.incident_id}  {inc.severity:<8} risk={inc.risk:<3} {inc.entity:<14} {', '.join(inc.rules)}")
    print(f"\nReport written to {args.out / 'report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
