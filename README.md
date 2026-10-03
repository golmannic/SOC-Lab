# SOC Lab: Bank Fraud & Account-Takeover Detection

![tests](https://github.com/golmannic/SOC-Lab/actions/workflows/tests.yml/badge.svg)

A self-contained Security Operations Center (SOC) lab for a simulated retail bank. It generates a month of realistic customer telemetry, injects labelled attacks, runs detection rules over the logs, correlates alerts into incidents, recommends response actions, and scores the detections against ground truth.

Pure Python standard library. No dependencies, no Docker, runs in about a second.

```
 generator.py          detections.py          triage.py                 report.py
┌──────────────┐     ┌────────────────┐     ┌──────────────────┐     ┌──────────────┐
│ 50 customers │     │ 7 rules        │     │ correlate alerts │     │ report.md    │
│ 30 days      │ ──▶ │ (auth + txn)   │ ──▶ │ → incidents      │ ──▶ │ alerts.json  │
│ + 6 attacks  │     │ MITRE-mapped   │     │ risk + playbooks │     │ incidents.json│
│ + 3 benign   │     └────────────────┘     │ eval vs truth    │     │ events.jsonl │
│   look-alikes│                            └──────────────────┘     └──────────────┘
└──────────────┘
```

## Quick start

```bash
python -m soc_lab                 # seed 42, writes ./output/
python -m soc_lab --seed 7 --users 100 --out runs/seed7
python -m unittest -v             # 13 tests, including a 10-seed regression sweep
```

```
Events:     6,003
Alerts:     12
Incidents:  7
Recall:     100% of attack scenarios detected
Precision:  92% of alerts were true positives

  INC-0001  critical risk=95  cust0034       MONEY_MULE_FANOUT, NEW_PAYEE_HIGH_VALUE
  INC-0002  critical risk=85  cust0044       CARD_TESTING
  INC-0003  critical risk=85  cust0007       BRUTE_FORCE_SUCCESS, NEW_PAYEE_HIGH_VALUE
  INC-0004  high     risk=75  cust0004       IMPOSSIBLE_TRAVEL, NEW_PAYEE_HIGH_VALUE
  INC-0005  high     risk=70  cust0009       STRUCTURING
  INC-0006  medium   risk=60  203.0.113.77   PASSWORD_SPRAY
  INC-0007  medium   risk=55  cust0002       IMPOSSIBLE_TRAVEL
```

A full example report is in [`sample_output/report.md`](sample_output/report.md).

## What gets simulated

**Normal activity** for each customer: logins from a home city and device (with an occasional mistyped password), card purchases, payroll on a schedule, rent and bill transfers to known payees, ATM withdrawals, and small cash deposits.

**Injected attacks**

| Scenario | What happens |
|---|---|
| Brute-force account takeover | 14 failed logins from one foreign IP, then success, then a $7,850 transfer to a new payee |
| Phished credentials / impossible travel | Login from Lagos 45 min after the real customer logged in from the US, then a transfer to a new payee |
| Password spray | One IP tries one password against 25 different accounts |
| Card testing | 9 sub-$3 online purchases across 6 merchants in ~6 min, then a $1,349.99 purchase |
| Structuring (BSA/AML) | Four cash deposits of $8.7k–$9.85k over 3 days, all just under the $10k CTR threshold |
| Money mule | $24.5k inbound wire fanned out to 5 new payees within 90 minutes |

**Benign look-alikes** (to measure false positives)

| Scenario | Why it is tricky |
|---|---|
| VPN user | Logs in from the US, then from a Romanian VPN exit 25 min later |
| Cross-country traveler | Logins far apart, but the travel speed is physically possible |
| Large legitimate transfer | $15,000 to a long-standing payee |

Labels go to `ground_truth.json`. Detections never see them.

## Detection rules

| Rule ID | Logic | MITRE ATT&CK / typology |
|---|---|---|
| `BRUTE_FORCE` / `BRUTE_FORCE_SUCCESS` | ≥5 failed logins, one account, one IP, gaps ≤10 min; escalates if a success follows within 30 min | T1110.001, T1078 |
| `PASSWORD_SPRAY` | One IP failing against ≥10 distinct accounts within 30 min | T1110.003 |
| `IMPOSSIBLE_TRAVEL` | Consecutive successful logins >500 km apart needing >900 km/h | T1078 |
| `NEW_PAYEE_HIGH_VALUE` | Transfer to a never-seen payee ≥ max($1,000, 3× the customer's average), after a 7-day learning period | T1657 |
| `STRUCTURING` | ≥3 cash deposits of $8k–$10k within 72 h | BSA/AML structuring |
| `CARD_TESTING` | ≥5 sub-$5 card purchases across ≥3 merchants; critical if a ≥$500 purchase follows within 1 h | Card-not-present fraud |
| `MONEY_MULE_FANOUT` | ≥$10k inbound, then ≥3 distinct outbound payees moving ≥50% of it within 2 h | AML layering |

Thresholds are constants at the top of each rule in [`soc_lab/detections.py`](soc_lab/detections.py).

## Triage and incident response

- **Correlation:** alerts on the same entity (customer or IP) within 24 h become one incident. A brute force followed by a new-payee transfer turns into a single critical account-takeover incident instead of two separate tickets.
- **Risk scoring:** the incident's risk is its highest alert score plus 10 for each additional distinct rule, because chained behaviour is more suspicious than any single signal.
- **Playbooks:** each rule maps to response steps (lock the session, recall the wire, reissue the card, escalate to BSA/AML for SAR review). These are merged and listed per incident.
- **Evaluation:** an alert counts as a true positive if it overlaps a malicious scenario on the same entity. The report shows precision per rule, which scenarios were caught, and why each false positive fired.

## Findings and tuning notes

Across seeds 1–30, every attack scenario is detected. Every false positive in that sweep comes from the VPN look-alike. This is the classic weakness of impossible-travel detection, and these are the usual fixes:

1. Enrich source IPs with VPN/hosting-provider intelligence and suppress or downgrade known VPN exit nodes.
2. Use device fingerprint continuity: the same device on a new IP is less suspicious than a new device.
3. Raise severity only when impossible travel is followed by a sensitive action (a new payee, a password change). Correlation already does this.

Another limitation shows up in the sample money-mule incident: `NEW_PAYEE_HIGH_VALUE` flags only 3 of the 5 mule transfers, because the attacker's own transfers raise the customer's average. A production rule would compute the baseline from a fixed lookback window that excludes the current session.

## Output files

| File | Contents |
|---|---|
| `events.jsonl` | Every login and transaction, one JSON object per line. Can be loaded into Splunk, Elastic, or `jq` |
| `alerts.json` | Every alert with rule, score, severity, MITRE techniques, evidence, and source event IDs |
| `incidents.json` | Correlated incidents with timeline, risk, and recommended actions |
| `ground_truth.json` | Injected scenario labels |
| `report.md` | Human-readable SOC report |

## Project layout

```
soc_lab/
  generator.py    synthetic customers, normal behaviour, attack + benign scenarios
  detections.py   detection rules and the Alert model
  triage.py       correlation, risk scoring, playbooks, evaluation
  report.py       Markdown / JSON output
  __main__.py     CLI
tests/            unit tests per rule + end-to-end regression across seeds
sample_output/    example report (seed 42)
archive/          earlier unrelated FastAPI course-registration exercise
```

## Ideas for extending

- Load `events.jsonl` into Splunk or Elastic and rewrite the rules as SPL / KQL / Sigma.
- Add a VPN-exit allowlist and measure how precision changes.
- Add scenarios: SIM swap (phone number change followed by a password reset), new-device enrollment then wire transfer, or an insider looking up many customer records.
- Replace the static `3×` multiplier with a per-customer z-score or an isolation forest and compare results.

All IP addresses use the RFC 5737 documentation ranges, and all customers are synthetic.
