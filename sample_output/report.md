# SOC Lab: Incident Report

Simulation seed `42`, 2026-09-01 06:00:00Z to 2026-09-30 22:57:17Z.

## Summary

| Metric | Value |
|---|---|
| Events ingested | 6,003 (2,415 logins, 3,588 transactions) |
| Alerts raised | 12 |
| Incidents after correlation | 7 (3 critical, 2 high, 2 medium, 0 low) |
| Attack scenarios detected (recall) | 100% |
| Alert precision | 92% |

## Detection performance

| Rule | True positives | False positives | Precision |
|---|---|---|---|
| `BRUTE_FORCE_SUCCESS` | 1 | 0 | 100% |
| `CARD_TESTING` | 1 | 0 | 100% |
| `IMPOSSIBLE_TRAVEL` | 1 | 1 | 50% |
| `MONEY_MULE_FANOUT` | 1 | 0 | 100% |
| `NEW_PAYEE_HIGH_VALUE` | 5 | 0 | 100% |
| `PASSWORD_SPRAY` | 1 | 0 | 100% |
| `STRUCTURING` | 1 | 0 | 100% |

### Injected scenarios

| Scenario | Entity | Malicious | Detected by |
|---|---|---|---|
| benign_traveler | `cust0023` | no (benign) | not flagged (correct) |
| benign_vpn | `cust0002` | no (benign) | `IMPOSSIBLE_TRAVEL` (false positive) |
| password_spray | `203.0.113.77` | yes | `PASSWORD_SPRAY` |
| structuring | `cust0009` | yes | `STRUCTURING` |
| card_testing | `cust0044` | yes | `CARD_TESTING` |
| benign_large_transfer | `cust0037` | no (benign) | not flagged (correct) |
| brute_force_ato | `cust0007` | yes | `BRUTE_FORCE_SUCCESS`, `NEW_PAYEE_HIGH_VALUE` |
| impossible_travel_ato | `cust0004` | yes | `IMPOSSIBLE_TRAVEL`, `NEW_PAYEE_HIGH_VALUE` |
| money_mule | `cust0034` | yes | `MONEY_MULE_FANOUT`, `NEW_PAYEE_HIGH_VALUE` |

### False positives

- `IMPOSSIBLE_TRAVEL` on `cust0002` at 2026-09-19 10:00:00Z, caused by **benign_vpn**: {"from": "Seattle (198.51.100.3)", "to": "Bucharest (203.0.113.200)", "distance_km": 9326, "implied_kmh": 22381}

## Incidents

### INC-0001: CRITICAL (risk 95), `cust0034`

- **Window:** 2026-09-28 10:05:00Z to 2026-09-28 11:26:00Z
- **Rules:** `MONEY_MULE_FANOUT`, `NEW_PAYEE_HIGH_VALUE`
- **MITRE ATT&CK:** T1657

| Time | Alert | Evidence |
|---|---|---|
| 2026-09-28 10:05:00Z | Inbound funds rapidly fanned out (mule pattern) | inbound=24500.0; inbound_from=WIRE-ORIG-77120; outbound_total=23746.35; payees=5; pct_moved=97 |
| 2026-09-28 10:30:00Z | High-value transfer to a new payee | payee=EXT-MULE-4400; amount=4715.68; avg_transfer=488.24; channel=mobile; src_ip=198.51.100.35; geo=Houston |
| 2026-09-28 10:45:00Z | High-value transfer to a new payee | payee=EXT-MULE-4401; amount=4685.44; avg_transfer=957.95; channel=mobile; src_ip=198.51.100.35; geo=Houston |
| 2026-09-28 10:58:00Z | High-value transfer to a new payee | payee=EXT-MULE-4402; amount=4689.32; avg_transfer=1330.7; channel=mobile; src_ip=198.51.100.35; geo=Houston |

**Recommended actions:**

1. Freeze outbound transfers on account
2. Contact originating bank for wire recall
3. Escalate to BSA/AML team for SAR review
4. Hold or recall the transfer
5. Call customer back to confirm the payee

### INC-0002: CRITICAL (risk 85), `cust0044`

- **Window:** 2026-09-23 03:12:00Z to 2026-09-23 03:20:17Z
- **Rules:** `CARD_TESTING`
- **MITRE ATT&CK:** T1657

| Time | Alert | Evidence |
|---|---|---|
| 2026-09-23 03:12:00Z | Card testing (micro-transactions) | micro_txns=9; merchants=6; src_ip=203.0.113.30; geo=Sao Paulo; cash_out_purchase=1349.99 |

**Recommended actions:**

1. Block card and reissue
2. Dispute fraudulent purchases
3. Block source IP for card-not-present traffic

### INC-0003: CRITICAL (risk 85), `cust0007`

- **Window:** 2026-09-25 02:10:00Z to 2026-09-25 02:23:28Z
- **Rules:** `BRUTE_FORCE_SUCCESS`, `NEW_PAYEE_HIGH_VALUE`
- **MITRE ATT&CK:** T1078, T1110.001, T1657

| Time | Alert | Evidence |
|---|---|---|
| 2026-09-25 02:10:00Z | Brute force followed by successful login | src_ip=203.0.113.10; failed_attempts=14; geo=Moscow; user_agent=python-requests/2.32.3 |
| 2026-09-25 02:23:28Z | High-value transfer to a new payee | payee=EXT-PAYEE-5521; amount=7850.0; avg_transfer=521.03; channel=web; src_ip=203.0.113.10; geo=Moscow |

**Recommended actions:**

1. Lock online banking session and force password reset
2. Block source IP at WAF
3. Require step-up MFA on next login
4. Hold or recall the transfer
5. Call customer back to confirm the payee

### INC-0004: HIGH (risk 75), `cust0004`

- **Window:** 2026-09-27 13:00:00Z to 2026-09-27 13:52:00Z
- **Rules:** `IMPOSSIBLE_TRAVEL`, `NEW_PAYEE_HIGH_VALUE`
- **MITRE ATT&CK:** T1078, T1657

| Time | Alert | Evidence |
|---|---|---|
| 2026-09-27 13:00:00Z | Impossible travel between logins | from=Houston (198.51.100.5); to=Lagos (203.0.113.20); distance_km=10485; implied_kmh=13980 |
| 2026-09-27 13:52:00Z | High-value transfer to a new payee | payee=EXT-PAYEE-8830; amount=4200.0; avg_transfer=393.13; channel=web; src_ip=203.0.113.20; geo=Lagos |

**Recommended actions:**

1. Hold or recall the transfer
2. Call customer back to confirm the payee
3. Verify recent login with customer through a known channel
4. Check whether the IP is a known VPN or proxy exit node

### INC-0005: HIGH (risk 70), `cust0009`

- **Window:** 2026-09-22 10:55:00Z to 2026-09-24 12:25:00Z
- **Rules:** `STRUCTURING`
- **MITRE ATT&CK:** n/a (financial-crime typology)

| Time | Alert | Evidence |
|---|---|---|
| 2026-09-22 10:55:00Z | Cash deposits structured below CTR threshold | deposits=4; total=37050; locations=['Branch-0', 'Branch-1', 'Branch-2', 'Branch-3'] |

**Recommended actions:**

1. Escalate to BSA/AML team for SAR review
2. Do not tip off the customer

### INC-0006: MEDIUM (risk 60), `203.0.113.77`

- **Window:** 2026-09-20 04:00:00Z to 2026-09-20 04:18:09Z
- **Rules:** `PASSWORD_SPRAY`
- **MITRE ATT&CK:** T1110.003

| Time | Alert | Evidence |
|---|---|---|
| 2026-09-20 04:00:00Z | Password spraying from a single IP | distinct_accounts=25; attempts=25; geo=Bucharest; user_agent=python-requests/2.32.3 |

**Recommended actions:**

1. Block source IP / ASN at WAF
2. Check targeted accounts for later successful logins
3. Confirm rate limiting on login endpoint

### INC-0007: MEDIUM (risk 55), `cust0002`

- **Window:** 2026-09-19 10:00:00Z to 2026-09-19 10:25:00Z
- **Rules:** `IMPOSSIBLE_TRAVEL`
- **MITRE ATT&CK:** T1078

| Time | Alert | Evidence |
|---|---|---|
| 2026-09-19 10:00:00Z | Impossible travel between logins | from=Seattle (198.51.100.3); to=Bucharest (203.0.113.200); distance_km=9326; implied_kmh=22381 |

**Recommended actions:**

1. Verify recent login with customer through a known channel
2. Check whether the IP is a known VPN or proxy exit node
