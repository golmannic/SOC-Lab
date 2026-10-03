import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from soc_lab import detections as d
from soc_lab.__main__ import main
from soc_lab.generator import generate
from soc_lab.triage import correlate, evaluate

T0 = datetime(2026, 9, 10, 12, tzinfo=timezone.utc)
NYC = {"city": "New York", "lat": 40.71, "lon": -74.01}
LAGOS = {"city": "Lagos", "lat": 6.52, "lon": 3.38}
LA = {"city": "Los Angeles", "lat": 34.05, "lon": -118.24}


def login(minutes, success=True, user="u1", ip="198.51.100.1", geo=NYC):
    return {"event_id": f"L{minutes}{user}{ip}", "ts": T0 + timedelta(minutes=minutes),
            "event_type": "login", "user": user, "src_ip": ip, "success": success,
            "user_agent": "test", **geo}


def txn(minutes, txn_type, amount, counterparty="Shop", user="u1"):
    return {"event_id": f"T{minutes}{counterparty}", "ts": T0 + timedelta(minutes=minutes),
            "event_type": "transaction", "user": user, "txn_type": txn_type, "amount": amount,
            "counterparty": counterparty, "channel": "web", "src_ip": "198.51.100.1",
            "city": "New York"}


class BruteForceTests(unittest.TestCase):
    def test_failures_then_success_escalates(self):
        evs = [login(i, success=False, ip="203.0.113.9") for i in range(6)] + [login(7, ip="203.0.113.9")]
        [alert] = d.brute_force(evs)
        self.assertEqual(alert.rule_id, "BRUTE_FORCE_SUCCESS")
        self.assertEqual(alert.severity, "high")

    def test_few_failures_ignored(self):
        evs = [login(i, success=False) for i in range(3)] + [login(4)]
        self.assertEqual(d.brute_force(evs), [])

    def test_password_spray(self):
        evs = [login(i, success=False, user=f"u{i}", ip="203.0.113.77") for i in range(12)]
        [alert] = d.password_spray(evs)
        self.assertEqual(alert.entity, "203.0.113.77")
        self.assertEqual(d.brute_force(evs), [])


class TravelTests(unittest.TestCase):
    def test_impossible_travel(self):
        [alert] = d.impossible_travel([login(0), login(45, geo=LAGOS)])
        self.assertGreater(alert.evidence["implied_kmh"], 900)

    def test_plausible_flight(self):
        self.assertEqual(d.impossible_travel([login(0), login(8 * 60, geo=LA)]), [])


class TransactionTests(unittest.TestCase):
    def test_new_payee_after_learning_period(self):
        history = [txn(i * 24 * 60, "transfer_out", 200, "Friend") for i in range(8)]
        [alert] = d.new_payee_high_value(history + [txn(9 * 24 * 60, "transfer_out", 5000, "Stranger")])
        self.assertEqual(alert.evidence["payee"], "Stranger")

    def test_large_transfer_to_known_payee_ok(self):
        history = [txn(i * 24 * 60, "transfer_out", 200, "Landlord") for i in range(8)]
        self.assertEqual(d.new_payee_high_value(history + [txn(9 * 24 * 60, "transfer_out", 15000, "Landlord")]), [])

    def test_structuring(self):
        evs = [txn(h * 60, "cash_deposit", 9500) for h in (0, 20, 40)]
        self.assertEqual(len(d.structuring(evs)), 1)
        self.assertEqual(d.structuring([txn(0, "cash_deposit", 9500), txn(60, "cash_deposit", 12000)]), [])

    def test_card_testing(self):
        evs = [txn(i, "card_purchase", 1.00, f"M{i % 4}") for i in range(6)]
        [alert] = d.card_testing(evs + [txn(10, "card_purchase", 999, "Electronics")])
        self.assertEqual(alert.severity, "critical")

    def test_money_mule(self):
        evs = [txn(0, "wire_in", 20000, "Origin")] + [txn(10 + i * 10, "transfer_out", 4000, f"P{i}") for i in range(4)]
        self.assertEqual(len(d.money_mule(evs)), 1)


class EndToEndTests(unittest.TestCase):
    def test_all_attacks_detected_across_seeds(self):
        for seed in range(1, 11):
            events, truth = generate(seed=seed)
            alerts = d.run_detections(events)
            metrics = evaluate(alerts, truth)
            self.assertEqual(metrics["scenario_recall"], 1.0, f"seed {seed}")
            causes = {fp["cause"] for fp in metrics["false_positives"]}
            self.assertLessEqual(causes, {"benign_vpn"}, f"seed {seed}")

    def test_ato_chain_correlates_into_one_incident(self):
        events, truth = generate(seed=42)
        victim = next(t["entity"] for t in truth if t["scenario"] == "brute_force_ato")
        [inc] = [i for i in correlate(d.run_detections(events)) if i.entity == victim]
        self.assertEqual(inc.rules, ["BRUTE_FORCE_SUCCESS", "NEW_PAYEE_HIGH_VALUE"])
        self.assertEqual(inc.severity, "critical")

    def test_cli_writes_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            main(["--seed", "1", "--out", tmp])
            for name in ("events.jsonl", "alerts.json", "incidents.json", "ground_truth.json", "report.md"):
                self.assertTrue((Path(tmp) / name).stat().st_size > 0, name)


if __name__ == "__main__":
    unittest.main()
