"""Synthetic retail-bank telemetry generator.

Produces 30 days of normal customer activity (logins, card purchases,
transfers, payroll, ATM and cash activity), then injects labelled attack
scenarios and benign look-alikes on top. The labels are written to a separate
ground-truth list so detections never see them.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

START = datetime(2026, 9, 1, tzinfo=timezone.utc)
DAYS = 30

# city -> (country, lat, lon)
HOME_CITIES = {
    "New York": ("US", 40.71, -74.01),
    "Chicago": ("US", 41.88, -87.63),
    "Los Angeles": ("US", 34.05, -118.24),
    "Houston": ("US", 29.76, -95.37),
    "Miami": ("US", 25.76, -80.19),
    "Seattle": ("US", 47.61, -122.33),
}
FOREIGN_CITIES = {
    "Moscow": ("RU", 55.76, 37.62),
    "Lagos": ("NG", 6.52, 3.38),
    "Bucharest": ("RO", 44.43, 26.10),
    "Sao Paulo": ("BR", -23.55, -46.63),
}
CITIES = {**HOME_CITIES, **FOREIGN_CITIES}

MERCHANTS = [
    "Whole Foods", "Shell", "Starbucks", "Target", "Amazon", "Uber",
    "Netflix", "CVS Pharmacy", "Home Depot", "Chipotle", "Costco", "Spotify",
]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Safari/17.5",
    "BankApp/5.2 (iPhone; iOS 18.0)",
    "BankApp/5.2 (Android 14; Pixel 8)",
]
ATTACKER_UA = "python-requests/2.32.3"


@dataclass
class Customer:
    user: str
    account: str
    city: str
    ip: str
    user_agent: str
    salary: float
    rent: float
    payees: dict[str, tuple[float, float]] = field(default_factory=dict)


class Simulator:
    def __init__(self, seed: int = 42, n_users: int = 50):
        if n_users < 30:
            raise ValueError("n_users must be >= 30 (password spray needs 25 targets)")
        self.rng = random.Random(seed)
        self.events: list[dict] = []
        self.truth: list[dict] = []
        self.customers = [self._make_customer(i) for i in range(n_users)]
        self._skip_logins: set[tuple[str, int]] = set()

    # ---------------------------------------------------------------- helpers
    def _make_customer(self, i: int) -> Customer:
        r = self.rng
        payees = {
            f"Utility-{r.randint(100, 999)}": (60, 220),
            f"P2P-{r.choice(['Alex', 'Sam', 'Jordan', 'Taylor', 'Casey'])}-{i}": (20, 300),
            f"CreditCard-{r.randint(1000, 9999)}": (200, 1500),
        }
        rent = round(r.uniform(1200, 2800), -1)
        payees["Landlord-" + str(i)] = (rent, rent)
        return Customer(
            user=f"cust{i:04d}",
            account=f"ACCT-{100000 + i}",
            city=r.choice(list(HOME_CITIES)),
            ip=f"198.51.100.{i + 1}",
            user_agent=r.choice(USER_AGENTS),
            salary=round(r.uniform(3800, 12000), 2),
            rent=rent,
            payees=payees,
        )

    @staticmethod
    def _day(d: int, hour: int = 0, minute: int = 0, second: int = 0) -> datetime:
        return START + timedelta(days=d, hours=hour, minutes=minute, seconds=second)

    def _rand_time(self, d: int, lo: int = 7, hi: int = 23) -> datetime:
        return self._day(d) + timedelta(seconds=self.rng.randint(lo * 3600, hi * 3600 - 1))

    def _login(self, ts, c: Customer, success: bool, *, ip=None, city=None, ua=None):
        city = city or c.city
        country, lat, lon = CITIES[city]
        self.events.append({
            "ts": ts, "event_type": "login", "user": c.user,
            "src_ip": ip or c.ip, "city": city, "country": country,
            "lat": lat, "lon": lon, "user_agent": ua or c.user_agent,
            "success": success,
        })

    def _txn(self, ts, c: Customer, txn_type: str, amount: float, channel: str,
             counterparty: str, *, ip=None, city=None):
        city = city or c.city
        direction = "credit" if txn_type in {"payroll", "transfer_in", "cash_deposit", "wire_in"} else "debit"
        self.events.append({
            "ts": ts, "event_type": "transaction", "user": c.user,
            "account": c.account, "txn_type": txn_type, "direction": direction,
            "amount": round(amount, 2), "currency": "USD", "channel": channel,
            "counterparty": counterparty, "city": city,
            "country": CITIES[city][0], "src_ip": ip or c.ip,
        })

    def _label(self, scenario: str, entity: str, start: datetime, end: datetime,
               malicious: bool, description: str):
        self.truth.append({
            "scenario": scenario, "entity": entity, "start": start, "end": end,
            "malicious": malicious, "description": description,
        })

    # ------------------------------------------------------- normal behaviour
    def _normal_day(self, c: Customer, d: int):
        r = self.rng
        if (c.user, d) not in self._skip_logins:
            for _ in range(r.choice([0, 1, 1, 2, 2, 3])):
                ts = self._rand_time(d)
                if r.random() < 0.04:  # fat-fingered password, then success
                    for k in range(r.randint(1, 3)):
                        self._login(ts - timedelta(seconds=20 * (k + 1)), c, False)
                self._login(ts, c, True)

        for _ in range(r.choice([0, 1, 1, 2, 3, 4])):
            amount = min(400.0, max(2.0, r.lognormvariate(3.2, 0.8)))
            channel = r.choice(["pos", "pos", "ecommerce"])
            self._txn(self._rand_time(d), c, "card_purchase", amount, channel, r.choice(MERCHANTS))

        if d in (0, 14, 28):
            self._txn(self._day(d, 6), c, "payroll", c.salary / 2, "ach", "Employer Payroll")

        # First week establishes every payee in the customer's history.
        for i, (payee, (lo, hi)) in enumerate(c.payees.items()):
            if d == i or (d > 6 and r.random() < 0.06 and not payee.startswith("Landlord")):
                self._txn(self._rand_time(d), c, "transfer_out", r.uniform(lo, hi),
                          r.choice(["web", "mobile"]), payee)

        if r.random() < 0.08:
            self._txn(self._rand_time(d), c, "atm_withdrawal", r.randrange(40, 420, 20), "atm", "ATM")
        if r.random() < 0.03:
            self._txn(self._rand_time(d, 9, 17), c, "cash_deposit", r.uniform(50, 2500), "branch", "Branch")

    # --------------------------------------------------------------- scenarios
    def _brute_force_ato(self, c: Customer, d: int):
        ip, city = "203.0.113.10", "Moscow"
        t = self._day(d, 2, 10)
        for _ in range(14):
            self._login(t, c, False, ip=ip, city=city, ua=ATTACKER_UA)
            t += timedelta(seconds=self.rng.randint(15, 30))
        self._login(t, c, True, ip=ip, city=city, ua=ATTACKER_UA)
        self._txn(t + timedelta(minutes=8), c, "transfer_out", 7850.00, "web",
                  "EXT-PAYEE-5521", ip=ip, city=city)
        self._label("brute_force_ato", c.user, self._day(d, 2), self._day(d + 1),
                    True, "Online brute force against one account, successful login, "
                          "then a high-value transfer to a new payee.")

    def _impossible_travel_ato(self, c: Customer, d: int):
        ip, city = "203.0.113.20", "Lagos"
        self._login(self._day(d, 13, 0), c, True)
        t = self._day(d, 13, 45)
        self._login(t, c, True, ip=ip, city=city, ua=ATTACKER_UA)
        self._txn(t + timedelta(minutes=7), c, "transfer_out", 4200.00, "web",
                  "EXT-PAYEE-8830", ip=ip, city=city)
        self._label("impossible_travel_ato", c.user, self._day(d, 13), self._day(d + 1),
                    True, "Phished credentials used from another continent 45 minutes "
                          "after the real customer logged in; funds moved to a new payee.")

    def _card_testing(self, c: Customer, d: int):
        ip, city = "203.0.113.30", "Sao Paulo"
        t = self._day(d, 3, 12)
        for i in range(9):
            self._txn(t, c, "card_purchase", self.rng.uniform(0.5, 2.99), "ecommerce",
                      f"Online-Donation-{i % 6}", ip=ip, city=city)
            t += timedelta(seconds=self.rng.randint(30, 50))
        self._txn(t + timedelta(minutes=2), c, "card_purchase", 1349.99, "ecommerce",
                  "ElectroMart Online", ip=ip, city=city)
        self._label("card_testing", c.user, self._day(d, 3), self._day(d, 4),
                    True, "Stolen card validated with micro-purchases across many "
                          "merchants, then used for a large purchase.")

    def _structuring(self, c: Customer, d: int):
        plan = [(0, 10, 9400), (0, 15, 9850), (1, 11, 8700), (2, 12, 9100)]
        for i, (offset, hour, amount) in enumerate(plan):
            self._txn(self._day(d + offset, hour, self.rng.randint(0, 59)), c, "cash_deposit",
                      amount, "branch", f"Branch-{i}")
        self._label("structuring", c.user, self._day(d), self._day(d + 3),
                    True, "Cash deposits kept just under the $10,000 CTR reporting "
                          "threshold across several days and branches.")

    def _money_mule(self, c: Customer, d: int):
        t = self._day(d, 10, 5)
        self._txn(t, c, "wire_in", 24500.00, "wire", "WIRE-ORIG-77120")
        t += timedelta(minutes=25)
        for i in range(5):
            self._txn(t, c, "transfer_out", self.rng.uniform(4600, 4900), "mobile",
                      f"EXT-MULE-{4400 + i}")
            t += timedelta(minutes=self.rng.randint(10, 18))
        self._label("money_mule", c.user, self._day(d, 10), self._day(d, 13),
                    True, "Large inbound wire immediately fanned out to several "
                          "new payees (layering).")

    def _password_spray(self, targets: list[Customer], d: int):
        ip = "203.0.113.77"
        t = self._day(d, 4, 0)
        for c in targets:
            self._login(t, c, False, ip=ip, city="Bucharest", ua=ATTACKER_UA)
            t += timedelta(seconds=self.rng.randint(20, 60))
        self._label("password_spray", ip, self._day(d, 4), t, True,
                    f"One IP tried a single common password against {len(targets)} accounts.")

    def _benign_vpn(self, c: Customer, d: int):
        self._login(self._day(d, 10, 0), c, True)
        self._login(self._day(d, 10, 25), c, True, ip="203.0.113.200", city="Bucharest")
        self._label("benign_vpn", c.user, self._day(d), self._day(d + 1), False,
                    "Customer switched on a commercial VPN with a Romanian exit node.")

    def _benign_traveler(self, c: Customer, d: int):
        dest = "Los Angeles" if c.city != "Los Angeles" else "New York"
        for k in range(3):
            self._skip_logins.add((c.user, d + k))
        self._login(self._day(d, 7, 30), c, True)
        self._login(self._day(d, 19, 0), c, True, ip="198.51.100.250", city=dest)
        self._login(self._day(d + 1, 12, 0), c, True, ip="198.51.100.250", city=dest)
        self._login(self._day(d + 2, 9, 0), c, True, ip="198.51.100.250", city=dest)
        self._label("benign_traveler", c.user, self._day(d), self._day(d + 3), False,
                    "Customer flew cross-country; logins are far apart but physically plausible.")

    def _benign_large_transfer(self, c: Customer, d: int):
        landlord = next(p for p in c.payees if p.startswith("Landlord"))
        self._txn(self._day(d, 11), c, "transfer_out", 15000.00, "web", landlord)
        self._label("benign_large_transfer", c.user, self._day(d), self._day(d + 1), False,
                    "Large but legitimate transfer to a long-standing payee.")

    # -------------------------------------------------------------------- run
    def run(self) -> tuple[list[dict], list[dict]]:
        r = self.rng
        roles = r.sample(self.customers, 8)
        (bf, it, card, struct, mule, vpn, trav, big) = roles

        # Schedule login suppression before normal traffic is generated.
        self._benign_traveler(trav, 20)

        for d in range(DAYS):
            for c in self.customers:
                self._normal_day(c, d)

        self._benign_vpn(vpn, 18)
        self._password_spray(r.sample(self.customers, 25), 19)
        self._structuring(struct, 21)
        self._card_testing(card, 22)
        self._benign_large_transfer(big, 23)
        self._brute_force_ato(bf, 24)
        self._impossible_travel_ato(it, 26)
        self._money_mule(mule, 27)

        self.events.sort(key=lambda e: e["ts"])
        for i, e in enumerate(self.events, 1):
            e["event_id"] = f"EVT-{i:06d}"
        return self.events, self.truth


def generate(seed: int = 42, n_users: int = 50) -> tuple[list[dict], list[dict]]:
    return Simulator(seed=seed, n_users=n_users).run()
