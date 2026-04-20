# The Eye – Fraud Detection Agent System
# Reply Mirror Challenge 2026

import os
import re
import csv
import json
import math
import ulid
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

# ── Config ──────────────────────────────────────────────────────
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
LANGFUSE_PUBLIC_KEY = os.getenv("LANGFUSE_PUBLIC_KEY")
LANGFUSE_SECRET_KEY = os.getenv("LANGFUSE_SECRET_KEY")
LANGFUSE_HOST = os.getenv("LANGFUSE_HOST", "https://challenges.reply.com/langfuse")
TEAM_NAME = os.getenv("TEAM_NAME", "Dogtors")
AUDIO_MODEL = "google/gemini-2.0-flash-001"  # Supports audio input, $0.10/M input
TEXT_MODEL = "openai/gpt-4o-mini"
ANALYSIS_MODEL = "openai/gpt-4o"  # Heavy analysis — citizen fraud detection

# Phishing detection patterns
PHISHING_DOMAIN_PATTERNS = [
    r"paypa1", r"amaz0n", r"ub3r", r"netfl1x", r"citydriv3",
    r"r1d3share", r"deutschebank-secure\d+", r"uber-secure-verify",
    r"ub3r-secure", r"ub3r-verify",
]
PHISHING_URL_PATTERNS = [
    r"paypa1-secure\.net", r"amaz0n-verify\.com", r"ub3r-verify",
    r"netfl1x-bill\.com", r"citydriv3-verify\.com", r"r1d3share-verify\.com",
    r"uber-secure-verify\.net", r"deutschebank-secure\d+\.com",
]
PHISHING_SIGNAL_WORDS = ["urgent", "suspicious", "verify now", "avoid lock",
                         "avoid suspension", "account lock", "temporarily limited"]


# ── Data Loading ────────────────────────────────────────────────

def load_level_data(level_dir):
    """Load all data files for a level."""
    data = {}

    # Transactions
    txn_path = os.path.join(level_dir, "transactions.csv")
    if os.path.exists(txn_path):
        with open(txn_path, encoding="utf-8") as f:
            data["transactions"] = list(csv.DictReader(f))
    else:
        data["transactions"] = []

    # Users
    users_path = os.path.join(level_dir, "users.json")
    if os.path.exists(users_path):
        with open(users_path, encoding="utf-8") as f:
            data["users"] = json.load(f)
    else:
        data["users"] = []

    # Locations
    loc_path = os.path.join(level_dir, "locations.json")
    if os.path.exists(loc_path):
        with open(loc_path, encoding="utf-8") as f:
            data["locations"] = json.load(f)
    else:
        data["locations"] = []

    # SMS
    sms_path = os.path.join(level_dir, "sms.json")
    if os.path.exists(sms_path):
        with open(sms_path, encoding="utf-8") as f:
            data["sms"] = json.load(f)
    else:
        data["sms"] = []

    # Mails
    mail_path = os.path.join(level_dir, "mails.json")
    if os.path.exists(mail_path):
        with open(mail_path, encoding="utf-8") as f:
            data["mails"] = json.load(f)
    else:
        data["mails"] = []

    return data


# ── Citizen ID / IBAN Mapping ───────────────────────────────────

CITIZEN_ID_PATTERN = re.compile(r"^[A-ZÀ-Ü]{4}-[A-ZÀ-Ü]{4}-[0-9A-F]{3}-[A-Z]{3}-\d$")

def build_citizen_index(data):
    """Build mappings between citizen IDs, IBANs, names, and phone numbers."""
    users = data["users"]
    txns = data["transactions"]

    # Map IBAN -> user info
    iban_to_user = {}
    for u in users:
        iban_to_user[u["iban"]] = u

    # Discover citizen IDs from transactions
    citizen_ids = set()
    for t in txns:
        for fld in ["sender_id", "recipient_id"]:
            v = t.get(fld, "")
            if v and CITIZEN_ID_PATTERN.match(v):
                citizen_ids.add(v)

    # Map citizen_id -> user (via IBAN linkage in transactions)
    cid_to_user = {}
    for cid in citizen_ids:
        # Try sender_iban first
        for t in txns:
            if t["sender_id"] == cid and t.get("sender_iban", ""):
                iban = t["sender_iban"]
                if iban in iban_to_user:
                    cid_to_user[cid] = iban_to_user[iban]
                    break
        # Fall back to recipient_iban if not found via sender
        if cid not in cid_to_user:
            for t in txns:
                if t.get("recipient_id", "") == cid and t.get("recipient_iban", ""):
                    iban = t["recipient_iban"]
                    if iban in iban_to_user:
                        cid_to_user[cid] = iban_to_user[iban]
                        break

    # Map user name -> citizen_id (for SMS/mail linkage)
    name_to_cid = {}
    for cid, u in cid_to_user.items():
        first = u["first_name"].lower()
        last = u["last_name"].lower()
        name_to_cid[first] = cid
        name_to_cid[f"{first} {last}"] = cid
        # Also try with the citizen ID prefix
        name_to_cid[cid] = cid

    # Map phone number -> citizen_id (from SMS)
    phone_to_cid = {}
    for sms_item in data["sms"]:
        text = sms_item.get("sms", "")
        # Extract phone number from To: field
        to_match = re.search(r"To: (\+\d+)", text)
        if to_match:
            phone = to_match.group(1)
            # Try to find which citizen this phone belongs to
            for cid, u in cid_to_user.items():
                fname = u["first_name"]
                if fname.lower() in text.lower()[:300]:
                    phone_to_cid[phone] = cid
                    break

    return {
        "citizen_ids": citizen_ids,
        "iban_to_user": iban_to_user,
        "cid_to_user": cid_to_user,
        "name_to_cid": name_to_cid,
        "phone_to_cid": phone_to_cid,
    }


# ── Phishing Analysis ──────────────────────────────────────────

def is_phishing_sms(text):
    """Detect if an SMS is a phishing attempt."""
    text_lower = text.lower()
    for pattern in PHISHING_URL_PATTERNS:
        if re.search(pattern, text_lower):
            return True
    for pattern in PHISHING_DOMAIN_PATTERNS:
        if re.search(pattern, text_lower):
            return True
    return False


def is_phishing_mail(text):
    """Detect if an email is a phishing attempt."""
    text_lower = text.lower()
    # Check From: domain
    from_match = re.search(r"from:.*?<([^>]+)>", text_lower)
    if from_match:
        domain = from_match.group(1)
        for pattern in PHISHING_DOMAIN_PATTERNS:
            if re.search(pattern, domain):
                return True
    # Check URLs in body
    for pattern in PHISHING_URL_PATTERNS:
        if re.search(pattern, text_lower):
            return True
    return False


def extract_phishing_date(text):
    """Extract date from SMS or mail."""
    date_match = re.search(r"Date:\s*[\w,]*\s*(\d{4}-\d{2}-\d{2})", text)
    if date_match:
        try:
            return datetime.strptime(date_match.group(1), "%Y-%m-%d")
        except ValueError:
            pass
    date_match = re.search(r"Date:\s*\w+,\s*(\d{2}\s\w+\s\d{4})", text)
    if date_match:
        try:
            return datetime.strptime(date_match.group(1), "%d %b %Y")
        except ValueError:
            pass
    return None


def analyze_phishing(data, index):
    """Return per-citizen phishing timeline."""
    phishing_events = defaultdict(list)  # cid -> [(date, source_type, snippet)]

    # Analyze SMS
    for sms_item in data["sms"]:
        text = sms_item.get("sms", "")
        if is_phishing_sms(text):
            date = extract_phishing_date(text)
            # Identify target citizen
            target_cid = None
            to_match = re.search(r"To: (\+\d+)", text)
            if to_match:
                phone = to_match.group(1)
                target_cid = index["phone_to_cid"].get(phone)
            if not target_cid:
                # Try matching by first name in message
                for name, cid in index["name_to_cid"].items():
                    if name in text.lower():
                        target_cid = cid
                        break
            if target_cid and date:
                phishing_events[target_cid].append((date, "sms", text[:120]))

    # Analyze Mails
    for mail_item in data["mails"]:
        text = mail_item.get("mail", "")
        if is_phishing_mail(text):
            date = extract_phishing_date(text)
            target_cid = None
            to_match = re.search(r'To:.*?"([^"]+)"', text)
            if to_match:
                recipient_name = to_match.group(1).lower()
                for name, cid in index["name_to_cid"].items():
                    if name in recipient_name:
                        target_cid = cid
                        break
            if target_cid and date:
                phishing_events[target_cid].append((date, "mail", text[:120]))

    # Sort events per citizen
    for cid in phishing_events:
        phishing_events[cid].sort(key=lambda x: x[0])

    return phishing_events


# ── Phishing Susceptibility Extraction ──────────────────────────

def extract_phishing_susceptibility(description):
    """Extract phishing susceptibility score from user description (0.0-1.0)."""
    desc_lower = description.lower()

    # Look for explicit percentage near phishing-related words
    pct_match = re.search(r"(?:phishing|hereinfallen|cadere|susceptib|cliquer|klick|piège).*?(\d{1,3})\s*%", desc_lower)
    if pct_match:
        return int(pct_match.group(1)) / 100.0
    # Also try reverse order (percentage before keyword)
    pct_match2 = re.search(r"(\d{1,3})\s*%.*?(?:phishing|hereinfallen|cadere|susceptib|cliquer|klick|piège)", desc_lower)
    if pct_match2:
        return int(pct_match2.group(1)) / 100.0

    # Written-out ~50% in multiple languages
    if re.search(r"(?:cinquanta|fünfzig|fifty|cinquante)\s*(?:per\s*cento|prozent|percent|pour\s*cent)", desc_lower):
        return 0.5
    if "about half" in desc_lower or "circa la metà" in desc_lower or "environ la moitié" in desc_lower:
        return 0.5

    # Keywords indicating high susceptibility
    high_keywords = ["fait preuve de confiance", "tends to trust", "si fida",
                     "tendency to click", "clicked dubious", "click on risky",
                     "nicht vorsichtig", "non è impermeabile",
                     "not immune", "tende a fidarsi", "nicht ganz immun",
                     "sort to click", "trusting online"]
    low_keywords = ["très prudent", "very cautious", "sehr vorsichtig", "molto prudente",
                    "skeptical", "sospettoso", "méfiant", "immune to", "immun gegen"]
    mid_keywords = ["about as likely", "mäßig vorsichtig", "moderately cautious",
                    "probabilità intermedia", "pragmatically susceptible",
                    "occasionally", "parfois", "gelegentlich",
                    "geschätzten wahrscheinlichkeit"]

    for kw in high_keywords:
        if kw in desc_lower:
            return 0.7
    for kw in mid_keywords:
        if kw in desc_lower:
            return 0.5
    for kw in low_keywords:
        if kw in desc_lower:
            return 0.2

    # If phishing is mentioned at all, assume moderate susceptibility
    if any(kw in desc_lower for kw in ["phishing", "hereinfallen", "cadere", "piège", "cliquer", "klick"]):
        return 0.5

    return 0.3  # default lower if no phishing mentioned


# ── Transaction Baseline Building ───────────────────────────────

def build_citizen_baselines(txns, index):
    """Build per-citizen transaction baselines.

    Uses only 'safe' transactions to avoid baseline contamination:
    - Excludes ALL e-commerce (all lack descriptions, many are fraud vectors)
    - Excludes transfers without descriptions to non-housing/non-utility recipients
    - Includes: salary, rent, utility payments, described transfers, in-person, withdrawals
    """
    baselines = {}

    safe_prefixes = ("ABIT", "RES", "HOME", "DOM", "PROP", "RENT",
                     "ACC", "CMP", "BIL", "SUB", "SRV", "UTL", "SYS", "EMP")

    for cid in index["citizen_ids"]:
        all_citizen_txns = [t for t in txns if t["sender_id"] == cid]
        citizen_recv = [t for t in txns if t["recipient_id"] == cid]

        # Filter to safe transactions for baseline building
        citizen_txns = []
        for t in all_citizen_txns:
            ttype = t["transaction_type"]
            recip = t.get("recipient_id", "")
            desc = t.get("description", "").strip()
            # Exclude e-commerce entirely (high fraud rate, no descriptions)
            if ttype == "e-commerce":
                continue
            # Exclude descriptionless transfers to unknown recipients
            if ttype == "transfer" and not desc:
                if recip and not any(recip.startswith(p) for p in safe_prefixes):
                    continue
            citizen_txns.append(t)

        # Use ALL transactions for recipient counting (needed for new_recipient detection)
        # but mark which recipients appear in SAFE transactions only
        recipient_counts_all = Counter(t["recipient_id"] for t in all_citizen_txns if t["recipient_id"])
        recipient_counts = Counter(t["recipient_id"] for t in citizen_txns if t["recipient_id"])
        regular_recipients = {r for r, c in recipient_counts.items() if c >= 2}

        # Transaction type distribution
        type_counts = Counter(t["transaction_type"] for t in citizen_txns)

        # Amount statistics per (recipient, type) pair
        amount_stats = {}
        for t in citizen_txns:
            key = (t["recipient_id"], t["transaction_type"])
            amt = float(t["amount"])
            if key not in amount_stats:
                amount_stats[key] = []
            amount_stats[key].append(amt)

        # Compute mean and std for each pair
        for key in amount_stats:
            vals = amount_stats[key]
            mean = sum(vals) / len(vals)
            std = (sum((v - mean) ** 2 for v in vals) / len(vals)) ** 0.5 if len(vals) > 1 else mean * 0.1
            amount_stats[key] = {"mean": mean, "std": max(std, 1.0), "count": len(vals)}

        # Salary baseline (incoming from EMP*)
        salary_txns = [t for t in citizen_recv if t["sender_id"].startswith("EMP") and "salary" in t.get("description", "").lower()]
        salary_mean = sum(float(t["amount"]) for t in salary_txns) / len(salary_txns) if salary_txns else 0
        salary_std = (sum((float(t["amount"]) - salary_mean) ** 2 for t in salary_txns) / len(salary_txns)) ** 0.5 if len(salary_txns) > 1 else salary_mean * 0.05

        # Balance statistics
        balances = [float(t["balance_after"]) for t in citizen_txns if t["balance_after"]]
        bal_mean = sum(balances) / len(balances) if balances else 0
        bal_min = min(balances) if balances else 0

        # Timing patterns: typical hours
        hours = []
        for t in citizen_txns:
            try:
                ts = datetime.fromisoformat(t["timestamp"])
                hours.append(ts.hour)
            except:
                pass

        # Payment methods used
        methods = Counter(t["payment_method"] for t in citizen_txns if t["payment_method"])

        # Locations used for in-person
        locations = set()
        for t in citizen_txns:
            if t["transaction_type"] == "in-person payment" and t.get("location"):
                locations.add(t["location"])

        baselines[cid] = {
            "regular_recipients": regular_recipients,
            "recipient_counts": recipient_counts,
            "type_counts": type_counts,
            "amount_stats": amount_stats,
            "salary_mean": salary_mean,
            "salary_std": max(salary_std, 1.0),
            "balance_mean": bal_mean,
            "balance_min": bal_min,
            "hours": hours,
            "payment_methods": methods,
            "known_locations": locations,
            "total_sent": len(citizen_txns),
            "total_recv": len(citizen_recv),
        }

    return baselines


# ── Location / Impossible Travel Detection ──────────────────────

def haversine_km(lat1, lon1, lat2, lon2):
    """Haversine distance in km."""
    R = 6371
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2) ** 2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2
    return R * 2 * math.asin(min(1, math.sqrt(a)))


def build_location_timeline(locations, index):
    """Build per-citizen GPS timeline sorted by time."""
    loc_timeline = defaultdict(list)
    for loc in locations:
        biotag = loc.get("biotag", "")
        if biotag in index["citizen_ids"]:
            try:
                ts = datetime.fromisoformat(loc["timestamp"])
                lat = float(loc["lat"])
                lng = float(loc["lng"])
                loc_timeline[biotag].append((ts, lat, lng, loc.get("city", "")))
            except:
                pass
    for cid in loc_timeline:
        loc_timeline[cid].sort(key=lambda x: x[0])
    return loc_timeline


def check_impossible_travel(txn, loc_timeline, index):
    """Check if a transaction's location is impossible given GPS data."""
    cid = txn["sender_id"]
    if cid not in loc_timeline:
        return 0.0

    txn_location = txn.get("location", "")
    if not txn_location:
        return 0.0

    try:
        txn_time = datetime.fromisoformat(txn["timestamp"])
    except:
        return 0.0

    # Find nearest GPS pings
    timeline = loc_timeline[cid]
    window_hours = 4
    nearby_pings = []
    for ts, lat, lng, city in timeline:
        delta = abs((txn_time - ts).total_seconds()) / 3600
        if delta <= window_hours:
            nearby_pings.append((ts, lat, lng, city, delta))

    if not nearby_pings:
        return 0.0

    # Check if transaction location matches GPS city
    txn_city = txn_location.split(" - ")[0].strip() if " - " in txn_location else txn_location.strip()
    for ts, lat, lng, city, delta in nearby_pings:
        if city and txn_city.lower() in city.lower():
            return 0.0  # Location matches
        if city and city.lower() in txn_city.lower():
            return 0.0

    # Get user's residence city
    user = index["cid_to_user"].get(cid)
    if user:
        res_city = user["residence"]["city"]
        res_lat = float(user["residence"]["lat"])
        res_lng = float(user["residence"]["lng"])

        # Check if transaction is near residence
        if res_city.lower() in txn_city.lower() or txn_city.lower() in res_city.lower():
            return 0.0

    # If we have GPS pings showing citizen is elsewhere, that's suspicious
    closest_ping = min(nearby_pings, key=lambda x: x[4])
    if closest_ping[3] and txn_city.lower() not in closest_ping[3].lower():
        return 0.8  # Likely impossible travel

    return 0.3  # Moderate suspicion


# ── Safe Transaction Prefixes ──────────────────────────────────

HOUSING_PREFIXES = ("ABIT", "RES", "HOME", "DOM", "PROP", "RENT")
UTILITY_PREFIXES = ("ACC", "CMP", "BIL", "SUB", "SRV", "UTL", "SYS")


# ── Per-Transaction Fraud Scoring (V3 — phishing-centric) ─────

def score_transaction(txn, baselines, phishing_events, loc_timeline, index):
    """Score a single transaction for fraud probability (0.0-1.0).

    V3 architecture: phishing correlation is the PRIMARY fraud driver.
    - Citizens who were EVER phished: anomalous transactions get high scores
    - Temporal proximity to phishing event amplifies score further
    - Without phishing: only impossible travel is flagged
    """
    cid = txn["sender_id"]
    if not CITIZEN_ID_PATTERN.match(cid):
        return 0.0, {}  # Not a citizen-initiated transaction

    # Salary deposits are always safe
    if txn["sender_id"].startswith("EMP"):
        return 0.0, {}

    # Housing payments are always safe
    recipient = txn["recipient_id"]
    if recipient and any(recipient.startswith(p) for p in HOUSING_PREFIXES):
        return 0.0, {}

    baseline = baselines.get(cid)
    if not baseline:
        return 0.0, {}

    signals = {}
    score = 0.0
    amount = float(txn["amount"])
    ttype = txn["transaction_type"]
    desc = txn.get("description", "").strip()
    user = index["cid_to_user"].get(cid)
    susceptibility = extract_phishing_susceptibility(user.get("description", "")) if user else 0.3

    recv_count = baseline["recipient_counts"].get(recipient, 0)
    is_new_recipient = recv_count == 0
    is_rare_recipient = recv_count == 1
    is_known_utility = recipient and any(recipient.startswith(p) for p in UTILITY_PREFIXES)

    # ── STEP 1: Phishing status ────────────────────────────────
    was_ever_phished = cid in phishing_events and len(phishing_events[cid]) > 0
    phishing_proximity = 0.0  # 0.0-1.0, higher = closer to phishing event

    if was_ever_phished:
        try:
            txn_time = datetime.fromisoformat(txn["timestamp"])
            for phish_date, phish_type, _ in phishing_events[cid]:
                days_after = (txn_time - phish_date).total_seconds() / 86400
                if 0 <= days_after <= 45:  # 45-day window
                    prox = max(0, 1.0 - days_after / 45)
                    phishing_proximity = max(phishing_proximity, prox)
        except Exception:
            pass

    # ── STEP 2: Impossible travel (independent of phishing) ────
    if ttype in ("in-person payment", "withdrawal") and txn.get("location"):
        travel_score = check_impossible_travel(txn, loc_timeline, index)
        if travel_score > 0:
            signals["impossible_travel"] = travel_score
            score += travel_score * 0.40

    # ── STEP 3: Anomaly signals ──
    # New recipient (weighted by phishing status)
    if is_new_recipient and not is_known_utility:
        signals["new_recipient"] = 1.0
        score += 0.10 if was_ever_phished else 0.03

    if is_rare_recipient and not is_known_utility:
        signals["rare_recipient"] = 0.5
        score += 0.04 if was_ever_phished else 0.01

    # Amount anomaly vs baseline for same recipient+type
    key = (recipient, ttype)
    if key in baseline.get("amount_stats", {}):
        stats = baseline["amount_stats"][key]
        z_score = abs(amount - stats["mean"]) / stats["std"] if stats["std"] > 0 else 0
        if z_score > 2.0:
            signals["amount_anomaly"] = min(z_score / 5, 1.0)
            score += signals["amount_anomaly"] * 0.12

    # Large amount relative to salary (key for economic impact)
    salary = baseline.get("salary_mean", 0)
    if salary > 0 and amount > salary * 0.3:
        ratio = amount / salary
        signals["high_salary_ratio"] = min(ratio, 2.0) / 2.0
        score += signals["high_salary_ratio"] * 0.10

    # ── STEP 4: Type-specific signals ──────────────────────────
    if ttype == "e-commerce":
        # Flag new merchants — stronger with phishing correlation
        if is_new_recipient and phishing_proximity > 0:
            signals["phished_new_merchant"] = phishing_proximity
            score += 0.14 * phishing_proximity
        elif is_new_recipient and was_ever_phished:
            signals["phished_new_merchant_weak"] = susceptibility
            score += 0.08 * susceptibility
        elif is_new_recipient:
            signals["new_merchant"] = 0.3
            score += 0.03

    elif ttype == "transfer":
        if is_new_recipient and not is_known_utility:
            if not desc:
                signals["transfer_no_desc_new"] = 1.0
                score += 0.14
                if phishing_proximity > 0:
                    score += 0.08 * phishing_proximity
            else:
                score += 0.03
                if phishing_proximity > 0:
                    score += 0.03 * phishing_proximity

    elif ttype == "direct debit":
        if is_new_recipient and not is_known_utility:
            signals["unknown_dd_service"] = 0.7
            score += 0.10
            if phishing_proximity > 0:
                score += 0.05 * phishing_proximity

    elif ttype == "withdrawal":
        if amount > 200 and phishing_proximity > 0:
            signals["large_withdrawal"] = 0.5
            score += 0.08
        elif amount > 500:
            signals["very_large_withdrawal"] = 0.5
            score += 0.06

    # Unusual timing (late night)
    try:
        ts = datetime.fromisoformat(txn["timestamp"])
        if ts.hour < 5 or ts.hour >= 23:
            if baseline["hours"] and ts.hour not in set(baseline["hours"]):
                signals["unusual_hour"] = 0.5
                score += 0.04
    except Exception:
        pass

    # ── STEP 5: Phishing proximity amplifier ───────────
    if phishing_proximity > 0 and score > 0:
        signals["phishing_proximity"] = phishing_proximity
        score += phishing_proximity * susceptibility * 0.15

        if susceptibility >= 0.5:
            score *= (1.0 + susceptibility * 0.20)

    return min(score, 1.0), signals


# ── LLM Agent for Borderline Cases ─────────────────────────────

def llm_review_transactions(borderline_txns, session_id):
    """Use LLM to review borderline transactions."""
    from langchain_openai import ChatOpenAI
    from langchain_core.messages import SystemMessage, HumanMessage
    from langfuse import Langfuse
    from langfuse.langchain import CallbackHandler
    from langfuse.types import TraceContext

    model = ChatOpenAI(
        api_key=OPENROUTER_API_KEY,
        base_url="https://openrouter.ai/api/v1",
        model=TEXT_MODEL,
        temperature=0.1, max_tokens=300,
    )
    lf = Langfuse(public_key=LANGFUSE_PUBLIC_KEY, secret_key=LANGFUSE_SECRET_KEY, host=LANGFUSE_HOST)

    sys_prompt = """You are a fraud detection agent for MirrorPay (year 2087). Analyze a transaction and decide: FRAUD or LEGITIMATE.

FRAUD pattern: Citizen receives phishing SMS/email → account compromised → fraudster makes unauthorized transactions (to new recipients, unusual merchants, wrong locations).
Key fraud signals: phishing_proximity > 0 (citizen was recently phished), new_recipient (never transacted before), impossible_travel (GPS shows citizen elsewhere), amount anomaly.
Key legitimate signals: known recurring recipient, transaction with clear description matching normal behavior, rent/salary/utility payments.

IMPORTANT: Not every transaction after phishing is fraud. Recurring payments to known recipients (rent, utilities) remain legitimate even after phishing. Focus on NEW recipients and unusual patterns.
Reply ONLY with JSON: {"verdict": "fraud" or "legitimate", "confidence": 0.0-1.0, "reasoning": "brief"}"""

    results = {}
    for txn_id, info in borderline_txns.items():
        txn = info["txn"]
        signals = info["signals"]
        score = info["score"]

        summary = f"""Transaction: {txn_id}
Sender: {txn['sender_id']} -> Recipient: {txn['recipient_id']}
Type: {txn['transaction_type']}, Amount: {txn['amount']}, Timestamp: {txn['timestamp']}
Description: {txn.get('description', 'N/A')}
Location: {txn.get('location', 'N/A')}
Balance after: {txn.get('balance_after', 'N/A')}
Risk score: {score:.3f}
Signals: {json.dumps(signals)}"""

        trace_id = lf.create_trace_id()
        handler = CallbackHandler(trace_context=TraceContext(trace_id=trace_id))

        try:
            resp = model.invoke(
                [SystemMessage(content=sys_prompt), HumanMessage(content=summary)],
                config={"callbacks": [handler],
                        "metadata": {"langfuse_session_id": session_id, "transaction_id": txn_id}},
            )
            text = resp.content.strip()
            if "```" in text:
                text = text.split("```")[1].replace("json", "")
            parsed = json.loads(text)
            results[txn_id] = parsed.get("verdict", "legitimate") == "fraud"
        except Exception as e:
            print(f"    LLM error for {txn_id}: {e}")
            results[txn_id] = score >= 0.55  # Conservative fallback

    lf.flush()
    return results


# ── Audio Transcription (for Deus Ex level) ─────────────────────

def transcribe_audio_files(level_dir, session_id):
    """Transcribe audio files using Gemini 2.0 Flash (supports audio input).
    Returns list of transcription dicts with fraud intelligence."""
    audio_dir = os.path.join(level_dir, "audio")
    if not os.path.isdir(audio_dir):
        return []

    from langchain_openai import ChatOpenAI
    from langchain_core.messages import SystemMessage, HumanMessage
    from langfuse import Langfuse
    from langfuse.langchain import CallbackHandler
    from langfuse.types import TraceContext
    import base64

    audio_files = sorted(f for f in os.listdir(audio_dir) if f.endswith(".mp3"))
    if not audio_files:
        return []

    print(f"  Found {len(audio_files)} audio files — transcribing with {AUDIO_MODEL}...")

    model = ChatOpenAI(
        api_key=OPENROUTER_API_KEY,
        base_url="https://openrouter.ai/api/v1",
        model=AUDIO_MODEL,
        temperature=0.1, max_tokens=1000,
    )
    lf = Langfuse(public_key=LANGFUSE_PUBLIC_KEY, secret_key=LANGFUSE_SECRET_KEY, host=LANGFUSE_HOST)

    sys_content = (
        "You are a fraud intelligence agent for MirrorPay. Listen to this audio and analyze it. "
        "Determine if it contains evidence of: social engineering, phishing attempts, scam calls, "
        "financial manipulation, or someone being tricked into revealing credentials or making payments. "
        'Return ONLY JSON: {"suspicious": true/false, "fraud_type": "phishing|social_engineering|scam|none", '
        '"target_person": "name of person being targeted or empty", '
        '"summary": "brief summary of conversation and any fraud indicators"}'
    )

    def _transcribe_one(audio_file):
        fname = audio_file.replace(".mp3", "")
        parts = fname.split("-", 1)
        date_str = parts[0] if parts else ""
        person_name = parts[1].replace("_", " ") if len(parts) > 1 else ""
        try:
            audio_date = datetime.strptime(date_str, "%Y%m%d_%H%M%S")
        except Exception:
            audio_date = None
        audio_path = os.path.join(audio_dir, audio_file)
        with open(audio_path, "rb") as af:
            audio_b64 = base64.b64encode(af.read()).decode("utf-8")
        trace_id = lf.create_trace_id()
        handler = CallbackHandler(trace_context=TraceContext(trace_id=trace_id))
        try:
            resp = model.invoke(
                [SystemMessage(content=sys_content),
                 HumanMessage(content=[
                     {"type": "text", "text": f"Analyze this audio recording involving {person_name} from {audio_date}:"},
                     {"type": "input_audio", "input_audio": {"data": audio_b64, "format": "mp3"}},
                 ])],
                config={"callbacks": [handler],
                        "metadata": {"langfuse_session_id": session_id, "audio_file": audio_file}},
            )
            text = resp.content.strip()
            if "```" in text:
                text = text.split("```")[1].replace("json", "").strip()
            parsed = json.loads(text)
            tag = "SUSPICIOUS" if parsed.get("suspicious") else "  clean"
            print(f"    {tag}: {audio_file} — {parsed.get('summary', '')[:80]}")
            return {"file": audio_file, "person": person_name, "date": audio_date,
                    "suspicious": parsed.get("suspicious", False), "fraud_type": parsed.get("fraud_type", "none"),
                    "target_person": parsed.get("target_person", ""), "summary": parsed.get("summary", "")}
        except Exception as e:
            print(f"    Audio error {audio_file}: {e}")
            return {"file": audio_file, "person": person_name, "date": audio_date,
                    "suspicious": False, "fraud_type": "none", "target_person": "", "summary": f"Error: {e}"}

    transcriptions = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_transcribe_one, af): af for af in audio_files}
        for fut in as_completed(futures):
            transcriptions.append(fut.result())

    lf.flush()
    return transcriptions


def integrate_audio_into_phishing(audio_transcriptions, phishing_events, index):
    """Feed suspicious audio findings into the phishing event timeline."""
    if not audio_transcriptions:
        return

    # Build reverse name->cid lookup
    name_to_cid = {}
    for cid, u in index["cid_to_user"].items():
        first = u["first_name"].lower()
        last = u["last_name"].lower()
        name_to_cid[f"{first} {last}"] = cid
        name_to_cid[first] = cid
        name_to_cid[last] = cid

    added = 0
    for t in audio_transcriptions:
        if not t.get("suspicious"):
            continue

        audio_date = t.get("date")
        if not audio_date:
            continue

        # Try to find which citizen is targeted
        target_cid = None

        # Check target_person field from LLM
        target = t.get("target_person", "").lower().strip()
        if target:
            for name, cid in name_to_cid.items():
                if name in target or target in name:
                    target_cid = cid
                    break

        # Fall back to person in filename
        if not target_cid:
            person = t.get("person", "").lower().strip()
            for name, cid in name_to_cid.items():
                if name in person or person in name:
                    target_cid = cid
                    break

        if target_cid:
            phishing_events[target_cid].append(
                (audio_date, "audio", t.get("summary", "")[:120])
            )
            added += 1

    if added:
        # Re-sort events
        for cid in phishing_events:
            phishing_events[cid].sort(key=lambda x: x[0])
        print(f"  Audio: added {added} phishing events from suspicious audio")


# ── LLM Agent: Per-Citizen Fraud Analysis ──────────────────────

def analyze_citizen_fraud(cid, all_txns, phishing_events, user_info, session_id):
    """Use a capable LLM to analyze a citizen's full transaction history for fraud.

    Sends the complete context (transactions, phishing timeline, profile)
    and asks the LLM to identify ALL fraudulent transactions.
    """
    from langchain_openai import ChatOpenAI
    from langchain_core.messages import SystemMessage, HumanMessage
    from langfuse import Langfuse
    from langfuse.langchain import CallbackHandler
    from langfuse.types import TraceContext

    # Gather all transactions involving this citizen
    citizen_txns = [t for t in all_txns if t["sender_id"] == cid or t["recipient_id"] == cid]
    citizen_txns.sort(key=lambda t: t["timestamp"])

    # Format transaction table — show FULL transaction_id so LLM can return it exactly
    txn_lines = []
    for t in citizen_txns:
        direction = "OUT" if t["sender_id"] == cid else "IN "
        counterparty = t["recipient_id"] if direction == "OUT" else t["sender_id"]
        desc = t.get("description", "").strip()[:40]
        loc = t.get("location", "").strip()[:20]
        method = t.get("payment_method", "").strip()[:15]
        txn_lines.append(
            f"{t['transaction_id']}  {t['timestamp'][:16]:16s} {direction} {t['transaction_type']:20s} "
            f"{counterparty:16s} {float(t['amount']):>10.2f}  {desc:40s} {loc:20s} {method:15s}"
        )

    # Format phishing events
    phish_lines = []
    for date, ptype, snippet in sorted(phishing_events.get(cid, [])):
        phish_lines.append(f"  {date.strftime('%Y-%m-%d')}  [{ptype:5s}]  {snippet[:100]}")

    susceptibility = extract_phishing_susceptibility(user_info.get("description", ""))

    # Build the case file prompt
    prompt = f"""## Citizen: {user_info.get('first_name','?')} {user_info.get('last_name','?')} ({cid})
Job: {user_info.get('job','?')} | Salary: {user_info.get('salary',0)} | City: {user_info.get('residence',{}).get('city','?')}
Phishing susceptibility: {susceptibility:.0%}
User notes: {user_info.get('description','')[:200]}

## Phishing / Scam Events ({len(phish_lines)})
{chr(10).join(phish_lines) if phish_lines else "  None detected"}

## Transaction History ({len(citizen_txns)})
transaction_id                              timestamp        dir  type                 counterparty     amount       description                              location             method
{chr(10).join(txn_lines)}

## TASK
You are a senior fraud investigator for MirrorPay bank in year 2087.

Examine ALL OUTGOING (dir=OUT) transactions from this citizen and identify which are FRAUDULENT.

Fraud patterns in this dataset:
- Phishing → account compromise → unauthorized e-commerce / transfers to new recipients
- Transactions to brand-new recipients (never seen before) shortly AFTER phishing/scam events
- E-commerce to unknown merchants after phishing (legitimate e-commerce has store names in description)
- Unusually large amounts for this citizen's normal behavior
- Transactions at unusual hours (late night)
- Impossible travel: in-person payment in city X but citizen's GPS shows them in city Y

Legitimate patterns (do NOT flag):
- Monthly rent payments (to ABIT*/RES*/HOME*/DOM*/PROP*)
- Salary deposits (IN from EMP*)
- Utility / service bills with descriptions (ACC*/CMP*/BIL*/SUB*/SRV*)
- Recurring payments to the same known recipient at consistent amounts

For each fraudulent transaction, provide the full transaction_id.
Return ONLY valid JSON:
{{"fraudulent_ids": ["full-transaction-id-1", "full-transaction-id-2"], "reasoning": "brief explanation"}}"""

    # Call LLM with Langfuse tracing
    model = ChatOpenAI(
        api_key=OPENROUTER_API_KEY,
        base_url="https://openrouter.ai/api/v1",
        model=ANALYSIS_MODEL,
        temperature=0.05, max_tokens=2000,
    )
    lf = Langfuse(public_key=LANGFUSE_PUBLIC_KEY, secret_key=LANGFUSE_SECRET_KEY, host=LANGFUSE_HOST)
    trace_id = lf.create_trace_id()
    handler = CallbackHandler(trace_context=TraceContext(trace_id=trace_id))

    try:
        resp = model.invoke(
            [SystemMessage(content="You are a senior fraud investigator for a major bank. Analyze transaction histories precisely and identify fraudulent activity."),
             HumanMessage(content=prompt)],
            config={"callbacks": [handler],
                    "metadata": {"langfuse_session_id": session_id, "citizen_id": cid}},
        )
        lf.flush()

        text = resp.content.strip()
        if "```" in text:
            text = text.split("```")[1].replace("json", "").strip()
        parsed = json.loads(text)
        fraud_ids = parsed.get("fraudulent_ids", [])
        reasoning = parsed.get("reasoning", "")

        name = f"{user_info.get('first_name','?')} {user_info.get('last_name','?')}"
        print(f"    {name}: {len(fraud_ids)} fraud — {reasoning[:100]}")
        return fraud_ids

    except Exception as e:
        print(f"    LLM analysis error for {cid}: {e}")
        lf.flush()
        return []


# ── Main Pipeline ───────────────────────────────────────────────

def run_level(level_dir, session_id):
    """Run fraud detection pipeline on a single level using LLM agent analysis."""
    print(f"  Loading data from {level_dir}...")
    data = load_level_data(level_dir)
    txns = data["transactions"]
    print(f"  Transactions: {len(txns)}, Users: {len(data['users'])}, SMS: {len(data['sms'])}, Mails: {len(data['mails'])}, Locations: {len(data['locations'])}")

    # Build index
    index = build_citizen_index(data)
    print(f"  Citizens: {len(index['citizen_ids'])}")

    # Analyze phishing
    phishing = analyze_phishing(data, index)
    for cid, events in phishing.items():
        user = index["cid_to_user"].get(cid, {})
        name = f"{user.get('first_name', '?')} {user.get('last_name', '?')}"
        print(f"  Phishing events for {name} ({cid}): {len(events)}")

    # Build location timeline
    loc_timeline = build_location_timeline(data["locations"], index)

    # Audio transcription (Deus Ex level)
    audio_transcriptions = transcribe_audio_files(level_dir, session_id)
    integrate_audio_into_phishing(audio_transcriptions, phishing, index)
    if audio_transcriptions:
        for cid, events in phishing.items():
            audio_events = [e for e in events if e[1] == "audio"]
            if audio_events:
                user = index["cid_to_user"].get(cid, {})
                name = f"{user.get('first_name', '?')} {user.get('last_name', '?')}"
                print(f"  Updated phishing for {name}: {len(events)} total (+{len(audio_events)} audio)")

    # ── LLM Agent Analysis: parallel per citizen ──────────────
    print(f"\n  Running LLM fraud analysis per citizen ({ANALYSIS_MODEL}) — PARALLEL...")
    valid_ids = {t["transaction_id"] for t in txns}

    def _analyze_citizen(cid):
        user = index["cid_to_user"].get(cid)
        if not user:
            return []
        citizen_fraud = analyze_citizen_fraud(cid, txns, phishing, user, session_id)
        matched = []
        for fid in citizen_fraud:
            if fid in valid_ids:
                matched.append(fid)
            else:
                prefix_matches = [vid for vid in valid_ids if vid.startswith(fid)]
                if len(prefix_matches) == 1:
                    matched.append(prefix_matches[0])
                elif len(prefix_matches) > 1:
                    print(f"    WARNING: ambiguous prefix '{fid}' matches {len(prefix_matches)} IDs — skipping")
        return matched

    fraud_ids = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_analyze_citizen, cid): cid for cid in sorted(index["citizen_ids"])}
        for fut in as_completed(futures):
            try:
                fraud_ids.extend(fut.result())
            except Exception as e:
                print(f"    Citizen analysis error: {e}")

    # Deduplicate
    fraud_ids = sorted(set(fraud_ids))

    # Print summary
    print(f"\n  Final fraud count: {len(fraud_ids)} / {len(txns)} transactions")

    # Validate output
    if len(fraud_ids) == 0:
        print("  WARNING: No fraud detected — output may be invalid!")
    if len(fraud_ids) == len(txns):
        print("  WARNING: All transactions flagged — output may be invalid!")

    return fraud_ids


def main():
    # Level directories
    levels = {
        "Blade Runner": os.path.join("Blade Runner - validation"),
        "1984": os.path.join("1984 - train"),
    }

    base = os.getenv("PROJECT_DIR", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    session_ids = {}
    for level_name, level_rel in levels.items():
        level_dir = os.path.join(base, level_rel)
        if not os.path.isdir(level_dir):
            print(f"{level_name}: directory not found ({level_dir}), skipping")
            continue

        # Generate a unique session ID per level
        session_id = f"{TEAM_NAME}-{ulid.new().str}"
        session_ids[level_name] = session_id

        print(f"{'=' * 60}\n{level_name}\nSession ID: {session_id}\n{'=' * 60}")
        fraud_ids = run_level(level_dir, session_id)

        # Output file
        safe_name = level_name.replace(" ", "_").lower()
        out_path = os.path.join(base, "outputs", f"{safe_name}.txt")
        with open(out_path, "w") as f:
            f.write("\n".join(fraud_ids) + "\n" if fraud_ids else "")
        print(f"  → {out_path}: {len(fraud_ids)} fraud IDs\n")

    # Print summary of all session IDs
    print("=" * 60)
    print("SESSION IDs SUMMARY")
    print("=" * 60)
    for level_name, sid in session_ids.items():
        print(f"  {level_name}: {sid}")


if __name__ == "__main__":
    main()
