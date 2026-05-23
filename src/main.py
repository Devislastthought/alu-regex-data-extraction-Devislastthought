import re
import json
import os

# File paths
UPLOAD_PATH = "/mnt/user-data/uploads/raw-text.txt"
LOCAL_PATH  = os.path.join(os.path.dirname(__file__), "../input/raw-text.txt")
INPUT_FILE  = UPLOAD_PATH if os.path.exists(UPLOAD_PATH) else LOCAL_PATH
OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "../output/sample-output.json")


# Read the text file
def read_input(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


# Security: check for dangerous/injection content
DANGER_PATTERNS = [r"<script", r"javascript:", r"DROP\s+TABLE", r"onerror\s*=", r"alert\s*\("]

def is_dangerous(value):
    for pattern in DANGER_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            return True
    return False


# Hide full card number, show only last 4 digits
def mask_card(number):
    digits = re.sub(r"\D", "", number)
    return "**** **** **** " + digits[-4:]


# EMAIL
def diagnose_email(email):
    if email.count("@") == 0:   return "missing @ symbol"
    if email.count("@") > 1:    return "more than one @ symbol"
    local, _, domain = email.partition("@")
    if not local:                return "nothing before @"
    if not domain:               return "nothing after @"
    if domain.startswith("."):   return "domain starts with a dot"
    if "." not in domain:        return "no extension like .com"
    if " " in email:             return "contains spaces"
    return "invalid email format"

def classify_email(email):
    if re.search(r"@si\.alueducation\.com$",     email, re.IGNORECASE): return "alu_si"
    if re.search(r"@alumni\.alueducation\.com$",  email, re.IGNORECASE): return "alu_alumni"
    if re.search(r"@alueducation\.com$",          email, re.IGNORECASE): return "alu_official"
    return "external"

def extract_emails(text):
    valid, rejected = [], []
    for raw in re.findall(r"(?i)email address\s*:\s*(\S+)", text):
        raw = raw.strip()
        if is_dangerous(raw):
            rejected.append({"value": "[REDACTED]", "reason": "dangerous content"})
        elif re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", raw):
            valid.append({"email": raw, "category": classify_email(raw)})
        else:
            rejected.append({"value": raw, "reason": diagnose_email(raw)})
    return valid, rejected


# CREDIT CARD
def diagnose_card(raw):
    digits = re.sub(r"\D", "", raw)
    if len(set(digits)) == 1:  return f"all digits are '{digits[0]}' . fake card"
    if len(digits) < 15:       return f"too few digits ({len(digits)}), minimum is 15"
    if len(digits) > 16:       return f"too many digits ({len(digits)}), maximum is 16"
    return "wrong format (expected 4-4-4-4 or 4-6-5)"

def extract_cards(text):
    valid, rejected = [], []
    pattern = r"(?i)card number\s*:\s*([\d\s]+)"
    valid_fmt = r"^(\d{4} \d{4} \d{4} \d{4}|\d{4} \d{6} \d{5}|\d{4} \d{6} \d{6})$"
    for raw in re.findall(pattern, text):
        raw = raw.strip()
        if is_dangerous(raw):
            rejected.append({"value": "[REDACTED]", "reason": "injection attempt"})
        elif re.match(valid_fmt, raw) and len(set(re.sub(r"\D","",raw))) > 1:
            valid.append({"masked": mask_card(raw)})
        else:
            rejected.append({"value": mask_card(raw), "reason": diagnose_card(raw)})
    return valid, rejected


# PHONE NUMBER
def diagnose_phone(raw):
    if not raw.startswith("+"):  return "missing + at the start"
    digits = re.sub(r"\D", "", raw)
    if len(digits) < 9:          return f"too few digits ({len(digits)}), number too short"
    if len(digits) > 15:         return f"too many digits ({len(digits)}), number too long"
    return "invalid phone format"

def extract_phones(text):
    valid, rejected = [], []
    for raw in re.findall(r"(?i)phone numbers?\s*:\s*(\S+)", text):
        raw = raw.strip()
        if is_dangerous(raw):
            rejected.append({"value": "[REDACTED]", "reason": "dangerous content"})
        elif re.match(r"^\+\d{1,3}\d{7,12}$", raw):
            valid.append({"phone": raw})
        else:
            rejected.append({"value": raw, "reason": diagnose_phone(raw)})
    return valid, rejected


# CURRENCY
def diagnose_currency(raw):
    if not re.search(r"\d", raw):  return "no number found"
    symbols = ["FRw", "KSh", "TSh", "£", "¥", "$", "€"]
    if not any(s in raw for s in symbols):
        return "unknown currency symbol — use FRw, KSh, TSh, £, ¥, $ or €"
    return "invalid currency format"

def extract_currency(text):
    valid, rejected = [], []
    valid_fmt = r"^([\d,]+\s*FRw|KSh\s*[\d,]+|TSh\s*[\d,]+|£[\d,]+|¥[\d,]+|\$[\d,.]+|€[\d,.]+)$"
    for raw in re.findall(r"(?i)currency_amounts?\s*:\s*(.+)", text):
        raw = raw.strip()
        if is_dangerous(raw):
            rejected.append({"value": "[REDACTED]", "reason": "dangerous content"})
        elif re.match(valid_fmt, raw):
            valid.append({"amount": raw})
        else:
            rejected.append({"value": raw, "reason": diagnose_currency(raw)})
    return valid, rejected


# MAIN
def main():
    text = read_input(INPUT_FILE)

    emails,   bad_emails   = extract_emails(text)
    cards,    bad_cards    = extract_cards(text)
    phones,   bad_phones   = extract_phones(text)
    currency, bad_currency = extract_currency(text)

    output = {
        "emails":           {"valid": emails,   "rejected": bad_emails},
        "credit_cards":     {"valid": cards,    "rejected": bad_cards},
        "phone_numbers":    {"valid": phones,   "rejected": bad_phones},
        "currency_amounts": {"valid": currency, "rejected": bad_currency}
    }

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print("=== Extraction Complete ===")
    for label, good, bad in [
        ("Emails",    emails,   bad_emails),
        ("Cards",     cards,    bad_cards),
        ("Phones",    phones,   bad_phones),
        ("Currency",  currency, bad_currency),
    ]:
        print(f"\n  {label}: {len(good)} valid, {len(bad)} rejected")
        for r in bad:
            print(f"    REJECTED: '{r['value']}' — {r['reason']}")

    print(f"\nResults saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
