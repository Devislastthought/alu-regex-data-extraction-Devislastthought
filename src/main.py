"""
ALU Regex Data Extraction main.py
GitHub: Devislastthought
What this program does:
  - Reads a raw text file (simulating messy API output)
  - Uses regex to extract: emails, credit cards, phone numbers, currency amounts
  - Validates ALU-specific email domains
  - Flags and rejects suspicious / malformed input
  - Saves clean results to output/sample-output.json
Data types extracted (4 total):
  1. Email addresses   (required)
  2. Credit card numbers (required)
  3. Phone numbers
  4. Currency amounts
"""

import re
import json
import os

# File paths 
INPUT_FILE  = os.path.join(os.path.dirname(__file__), "../input/raw-text.txt")
OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "../output/sample-output.json")


# 1.Read the raw text
def read_input(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


# 2. Security helpers

# Patterns that signal hostile/injected content
DANGER_PATTERNS = [
    r"<script",        # XSS
    r"javascript:",    # JS protocol
    r"DROP\s+TABLE",   # SQL injection
    r"onerror\s*=",    # HTML event injection
    r"alert\s*\(",     # JS alert
]

def is_dangerous(value):
    """Return True if the string looks like an injection attempt."""
    for pattern in DANGER_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            return True
    return False

def mask_card(number):
    """
    Show only last 4 digits — never log full card numbers.
    e.g. '5500 0730 0200 0004' → '**** **** **** 0004'
    """
    digits = re.sub(r"\D", "", number)
    return "**** **** **** " + digits[-4:]


# 3. Regex patterns

#  EMAIL
# Matches: pep@mail.com - d.anthony@alumni.alueducation.com
EMAIL_PATTERN = r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"

def classify_email(email):
    """Label ALU emails by domain, or mark as external."""
    if re.search(r"@si\.alueducation\.com$",     email, re.IGNORECASE): return "alu_si"
    if re.search(r"@alumni\.alueducation\.com$",  email, re.IGNORECASE): return "alu_alumni"
    if re.search(r"@alueducation\.com$",          email, re.IGNORECASE): return "alu_official"
    return "external"

# --- CREDIT CARD ---
# Matches 16-digit cards (4-4-4-4): 5500 0730 0200 0004
# Matches 15-digit JCB/Amex style (4-6-6): 3530 111333 000000
CARD_PATTERN = r"""
    (?:
        \d{4}[\s]\d{4}[\s]\d{4}[\s]\d{4}   # 16-digit: 4-4-4-4  e.g Visa/MC
        |
        \d{4}[\s]\d{6}[\s]\d{6}             # 16-digit: 4-6-6    e.g JCB
        |
        \d{4}[\s]\d{6}[\s]\d{5}             # 15-digit: 4-6-5    e.g Amex
    )
"""

def is_valid_card(raw):
    """Reject cards where all digits are the same (e.g. 0000 000000 00000)."""
    digits = re.sub(r"\D", "", raw)
    if len(set(digits)) == 1:    # all same digit — fake
        return False
    if len(digits) not in (15, 16):
        return False
    return True

#  PHONE NUMBER 
# Matches your format: +250784293730 or +254712458963
# Must start with + and have 7–13 digits after
PHONE_PATTERN = r"\+\d{1,3}\d{7,13}"

def is_valid_phone(raw):
    """Reject clearly invalid numbers (too short after country code)."""
    digits = re.sub(r"\D", "", raw)
    if len(digits) < 9:      # too few digits to be real
        return False
    return True

#  CURRENCY 
# Matches your formats:
#   40000 FRw | KSh 15,000 or £250 or TSh 85,000 or ¥1,200
CURRENCY_PATTERN = r"""
    (?:
        [\d,]+\s*FRw           # Rwandan Franc:   40000 FRw
        |
        KSh\s*[\d,]+           # Kenyan Shilling: KSh 15,000
        |
        £[\d,]+                # British Pound:   £250
        |
        TSh\s*[\d,]+           # Tanzanian Shilling: TSh 85,000
        |
        ¥[\d,]+                # Chinese Yuan:    ¥1,200
        |
        \$[\d,]+(?:\.\d{2})?   # US Dollar:       $29.99
        |
        €[\d,]+(?:\.\d{2})?    # Euro:            €45.00
    )
"""


# 4. Extract functions 

def extract_emails(text):
    found    = re.findall(EMAIL_PATTERN, text)
    valid    = []
    rejected = []

    for email in found:
        if is_dangerous(email):
            rejected.append({"value": "[REDACTED]", "reason": "dangerous content"})
            continue
        valid.append({
            "email":    email,
            "category": classify_email(email)
        })

    return valid, rejected


def extract_cards(text):
    found    = re.findall(CARD_PATTERN, text, re.VERBOSE)
    valid    = []
    rejected = []

    for card in found:
        card = card.strip()
        if is_dangerous(card):
            rejected.append({"value": "[REDACTED]", "reason": "injection attempt"})
            continue
        if not is_valid_card(card):
            rejected.append({"value": mask_card(card), "reason": "invalid card number"})
            continue
        valid.append({"masked": mask_card(card)})   # never log full number

    return valid, rejected


def extract_phones(text):
    found    = re.findall(PHONE_PATTERN, text)
    valid    = []
    rejected = []

    for phone in found:
        phone = phone.strip()
        if not is_valid_phone(phone):
            rejected.append({"value": phone, "reason": "too short / invalid"})
            continue
        valid.append({"phone": phone})

    return valid, rejected


def extract_currency(text):
    found = re.findall(CURRENCY_PATTERN, text, re.VERBOSE)
    return [{"amount": amt.strip()} for amt in found if amt.strip()]


# 5. Main 

def main():
    text = read_input(INPUT_FILE)

    emails,  bad_emails = extract_emails(text)
    cards,   bad_cards  = extract_cards(text)
    phones,  bad_phones = extract_phones(text)
    currency            = extract_currency(text)

    output = {
        "emails": {
            "valid":    emails,
            "rejected": bad_emails
        },
        "credit_cards": {
            "valid":    cards,
            "rejected": bad_cards
        },
        "phone_numbers": {
            "valid":    phones,
            "rejected": bad_phones
        },
        "currency_amounts": currency
    }

    # Save JSON output
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    # Console summary
    print("=== Extraction Complete ===")
    print(f"  Emails found     : {len(emails)}  | Rejected: {len(bad_emails)}")
    print(f"  Cards found      : {len(cards)}   | Rejected: {len(bad_cards)}")
    print(f"  Phones found     : {len(phones)}  | Rejected: {len(bad_phones)}")
    print(f"  Currency amounts : {len(currency)}")
    print(f"\n  Full results saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
