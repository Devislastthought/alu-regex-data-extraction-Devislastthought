# ALU Regex Data Extraction — Devislastthought

A beginner friendly Python project that extracts and validates structured data from messy, real-world text using Regular Expressions (Regex).

---

## Overview

This project simulates how real  world systems process unstructured data such as API logs, support tickets, or raw text files and convert them into clean, structured information.

It focuses on extracting important data types while also validating and securing the input.

---

## What It Does

The program reads a raw `.txt` file containing messy text and extracts the following:

- Email addresses
  - Detects ALU-specific domains:
    - @alueducation.com → official staff
    - @alumni.alueducation.com → alumni users
    - @si.alueducation.com → Student Innovation users

- Credit card numbers
  - Supports major formats (Visa, Mastercard, Amex)
  - Masks sensitive data (only last 4 digits shown)
  - Rejects invalid or fake patterns

- Phone numbers
  - Supports international formats (e.g. +250, +1, +44)
  - Detects malformed or invalid numbers

- Currency amounts
  - Supports $, £, and € formats
  - Extracts numeric values for processing

---

## Security Features

The project also includes basic security handling:

- Detects malicious patterns (SQL injection, XSS attempts)
- Rejects invalid or suspicious input
- Masks sensitive financial data
- Filters placeholder or null values (e.g. 0000-0000-0000-0000)

---

---

## How to Run

### Requirements
- Python 3.6+

### Steps

```bash
cd alu-regex-data-extraction-Devislastthought
python src/main.py
