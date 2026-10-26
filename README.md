# ShadowPrompt v2.6 — Indirect AI Prompt Injection & Steganographic Document Firewall

- **Domain:** AI Security / Application Security (OWASP LLM01: Prompt Injection)

## Overview
ShadowPrompt detects and sanitizes hidden adversarial instructions embedded inside PDFs, resumes, and web documents before they are processed by Large Language Models (LLMs) or AI Applicant Tracking Systems (ATS).

## Key Features
1. **Zero-Width Unicode Detector:** Identifies `U+200B`, `U+200C`, `U+200D`, `U+2060`, and `U+FEFF` steganography.
2. **Trojan Source BiDi Detector:** Catches Right-to-Left Override (`U+202E`, CVE-2021-42574) and Cyrillic homographs.
3. **White-on-White & 0px Layer Detector:** Flags hidden HTML/PDF styling (`font-size:0`, `opacity:0`, `color:#ffffff`).
4. **X-Ray Forensic Decompiler & 1-Click Sanitizer:** Visualizes invisible characters and strips malicious payloads.

## Files Included
- `index.html`: Mobile-ready interactive web application & live forensic scanner.
- `shadowprompt_scanner.py`: Standalone Python CLI scanning and sanitization module.
- `README.md`: Project documentation and architecture overview.
