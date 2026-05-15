# WebCheck

> **Web Vulnerability & Recon Tool**
> A Python-based security reconnaissance and vulnerability scanning tool for authorised penetration testing and security research.

```
 ________         __     ______ __                __    
|  |  |  |.-----.|  |--.|      |  |--.-----.----.|  |--.
|  |  |  ||  -__||  _  ||   ---|     |  -__|  __||    < 
|________||_____||_____||______|__|__|_____|____||__|__|
                                                        
  WebCheck v1.2 -- Web Vulnerability & Recon Tool
                    by X3RX3S
  https://github.com/X3RX3SSec  instagram @mindfuckerrrr
```

---

## Disclaimer

> **WebCheck is intended for authorised security testing only.**
> Only use this tool against systems you own or have explicit written permission to test.
> Unauthorised scanning may be illegal in your jurisdiction. The author accepts no liability for misuse.

---

## Features

WebCheck covers **28 security modules** across reconnaissance, vulnerability detection, and reporting all with zero external dependencies (pure Python 3 stdlib).

| # | Module | What it checks |
|---|--------|----------------|
| 01 | Security Headers | HSTS, CSP, X-Frame-Options, version disclosure |
| 02 | TLS / SSL | Cert expiry, weak ciphers, TLSv1.0/1.1 |
| 03 | Sensitive Paths | `.env`, `.git`, admin panels, backups, CI/CD files |
| 04 | Cookie Security | HttpOnly, Secure, SameSite per cookie |
| 05 | CORS | Origin reflection, wildcard + credentials combo |
| 06 | HTTP Methods | TRACE, PUT, DELETE, PROPFIND |
| 07 | Port Scan + Banner Grab | 28 common ports with service banners |
| 08 | Tech Fingerprinting | 20+ stacks + version-based CVE hints |
| 09 | CVE Scan + Exploit Hints | Signature DB + live NVD API lookup |
| 10 | SQL Injection | Error-based, boolean, time-based blind |
| 11 | XSS Probes | Reflected XSS across common parameters |
| 12 | Open Redirect | 12 common redirect parameters + bypass payloads |
| 13 | Subdomain Enumeration | DNS bruteforce across 70+ common names |
| 14 | DNS & Email Security | SPF, DMARC enforcement, MX records |
| 15 | WAF / CDN Detection | 10 WAF signatures + bypass hints |
| 16 | JS Secret Scanner | API keys, AWS keys, JWTs, DB URIs, webhooks |
| 17 | HTTP Request Smuggling | CL.TE probe |
| 18 | Directory Fuzzing | 70+ path wordlist, threaded |
| 19 | SSRF Probe | AWS/GCP metadata, internal IPs, file:// |
| 20 | Clickjacking | X-Frame-Options + CSP frame-ancestors |
| 21 | Auth Checks | Login detection, rate limiting, Basic Auth |
| 22 | ASN & IP Reputation | ipinfo.io ASN/org lookup, VPS flagging |
| 23 | Google Dork Generator | 20 targeted dorks for the scanned domain |
| 24 | Email Harvesting | Emails scraped from common pages + mailto links |
| 25 | LFI + PHP Filter Chain | 40 params x 15 payloads + filter chain RCE hints |
| 26 | JWT Weakness Checker | alg=none, weak HMAC, RS->HS confusion, expiry |
| 27 | IDOR Probe | Numeric ID enumeration in URLs and params |
| 28 | XXE Detection | XML endpoint detection + entity injection probe |

---

## Requirements

- Python 3.8 or higher (tested on 3.10, 3.11, 3.13)
- No external libraries required, uses stdlib only ;)

---

## Installation

```bash
git clone https://github.com/X3RX3SSec/webcheck.git
cd webcheck
python3 webcheck.py
```

That's it. No pip install, no virtualenv needed.

---

## Usage

### Interactive mode
```bash
python3 webcheck.py
```
Enter your target, pick modules or a preset from the menu, and go.

### CLI flags
```bash
# Scan a specific target with a preset
python3 webcheck.py --target fbi.gov --preset web

# Pick individual modules
python3 webcheck.py --target cia.gov --modules 1,3,9,25

# Save an HTML report
python3 webcheck.py --target nsa.gov --preset full --output html

# Add a delay between requests (ms) to avoid WAF triggers
python3 webcheck.py --target trump.com --preset quick --delay 500

# Scan a list of hosts from a file
python3 webcheck.py --hosts targets.txt --preset quick --output json

# Skip the banner (useful for scripting)
python3 webcheck.py --target epstein.com --no-banner --preset recon
```

### All flags

| Flag | Short | Description |
|------|-------|-------------|
| `--target` | `-t` | Target host (e.g. `fbi.gov` or `https://fbi.gov`) |
| `--preset` | `-p` | Run a named preset (see below) |
| `--modules` | `-m` | Comma-separated module numbers (e.g. `1,3,9`) |
| `--output` | `-o` | Report format: `txt` (default), `html`, `json` |
| `--delay` | `-d` | Delay between requests in milliseconds |
| `--hosts` | `-H` | Path to a file containing one host per line |
| `--no-banner` | | Suppress ASCII banner |

---

## Presets

| Preset | Modules | Best for |
|--------|---------|----------|
| `quick` | 1,2,3,4,15,22 | Fast surface check, first look at a target |
| `web` | 5,10,11,12,19,20,21,25,26,27,28 | Web app pen testing |
| `recon` | 7,8,13,14,16,18,22,23,24 | Passive recon and footprinting |
| `cve` | 8,9,17 | CVE hunting based on tech stack |
| `full` | 1–28 | Full scan, all modules |

---

## Report Formats

WebCheck can export findings in three formats:

**TXT**  plain text, good for notes and piping
```
[CRITICAL] LFI: LFI confirmed via ?page= payload=../../../etc/passwd
[HIGH]     CVE: CVE-2021-41773 (CVSS 9.8): Path traversal + RCE Apache 2.4.49
[MEDIUM]   Auth: No rate limiting on login endpoint
```

**HTML** — dark-themed report with colour-coded severity table, ready to share

**JSON** — structured output for importing into other tools or pipelines
```json
{
  "tool": "WebCheck",
  "host": "https://example.com",
  "findings": [
    { "severity": "HIGH", "module": "SQLi", "detail": "Error-based SQLi in 'id'" }
  ],
  "summary": { "CRITICAL": 1, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 4 }
}
```

---

## Module Highlights

### LFI + PHP Filter Chain (Module 25) Inspired by Chocapikk
Tests **40 common PHP parameters** (`page`, `file`, `path`, `include`, `template`, `view`, `load`, `doc`, `lang`, `locale`, and more) against **15 traversal payloads** including:
- Standard `../../../etc/passwd` traversal
- Double-encoded and Unicode variants
- `php://filter` base64 chain for source disclosure
- `data://` and `expect://` wrappers
- PHP Filter Chain RCE path via [synacktiv/php_filter_chain_generator](https://github.com/synacktiv/php_filter_chain_generator)

### CVE Scan (Module 9)
Matches server banners and page content against a built-in CVE signature database covering Apache, Nginx, PHP-FPM, OpenSSL, WordPress, Drupal, Joomla, Spring, Log4j, Struts2, Telerik, Jenkins, and more — then queries the live NVD API for additional results based on the detected server version.

### JWT Checker (Module 26)
Detects JWTs in response headers and common API endpoints, then checks for:
- `alg: none` signature bypass
- Weak HMAC symmetric secrets (hashcat command provided)
- RS256 → HS256 algorithm confusion
- Missing or expired `exp` claims

---

## Hosts File Format

One host per line, `#` for comments:
```
# Production targets
nsa.gov
https://api.nsa.gov
staging.nsa.gov

# Third-party
partner.com
```

---

## Legal

This tool is provided for **educational and authorised security testing purposes only**.

- Do not run WebCheck against systems without explicit written authorisation
- Check local laws before scanning — unauthorised access is a criminal offence in most jurisdictions
- The developer assumes no responsibility for misuse

---

## Contributing

Pull requests welcome. If you add a module, follow the existing pattern:
1. Write a `check_yourmodule(base)` function
2. Add it to the `MODULES` dict with a number key
3. Add it to relevant presets if applicable
4. Test on Python 3.8 and 3.13

---

## Author

**X3RX3S**
- GitHub: [X3RX3SSec](https://github.com/X3RX3SSec)
- Instagram: [@mindfuckerrrr](https://instagram.com/mindfuckerrrr)

Found a bug or want a feature? Open an issue.

---

*WebCheck because knowing it all is half the battle.*
