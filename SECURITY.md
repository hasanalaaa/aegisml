# Security Policy

## Reporting a Vulnerability

AegisML is a security tool — we take vulnerabilities in our own codebase extremely seriously.

If you discover a security vulnerability in AegisML itself, **please do not open a public GitHub issue.** Instead, report it privately so we can address it before it is exploited.

### How to Report

1. **Email**: Send a detailed report to **security@aegisml.dev**
2. **Subject line**: `[SECURITY] Brief description of the vulnerability`
3. **Include**:
   - A clear description of the vulnerability
   - Steps to reproduce the issue
   - The potential impact (what an attacker could achieve)
   - Any suggested fixes, if you have them
   - Your name/handle for credit (optional)

### What Happens Next

| Timeframe | Action |
|-----------|--------|
| **24 hours** | We acknowledge receipt of your report |
| **72 hours** | We provide an initial assessment and severity rating |
| **14 days** | We develop and test a fix |
| **90 days** | We publicly disclose the vulnerability (Responsible Disclosure) |

### Responsible Disclosure Policy

We follow a **90-day disclosure policy**:

- Once a vulnerability is reported, we have **90 days** to develop and release a fix.
- After 90 days, the reporter is free to publicly disclose the vulnerability, regardless of whether a fix has been released.
- If we release a fix before the 90-day window, we will coordinate with the reporter on a joint public disclosure.
- We will credit the reporter in our security advisory (unless they prefer to remain anonymous).

### Scope

The following are **in scope** for security reports:

- Vulnerabilities in AegisML's CLI tool or inspectors
- Vulnerabilities in the scan engine API (FastAPI backend)
- Vulnerabilities in the web application
- Bypass techniques that allow malicious models to evade detection
- Supply chain attacks against AegisML's dependencies

The following are **out of scope**:

- Malicious AI models discovered using AegisML — please use the [Threat Report](https://github.com/aegisml/aegisml/issues/new?template=threat_report.yml) issue template instead
- Vulnerabilities in third-party dependencies — please report those to the respective maintainers

### Safe Harbor

We consider security research conducted in accordance with this policy to be:

- Authorized and not subject to legal action
- Helpful and conducted in good faith
- Exempt from any bug bounty minimums — we will credit all valid reports

### Security Advisories

Past security advisories are published on the [GitHub Security Advisories](https://github.com/aegisml/aegisml/security/advisories) page.

---

Thank you for helping keep AegisML and the AI ecosystem safe.
