# Security Policy

Thank you for helping keep **Valorant Zoro** and its users safe.

This document explains how to report vulnerabilities, our disclosure process, what’s in scope, and baseline security practices for contributors and maintainers.

---

## Reporting a Vulnerability

**Please report security vulnerabilities privately. Do not open a public Issue or Discussion.**

* **Preferred:** Open a **GitHub Security Advisory** ("Report a vulnerability") for this repository.
* **Alternative:** Email the maintainer at **[saucywan@gmail.com](mailto:saucywan@gmail.com)** with a clear description, steps to reproduce, impact, and any proof-of-concept code or screenshots.
* If possible, include an estimated **CVSS v3.1** vector/score.
* We accept reports for both code and the supply chain (builds, dependencies, release artifacts).

### Our Commitment & Disclosure Timeline

* **Acknowledgement:** within **72 hours** (business days) of receiving your report.
* **Fix or mitigation:** target **same day** for high/critical, **24/48 hours** for medium, and published alongside the next standard release for low severity issues.
* **Coordinated disclosure:** we’ll agree on a public disclosure date after a fix/mitigation is available. If active exploitation is observed or risk is extreme, we may accelerate.

We’ll keep you updated at key milestones and credit you (with consent) in release notes and the security advisory.

### Safe Harbor

We support good-faith research and **Safe Harbor** under responsible disclosure:

* As long as you comply with this policy and avoid privacy violations, data destruction, or service disruption, we will not pursue legal action or report you to law enforcement.
* **Prohibited:** social engineering, physical attacks, DDoS/volumetric traffic, spam, and accessing data you do not own without explicit consent.

---

## Scope

**In scope**

* This repository’s source code, configuration, and CI/CD workflows.
* Published **releases** and distributed binaries for Valorant Zoro.
* Project documentation and example configurations that affect security posture.
* **Local runtime behavior**: since Valorant Zoro is a local tracker that runs on the user's machine and communicates with Riot's non‑public (closed) endpoints using the user's own Riot account credentials, the local execution environment (process lifecycle, IPC, local ports, file writes) is in scope.

**Special note on the closed Riot API and credentials**

* Valorant Zoro uses the Riot client or closed Valorant APIs that are only accessible via an authenticated Riot account. We do **not** perform account authorization — Riot client handles all of that. Users must log in through Riot, and credentials are **not** persisted by production builds.
* Every time the application starts, the user will need to re‑log in through the Riot client. By default, we do not keep the connection open; if Riot client is closed or stops responding, credentials become invalid within \~5 minutes (the exact timer is controlled by Riot and may change). If the user enables the setting to keep the connection alive, Valorant Zoro periodically sends heartbeats to maintain the session.
* Reportable issues include any vulnerability that allows an attacker to: capture those credentials, exfiltrate locally‑accessible match/person data, impersonate the tracker to request additional sensitive data, or hijack the main process to make stealth requests that the user did not intend.
* Because the API access relies on the user's account, threats include credential theft, process injection/hijacking, malicious builds (e.g., debug builds that persist secrets), and local privilege escalation.

**Out of scope** (unless explicitly noted)

* Third‑party platforms (e.g., GitHub infrastructure, package registries) except where misconfiguration is in this project.
* Vulnerabilities requiring **root/admin** or physical access to the tester’s own device without a realistic attack path from normal usage.
* Non‑security bugs, UX suggestions, rate‑limit exhaustion, or purely informational findings without demonstrated impact.

---

## Data & Privacy Considerations

Valorant Zoro may interact with:

* **Riot/Valorant APIs** and related credentials or tokens.
* **User configuration and local logs** (may contain usernames, match IDs, telemetry).

**Guidelines**

* Do **not** submit real tokens, API keys, or personal data in reports. Redact sensitive data.
* Demonstrate impact using test accounts or sanitized artifacts where possible.
* If you inadvertently access user data, **stop**, minimize exposure, and report immediately.

---

## Secrets & Credentials

* Never commit secrets (API keys, tokens, passwords) to the repository.
* Use environment variables and local `.env` files that are **git‑ignored**.
* If a secret is exposed, rotate it immediately and open a private advisory describing exposure scope and mitigation.
* Maintainers run **secret scanning** on pushes and PRs; findings may block merges until resolved.

### Debug Build Behavior

* In the `dev` branch, Debug mode is enabled. This mode:

  * Shows debug information in the console.
  * Writes a log file containing diagnostic details.
  * **Potentially sensitive information that may appear in debug logs:**

    * Riot authentication token **!sensitive!**
    * Region (NA/EU, ping times from all region servers)
    * Riot username / PUUID
    * Match data (usernames, server, player stats)
    * Party data (usernames, leader, server)
    * Store data (items available in shop)
    * In‑game currency balances (Valorant Points, Radianite Points, Kingdom Credits)
  * **Not logged:** payment information (Valorant Zoro has no access to payment methods or billing data).
* Debug builds are intended for development and troubleshooting only. Users should avoid running debug builds unless necessary, and should treat generated logs as sensitive artifacts.

---

## Supply Chain Security

* **Dependency management:**

  * Keep dependencies current; prioritize security updates.
  * Use lockfiles where supported.
  * Avoid unmaintained or suspicious packages.
* **Build integrity:**

  * CI builds run in least‑privilege environments.
  * Release artifacts should be reproducible where feasible.
  * Sign releases with a maintainer **GPG** or **Sigstore** identity; publish checksums.
* **Third‑party services:** Keep minimal permissions and rotate tokens regularly.

---

## Supported Versions

Security fixes are only provided for the current **latest** release. All older versions will **not** receive security updates. Users should upgrade to the newest release as soon as a security advisory is published.

| Version         | Status                                    |
| --------------- | ----------------------------------------- |
| `latest`        | **Supported** — receives security patches |
| older (any tag) | **Not supported** — no security updates   |

---

## Vulnerability Severity & Triage

We use **CVSS v3.1** for severity and consider exploitability, impact, and real‑world usage. Example priority order:

1. **Critical:** Credential disclosure, remote code execution, supply‑chain compromise.
2. **High:** Privilege escalation, authentication bypass, sensitive data exposure.
3. **Medium:** CSRF/logic flaws with limited impact, path traversal without data exfiltration.
4. **Low/Informational:** Errors, hardening gaps, missing headers without practical exploit. Low severity issues will still be fixed and published in the next standard release.

Each advisory will include: affected versions, description, remediation, and acknowledgements.

---

## Hardening & Secure Development Guidelines

* **Principle of least privilege:** only request permissions strictly necessary to function.
* **Input validation & output encoding:** treat game/API responses as untrusted.
* **Local file I/O:** avoid writing secrets to disk; prefer memory or encrypted stores.
* **Logging:** do not log secrets or full tokens; provide redaction.
* **Error handling:** avoid leaking stack traces or system paths in user‑visible output.
* **Update channel:** clearly notify users about security updates and how to upgrade.
* **Runtime sandboxing:** when possible, restrict OS capabilities and network egress.
* **Permissions:** Valorant Zoro does not require admin/root privileges for normal operation. The separate updater component may require elevated permissions, but it is outside the scope of this project’s security policy.

---

## Coordinated Release Process (Maintainer)

1. Receive private report (advisory/email) and acknowledge.
2. Reproduce, assign CVE (if eligible) via GitHub advisory.
3. Create a private fix branch; add tests to prevent regression.
4. Prepare patched release notes including mitigation/workarounds.
5. Publish release + advisory.

---

## Contact

* Security contact: **[saucywan@gmail.com](mailto:saucywan@gmail.com)**

---

## Attribution

This policy is inspired by community best practices (CERT/CC, OpenSSF, GitHub Advisories). Contributions to improve this policy are welcome via pull request.
