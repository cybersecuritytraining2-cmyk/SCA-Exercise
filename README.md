# SCA Findings — a dependency-triage exercise

Software Composition Analysis (SCA) scanners match the versions in your dependency
manifest against vulnerability databases and report **every** advisory for every
version. They do **not**, by default, know whether your code actually *reaches* the
vulnerable function, whether the bug *applies* to how you use the library, or
whether the package even ships to production. So a clean-looking app routinely
produces **hundreds** of findings, most of which are noise *in context*.

This exercise is a small, realistic Flask service, **InventoryService**, pinned to
old dependencies. An SCA scan reports **100+ findings**. Your job is the job a real
AppSec engineer does: triage them into *fix now*, *not applicable*, and *dev-only*,
then tune the scan so the noise stops drowning the signal — **without** silencing
the genuine bugs.

> Companion to the SAST false-positives exercise in this repo. SAST noise is about
> code *shapes*; SCA noise is about dependency *reachability and applicability*.

---

## The application

```
SCA-Exercise/
├── requirements.txt            # production dependencies (pinned, vulnerable)
├── requirements-dev.txt        # dev/test-only dependencies (not shipped)
├── app.py                      # Flask routes — where each dependency is exercised
├── config.py                   # DEBUG=False (matters for a Werkzeug finding)
├── inventory_service/
│   ├── importer.py             # PyYAML  — yaml.load on an upload
│   ├── images.py               # Pillow  — decodes uploaded images
│   ├── pricing.py              # requests/urllib3 — fixed internal URL
│   └── tokens.py               # cryptography — Fernet only
├── templates/product.html      # Jinja — plain rendering, no urlize
└── osv-scanner.toml            # triaged ignore list (the noise-reduction artefact)
```

---

## Prerequisites

- **OSV-Scanner** (Google). Install one of:
  - `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest`
  - or grab a binary from <https://github.com/google/osv-scanner/releases>
- Network access (OSV-Scanner queries the OSV.dev database).

You do **not** need to install the Python packages — SCA reads the manifest, it
doesn't run the app.

---

## Run the app (optional)

> **Python version requirement:** the dependencies are deliberately pinned to old,
> vulnerable versions (that is the point of the exercise). Several of them —
> notably Pillow 8.1.0 — **cannot build on Python 3.12+**. You will get a build
> error or a `ResolutionImpossible` conflict on modern Python.
> To run the app you need **Python 3.9, 3.10, or 3.11** (e.g. via `pyenv`).
>
> **Running the app is not required.** OSV-Scanner reads `requirements.txt` directly —
> nothing needs to be installed. Skip this section unless you specifically want to
> interact with the endpoints.

If you have Python ≤3.11 available:

```bash
# create and activate a virtual environment with a compatible Python
python3.11 -m venv scavenv
source scavenv/bin/activate      # Windows: scavenv\Scripts\activate

# install dependencies
pip install -r requirements.txt

# start the dev server
flask --app app run --debug --port 5001
```

The app will be available at <http://127.0.0.1:5001>.

> Port 5000 may be reserved on your machine. Use `--port 5001` or any other free port.

---

## Run the scan

```bash
# Production dependencies — expect ~112 findings across 8 packages.
osv-scanner scan source --lockfile requirements.txt --no-config-ignores

# Development-only dependencies — 2 findings.
osv-scanner scan source --lockfile requirements-dev.txt
```

(The count rises over time: these versions are frozen, so every new advisory
published against them adds to the pile — a lesson in itself.) `--no-config-ignores`
shows the raw, pre-triage picture; drop it to see the triaged result (below).

---

## The challenges

Work package by package. The verdicts depend on **how InventoryService actually
uses each library** — read the linked source, not just the CVE.

### PyYAML 5.3.1 — `inventory_service/importer.py`
**Scanner says:** CVE-2020-14343 (and PYSEC) — arbitrary code execution parsing
untrusted YAML with the full loader.
**Verdict: TRUE POSITIVE — fix now.** `import_inventory` calls `yaml.load()` (full
loader) on the raw bytes of an **uploaded file**. A payload like
`!!python/object/apply:os.system ["id"]` runs commands. Untrusted input, reachable
sink, exploitable. **Action:** upgrade PyYAML (≥6.0) **and** switch to
`yaml.safe_load`.

### Pillow 8.1.0 — `inventory_service/images.py`
**Scanner says:** ~50 advisories — buffer overflows / OOB reads in many image
decoders (CVE-2021-25287, CVE-2021-34552, CVE-2022-22817, …).
**Verdict: TRUE POSITIVE — fix now.** `make_thumbnail` runs `Image.open()` over an
**untrusted uploaded image**, which is exactly the decoder path these cover.
**Action:** upgrade Pillow to the current release. Note the leverage: **one upgrade
clears ~50 findings.** Prioritise by *package*, not by *finding count*.

### Jinja2 2.11.2 — `templates/product.html`
**Scanner says:** CVE-2020-28493 (`urlize` ReDoS), CVE-2024-34064 (`xmlattr`), and
sandbox-escape CVEs.
**Verdict: FALSE POSITIVE in context (unreachable).** These live in the `urlize`
and `xmlattr` filters and the sandboxed environment. This app renders with plain
auto-escaped `{{ }}` and uses none of them, so there is no reachable trigger.
**Action:** ignore with justification (still upgrade eventually as hygiene).

### Werkzeug 0.15.5 — `config.py`
**Scanner says:** CVE-2024-34069 (interactive-debugger RCE) plus multipart-DoS and
open-redirect advisories.
**Verdict: NOT APPLICABLE for the debugger RCE (config-dependent).** That bug needs
the interactive debugger running (`DEBUG=True`). Production runs with `DEBUG=False`
behind gunicorn, so the vulnerable feature is never active. *Caveat:* the
multipart-DoS items (e.g. CVE-2023-25577) **are** reachable if you accept uploads —
don't ignore those by reflex. Same package, different verdicts per CVE.
**Action:** ignore the debugger CVE with justification; assess the DoS items on merit.

### requests 2.19.1 + urllib3 1.25.8 — `inventory_service/pricing.py`
**Scanner says:** requests CVE-2018-18074 (auth header leaked on cross-host
redirect); urllib3 redirect/proxy/CRLF advisories.
**Verdict: NOT APPLICABLE in this usage (urllib3 is also transitive).** The pricing
client hits a **fixed internal URL**, sends no `Authorization` header, follows no
user-controlled redirects, and uses no proxy — none of the vulnerable behaviours
are triggered. urllib3 is pulled in *by* requests (transitive); upgrading the top
of the tree usually carries it along.
**Action:** low priority; keep current as hygiene, ignore the redirect-leak CVE with
justification.

### cryptography 3.3.1 — `inventory_service/tokens.py`
**Scanner says:** CVE-2023-0286 (X.509 GeneralName), CVE-2024-0727 (PKCS12 DoS),
CVE-2020-36242 (overflow on huge inputs), …
**Verdict: NOT APPLICABLE (vulnerable features unused).** We use only Fernet on
small server-generated payloads. The X.509/PKCS parsing paths are never called and
CVE-2020-36242 needs multi-GB inputs we never pass.
**Action:** low priority; upgrade on the next maintenance pass.

### Dev-only: pytest 6.2.2, py 1.10.0 — `requirements-dev.txt`
**Scanner says:** py CVE-2022-42969 (ReDoS in `py.path.svnwc`), a pytest advisory.
**Verdict: FALSE POSITIVE in context (dev-only + unreachable).** These are test
dependencies, not in the production image, and the py ReDoS needs untrusted SVN
metadata this project never processes.
**Action:** keep dev and prod findings in separate gates; don't block a release on
dev-only noise (but do keep tooling patched).

---

## Reducing the noise

Apply roughly in order. The aim is a *trustworthy* gate, not a *silent* one.

### 0. Triage by reachability & exploitability, not by count or raw CVSS
A version match is a *question*, not a verdict. Ask: is the vulnerable function
reachable? does the bug apply to our usage/config/platform? is it prod or dev? Use
**CISA KEV** (is it actively exploited?) and **EPSS** (exploit probability) to rank —
a reachable KEV entry beats ten unreachable "criticals".

### 1. Separate production from development
Scan and gate them differently. A dev-only ReDoS shouldn't block a release. Best of
all, scan the **built artefact / container image**, which contains only what ships:
```bash
osv-scanner scan source --lockfile requirements.txt        # prod gate
osv-scanner scan source --lockfile requirements-dev.txt    # dev, informational
```

### 2. Fix the true positives — upgrade
The real remediation. Upgrading **PyYAML** and **Pillow** here removes the only
exploitable findings *and* (for Pillow) ~50 advisories in one move. Always prefer
upgrading the **direct** dependency; it usually pulls fixed transitive versions too.

### 3. Ignore triaged findings — with a reason and an expiry
For findings you've judged not-applicable, record the decision in `osv-scanner.toml`
so the gate stays quiet *and auditable*. See the included file:
```toml
[[IgnoredVulns]]
id = "CVE-2020-28493"                       # also accepts GHSA-/PYSEC- ids
reason = "urlize filter not used; unreachable."
ignoreUntil = "2026-12-31T00:00:00Z"        # MUST be full RFC3339 — a bare date is silently ignored
```
**Verified:** with this file present, the scan filters those CVEs (and their
aliases) and prints the reason for each. `ignoreUntil` forces you to re-confirm —
silence is time-boxed, never permanent. Never ignore a finding you haven't actually
triaged (that's how the PyYAML RCE would slip through).

### 4. Record applicability as VEX
For sharing triage with downstream consumers (or your own platform), a **VEX**
(Vulnerability Exploitability eXchange) document states "not affected" with a
machine-readable justification (`vulnerable_code_not_in_execute_path`,
`component_not_present`, …). It's the portable, standardised cousin of the ignore
file — the same decisions, consumable by other tools.

### 5. Make it continuous
Pinned-and-forgotten is why this app has 112 findings. Use a lockfile, automate
upgrades (**Dependabot / Renovate**), generate an **SBOM**, and re-scan in CI so new
advisories surface as small, reviewable PRs instead of an annual avalanche.

---

## Summary

| Package | Scanner finding(s) | Verdict | Action |
|---------|--------------------|---------|--------|
| PyYAML 5.3.1 | CVE-2020-14343 (RCE) | **TRUE POSITIVE** (reachable, untrusted) | **Upgrade + `safe_load` now** |
| Pillow 8.1.0 | ~50 decoder CVEs | **TRUE POSITIVE** (decodes uploads) | **Upgrade now** (clears ~50) |
| Jinja2 2.11.2 | urlize/xmlattr/sandbox CVEs | False positive (filters unused) | Ignore w/ reason; upgrade later |
| Werkzeug 0.15.5 | debugger RCE / multipart DoS | Debugger N/A (DEBUG=False); **DoS = assess** | Ignore debugger; judge DoS |
| requests/urllib3 | redirect/proxy/CRLF CVEs | Not applicable (fixed internal URL) | Low priority; hygiene upgrade |
| cryptography 3.3.1 | X.509/PKCS CVEs | Not applicable (Fernet only) | Low priority |
| pytest / py (dev) | ReDoS etc. | Dev-only + unreachable | Separate gate; don't block release |

### Key takeaways
- **A version match is not an exploitable bug.** Reachability and applicability turn
  a finding into a verdict.
- **Prioritise by package and by exploitability.** One Pillow upgrade beats triaging
  fifty findings; a reachable KEV entry beats an unreachable "critical".
- **Prod ≠ dev.** Gate them separately, or scan what actually ships.
- **Never blanket-ignore.** Ignore *specific, triaged* findings with a reason and an
  expiry — the PyYAML RCE is one lazy mute away from shipping.
- **The real fix is upgrading.** Ignore files manage noise; they don't remove risk.

### Discovery methods
- **Manual triage:** for each finding, open the linked module and decide reachable /
  applicable / dev-only.
- **Code review:** the safe-vs-unsafe usage (`yaml.load` vs none; `Image.open` on
  uploads vs a fixed URL) is right there in `inventory_service/`.
- **Tooling:** re-run with `osv-scanner.toml` in place and confirm the triaged CVEs
  drop out *while the PyYAML and Pillow findings remain*.
