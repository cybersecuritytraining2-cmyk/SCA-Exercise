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
# Production dependencies — expect ~112 findings across 8 packages (raw, pre-triage).
osv-scanner scan source --lockfile requirements.txt

# Development-only dependencies — 2 findings.
osv-scanner scan source --lockfile requirements-dev.txt
```

The count rises over time: these versions are frozen, so every new advisory
published against them adds to the pile — a lesson in itself. The first command
shows the raw, pre-triage picture; once you have worked through the challenges,
the `osv-scanner.toml` ignore list will suppress the noise and you can re-run to
see the triaged result.

> **Note (v2):** In OSV-Scanner v2 the `--no-config-ignores` flag was removed.
> To see raw results, simply run without an `osv-scanner.toml` present, or
> temporarily rename it: `mv osv-scanner.toml osv-scanner.toml.bak`.

---

## Triage framework

A version match is a *question*, not a verdict. Before assigning any finding,
work through these questions:

| # | Question | Why it matters |
|---|----------|----------------|
| 1 | Is this a **production** or **dev-only** dependency? | Dev findings shouldn't block a release gate |
| 2 | Is it a **direct** dependency or pulled in **transitively**? | Upgrading the direct dep usually fixes the transitive one too |
| 3 | What does the **vulnerable feature** actually do? | Read the CVE/advisory, not just the headline |
| 4 | Does this app **call that feature**? | A function that is never invoked is unreachable |
| 5 | If reachable — is the **input user-controlled** or internal/trusted? | Untrusted input is what turns a finding into an exploitable bug |
| 6 | Does any **configuration** affect whether the bug is active? | Some vulns only fire in debug mode, with a specific flag, etc. |
| 7 | Is it **actively exploited**? | Check CISA KEV; use EPSS score to rank |

Apply this to every package below before revealing the verdict.

---

## The challenges

Work package by package. Read the linked source file first — the verdict depends on
**how InventoryService actually uses each library**, not on the CVE headline alone.

---

### 1. PyYAML 5.3.1 — `inventory_service/importer.py`

**Scanner says:** CVE-2020-14343 (CVSS 9.8) — arbitrary code execution when parsing
untrusted YAML with the full loader.

**Read:** `inventory_service/importer.py`

**Work through the checklist:**
- What function does `importer.py` call to parse YAML? Is it the safe variant?
- Where does the data being parsed come from? Is it an internal config file, or something a user sends?
- If a user can supply the YAML, what would a payload like `!!python/object/apply:os.system ["id"]` do?
- Is this dependency direct or transitive? Prod or dev?

<details>
<summary>Verdict and recommended action</summary>

**TRUE POSITIVE — fix now.**

`import_inventory` calls `yaml.load()` with the full loader on the raw bytes of an
**uploaded file**. That is the exact path CVE-2020-14343 describes: untrusted input
reaching the full YAML loader, which can execute arbitrary Python via tags like
`!!python/object/apply:os.system ["id"]`.

The input is user-controlled, the sink is reachable, and the bug is exploitable.

**Action:** upgrade PyYAML to ≥6.0 **and** change the call to `yaml.safe_load()`.
Both are required — the safe loader is the real fix; the upgrade removes related
advisories.

</details>

---

### 2. Pillow 8.1.0 — `inventory_service/images.py`

**Scanner says:** ~50 advisories — buffer overflows and out-of-bounds reads in
multiple image decoders (CVE-2021-25287, CVE-2021-34552, CVE-2022-22817, and many
others).

**Read:** `inventory_service/images.py`

**Work through the checklist:**
- What does `make_thumbnail` do with the file it receives? Which Pillow function opens it?
- Where does that file come from — an internal asset directory, or a user upload?
- The CVEs affect image *decoders*. Is Pillow decoding anything here?
- There are ~50 findings for this one package. Does that mean there are ~50 separate problems to fix, or one?

<details>
<summary>Verdict and recommended action</summary>

**TRUE POSITIVE — fix now.**

`make_thumbnail` calls `Image.open()` on an **untrusted uploaded image**. That is
exactly the decoder path covered by this family of CVEs — buffer overflows and
out-of-bounds reads triggered by malformed image data in the JPEG, TIFF, and other
decoders Pillow uses.

Note the leverage: **one upgrade clears ~50 findings.** This is the key lesson about
prioritising by *package* rather than by raw finding count — the number 50 is
alarming but the fix is a single `pip install --upgrade pillow`.

**Action:** upgrade Pillow to the current release. It is a direct dependency, so
a version bump in `requirements.txt` is all that is needed.

</details>

---

### 3. Jinja2 2.11.2 — `templates/product.html`

**Scanner says:** CVE-2020-28493 (`urlize` filter ReDoS), CVE-2024-34064 (`xmlattr`
filter XSS), and several sandbox-escape CVEs.

**Read:** `templates/product.html`

**Work through the checklist:**
- The `urlize` ReDoS lives in the `urlize` Jinja filter. Does `product.html` use that filter anywhere?
- The `xmlattr` XSS lives in the `xmlattr` filter. Is that filter used?
- The sandbox-escape CVEs require a sandboxed Jinja environment. Does this app use `SandboxedEnvironment`?
- If none of the vulnerable features are used, can the vulnerabilities be triggered?

<details>
<summary>Verdict and recommended action</summary>

**NOT APPLICABLE in context — unreachable.**

All three CVE families require features this app does not use:
- `urlize` and `xmlattr` are Jinja filters that are not referenced anywhere in the templates.
- The sandbox escapes need `SandboxedEnvironment`, which is not used — Flask's default `Environment` is not sandboxed.

Because the vulnerable code paths are never called, there is no trigger.

**Action:** ignore each CVE in `osv-scanner.toml` with a justification (e.g.
`"urlize filter not used; unreachable"`). Plan a hygiene upgrade on the next
maintenance pass — it is still worth staying current.

</details>

---

### 4. Werkzeug 0.15.5 — `config.py`

**Scanner says:** CVE-2024-34069 — the Werkzeug interactive debugger can be used for
remote code execution. Also: multipart-parsing DoS advisories (e.g. CVE-2023-25577)
and an open-redirect advisory.

**Read:** `config.py`

**Work through the checklist:**
- CVE-2024-34069 requires the interactive debugger to be running. What controls that in Werkzeug/Flask? Check `config.py`.
- If `DEBUG=False`, is the debugger active in production?
- Now look at the multipart-DoS advisories separately. Does this app accept file uploads?
- Should both CVEs get the same verdict? Or does the same package version require two different assessments?

<details>
<summary>Verdict and recommended action</summary>

**Split verdict — same package, different answers per CVE.**

- **CVE-2024-34069 (debugger RCE): NOT APPLICABLE.** The interactive debugger only
  activates when `DEBUG=True`. `config.py` sets `DEBUG=False` and production runs
  behind gunicorn, so the vulnerable feature is never enabled.

- **Multipart-DoS CVEs (e.g. CVE-2023-25577): REQUIRES ASSESSMENT.** This app does
  accept file uploads (`/inventory/import`, `/products/image`). The DoS path is
  potentially reachable — do not ignore these by reflex just because the debugger CVE
  was not applicable.

This is the key Werkzeug lesson: **never blanket-ignore a package**. Read each CVE
individually — the same version can have one not-applicable finding and one genuine
risk sitting side by side.

**Action:** ignore the debugger CVE with justification; assess the multipart-DoS
items on their own merit and upgrade when a fix is available.

</details>

---

### 5. requests 2.19.1 + urllib3 1.25.8 — `inventory_service/pricing.py`

**Scanner says:** requests CVE-2018-18074 — `Authorization` header leaked on
cross-host redirect. urllib3 advisories covering redirect handling, proxy header
injection, and CRLF injection.

**Read:** `inventory_service/pricing.py`

**Work through the checklist:**
- What URL does the pricing client call? Is it user-supplied or hard-coded?
- Does the client send an `Authorization` header? If not, can it be leaked?
- Does the code follow redirects to user-controlled destinations?
- urllib3 is not in `requirements.txt` directly. Where does it come from? Does that affect what you upgrade?

<details>
<summary>Verdict and recommended action</summary>

**NOT APPLICABLE in this usage.**

The pricing client hits a **fixed, hard-coded internal URL**. It sends no
`Authorization` header, follows no user-controlled redirects, and uses no proxy —
none of the behaviours the CVEs describe are present in this code.

urllib3 is a **transitive dependency** pulled in by requests. It does not appear
directly in `requirements.txt`. Upgrading `requests` to a current release will
pull in a fixed urllib3 as well — you do not need to pin urllib3 separately.

**Action:** low priority; ignore the redirect-leak CVE with justification. Upgrade
`requests` on the next maintenance pass as hygiene — the transitive urllib3 fix
comes along for free.

</details>

---

### 6. cryptography 3.3.1 — `inventory_service/tokens.py`

**Scanner says:** CVE-2023-0286 (X.509 GeneralName confusion), CVE-2024-0727
(PKCS12 DoS), CVE-2020-36242 (integer overflow on very large inputs), and others.

**Read:** `inventory_service/tokens.py`

**Work through the checklist:**
- Which part of the `cryptography` library does `tokens.py` use? Look at the import.
- CVE-2023-0286 and CVE-2024-0727 live in the X.509 certificate and PKCS12 parsing code. Does this app parse any certificates or PKCS12 files?
- CVE-2020-36242 triggers on inputs larger than 2 GB. What size are the payloads this app passes to `cryptography`?
- If the vulnerable subsystems are never imported or called, can they be reached?

<details>
<summary>Verdict and recommended action</summary>

**NOT APPLICABLE — vulnerable features unused.**

`tokens.py` uses only `Fernet` on small, server-generated payloads. Fernet is a
symmetric encryption wrapper that internally uses AES-CBC and HMAC — it does not
touch the X.509, PKCS12, or certificate-parsing subsystems that the reported CVEs
affect. CVE-2020-36242 requires inputs measured in gigabytes; nothing this app
processes comes close.

**Action:** low priority; no immediate risk. Upgrade `cryptography` on the next
maintenance pass as hygiene.

</details>

---

### 7. pytest 6.2.2 + py 1.10.0 — `requirements-dev.txt`

**Scanner says:** py CVE-2022-42969 — ReDoS in `py.path.svnwc` when processing
SVN repository metadata. A pytest advisory is also present.

**Work through the checklist:**
- Where are these packages listed — `requirements.txt` or `requirements-dev.txt`?
- Does a dev-only package ship in the production container image?
- CVE-2022-42969 triggers when processing untrusted SVN metadata. Does this project use SVN?
- Should a dev-only ReDoS block a production release?

<details>
<summary>Verdict and recommended action</summary>

**NOT APPLICABLE in production — dev-only and unreachable.**

`pytest` and `py` are test dependencies. They are not installed in the production
image, so there is no runtime exposure. The py ReDoS additionally requires untrusted
SVN repository metadata, which this project never processes (it uses git).

The broader lesson: **gate prod and dev findings separately.** A finding in
`requirements-dev.txt` should feed an informational report, not block a release.
That said, keep dev tooling patched — a compromised test environment is still a
supply-chain risk.

**Action:** keep `requirements-dev.txt` on a separate, non-blocking scan gate.
Upgrade `pytest` and `py` during normal tooling maintenance.

</details>

---

## Reducing the noise

Apply roughly in order. The aim is a *trustworthy* gate, not a *silent* one.

### 1. Fix the true positives first — upgrade
The only real remediation. Upgrading **PyYAML** and **Pillow** removes the only
exploitable findings and (for Pillow) ~50 advisories in one move. Always upgrade the
**direct** dependency; it usually pulls fixed transitive versions too.

### 2. Separate production from development
Scan and gate them differently. A dev-only ReDoS shouldn't block a release. Best of
all, scan the **built artefact / container image**, which contains only what ships:
```bash
osv-scanner scan source --lockfile requirements.txt        # prod gate
osv-scanner scan source --lockfile requirements-dev.txt    # dev, informational
```

### 3. Ignore triaged findings — with a reason and an expiry
For findings you've judged not-applicable, record the decision in `osv-scanner.toml`
so the gate stays quiet *and auditable*:
```toml
[[IgnoredVulns]]
id = "CVE-2020-28493"                       # also accepts GHSA-/PYSEC- ids
reason = "urlize filter not used; unreachable."
ignoreUntil = "2026-12-31T00:00:00Z"        # MUST be full RFC3339 — a bare date is silently ignored
```
`ignoreUntil` forces you to re-confirm — silence is time-boxed, never permanent.
Never ignore a finding you haven't actually triaged (that's how the PyYAML RCE
would slip through).

### 4. Record applicability as VEX
For sharing triage decisions with downstream consumers or your security platform, a
**VEX** (Vulnerability Exploitability eXchange) document states "not affected" with a
machine-readable justification (`vulnerable_code_not_in_execute_path`,
`component_not_present`, …). It is the portable, standardised cousin of the ignore
file — the same decisions, consumable by other tools.

### 5. Make it continuous
Pinned-and-forgotten is why this app has 112 findings. Use a lockfile, automate
upgrades (**Dependabot / Renovate**), generate an **SBOM**, and re-scan in CI so new
advisories surface as small, reviewable PRs instead of an annual avalanche.

---

## Key takeaways

- **A version match is not an exploitable bug.** Reachability and applicability turn a finding into a verdict.
- **Prioritise by package and by exploitability.** One Pillow upgrade beats triaging fifty findings individually; a reachable KEV entry beats ten unreachable criticals.
- **Same package, different verdicts per CVE.** Never blanket-ignore a package — read each advisory separately (Werkzeug is the clearest example here).
- **Prod ≠ dev.** Gate them separately, or scan what actually ships.
- **Never blanket-suppress.** Ignore specific, triaged findings with a reason and an expiry — the PyYAML RCE is one lazy `osv-scanner.toml` entry away from being silenced.
- **The real fix is upgrading.** Ignore files manage noise; they don't remove risk.
