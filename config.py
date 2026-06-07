"""Runtime configuration for InventoryService."""


class Config:
    # The interactive debugger is OFF in every deployed environment.
    #
    # SCA finding: Werkzeug 0.15.5 — CVE-2024-34069 (the debugger can be abused
    # for RCE) and related debugger/dev-server advisories.
    #
    # Verdict: NOT APPLICABLE in this configuration. Those advisories require the
    # interactive debugger / dev server to be running (DEBUG=True). Production
    # runs behind gunicorn with DEBUG=False, so the vulnerable feature is never
    # active. (The multipart-DoS advisories are a separate question — see README.)
    DEBUG = False
    UPLOAD_MAX_BYTES = 5 * 1024 * 1024
