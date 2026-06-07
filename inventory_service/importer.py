"""Bulk inventory import from a YAML file uploaded by an operator."""

import yaml


def import_inventory(uploaded_bytes):
    """Parse an uploaded inventory file.

    SCA finding: PyYAML 5.3.1 — CVE-2020-14343 (arbitrary code execution when
    untrusted input is parsed with the full loader).

    Verdict: TRUE POSITIVE. `uploaded_bytes` comes straight from an HTTP upload
    (untrusted) and `yaml.load` here uses the default full loader, which executes
    Python object tags like `!!python/object/apply:os.system`. This is exactly
    the reachable, exploitable path the advisory describes. Fix it.
    """
    return yaml.load(uploaded_bytes)  # reachable on untrusted input — see README
