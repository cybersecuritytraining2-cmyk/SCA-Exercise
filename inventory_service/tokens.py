"""Session token helpers — symmetric (Fernet) tokens only."""

from cryptography.fernet import Fernet


def issue_token(key, payload):
    """Issue a Fernet token.

    SCA findings: cryptography 3.3.1 (e.g. CVE-2023-0286 X.509 GeneralName type
    confusion, CVE-2024-0727 PKCS12 DoS, CVE-2020-36242 symmetric overflow on
    very large payloads).

    Verdict: mostly NOT APPLICABLE. We use cryptography only for Fernet tokens of
    small, server-generated payloads. The X.509/PKCS parsing advisories live in
    code paths we never call, and CVE-2020-36242 needs multi-GB inputs we never
    pass. Keep current as hygiene; not an exploitable path here.
    """
    return Fernet(key).encrypt(payload)


def read_token(key, token):
    return Fernet(key).decrypt(token)
